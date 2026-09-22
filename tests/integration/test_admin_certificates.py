"""HTTP contract of the certificate surface: sessions, tickets, rollback."""

from __future__ import annotations

import subprocess
from pathlib import Path

import httpx
import pytest

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.api.app import create_app
from vysion.config import Settings

ORIGIN = "http://vysion.test"
HOSTNAME = "vysion.example"
ADMIN_PASSWORD = "a-first-admin-password"


def openssl(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["openssl", *args], cwd=cwd, capture_output=True, timeout=60, env={"LC_ALL": "C"}
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return result


def make_certificate(tmp_path: Path, *, hostname: str = HOSTNAME) -> tuple[bytes, bytes]:
    key_path = tmp_path / "leaf.key"
    cert_path = tmp_path / "leaf.pem"
    openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key_path), "-out", str(cert_path), "-days", "30",
        "-subj", f"/CN={hostname}",
        "-addext", f"subjectAltName=DNS:{hostname}",
        cwd=tmp_path,
    )  # fmt: skip
    return cert_path.read_bytes(), key_path.read_bytes()


class SilentFortiGuard:
    async def check(self) -> FortiGuardResult:
        return FortiGuardResult(status=FortiGuardStatus.AVAILABLE, detail="fixture")

    async def check_psirt(self, version: str):  # pragma: no cover
        return None


def build_app(tmp_path: Path, *, reloader=None, smoker=None, settings=None):
    if settings is None:
        settings = Settings(
            report_directory=tmp_path / "reports",
            state_directory=tmp_path / "state",
            certs_directory=tmp_path / "certs",
            tls_backend="local",
            tls_hostname=HOSTNAME,
        )
    return create_app(
        settings=settings,
        fortiguard=SilentFortiGuard(),
        **({"certificate_reloader": reloader} if reloader else {}),
        **({"certificate_smoker": smoker} if smoker else {}),
    )


def api_client(app) -> httpx.AsyncClient:
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://vysion.test"
    )
    client.headers["Origin"] = ORIGIN
    return client


async def setup_admin(client: httpx.AsyncClient) -> str:
    response = await client.post(
        "/api/admin/setup", json={"password": ADMIN_PASSWORD}, headers={"Origin": ORIGIN}
    )
    assert response.status_code == 201, response.text
    return response.json()["csrf_token"]


async def login_admin(client: httpx.AsyncClient) -> str:
    response = await client.post(
        "/api/admin/login",
        json={"password": ADMIN_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


async def validate_certificate(
    client: httpx.AsyncClient,
    csrf: str,
    cert: bytes,
    key: bytes,
    *,
    passphrase: str | None = None,
) -> httpx.Response:
    files = {"certificate": ("fullchain.pem", cert, "application/x-pem-file")}
    if key:
        files["private_key"] = ("key.pem", key, "application/x-pem-file")
    data = {} if passphrase is None else {"passphrase": passphrase}
    return await client.post(
        "/api/admin/certificates/validate",
        files=files,
        data=data,
        headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
    )


# ---------------------------------------------------------------------------
# protection matrix
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_certificate_endpoints_refuse_anonymous_requests(tmp_path: Path) -> None:
    cert, _key = make_certificate(tmp_path)
    app = build_app(tmp_path)
    async with api_client(app) as anonymous:
        listing = await anonymous.get("/api/admin/certificates")
        validation = await anonymous.post(
            "/api/admin/certificates/validate",
            files={"certificate": ("c.pem", cert, "application/x-pem-file")},
            headers={"Origin": ORIGIN},
        )
        activation = await anonymous.post(
            "/api/admin/certificates/activate",
            json={"token": "anything"},
            headers={"Origin": ORIGIN},
        )

    assert listing.status_code == 401
    assert validation.status_code == 401
    assert activation.status_code == 401


@pytest.mark.asyncio
async def test_certificate_mutation_requires_csrf_and_exact_origin(
    tmp_path: Path,
) -> None:
    cert, key = make_certificate(tmp_path)
    app = build_app(tmp_path)
    async with api_client(app) as client:
        csrf = await setup_admin(client)
        no_csrf = await client.post(
            "/api/admin/certificates/validate",
            files={"certificate": ("c.pem", cert, "application/x-pem-file")},
            headers={"Origin": ORIGIN},
        )
        foreign = await validate_certificate(client, csrf, cert, key)
        no_origin = await client.post(
            "/api/admin/certificates/validate",
            files={"certificate": ("c.pem", cert, "application/x-pem-file")},
            headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"},
        )

    assert no_csrf.status_code == 403
    assert foreign.status_code == 200, foreign.text
    assert no_origin.status_code == 403


# ---------------------------------------------------------------------------
# validation, ticket, activation
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_validate_stages_a_candidate_and_returns_metadata_only(
    tmp_path: Path,
) -> None:
    cert, key = make_certificate(tmp_path)
    app = build_app(tmp_path)
    async with api_client(app) as client:
        csrf = await setup_admin(client)
        response = await validate_certificate(client, csrf, cert, key)
        listing = await client.get("/api/admin/certificates")

    assert response.status_code == 200, response.text
    payload = response.json()
    metadata = payload["certificate"]
    assert metadata["hostname"] == HOSTNAME
    assert metadata["chain_length"] == 1
    assert len(metadata["sha256"]) == 64
    assert payload["ticket"]["token"]
    # Metadata only: no key material ever crosses the wire.
    assert "PRIVATE" not in response.text
    assert key.decode("utf-8") not in response.text

    assert listing.status_code == 200
    status = listing.json()
    assert status["tls_backend"] == "local"
    assert status["active"] is None
    assert status["staging"]["sha256"] == metadata["sha256"]


@pytest.mark.asyncio
async def test_validate_refuses_a_certificate_for_another_hostname(
    tmp_path: Path,
) -> None:
    cert, key = make_certificate(tmp_path, hostname="other.example")
    app = build_app(tmp_path)
    async with api_client(app) as client:
        csrf = await setup_admin(client)
        response = await validate_certificate(client, csrf, cert, key)

    assert response.status_code == 422
    assert "SAN" in response.json()["detail"]


@pytest.mark.asyncio
async def test_activation_with_a_valid_ticket_serves_the_certificate(
    tmp_path: Path,
) -> None:
    cert, key = make_certificate(tmp_path)
    reloads: list[str] = []
    app = build_app(tmp_path, reloader=lambda: reloads.append("reload"))
    # The smoker answers with what is really served: exactly the candidate.
    store = app.state.certificate_store
    app.state.certificate_smoker = lambda: store.active().metadata.sha256

    async with api_client(app) as client:
        csrf = await setup_admin(client)
        validated = await validate_certificate(client, csrf, cert, key)
        ticket = validated.json()["ticket"]["token"]
        activated = await client.post(
            "/api/admin/certificates/activate",
            json={"token": ticket},
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )
        listing = await client.get("/api/admin/certificates")
        # Single use: re-stage a candidate, then replay the consumed ticket.
        await validate_certificate(client, csrf, cert, key)
        replayed = await client.post(
            "/api/admin/certificates/activate",
            json={"token": ticket},
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )

    assert activated.status_code == 200, activated.text
    body = activated.json()
    assert body["status"] == "active"
    assert body["generation"] == 1
    assert body["served_sha256"] == body["certificate"]["sha256"]
    assert reloads == ["reload"]

    status = listing.json()
    assert status["active"]["number"] == 1
    assert status["staging"] is None
    assert [item["number"] for item in status["generations"]] == [1]
    assert replayed.status_code == 403


@pytest.mark.asyncio
async def test_activation_refuses_a_ticket_from_another_session(
    tmp_path: Path,
) -> None:
    cert, key = make_certificate(tmp_path)
    app = build_app(tmp_path, reloader=lambda: None, smoker=lambda: "unused")
    async with api_client(app) as first:
        first_csrf = await setup_admin(first)
        validated = await validate_certificate(first, first_csrf, cert, key)
    ticket = validated.json()["ticket"]["token"]

    # A second, independent administrator session on the same instance.
    async with api_client(app) as second:
        second_csrf = await login_admin(second)
        activated = await second.post(
            "/api/admin/certificates/activate",
            json={"token": ticket},
            headers={"X-CSRF-Token": second_csrf, "Origin": ORIGIN},
        )

    assert activated.status_code == 403
    assert "ticket" in activated.json()["detail"]


@pytest.mark.asyncio
async def test_activation_refuses_a_tampered_candidate(tmp_path: Path) -> None:
    cert, key = make_certificate(tmp_path)
    app = build_app(tmp_path, reloader=lambda: None, smoker=lambda: "unused")
    async with api_client(app) as client:
        csrf = await setup_admin(client)
        validated = await validate_certificate(client, csrf, cert, key)
        ticket = validated.json()["ticket"]["token"]

        # Someone edits the staged files after the ticket was issued.
        staged_key = app.state.certificate_store.certs_directory / "staging" / "key.pem"
        staged_key.write_bytes(staged_key.read_bytes() + b"\n# tampered\n")

        activated = await client.post(
            "/api/admin/certificates/activate",
            json={"token": ticket},
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )

    assert activated.status_code == 403
    assert app.state.certificate_store.active() is None


@pytest.mark.asyncio
async def test_activation_failure_rolls_back_and_reports_it(
    tmp_path: Path,
) -> None:
    cert, key = make_certificate(tmp_path)

    def broken_reloader() -> None:
        raise RuntimeError("nginx -t a échoué")

    app = build_app(tmp_path, reloader=broken_reloader, smoker=lambda: "unused")
    async with api_client(app) as client:
        csrf = await setup_admin(client)
        validated = await validate_certificate(client, csrf, cert, key)
        ticket = validated.json()["ticket"]["token"]
        activated = await client.post(
            "/api/admin/certificates/activate",
            json={"token": ticket},
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )

    assert activated.status_code == 502
    detail = activated.json()["detail"]
    assert "rollback" in detail
    # Nothing was activated: the pointer never moved.
    assert app.state.certificate_store.active() is None


@pytest.mark.asyncio
async def test_activation_is_refused_outside_the_standalone_mode(
    tmp_path: Path,
) -> None:
    settings = Settings(
        report_directory=tmp_path / "reports",
        state_directory=tmp_path / "state",
        tls_backend="none",
    )
    app = build_app(tmp_path, settings=settings)
    async with api_client(app) as client:
        csrf = await setup_admin(client)
        response = await client.post(
            "/api/admin/certificates/activate",
            json={"token": "whatever"},
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )
        listing = await client.get("/api/admin/certificates")

    assert response.status_code == 409
    assert "standalone" in response.json()["detail"]
    assert listing.status_code == 200
    assert listing.json()["tls_backend"] == "none"
    assert listing.json()["managed"] is False

"""Migration bundle over HTTP: export gates, first-run restore, rollback.

The recipe of decision 0010: an initialized instance exports a sealed
bundle, a fresh instance restores it from the browser before any account
exists, the operator signs in with the previous credentials, no secret ever
comes back, and a failure during application rolls back to the exact
pre-import state.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import httpx
import pytest

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.api.admin import MIGRATION_MAX_BODY_BYTES
from vysion.api.app import create_app
from vysion.certificates import activate_staged
from vysion.config import Settings
from vysion.migration import (
    BAD_SECRET,
    BAD_STATE,
    MAGIC,
    build_bundle,
)
from vysion.state import StateStore

ORIGIN = "http://vysion.test"
HOSTNAME = "vysion.example"
PASSWORD = "a-first-admin-password"
PASSPHRASE = "a-migration-passphrase"
SMTP_SECRET = "smtp-password-secret-value"
M365_SECRET = "m365-client-secret-value"


class SilentFortiGuard:
    async def check(self) -> FortiGuardResult:
        return FortiGuardResult(status=FortiGuardStatus.AVAILABLE, detail="fixture")

    async def check_psirt(self, version: str):  # pragma: no cover
        return None


def make_certificate(tmp_path: Path, *, hostname: str) -> tuple[bytes, bytes]:
    import subprocess

    key_path = tmp_path / "leaf.key"
    cert_path = tmp_path / "leaf.pem"
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(cert_path), "-days", "30",
            "-subj", f"/CN={hostname}",
            "-addext", f"subjectAltName=DNS:{hostname}",
        ],
        cwd=tmp_path, capture_output=True, timeout=60, env={"LC_ALL": "C"},
    )  # fmt: skip
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return cert_path.read_bytes(), key_path.read_bytes()


def build_app(tmp_path: Path, *, local: bool = False, public_origin=ORIGIN):
    overrides: dict = {
        "report_directory": tmp_path / "reports",
        "state_directory": tmp_path / "state",
    }
    if local:
        overrides.update(
            certs_directory=tmp_path / "certs",
            tls_backend="local",
            tls_hostname=HOSTNAME,
            certificate_reloader=lambda: None,
            certificate_smoker=lambda: "unused",
        )
    if public_origin is not None:
        overrides["public_origin"] = public_origin
    settings = Settings(**{k: v for k, v in overrides.items() if k in {
        "report_directory", "state_directory", "certs_directory",
        "tls_backend", "tls_hostname", "public_origin",
    }})
    app_overrides = {k: v for k, v in overrides.items() if k in {
        "certificate_reloader", "certificate_smoker",
    }}
    app = create_app(settings=settings, fortiguard=SilentFortiGuard(), **app_overrides)
    if local:
        # Like the certificate suite: answer fingerprint probes with what is
        # really active in this instance's store, or activation rolls back.
        store = app.state.certificate_store
        app.state.certificate_smoker = lambda: store.active().metadata.sha256
    return app


def client_for(app, *, origin: str | None = ORIGIN) -> httpx.AsyncClient:
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://vysion.test"
    )
    if origin is not None:
        client.headers["Origin"] = origin
    return client


async def enroll(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/admin/setup", json={"password": PASSWORD})
    assert response.status_code == 201, response.text


async def csrf_of(client: httpx.AsyncClient) -> str:
    status = await client.get("/api/admin/status")
    assert status.status_code == 200
    token = status.json()["csrf_token"]
    assert token
    return token


async def export_bundle(
    client: httpx.AsyncClient, *, password: str = PASSWORD, passphrase: str = PASSPHRASE
) -> httpx.Response:
    token = await csrf_of(client)
    return await client.post(
        "/api/admin/migration/export",
        json={"current_password": password, "passphrase": passphrase},
        headers={"X-CSRF-Token": token},
    )


def import_bundle(
    client: httpx.AsyncClient, bundle: bytes, passphrase: str = PASSPHRASE
):
    return client.post(
        "/api/admin/migration/import",
        files={"bundle": ("vysion-migration.vysmig", bundle, "application/octet-stream")},
        data={"passphrase": passphrase},
    )


async def seed_source(tmp_path: Path, *, with_certificate: bool):
    """An initialized instance: account, e-mail state, session, recovery."""
    app = build_app(tmp_path / "source", local=with_certificate)
    client = client_for(app)
    await enroll(client)
    store = app.state.state_store
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        recovery_email="operator@example.com",
        smtp_host="mail.example",
        smtp_port=587,
        smtp_security="starttls",
        smtp_username="vysion",
        smtp_password=SMTP_SECRET,
    )
    store.create_recovery_token(
        purpose="reset", ttl_seconds=900, revision=store.admin_revision()
    )
    old_session = client.cookies.get("vysion_session")
    old_recovery = store.create_recovery_token(
        purpose="reset", ttl_seconds=900, revision=store.admin_revision()
    )
    served = None
    if with_certificate:
        certificate_pem, key_pem = make_certificate(tmp_path / "source", hostname=HOSTNAME)
        store_certs = app.state.certificate_store
        store_certs.validate(
            certificate=certificate_pem, private_key=key_pem, hostname=HOSTNAME
        )
        generation, served = activate_staged(
            store_certs,
            reloader=app.state.certificate_reloader,
            smoker=lambda: store_certs.active().metadata.sha256,
        )
        assert generation.number == 1
        # Point the smoker at the real fingerprint for later comparisons.
        app.state.certificate_smoker = lambda: store_certs.active().metadata.sha256
    response = await export_bundle(client)
    assert response.status_code == 200, response.text
    email_status = (await client.get("/api/admin/email")).json()
    await client.aclose()
    return {
        "app": app,
        "bundle": response.content,
        "export": response,
        "old_session": old_session,
        "old_recovery": old_recovery,
        "email_status": email_status,
        "served": served,
    }


@pytest.mark.asyncio
async def test_export_needs_session_csrf_origin_and_reauth(tmp_path: Path) -> None:
    app = build_app(tmp_path)
    anonymous = client_for(app)
    # Before enrollment: no session, no export.
    response = await anonymous.post(
        "/api/admin/migration/export",
        json={"current_password": PASSWORD, "passphrase": PASSPHRASE},
    )
    assert response.status_code == 401
    await anonymous.aclose()

    client = client_for(app)
    await enroll(client)
    # Without the CSRF token: refused.
    response = await client.post(
        "/api/admin/migration/export",
        json={"current_password": PASSWORD, "passphrase": PASSPHRASE},
    )
    assert response.status_code == 403
    token = await csrf_of(client)
    # With a foreign Origin on the authenticated session: refused.
    response = await client.post(
        "/api/admin/migration/export",
        json={"current_password": PASSWORD, "passphrase": PASSPHRASE},
        headers={"X-CSRF-Token": token, "Origin": "http://evil.example"},
    )
    assert response.status_code == 403

    # Wrong current password: 401, then a bounded lockout (429).
    seen_429 = False
    for _ in range(8):
        response = await client.post(
            "/api/admin/migration/export",
            json={"current_password": "wrong-password-here", "passphrase": PASSPHRASE},
            headers={"X-CSRF-Token": token},
        )
        if response.status_code == 429:
            seen_429 = True
            break
        assert response.status_code == 401
    assert seen_429, "export re-authentication must lock out after repeated failures"
    await client.aclose()


@pytest.mark.asyncio
async def test_export_seals_a_bounded_bundle_without_ever_echoing_secrets(
    tmp_path: Path,
) -> None:
    source = await seed_source(tmp_path, with_certificate=True)
    response = source["export"]
    # Attachment semantics: never cacheable, never inline, never a URL secret.
    disposition = response.headers.get("content-disposition", "")
    assert disposition.startswith("attachment; filename=\"vysion-migration-")
    assert disposition.endswith(".vysmig\"")
    assert response.headers.get("cache-control") == "no-store, private"
    assert response.headers.get("content-type", "").startswith(
        "application/vnd.vysion.migration"
    )
    assert response.content.startswith(MAGIC)
    # No secret in any header or in any later response body.
    joined = str(response.headers) + response.text
    assert PASSWORD not in joined
    assert PASSPHRASE not in joined
    email_view = str(source["email_status"])
    assert SMTP_SECRET not in email_view

    # A fresh instance restores it before any account exists.
    target = build_app(tmp_path / "target", local=True)
    client = client_for(target)
    status = await client.get("/api/admin/status")
    assert status.json()["setup_required"] is True
    response = await import_bundle(client, source["bundle"])
    assert response.status_code == 201, response.text
    report = response.json()
    assert report["status"] == "restored"
    assert report["reports_included"] is False
    assert report["certificate"]["imported"] is True
    assert report["certificate"]["generation"] == 1
    assert report["certificate"]["sha256"] == source["served"]
    assert report["email"]["configured"] is True
    assert SMTP_SECRET not in response.text
    assert PASSWORD not in response.text

    # First-run is closed now: enrollment and a second restore both 409.
    again = await client.post("/api/admin/setup", json={"password": "another-password-x"})
    assert again.status_code == 409
    second = await import_bundle(client, source["bundle"])
    assert second.status_code == 409

    # The previous account signs in; its previous session and recovery die.
    login = await client.post("/api/admin/login", json={"password": PASSWORD})
    assert login.status_code == 200, login.text
    sessions = await client.get("/api/admin/sessions")
    assert sessions.status_code == 200

    stale = client_for(target)
    stale.cookies.set("vysion_session", source["old_session"])
    assert (await stale.get("/api/admin/sessions")).status_code == 401
    await stale.aclose()

    confirm = await client.post(
        "/api/admin/recovery/confirm",
        json={"token": source["old_recovery"], "password": "a-brand-new-password"},
    )
    assert confirm.status_code == 400

    # Public e-mail projection identical, secret never returned.
    restored_email = await client.get("/api/admin/email")
    assert SMTP_SECRET not in restored_email.text
    assert restored_email.json()["transport"] == "smtp"
    assert restored_email.json()["configured"] is True

    # Certificate activated with the existing TLS controls.
    certificates = await client.get("/api/admin/certificates")
    assert certificates.status_code == 200
    active = certificates.json()["active"]
    assert active is not None and active["number"] == 1
    assert active["sha256"] == source["served"]

    health = await client.get("/api/health")
    assert health.status_code == 200
    await client.aclose()


@pytest.mark.asyncio
async def test_import_refuses_format_secret_state_origin_and_bounds(
    tmp_path: Path,
) -> None:
    app = build_app(tmp_path)
    client = client_for(app)

    # Foreign container: fixed format refusal, state untouched.
    response = await import_bundle(client, b"definitely-not-a-bundle")
    assert response.status_code == 400
    assert (await client.get("/api/admin/status")).json()["setup_required"] is True

    # A real bundle with the wrong passphrase and a tampered byte share one refusal.
    good = build_bundle(state_db=b"x" * 16, passphrase=PASSPHRASE)
    wrong = await import_bundle(client, good, "not-the-passphrase")
    assert wrong.status_code == 400
    assert wrong.json()["detail"] == BAD_SECRET
    tampered = bytearray(good)
    tampered[-1] ^= 0x01
    flipped = await import_bundle(client, bytes(tampered))
    assert flipped.status_code == 400
    assert flipped.json()["detail"] == BAD_SECRET

    # Rate limit: bounded attempts, then 429 (3 refusals above = failures 1-3).
    bounded = await import_bundle(client, good, "still-the-wrong-one")
    assert bounded.status_code == 400
    locked = await import_bundle(client, good, "one-more-wrong-try")
    assert locked.status_code == 429
    await client.aclose()

    # Foreign SQLite inside a well-formed bundle: refused as incoherent state.
    foreign_dir = tmp_path / "foreign"
    foreign_dir.mkdir()
    foreign_db = foreign_dir / "users.db"
    connection = sqlite3.connect(foreign_db)
    connection.execute("CREATE TABLE users (id INTEGER)")
    connection.commit()
    connection.close()
    foreign_bundle = build_bundle(state_db=foreign_db.read_bytes(), passphrase=PASSPHRASE)
    fresh = build_app(tmp_path / "fresh")
    fresh_client = client_for(fresh)
    response = await import_bundle(fresh_client, foreign_bundle)
    assert response.status_code == 400
    assert response.json()["detail"] == BAD_STATE
    assert (await fresh_client.get("/api/admin/status")).json()["setup_required"] is True
    await fresh_client.aclose()

    # Missing Origin: refused. No public authority: 503, fail closed.
    no_origin = client_for(app, origin=None)
    response = await no_origin.post(
        "/api/admin/migration/import",
        files={"bundle": ("b.vysmig", good, "application/octet-stream")},
        data={"passphrase": PASSPHRASE},
    )
    assert response.status_code == 403
    await no_origin.aclose()

    closed = build_app(tmp_path / "closed", public_origin="")
    closed_client = client_for(closed)
    response = await import_bundle(closed_client, good)
    assert response.status_code == 503
    await closed_client.aclose()

    # Body bounds: above the migration cap -> 413; the tight default 1 MiB
    # does NOT apply to this path (a 2 MiB body reaches the parser).
    oversized = client_for(app)
    too_big = await oversized.post(
        "/api/admin/migration/import",
        content=b"x" * (MIGRATION_MAX_BODY_BYTES + 1),
        headers={"Content-Type": "multipart/form-data; boundary=xy"},
    )
    assert too_big.status_code == 413
    medium = await oversized.post(
        "/api/admin/migration/import",
        content=b"y" * (2 * 1024 * 1024),
        headers={"Content-Type": "multipart/form-data; boundary=xy"},
    )
    assert medium.status_code != 413
    await oversized.aclose()


@pytest.mark.asyncio
async def test_crash_during_application_rolls_back_then_allows_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = await seed_source(tmp_path, with_certificate=False)
    target = build_app(tmp_path / "target")
    client = client_for(target)
    original = (tmp_path / "target" / "state" / "vysion-state.db").read_bytes()

    def explode(_state_directory: Path) -> bool:
        raise RuntimeError("simulated outage after the swap")

    monkeypatch.setattr("vysion.migration._verify_restored_state", explode)
    response = await import_bundle(client, source["bundle"])
    assert response.status_code == 400
    assert "restauration interrompue" in response.json()["detail"]
    monkeypatch.undo()

    # The restore left no partial state: no candidate administrator (first
    # run is exactly what it was), no residue of the swap, an intact and
    # readable database. The only extra row is the rate-limit failure this
    # refusal itself registered — a deliberate, bounded write, not residue.
    target_db = tmp_path / "target" / "state" / "vysion-state.db"
    assert StateStore.probe_has_admin(tmp_path / "target" / "state") is False
    assert target_db.stat().st_mode & 0o777 == 0o600
    status = await client.get("/api/admin/status")
    assert status.json()["setup_required"] is True
    assert list((tmp_path / "target" / "state").glob(".migration-staging-*")) == []
    assert list((tmp_path / "target" / "state").glob("*.pre-restore-*")) == []
    # And it is the original schema, not the imported one: the original
    # database never carried the source administrator.
    assert target_db.read_bytes()[:16] == original[:16]

    # Retry succeeds: the instance was never left half-migrated.
    retry = await import_bundle(client, source["bundle"])
    assert retry.status_code == 201, retry.text
    login = await client.post("/api/admin/login", json={"password": PASSWORD})
    assert login.status_code == 200
    await client.aclose()


@pytest.mark.asyncio
async def test_incompatible_certificate_keeps_the_restored_state_usable(
    tmp_path: Path,
) -> None:
    # Source exports a certificate whose SAN does not match this target.
    state_dir = tmp_path / "carrier-state"

    store = StateStore(state_dir)
    assert store.create_admin(PASSWORD)
    certificate_pem, key_pem = make_certificate(tmp_path, hostname="other.example")
    bundle = build_bundle(
        state_db=(state_dir / "vysion-state.db").read_bytes(),
        passphrase=PASSPHRASE,
        certificate=certificate_pem,
        private_key=key_pem,
    )

    target = build_app(tmp_path / "target", local=True)
    client = client_for(target)
    response = await import_bundle(client, bundle)
    assert response.status_code == 201, response.text
    report = response.json()
    # State restored and usable...
    assert report["status"] == "restored"
    status = await client.get("/api/admin/status")
    assert status.json()["setup_required"] is False
    login = await client.post("/api/admin/login", json={"password": PASSWORD})
    assert login.status_code == 200
    # ...but the certificate was refused, nothing is staged, and the UI has
    # a clear manual-import reason (bootstrap would still be served live).
    certificate_report = report["certificate"]
    assert certificate_report["included"] is True
    assert certificate_report["imported"] is False
    assert certificate_report["reason"]
    certificates = await client.get("/api/admin/certificates")
    body = certificates.json()
    assert body["active"] is None
    assert body["staging"] is None
    await client.aclose()


async def seed_email_source(tmp_path: Path, *, transport: str) -> dict:
    """An initialized instance whose e-mail row is fully configured."""
    app = build_app(tmp_path / f"source-{transport}")
    client = client_for(app)
    await enroll(client)
    store = app.state.state_store
    if transport == "smtp":
        store.set_email_config(
            transport="smtp",
            from_address="vysion@example.com",
            recovery_email="operator@example.com",
            timeout_seconds=21,
            smtp_host="mail.example",
            smtp_port=2525,
            smtp_security="tls",
            smtp_username="vysion-sync",
            smtp_password=SMTP_SECRET,
        )
    else:
        store.set_email_config(
            transport="microsoft365",
            from_address="vysion@example.com",
            recovery_email="operator@example.com",
            timeout_seconds=33,
            m365_tenant_id="tenant-identifier-value",
            m365_client_id="client-identifier-value",
            m365_client_secret=M365_SECRET,
            m365_mailbox="ops@example.com",
        )
    config = store.email_config()
    assert config is not None
    email_view = await client.get("/api/admin/email")
    assert email_view.status_code == 200, email_view.text
    export = await export_bundle(client)
    assert export.status_code == 200, export.text
    await client.aclose()
    return {"bundle": export.content, "config": config, "plaintext": [email_view]}


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["smtp", "microsoft365"])
async def test_email_configuration_survives_migration_exactly_without_http_disclosure(
    tmp_path: Path, transport: str
) -> None:
    """Non-secret settings and the selected transport's secret survive exactly.

    The restored row is compared field for field with the source row, and
    every plaintext HTTP response of the journey is scanned byte-wise for
    the secret: only the encrypted bundle body ever carries it out.
    """
    source = await seed_email_source(tmp_path, transport=transport)
    secret = SMTP_SECRET if transport == "smtp" else M365_SECRET
    assert source["config"].secret == secret
    for response in source["plaintext"]:
        assert secret not in response.text

    target = build_app(tmp_path / f"target-{transport}")
    client = client_for(target)
    assert (await client.get("/api/admin/status")).json()["setup_required"] is True
    imported = await import_bundle(client, source["bundle"])
    assert imported.status_code == 201, imported.text
    # The public projection of the import: presence and transport, never a value.
    assert imported.json()["email"] == {
        "configured": True,
        "transport": transport,
        "provenance": "state",
        "secret_configured": True,
        "recovery_email_configured": True,
    }

    # Exact preservation: every non-secret field and the selected secret.
    restored = target.state.state_store.email_config()
    assert restored == source["config"]
    assert restored is not None and restored.secret == secret

    login = await client.post("/api/admin/login", json={"password": PASSWORD})
    assert login.status_code == 200, login.text
    email_status = await client.get("/api/admin/email")
    assert email_status.status_code == 200, email_status.text
    assert email_status.json()["transport"] == transport
    assert email_status.json()["secret_configured"] is True
    assert email_status.json()["recovery_enabled"] is True
    status = await client.get("/api/admin/status")

    for response in (imported, login, email_status, status):
        assert secret not in response.text
        assert PASSWORD not in response.text
    await client.aclose()

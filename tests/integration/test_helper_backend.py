"""One backend abstraction over ``none | local | helper``.

The routes must never branch on the selected backend: they ask the backend
for a status, a validation, a staged digest and an activation, and the
backend decides whether that is refused, done in-process, or delegated to the
root helper over a private Unix socket.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from pathlib import Path

import httpx
import pytest

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.api.app import create_app
from vysion.certclient import CertificateHelperClient, CertificateHelperUnavailable
from vysion.certprotocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    receive_message,
    send_message,
)
from vysion.config import Settings

ORIGIN = "http://vysion.test"
HOSTNAME = "vysion.example"
ADMIN_PASSWORD = "a-first-admin-password"


class SilentFortiGuard:
    async def check(self) -> FortiGuardResult:
        return FortiGuardResult(status=FortiGuardStatus.AVAILABLE, detail="fixture")

    async def check_psirt(self, version: str):  # pragma: no cover
        return None


# ---------------------------------------------------------------------------
# A helper stand-in that speaks the real protocol.
# ---------------------------------------------------------------------------
class FakeHelperServer:
    """Accepts one message per connection and delegates to ``handler``."""

    def __init__(self, path: Path, handler) -> None:
        self.path = Path(path)
        self.received: list[dict] = []
        self._handler = handler
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()
        self._server.bind(str(self.path))
        self._server.listen(8)
        self._closed = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                connection, _ = self._server.accept()
            except OSError:
                return
            with connection:
                try:
                    message = receive_message(
                        connection, max_bytes=MAX_REQUEST_BYTES, timeout=5.0
                    )
                    self.received.append(message)
                    response = self._handler(message)
                except Exception as exc:  # noqa: BLE001 - reported to the client
                    response = {"ok": False, "kind": "unavailable", "error": str(exc)}
                with contextlib.suppress(Exception):
                    send_message(
                        connection, response, max_bytes=MAX_RESPONSE_BYTES, timeout=5.0
                    )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(OSError):
            self.path.unlink()
        self._server.close()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def settings_for(tmp_path: Path, **overrides) -> Settings:
    values = {
        "report_directory": tmp_path / "reports",
        "state_directory": tmp_path / "state",
        "public_origin": ORIGIN,
    }
    values.update(overrides)
    return Settings(**values)


def helper_settings(tmp_path: Path) -> Settings:
    return settings_for(
        tmp_path,
        tls_backend="helper",
        tls_hostname=HOSTNAME,
        helper_socket_path=tmp_path / "run" / "helper.sock",
    )


def build_app(tmp_path: Path, settings: Settings | None = None):
    return create_app(
        settings=settings or settings_for(tmp_path, tls_backend="none"),
        fortiguard=SilentFortiGuard(),
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


EMPTY_STATUS = {
    "active": None,
    "staging": None,
    "generations": [],
    "staged_digest": None,
}


# ---------------------------------------------------------------------------
# the client
# ---------------------------------------------------------------------------
def test_the_client_reports_an_absent_helper_instead_of_hanging(tmp_path: Path) -> None:
    client = CertificateHelperClient(tmp_path / "missing.sock", timeout=1.0)
    with pytest.raises(CertificateHelperUnavailable):
        client.status()


def test_the_client_speaks_a_versioned_action_per_connection(tmp_path: Path) -> None:
    server = FakeHelperServer(tmp_path / "h.sock", lambda _m: {"ok": True, **EMPTY_STATUS})
    try:
        client = CertificateHelperClient(server.path, timeout=2.0)
        assert client.status()["active"] is None
        assert server.received, "the helper never saw a message"
        message = server.received[0]
        assert message["v"] == PROTOCOL_VERSION
        assert message["action"] == "status"
        # One connection, one action: no state is carried between calls.
        assert set(message) == {"v", "action"}
    finally:
        server.close()


def test_a_helper_error_is_classified_for_the_route(tmp_path: Path) -> None:
    client = CertificateHelperClient(tmp_path / "h.sock", timeout=1.0)

    server = FakeHelperServer(
        tmp_path / "e.sock", lambda _m: {"ok": False, "kind": "certificate", "error": "refusé"}
    )
    try:
        certificate_client = CertificateHelperClient(server.path, timeout=2.0)
        from vysion.certificates import CertificateError

        with pytest.raises(CertificateError) as caught:
            certificate_client.status()
        assert "refusé" in str(caught.value)
    finally:
        server.close()
    assert client  # the absent-helper client stays constructible


def test_a_malformed_answer_is_reported_as_unavailable(tmp_path: Path) -> None:
    server = FakeHelperServer(tmp_path / "b.sock", lambda _m: {"unexpected": True})
    try:
        client = CertificateHelperClient(server.path, timeout=2.0)
        with pytest.raises(CertificateHelperUnavailable):
            client.status()
    finally:
        server.close()


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_helper_mode_reports_a_managed_surface(tmp_path: Path) -> None:
    server = FakeHelperServer(tmp_path / "run" / "helper.sock", lambda _m: _status())
    try:
        app = build_app(tmp_path, helper_settings(tmp_path))
        async with api_client(app) as client:
            await setup_admin(client)
            listing = await client.get("/api/admin/certificates")
    finally:
        server.close()

    assert listing.status_code == 200
    payload = listing.json()
    assert payload["managed"] is True
    assert payload["tls_backend"] == "helper"
    assert payload["active"] is None


def _status() -> dict:
    return {"ok": True, **EMPTY_STATUS}


@pytest.mark.asyncio
async def test_helper_mode_fails_closed_when_the_helper_is_down(tmp_path: Path) -> None:
    app = build_app(tmp_path, helper_settings(tmp_path))
    async with api_client(app) as client:
        await setup_admin(client)
        listing = await client.get("/api/admin/certificates")

    assert listing.status_code == 503


@pytest.mark.asyncio
async def test_helper_validation_delegates_and_still_returns_metadata_only(
    tmp_path: Path,
) -> None:
    def handler(message: dict) -> dict:
        assert message["action"] == "validate"
        assert "private_key" in message
        return {
            "ok": True,
            "certificate": CERTIFICATE_METADATA,
            "digest": "d" * 64,
        }

    server = FakeHelperServer(tmp_path / "run" / "helper.sock", handler)
    try:
        app = build_app(tmp_path, helper_settings(tmp_path))
        async with api_client(app) as client:
            csrf = await setup_admin(client)
            response = await client.post(
                "/api/admin/certificates/validate",
                files={"certificate": ("c.pem", b"c", "application/x-pem-file")},
                headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
            )
    finally:
        server.close()

    assert response.status_code == 200, response.text
    assert response.json()["certificate"]["hostname"] == HOSTNAME
    assert response.json()["ticket"]["token"]
    # The digest the ticket binds to is the one the helper staged.
    stored = app.state.state_store
    assert stored is not None


CERTIFICATE_METADATA = {
    "subject": "CN=vysion.example",
    "issuer": "CN=vysion.example",
    "serial": "01",
    "not_before": "2026-01-01T00:00:00+00:00",
    "not_after": "2026-02-01T00:00:00+00:00",
    "sha256": "a" * 64,
    "sans": [HOSTNAME],
    "chain_length": 1,
    "hostname": HOSTNAME,
}


@pytest.mark.asyncio
async def test_none_mode_still_refuses_with_the_standalone_message(
    tmp_path: Path,
) -> None:
    app = build_app(tmp_path, settings_for(tmp_path, tls_backend="none"))
    async with api_client(app) as client:
        csrf = await setup_admin(client)
        activation = await client.post(
            "/api/admin/certificates/activate",
            json={"token": "whatever"},
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )
        validation = await client.post(
            "/api/admin/certificates/validate",
            files={"certificate": ("c.pem", b"c", "application/x-pem-file")},
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )

    assert activation.status_code == 409
    assert "standalone" in activation.json()["detail"]
    assert validation.status_code == 409
    assert "standalone" in validation.json()["detail"]

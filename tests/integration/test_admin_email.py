"""HTTP contract of the single Email section: two transports, write-only secrets.

The public projections must never carry a secret, every mutation must demand
a session plus CSRF and an exact Origin, and the test send must be rate
limited per client while reading the last saved configuration.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from test_admin_api import RecordingMailer, api_client, build_app, setup_admin

from vysion.mail import RecoveryUnavailable, TransportMailer

CSRF = "x-csrf-token"

SMTP_PAYLOAD = {
    "transport": "smtp",
    "from_address": "vysion@internal.example",
    "recovery_email": "operator@internal.example",
    "timeout_seconds": 10,
    "smtp_host": "smtp.internal.example",
    "smtp_port": 587,
    "smtp_security": "starttls",
    "smtp_username": "vysion@internal.example",
    "smtp_password": "write-only-secret",
}

M365_PAYLOAD = {
    "transport": "microsoft365",
    "from_address": "vysion@internal.example",
    "recovery_email": "operator@internal.example",
    "timeout_seconds": 10,
    "m365_tenant_id": "00000000-0000-4000-8000-000000000000",
    "m365_client_id": "11111111-1111-4111-8111-111111111111",
    "m365_client_secret": "graph-write-only-secret",
    "m365_mailbox": "vysion@internal.example",
}


def _patched(payload: dict, **overrides) -> dict:
    merged = dict(payload)
    merged.update(overrides)
    return merged


class TransportRecorder:
    """Stands in for the transport: records which one was selected."""

    def __init__(self, recipients: list[str]) -> None:
        self._recipients = recipients

    def send(self, *, to: str, subject: str, body: str) -> None:
        self._recipients.append(to)


def _recorder(
    seen: list[str], recipients: list[str], config
) -> TransportRecorder:  # noqa: ARG001
    seen.append(config.transport)
    return TransportRecorder(recipients)


async def _signed_in(client, payload: dict | None = None) -> str:
    created = await setup_admin(client)
    token = created.json()["csrf_token"]
    if payload is not None:
        saved = await client.put(
            "/api/admin/email", json=payload, headers={CSRF: token}
        )
        assert saved.status_code == 200, saved.text
    return token


# ---------------------------------------------------------------------------
# Authentication and origin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_email_endpoint_demands_a_session(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as anonymous:
        read = await anonymous.get("/api/admin/email")
        saved = await anonymous.put("/api/admin/email", json=SMTP_PAYLOAD)
        tested = await anonymous.post("/api/admin/email/test")

    assert read.status_code == 401
    assert saved.status_code == 401
    assert tested.status_code == 401
    assert "write-only-secret" not in read.text


@pytest.mark.asyncio
async def test_a_mutation_without_csrf_is_refused(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        await setup_admin(client)
        saved = await client.put("/api/admin/email", json=SMTP_PAYLOAD)

    assert saved.status_code == 403


@pytest.mark.asyncio
async def test_a_mutation_from_another_origin_is_refused(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        token = await _signed_in(client)
        saved = await client.put(
            "/api/admin/email",
            json=SMTP_PAYLOAD,
            headers={CSRF: token, "Origin": "https://attacker.test"},
        )

    assert saved.status_code == 403
    assert app.state.state_store.email_config() is None


# ---------------------------------------------------------------------------
# Public projections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unconfigured_state_reports_nothing_beyond_absence(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        await setup_admin(client)
        payload = (await client.get("/api/admin/email")).json()

    assert payload["configured"] is False
    assert payload["transport"] is None
    assert payload["provenance"] is None
    assert payload["secret_configured"] is False
    assert payload["recovery_enabled"] is False


@pytest.mark.asyncio
async def test_a_saved_secret_is_never_returned(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        await _signed_in(client, SMTP_PAYLOAD)
        email = await client.get("/api/admin/email")
        status = await client.get("/api/admin/status")

    assert email.status_code == 200
    payload = email.json()
    assert payload["configured"] is True
    assert payload["transport"] == "smtp"
    assert payload["provenance"] == "state"
    assert payload["secret_configured"] is True
    assert payload["recovery_email_configured"] is True
    assert payload["recovery_enabled"] is True
    for body in (email.text, status.text):
        assert "write-only-secret" not in body
        assert "operator@internal.example" not in body
        assert "smtp.internal.example" not in body


@pytest.mark.asyncio
async def test_an_empty_secret_field_keeps_the_stored_one(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        token = await _signed_in(client, SMTP_PAYLOAD)
        rotated = await client.put(
            "/api/admin/email",
            json=_patched(SMTP_PAYLOAD, smtp_password=""),
            headers={CSRF: token},
        )
        unchanged = app.state.state_store.email_config()
        replaced = await client.put(
            "/api/admin/email",
            json=_patched(SMTP_PAYLOAD, smtp_password="rotated-secret"),
            headers={CSRF: token},
        )

    assert rotated.status_code == 200
    assert replaced.status_code == 200
    assert unchanged is not None
    assert unchanged.smtp_password == "write-only-secret"
    stored = app.state.state_store.email_config()
    assert stored is not None
    assert stored.smtp_password == "rotated-secret"


@pytest.mark.asyncio
async def test_switching_transport_clears_the_previous_secret(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        token = await _signed_in(client, SMTP_PAYLOAD)
        switched = await client.put(
            "/api/admin/email", json=M365_PAYLOAD, headers={CSRF: token}
        )

    assert switched.status_code == 200
    assert switched.json()["transport"] == "microsoft365"
    assert switched.json()["secret_configured"] is True  # the new one is set
    stored = app.state.state_store.email_config()
    assert stored is not None
    assert stored.smtp_password is None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base,overrides",
    [
        (SMTP_PAYLOAD, {"transport": "sendmail"}),
        (SMTP_PAYLOAD, {"from_address": "not-an-address"}),
        (SMTP_PAYLOAD, {"from_address": ""}),
        (SMTP_PAYLOAD, {"recovery_email": "nope"}),
        (SMTP_PAYLOAD, {"timeout_seconds": 0}),
        (SMTP_PAYLOAD, {"timeout_seconds": 700}),
        (SMTP_PAYLOAD, {"smtp_port": 0}),
        (SMTP_PAYLOAD, {"smtp_port": 70000}),
        (SMTP_PAYLOAD, {"smtp_port": None}),
        (SMTP_PAYLOAD, {"smtp_host": "not a host!"}),
        (SMTP_PAYLOAD, {"smtp_host": ""}),
        (SMTP_PAYLOAD, {"smtp_security": "plaintext"}),
        (SMTP_PAYLOAD, {"smtp_security": "none"}),
        (M365_PAYLOAD, {"m365_client_id": "not-a-guid"}),
        (M365_PAYLOAD, {"m365_client_id": ""}),
        (M365_PAYLOAD, {"m365_tenant_id": "not a tenant!"}),
        (M365_PAYLOAD, {"m365_client_secret": ""}),
        (M365_PAYLOAD, {"m365_mailbox": "nope"}),
    ],
)
async def test_invalid_values_are_refused(
    tmp_path: Path, base: dict, overrides: dict
) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        token = await _signed_in(client)
        response = await client.put(
            "/api/admin/email", json=_patched(base, **overrides), headers={CSRF: token}
        )

    assert response.status_code == 422, response.text
    assert app.state.state_store.email_config() is None


@pytest.mark.asyncio
async def test_unencrypted_smtp_needs_an_explicit_confirmation(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        token = await _signed_in(client)
        implied = await client.put(
            "/api/admin/email",
            json=_patched(SMTP_PAYLOAD, smtp_security="none"),
            headers={CSRF: token},
        )
        confirmed = await client.put(
            "/api/admin/email",
            json=_patched(
                SMTP_PAYLOAD, smtp_security="none", smtp_allow_plaintext=True
            ),
            headers={CSRF: token},
        )
        implicit_tls = await client.put(
            "/api/admin/email",
            json=_patched(SMTP_PAYLOAD, smtp_security="tls", smtp_port=465),
            headers={CSRF: token},
        )

    assert implied.status_code == 422
    assert confirmed.status_code == 200
    assert implicit_tls.status_code == 200
    stored = app.state.state_store.email_config()
    assert stored is not None
    assert stored.smtp_security == "tls"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base,overrides",
    [
        # Model-level refusals: the whole assembled body (secrets included)
        # is what pydantic carries into the validation error.
        (SMTP_PAYLOAD, {"transport": "sendmail"}),
        (SMTP_PAYLOAD, {"from_address": "not-an-address"}),
        (SMTP_PAYLOAD, {"smtp_security": "none"}),
        (SMTP_PAYLOAD, {"smtp_host": "not a host!"}),
        (M365_PAYLOAD, {"m365_tenant_id": "not a tenant!"}),
        (M365_PAYLOAD, {"m365_client_id": "not-a-guid"}),
        (M365_PAYLOAD, {"m365_mailbox": "nope"}),
        # Field-level refusals next to a secret that must never echo either.
        (SMTP_PAYLOAD, {"smtp_port": 70000}),
        (M365_PAYLOAD, {"timeout_seconds": 0}),
    ],
)
async def test_a_validation_error_never_echoes_a_secret(
    tmp_path: Path, base: dict, overrides: dict
) -> None:
    """A refused save answers with loc/msg/type only — never the input body."""
    marker = base.get("smtp_password") or base.get("m365_client_secret")
    assert marker  # the payload under test really carries a secret
    app = build_app(tmp_path)
    async with api_client(app) as client:
        token = await _signed_in(client)
        response = await client.put(
            "/api/admin/email", json=_patched(base, **overrides), headers={CSRF: token}
        )

    assert response.status_code == 422, response.text
    assert marker not in response.text, "a 422 echoed a write-only secret"
    for error in response.json()["detail"]:
        assert set(error) <= {"loc", "msg", "type", "url"}
    assert app.state.state_store.email_config() is None


@pytest.mark.asyncio
async def test_an_unknown_field_is_refused(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        token = await _signed_in(client)
        response = await client.put(
            "/api/admin/email",
            json=_patched(SMTP_PAYLOAD, unexpected="value"),
            headers={CSRF: token},
        )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Test send
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_test_send_is_rate_limited_per_client(tmp_path: Path) -> None:
    mailer = RecordingMailer()
    app = build_app(tmp_path, mailer=mailer)

    async with api_client(app) as client:
        token = await _signed_in(client, SMTP_PAYLOAD)
        statuses = [
            (
                await client.post(
                    "/api/admin/email/test", headers={CSRF: token}
                )
            ).status_code
            for _ in range(7)
        ]

    assert statuses[:4] == [200] * 4
    assert statuses[4:] == [429] * 3
    assert len(mailer.messages) == 4
    assert mailer.messages[0]["to"] == "operator@internal.example"


@pytest.mark.asyncio
async def test_the_test_send_uses_the_last_saved_configuration(tmp_path: Path) -> None:
    app = build_app(tmp_path)
    seen: list[str] = []
    recipients: list[str] = []

    async with api_client(app) as client:
        token = await _signed_in(client, SMTP_PAYLOAD)
        app.state.recovery_mailer = TransportMailer(
            app.state.state_store,
            factory=lambda config, _store: _recorder(seen, recipients, config),
        )
        via_smtp = await client.post("/api/admin/email/test", headers={CSRF: token})
        saved = await client.put(
            "/api/admin/email", json=M365_PAYLOAD, headers={CSRF: token}
        )
        via_m365 = await client.post("/api/admin/email/test", headers={CSRF: token})

    assert via_smtp.status_code == 200, via_smtp.text
    assert saved.status_code == 200, saved.text
    assert via_m365.status_code == 200, via_m365.text
    assert seen == ["smtp", "microsoft365"]
    assert recipients == ["operator@internal.example"] * 2


@pytest.mark.asyncio
async def test_a_transport_failure_is_reported_without_any_secret(
    tmp_path: Path,
) -> None:
    class RefusingMailer:
        def send(self, *, to: str, subject: str, body: str) -> None:
            raise RecoveryUnavailable("SMTP transport refused the message")

    app = build_app(tmp_path, mailer=RefusingMailer())

    async with api_client(app) as client:
        token = await _signed_in(client, SMTP_PAYLOAD)
        response = await client.post("/api/admin/email/test", headers={CSRF: token})

    assert response.status_code == 502
    assert response.json()["detail"] == "SMTP transport refused the message"
    assert "write-only-secret" not in response.text


@pytest.mark.asyncio
async def test_the_test_send_refuses_without_a_destination(tmp_path: Path) -> None:
    mailer = RecordingMailer()
    app = build_app(tmp_path, mailer=mailer)
    payload = _patched(SMTP_PAYLOAD, recovery_email="")

    async with api_client(app) as client:
        token = await _signed_in(client, payload)
        response = await client.post("/api/admin/email/test", headers={CSRF: token})

    assert response.status_code == 503
    assert mailer.messages == []


@pytest.mark.asyncio
async def test_the_test_send_refuses_when_nothing_is_configured(tmp_path: Path) -> None:
    mailer = RecordingMailer()
    app = build_app(tmp_path, mailer=mailer)

    async with api_client(app) as client:
        token = await setup_admin(client)
        token = token.json()["csrf_token"]
        response = await client.post("/api/admin/email/test", headers={CSRF: token})

    assert response.status_code == 503
    assert mailer.messages == []


# ---------------------------------------------------------------------------
# Recovery follows the selected transport
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [SMTP_PAYLOAD, M365_PAYLOAD])
async def test_recovery_follows_the_selected_transport(tmp_path: Path, payload: dict) -> None:
    app = build_app(tmp_path)
    seen: list[str] = []
    recipients: list[str] = []

    async with api_client(app) as client:
        await _signed_in(client, payload)
        app.state.recovery_mailer = TransportMailer(
            app.state.state_store,
            factory=lambda config, _store: _recorder(seen, recipients, config),
        )
        status = await client.get("/api/admin/status")
        requested = await client.post("/api/admin/recovery/request")

    assert status.json()["recovery_enabled"] is True
    assert requested.status_code == 200, requested.text
    assert requested.json() == {"status": "pending"}
    assert seen == [payload["transport"]]
    assert recipients == ["operator@internal.example"]


@pytest.mark.asyncio
async def test_recovery_stays_unavailable_without_a_recovery_address(
    tmp_path: Path,
) -> None:
    app = build_app(tmp_path)
    payload = _patched(SMTP_PAYLOAD, recovery_email="")

    async with api_client(app) as client:
        await _signed_in(client, payload)
        status = await client.get("/api/admin/status")
        requested = await client.post("/api/admin/recovery/request")

    assert status.json()["recovery_enabled"] is False
    assert requested.status_code == 503


@pytest.mark.asyncio
async def test_an_empty_m365_secret_keeps_the_stored_one(tmp_path: Path) -> None:
    """An empty secret field means "keep", exactly as it already does for SMTP."""
    app = build_app(tmp_path)

    async with api_client(app) as client:
        token = await _signed_in(client, M365_PAYLOAD)
        updated = await client.put(
            "/api/admin/email",
            json=_patched(M365_PAYLOAD, m365_client_secret=""),
            headers={CSRF: token},
        )

    assert updated.status_code == 200, updated.text
    assert updated.json()["secret_configured"] is True
    stored = app.state.state_store.email_config()
    assert stored is not None
    assert stored.m365_client_secret == M365_PAYLOAD["m365_client_secret"]


@pytest.mark.asyncio
async def test_a_microsoft365_configuration_without_any_secret_is_refused(
    tmp_path: Path,
) -> None:
    """Keeping is one thing; saving nothing usable is still refused."""
    app = build_app(tmp_path)

    async with api_client(app) as client:
        token = await _signed_in(client)
        refused = await client.put(
            "/api/admin/email",
            json=_patched(M365_PAYLOAD, m365_client_secret=""),
            headers={CSRF: token},
        )

    assert refused.status_code == 422, refused.text
    assert app.state.state_store.email_config() is None

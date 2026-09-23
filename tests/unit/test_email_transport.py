"""Transport selection: one selected transport, fail-closed when incomplete.

The mailer is built per send from the durable state, so a rotated credential
is picked up without a restart and an unfinished configuration can never be
mistaken for a working one.
"""

from __future__ import annotations

import pytest

from vysion.mail import (
    Microsoft365Mailer,
    RecoveryUnavailable,
    SmtpMailer,
    TransportMailer,
    _transport_mailer,
)
from vysion.state import StateStore


def _directory(tmp_path):
    return tmp_path / "vysion-state"


class RecordingMailer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str]] = []

    def send(self, *, to: str, subject: str, body: str) -> None:
        self.sent.append((to, subject, body))


def test_no_configuration_at_all_refuses_closed(tmp_path):
    mailer = TransportMailer(StateStore(_directory(tmp_path)))
    with pytest.raises(RecoveryUnavailable):
        mailer.send(to="ops@example.com", subject="s", body="b")


def test_an_incomplete_configuration_refuses_closed(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(transport="smtp", from_address="vysion@example.com")
    with pytest.raises(RecoveryUnavailable):
        TransportMailer(store).send(to="ops@example.com", subject="s", body="b")


def test_the_selected_transport_is_the_one_that_sends(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(
        transport="microsoft365",
        from_address="vysion@example.com",
        m365_tenant_id="00000000-0000-4000-8000-000000000000",
        m365_client_id="11111111-1111-4111-8111-111111111111",
        m365_client_secret="graph-secret",
    )
    seen: list[str] = []

    def factory(config, _store):
        seen.append(config.transport)
        return RecordingMailer()

    TransportMailer(store, factory=factory).send(
        to="ops@example.com", subject="s", body="b"
    )
    assert seen == ["microsoft365"]


def test_switching_to_smtp_selects_the_smtp_mailer(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_security="starttls",
    )
    seen: list[str] = []

    def factory(config, _store):
        seen.append(config.transport)
        return RecordingMailer()

    TransportMailer(store, factory=factory).send(
        to="ops@example.com", subject="s", body="b"
    )
    assert seen == ["smtp"]


def test_the_default_factory_maps_each_transport_to_its_mailer(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_security="starttls",
    )
    assert isinstance(_transport_mailer(store.email_config(), store), SmtpMailer)

    store.set_email_config(
        transport="microsoft365",
        from_address="vysion@example.com",
        m365_tenant_id="00000000-0000-4000-8000-000000000000",
        m365_client_id="11111111-1111-4111-8111-111111111111",
        m365_client_secret="graph-secret",
    )
    assert isinstance(
        _transport_mailer(store.email_config(), store), Microsoft365Mailer
    )


def test_microsoft365_refuses_before_any_network_call_when_unconfigured(tmp_path):
    mailer = Microsoft365Mailer(StateStore(_directory(tmp_path)))
    with pytest.raises(RecoveryUnavailable):
        mailer.send(to="ops@example.com", subject="s", body="b")


def test_transport_errors_surface_as_recovery_unavailable(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(
        transport="microsoft365",
        from_address="vysion@example.com",
        m365_tenant_id="00000000-0000-4000-8000-000000000000",
        m365_client_id="11111111-1111-4111-8111-111111111111",
        m365_client_secret="graph-secret",
    )
    mailer = Microsoft365Mailer(store, urlopen=_always_failing)
    with pytest.raises(RecoveryUnavailable) as caught:
        mailer.send(to="ops@example.com", subject="s", body="b")
    assert "graph-secret" not in str(caught.value)


def _always_failing(request, timeout=...):  # noqa: ARG001
    raise OSError("network is unreachable")


def test_a_configured_smtp_still_reaches_the_smtp_mailer(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_security="starttls",
        smtp_password="smtp-secret",
    )
    delivered: list[tuple[str, str, str]] = []

    class _PatchedSmtp(SmtpMailer):
        def send(self, *, to, subject, body):  # noqa: ANN001
            delivered.append((to, subject, body))

    # The default factory is the seam: swap it for a recording SMTP mailer.
    mailer = TransportMailer(store, factory=lambda config, s: _PatchedSmtp(s))
    mailer.send(to="ops@example.com", subject="Vysion", body="lien")
    assert delivered == [("ops@example.com", "Vysion", "lien")]

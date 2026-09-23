"""Administrator recovery mail over one selected, durable transport.

Two transports are available — SMTP and Microsoft 365 over OAuth2 application
credentials — and exactly one is selected at a time. Settings are read at
send time from the state volume: nothing secret comes from the environment
and nothing secret is ever logged or returned.
"""

from __future__ import annotations

import smtplib
import ssl
from collections.abc import Callable
from email.message import EmailMessage
from typing import Protocol

from vysion.graphmail import GraphMailClient, GraphMailError, Message
from vysion.state import SMTP_SECURITIES, EmailConfig, StateStore

MAX_TIMEOUT_SECONDS = 60


class RecoveryUnavailable(RuntimeError):
    """No usable transport: recovery must refuse, never pretend it sent."""


class RecoveryMailer(Protocol):
    """Anything able to hand a recovery message to an operator address."""

    def send(self, *, to: str, subject: str, body: str) -> None: ...


class SmtpMailer:
    """Sends through the SMTP settings stored in the private state.

    The settings (and the password they may carry) are read at send time from
    the state volume: nothing secret is taken from the environment and nothing
    secret is ever logged.

    The three stored security modes are honoured for real: ``tls`` opens an
    implicit-TLS session (``SMTP_SSL``), ``starttls`` upgrades in-band, and
    ``none`` speaks cleartext — only reachable because the save-time form
    demanded an explicit confirmation for it. An unknown or absent mode never
    downgrades to cleartext: STARTTLS is the fallback.
    """

    def __init__(
        self, store: StateStore, *, ssl_context: ssl.SSLContext | None = None
    ) -> None:
        self._store = store
        self._ssl_context = ssl_context

    def send(self, *, to: str, subject: str, body: str) -> None:
        config = self._store.email_config()
        if (
            config is None
            or config.transport != "smtp"
            or not config.smtp_host
        ):
            raise RecoveryUnavailable("SMTP transport is not configured")
        security = (
            config.smtp_security
            if config.smtp_security in SMTP_SECURITIES
            else "starttls"
        )
        port = config.smtp_port if config.smtp_port is not None else 587
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = config.from_address
        message["To"] = to
        message.set_content(body)
        # Bounded regardless of what the stored row claims: a hand-edited
        # value can never park a recovery send on an unbounded socket.
        timeout = float(min(max(int(config.timeout_seconds), 1), MAX_TIMEOUT_SECONDS))
        context = (
            self._ssl_context
            if self._ssl_context is not None
            else ssl.create_default_context()
        )
        try:
            if security == "tls":
                connection = smtplib.SMTP_SSL(
                    config.smtp_host, port, timeout=timeout, context=context
                )
            else:
                connection = smtplib.SMTP(config.smtp_host, port, timeout=timeout)
            with connection as client:
                if security == "starttls":
                    client.starttls(context=context)
                if config.smtp_username:
                    client.login(config.smtp_username, config.smtp_password or "")
                client.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise RecoveryUnavailable("SMTP transport refused the message") from exc


class Microsoft365Mailer:
    """Sends through Microsoft Graph with the stored application credentials."""

    def __init__(
        self,
        store: StateStore,
        *,
        urlopen: Callable[..., object] | None = None,
    ) -> None:
        self._store = store
        self._urlopen = urlopen

    def send(self, *, to: str, subject: str, body: str) -> None:
        config = self._store.email_config()
        if (
            config is None
            or config.transport != "microsoft365"
            or not config.complete
        ):
            raise RecoveryUnavailable("Microsoft 365 transport is not configured")
        keywords: dict[str, object] = {}
        if self._urlopen is not None:
            keywords["urlopen"] = self._urlopen
        client = GraphMailClient(
            tenant_id=config.m365_tenant_id or "",
            client_id=config.m365_client_id or "",
            client_secret=config.m365_client_secret or "",
            mailbox=config.m365_mailbox or "",
            from_address=config.from_address,
            timeout=float(config.timeout_seconds),
            **keywords,  # type: ignore[arg-type]
        )
        try:
            client.send(Message(to=to, subject=subject, body=body))
        except GraphMailError as exc:
            raise RecoveryUnavailable(str(exc)) from exc


# The one place that maps the selected transport onto its mailer. Both
# implementations read the state at send time, so a rotated credential is
# picked up without restarting the application.
def _transport_mailer(config: EmailConfig, store: StateStore) -> RecoveryMailer:
    if config.transport == "microsoft365":
        return Microsoft365Mailer(store)
    return SmtpMailer(store)


MailerFactory = Callable[[EmailConfig, StateStore], RecoveryMailer]


class TransportMailer:
    """Resolves the selected transport at send time and refuses when unfinished."""

    def __init__(self, store: StateStore, *, factory: MailerFactory | None = None) -> None:
        self._store = store
        self._factory = factory if factory is not None else _transport_mailer

    def send(self, *, to: str, subject: str, body: str) -> None:
        config = self._store.email_config()
        if config is None:
            raise RecoveryUnavailable("aucun transport d'email n'est configure")
        if not config.complete:
            raise RecoveryUnavailable("transport d'email incomplet")
        self._factory(config, self._store).send(to=to, subject=subject, body=body)

"""Optional SMTP transport for the administrator recovery messages."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Protocol

from vysion.state import StateStore


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
    """

    def __init__(self, store: StateStore) -> None:
        self._store = store

    def send(self, *, to: str, subject: str, body: str) -> None:
        config = self._store.smtp_config()
        if config is None or not config.host:
            raise RecoveryUnavailable("SMTP transport is not configured")
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = config.from_address
        message["To"] = to
        message.set_content(body)
        try:
            with smtplib.SMTP(config.host, config.port, timeout=10.0) as client:
                if config.starttls:
                    client.starttls()
                if config.username:
                    client.login(config.username, config.password or "")
                client.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise RecoveryUnavailable("SMTP transport refused the message") from exc

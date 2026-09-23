"""Microsoft 365 application mail over OAuth2 client credentials + Graph.

The endpoints are fixed by Microsoft and never taken from configuration or
from the environment: there is nothing an operator (or an attacker) could
point at another host. Only an application flow is used — no redirect, no
user login, no callback — so no interactive credential can ever be involved.

Every error is reduced to a whitelisted AADSTS hint or a status code. The
provider's raw body, the access token and the client secret must never reach
a log line, an exception message or an HTTP response.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
SEND_ENDPOINT = "https://graph.microsoft.com/v1.0/users/{mailbox}/sendMail"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
DEFAULT_TIMEOUT_SECONDS = 10.0

# Only these provider diagnostics may be surfaced. Everything else the
# provider returns (HTML gateways, internal traces, correlation ids) is
# dropped: an error message is for an operator, not for a leak.
AADSTS_HINTS = {
    "AADSTS7000218": "le secret du client est invalide ou absent",
    "AADSTS700016": "l'application est introuvable dans ce tenant",
    "AADSTS90002": "le tenant est introuvable",
    "AADSTS65001": "les permissions de l'application ne sont pas consenties",
    "AADSTS50034": "la boîte destinataire est introuvable",
    "AADSTS53003": "l'accès est bloque par une condition d'acces",
}

DEFAULT_URLOPEN: Callable[..., Any] = urllib.request.urlopen


class GraphMailError(RuntimeError):
    """A send failed; the message is already safe for an operator UI."""


@dataclass(frozen=True)
class Message:
    to: str
    subject: str
    body: str


def clean_provider_error(payload: bytes | str, status: int) -> str:
    """Whitelisted hint or status — never the provider's own wording."""
    text = (
        payload.decode("utf-8", "replace") if isinstance(payload, bytes) else str(payload)
    )
    for code, hint in AADSTS_HINTS.items():
        if code in text:
            return f"{code} : {hint}"
    if status:
        return f"service Microsoft 365 indisponible (HTTP {int(status)})"
    return "service Microsoft 365 indisponible"


class GraphMailClient:
    """Application-only sender bound to one tenant and one mailbox."""

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        mailbox: str,
        from_address: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        urlopen: Callable[..., Any] = DEFAULT_URLOPEN,
    ) -> None:
        if not tenant_id or not client_id or not client_secret:
            raise GraphMailError("identifiants Microsoft 365 incomplets")
        if not from_address:
            raise GraphMailError("expediteur Microsoft 365 manquant")
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._mailbox = mailbox or from_address
        self._from_address = from_address
        self._timeout = float(timeout)
        self._urlopen = urlopen

    # ------------------------------------------------------------------
    # transport plumbing
    # ------------------------------------------------------------------
    def _post(self, url: str, *, data: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            response = self._urlopen(request, timeout=self._timeout)
        except urllib.error.HTTPError as exc:
            body = exc.read()
            code = int(getattr(exc, "code", 0) or 0)
            raise GraphMailError(clean_provider_error(body, code)) from None
        except (urllib.error.URLError, OSError) as exc:
            raise GraphMailError("service Microsoft 365 injoignable") from exc
        except GraphMailError:
            raise
        try:
            status = int(getattr(response, "status", 0) or 0)
            body = response.read()
        finally:
            close = getattr(response, "close", None)
            if close is not None:
                close()
        if status and not 200 <= status < 300:
            raise GraphMailError(clean_provider_error(body, status))
        return status, body

    def _token(self) -> str:
        form = urllib.parse.urlencode(
            {
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "client_credentials",
                "scope": GRAPH_SCOPE,
            }
        ).encode("ascii")
        _status, body = self._post(
            TOKEN_ENDPOINT.format(tenant=self._tenant_id),
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            payload = json.loads(body.decode("utf-8"))
            token = payload["access_token"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            raise GraphMailError("reponse Microsoft 365 illisible") from exc
        if not isinstance(token, str) or not token:
            raise GraphMailError("reponse Microsoft 365 illisible")
        return token

    # ------------------------------------------------------------------
    # send
    # ------------------------------------------------------------------
    def send(self, message: Message) -> None:
        token = self._token()
        payload = {
            "message": {
                "subject": message.subject,
                "body": {"contentType": "Text", "content": message.body},
                "toRecipients": [
                    {"emailAddress": {"address": message.to}},
                ],
            },
            "saveToSentItems": False,
        }
        try:
            body = json.dumps(payload).encode("utf-8")
        except (TypeError, ValueError) as exc:  # pragma: no cover - plain strings
            raise GraphMailError("message preparer impossible") from exc
        self._post(
            SEND_ENDPOINT.format(mailbox=self._mailbox),
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )

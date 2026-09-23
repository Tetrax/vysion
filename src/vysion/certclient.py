"""Application side of the private certificate helper socket.

The container never writes certificate material itself in ``helper`` mode: it
hands a candidate to the root helper over a private Unix socket and receives
metadata, a staging digest and an activation result. No file path, no reload
and no nginx command is ever decided here.
"""

from __future__ import annotations

import base64
import socket
from pathlib import Path
from typing import Any

from vysion.certificates import CertificateError, CertificateMetadata
from vysion.certprotocol import (
    DEFAULT_TIMEOUT_SECONDS,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    receive_message,
    send_message,
)

DEFAULT_HELPER_SOCKET = "/run/vysion-cert-helper/helper.sock"


class CertificateHelperUnavailable(RuntimeError):
    """The helper is absent, unreachable, or answered something unusable."""


class CertificateHelperClient:
    """One connection, one action, one bounded exchange."""

    def __init__(
        self,
        socket_path: str | Path,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._socket_path = str(socket_path)
        self._timeout = float(timeout)

    def _call(self, message: dict[str, Any]) -> dict[str, Any]:
        request = {"v": PROTOCOL_VERSION, **message}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout)
                connection.connect(self._socket_path)
                send_message(
                    connection,
                    request,
                    max_bytes=MAX_REQUEST_BYTES,
                    timeout=self._timeout,
                )
                response = receive_message(
                    connection,
                    max_bytes=MAX_RESPONSE_BYTES,
                    timeout=self._timeout,
                )
        except (OSError, ProtocolError) as exc:
            raise CertificateHelperUnavailable(
                "service de certificats injoignable"
            ) from exc
        if not isinstance(response.get("ok"), bool):
            raise CertificateHelperUnavailable(
                "reponse du service de certificats illisible"
            )
        if not response["ok"]:
            detail = str(response.get("error", ""))
            if response.get("kind") == "certificate":
                raise CertificateError(detail or "certificat refuse")
            raise CertificateHelperUnavailable(
                detail or "service de certificats indisponible"
            )
        return response

    def ping(self) -> None:
        response = self._call({"action": "ping"})
        if response.get("version") != PROTOCOL_VERSION:
            raise CertificateHelperUnavailable(
                "protocole du service de certificats incompatible"
            )

    def status(self) -> dict[str, Any]:
        response = self._call({"action": "status"})
        return {
            key: value
            for key, value in response.items()
            if key not in {"ok", "kind"}
        }

    def validate(
        self,
        *,
        certificate: bytes,
        private_key: bytes | None,
        hostname: str,
        passphrase: str | None,
    ) -> tuple[CertificateMetadata, str]:
        response = self._call(
            {
                "action": "validate",
                "certificate": base64.b64encode(certificate).decode("ascii"),
                "private_key": (
                    base64.b64encode(private_key).decode("ascii")
                    if private_key
                    else None
                ),
                "passphrase": passphrase,
                "hostname": hostname,
            }
        )
        try:
            metadata = CertificateMetadata.from_dict(response["certificate"])
            digest = str(response["digest"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CertificateHelperUnavailable(
                "reponse du service de certificats illisible"
            ) from exc
        return metadata, digest

    def activate(self, digest: str) -> tuple[int, dict[str, Any], str]:
        response = self._call({"action": "activate", "digest": digest})
        try:
            generation = int(response["generation"])
            certificate = response["certificate"]
            served = str(response["served_sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CertificateHelperUnavailable(
                "reponse du service de certificats illisible"
            ) from exc
        if not isinstance(certificate, dict):
            raise CertificateHelperUnavailable(
                "reponse du service de certificats illisible"
            )
        return generation, certificate, served

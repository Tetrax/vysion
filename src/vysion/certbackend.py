"""The single certificate backend abstraction: ``none | local | helper``.

Routes ask a backend for a status, a validation, a staged digest and an
activation. They never ask which mode is selected, so a fourth backend could
be added without touching a single route or a single view.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from vysion.certclient import CertificateHelperClient
from vysion.certificates import (
    CertificateError,
    CertificateMetadata,
    CertificateStore,
    activate_staged,
    certificate_status_payload,
)
from vysion.config import Settings

NO_STANDALONE = "réservé au mode standalone TLS géré (VYSION_TLS_BACKEND=local ou helper)"
NO_HOOKS = "activation indisponible : hooks TLS non configurés"
CHANGED_CANDIDATE = "le candidat en staging a changé depuis la validation"


class CertificateBackendUnavailable(RuntimeError):
    """The selected backend cannot serve this operation at all."""


class CertificateBackend(Protocol):
    """What every certificate route is allowed to know."""

    name: str
    managed: bool

    def ensure_available(self) -> None: ...

    def status(self) -> dict[str, Any]: ...

    def validate(
        self,
        *,
        certificate: bytes,
        private_key: bytes | None,
        hostname: str,
        passphrase: str | None,
    ) -> tuple[CertificateMetadata, str]: ...

    def staged_digest(self) -> str | None: ...

    def activate(self, digest: str) -> tuple[int, dict[str, Any], str]: ...


class DisabledBackend:
    """An external proxy owns TLS: this application manages no certificate."""

    name = "none"
    managed = False

    def ensure_available(self) -> None:
        # Answered first, before any hostname or file question: the mode
        # itself is the reason nothing here can proceed.
        raise CertificateBackendUnavailable(NO_STANDALONE)

    def status(self) -> dict[str, Any]:
        # Informational only: "no managed certificate" is a fact, not a
        # failure, and the listing must keep answering.
        return {"active": None, "staging": None, "generations": []}

    def validate(
        self,
        *,
        certificate: bytes,
        private_key: bytes | None,
        hostname: str,
        passphrase: str | None,
    ) -> tuple[CertificateMetadata, str]:
        raise CertificateBackendUnavailable(NO_STANDALONE)

    def staged_digest(self) -> str | None:
        return None

    def activate(self, digest: str) -> tuple[int, dict[str, Any], str]:
        raise CertificateBackendUnavailable(NO_STANDALONE)


class LocalBackend:
    """Certificates live on the application's own volume."""

    name = "local"
    managed = True

    def __init__(self, store: CertificateStore, *, state: Any) -> None:
        self._store = store
        # The hooks are read from the application state at call time, not
        # captured here: a test (or a later rewiring) can replace them after
        # startup and the very next activation must see the new one.
        self._state = state

    def ensure_available(self) -> None:
        return None

    def _hook(self, name: str) -> Callable[[], Any] | None:
        return getattr(self._state, name, None)

    def status(self) -> dict[str, Any]:
        return certificate_status_payload(self._store)

    def validate(
        self,
        *,
        certificate: bytes,
        private_key: bytes | None,
        hostname: str,
        passphrase: str | None,
    ) -> tuple[CertificateMetadata, str]:
        metadata = self._store.validate(
            certificate=certificate,
            private_key=private_key,
            hostname=hostname,
            passphrase=passphrase,
        )
        return metadata, self._store.staged_digest() or ""

    def staged_digest(self) -> str | None:
        return self._store.staged_digest()

    def activate(self, digest: str) -> tuple[int, dict[str, Any], str]:
        # Re-read at activation time: the ticket is bound to this exact
        # content, so a candidate staged in between can never be promoted.
        if self._store.staged_digest() != digest:
            raise CertificateError(CHANGED_CANDIDATE)
        reloader = self._hook("certificate_reloader")
        smoker = self._hook("certificate_smoker")
        if reloader is None or smoker is None:
            raise CertificateBackendUnavailable(NO_HOOKS)
        generation, served = activate_staged(
            self._store, reloader=reloader, smoker=smoker
        )
        return generation.number, generation.metadata.as_dict(), served


class HelperBackend:
    """Certificates live on the host; a root helper owns them over a socket."""

    name = "helper"
    managed = True

    def __init__(self, client: CertificateHelperClient) -> None:
        self._client = client

    def ensure_available(self) -> None:
        return None

    def status(self) -> dict[str, Any]:
        payload = dict(self._client.status())
        # The staging digest is a routing detail between the two processes:
        # it is never part of the projection the admin surface renders.
        payload.pop("staged_digest", None)
        return payload

    def validate(
        self,
        *,
        certificate: bytes,
        private_key: bytes | None,
        hostname: str,
        passphrase: str | None,
    ) -> tuple[CertificateMetadata, str]:
        return self._client.validate(
            certificate=certificate,
            private_key=private_key,
            hostname=hostname,
            passphrase=passphrase,
        )

    def staged_digest(self) -> str | None:
        value = self._client.status().get("staged_digest")
        return str(value) if value else None

    def activate(self, digest: str) -> tuple[int, dict[str, Any], str]:
        return self._client.activate(digest)


def build_certificate_backend(
    settings: Settings,
    *,
    store: CertificateStore | None,
    state: Any,
) -> CertificateBackend:
    if settings.tls_backend == "helper":
        return HelperBackend(CertificateHelperClient(settings.helper_socket_path))
    if settings.tls_backend == "local" and store is not None:
        return LocalBackend(store, state=state)
    return DisabledBackend()

"""Secured administrator surface: first run, sessions, account, recovery.

Only these routes demand a session. The main audit flow (upload, preview,
creation, report downloads by UUID+TTL) stays anonymous behind the existing
network boundary, so nothing here installs a global authentication gate.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from vysion.build_info import VYSION_VERSION
from vysion.certbackend import CertificateBackend, CertificateBackendUnavailable
from vysion.certclient import CertificateHelperUnavailable
from vysion.certificates import CertificateError
from vysion.config import HOSTNAME_PATTERN, Settings
from vysion.mail import RecoveryUnavailable
from vysion.security import (
    CSRF_HEADER_NAME,
    FORWARDED_CLIENT_PROTO_HEADER,
    FORWARDED_FOR_HEADER,
    FORWARDED_PROTO_HEADER,
    MAX_PASSWORD_BYTES,
    MIN_PASSWORD_BYTES,
    REAL_IP_HEADER,
    SESSION_COOKIE_NAME,
    TrustedProxy,
    session_cookie,
)
from vysion.state import (
    EMAIL_TRANSPORTS,
    SMTP_SECURITIES,
    EmailConfig,
    SessionRecord,
    StateStore,
)

MAX_ADMIN_BODY_BYTES = 1 * 1024 * 1024
MAX_CERTIFICATE_BYTES = 512 * 1024
CERT_TICKET_TTL_SECONDS = 300
NO_STAGING = "aucun certificat en staging : validez d'abord un certificat"
BAD_TICKET = (
    "ticket d'activation invalide, expiré, déjà utilisé ou lié à une autre session"
)

ACCOUNT_LOCK_SCOPE = "account:admin"
ACCOUNT_LOCK_THRESHOLD = 5
ACCOUNT_LOCK_SECONDS = 900
CLIENT_LOCK_PREFIX = "client"
CLIENT_LOCK_THRESHOLD = 20
CLIENT_LOCK_SECONDS = 900
SETUP_LOCK_PREFIX = "setup"
SETUP_LOCK_THRESHOLD = 5
SETUP_LOCK_SECONDS = 900
RECOVERY_CLIENT_PREFIX = "recovery:client"
RECOVERY_GLOBAL_SCOPE = "recovery:global"
RECOVERY_CONFIRM_PREFIX = "recovery:confirm"
RECOVERY_CLIENT_THRESHOLD = 5
RECOVERY_GLOBAL_THRESHOLD = 30
RECOVERY_CONFIRM_THRESHOLD = 5
RECOVERY_RATE_SECONDS = 600
RECOVERY_TTL_SECONDS = 900
RECOVERY_PURPOSE = "reset"
# The test send costs a real outbound connection: it is bounded per client,
# counted whether it succeeds or fails, so it cannot become a relay.
EMAIL_TEST_PREFIX = "email:test"
EMAIL_TEST_THRESHOLD = 5
EMAIL_TEST_RATE_SECONDS = 600
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 60
# Address, GUID and tenant syntax. Deliberately conservative: this is an
# operator form, not a full RFC 5322 parser.
EMAIL_ADDRESS_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

PASSWORD_CONTRACT = "mot de passe refus\u00e9 : 12 \u00e0 1024 octets UTF-8"
LOCKED = "trop de tentatives, r\u00e9essayez plus tard"
GENERIC_CREDENTIALS = "identifiants invalides"
BAD_ORIGIN = "origine de la requ\u00eate refus\u00e9e"
NO_PUBLIC_ORIGIN = (
    "origine publique non configur\u00e9e : mutations administrateur indisponibles"
)
MISSING_CSRF = "jeton CSRF absent ou invalide"
AUTH_REQUIRED = "authentification requise"
STATE_UNAVAILABLE = "\u00e9tat administrateur indisponible"
SETUP_DONE = "la configuration initiale est d\u00e9j\u00e0 effectu\u00e9e"
BAD_RECOVERY_TOKEN = "jeton de r\u00e9cup\u00e9ration invalide"
RECOVERY_DOWN = "récupération indisponible"
RECOVERY_NO_ORIGIN = "récupération indisponible : origine publique non configurée"
BODY_TOO_LARGE = "corps de requ\u00eate trop volumineux"
LENGTH_REQUIRED = "longueur du corps requise"
BAD_LENGTH = "longueur du corps invalide"
EMAIL_NOT_CONFIGURED = "transport d'email non configuré ou incomplet"
EMAIL_INCOMPLETE = "configuration d'email incomplète : secret du transport manquant"
EMAIL_NO_DESTINATION = "adresse de récupération absente : envoi de test impossible"


class SetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str


class CertificateActivateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str
    password: str


class RecoveryConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
    password: str


class EmailConfigRequest(BaseModel):
    """The single Email form: one transport, write-only secrets.

    A secret field left empty keeps the stored one — that is what makes the
    browser able to round-trip a form it can never read back. Only the fields
    of the selected transport are validated: the other transport's material is
    discarded on save and can never be validated against the wrong shape.
    """

    model_config = ConfigDict(extra="forbid")

    transport: str
    from_address: str = ""
    recovery_email: str = ""
    timeout_seconds: int = Field(default=10, ge=MIN_TIMEOUT_SECONDS, le=MAX_TIMEOUT_SECONDS)
    smtp_host: str = ""
    smtp_port: int | None = None
    smtp_security: str | None = None
    smtp_username: str = ""
    # Write-only: empty means "keep what is stored", never "erase".
    smtp_password: str = ""
    smtp_allow_plaintext: bool = False
    m365_tenant_id: str = ""
    m365_client_id: str = ""
    # Write-only: empty means "keep what is stored", never "erase".
    m365_client_secret: str = ""
    m365_mailbox: str = ""

    @model_validator(mode="after")
    def _validate_selection(self) -> EmailConfigRequest:
        if self.transport not in EMAIL_TRANSPORTS:
            raise ValueError(f"transport must be one of: {', '.join(EMAIL_TRANSPORTS)}")
        if not EMAIL_ADDRESS_PATTERN.fullmatch(self.from_address.strip()):
            raise ValueError("from_address must be a valid email address")
        recovery = self.recovery_email.strip()
        if recovery and not EMAIL_ADDRESS_PATTERN.fullmatch(recovery):
            raise ValueError("recovery_email must be a valid email address")
        if self.transport == "smtp":
            self._validate_smtp()
        else:
            self._validate_microsoft365()
        return self

    def _validate_smtp(self) -> None:
        if not HOSTNAME_PATTERN.fullmatch(self.smtp_host.strip().lower()):
            raise ValueError("smtp_host must be a valid DNS name")
        if self.smtp_port is None or not 1 <= self.smtp_port <= 65535:
            raise ValueError("smtp_port must be between 1 and 65535")
        security = self.smtp_security or "starttls"
        if security not in SMTP_SECURITIES:
            raise ValueError(f"smtp_security must be one of: {', '.join(SMTP_SECURITIES)}")
        # Cleartext credentials are possible but never by omission: an
        # operator has to ask for them explicitly.
        if security == "none" and not self.smtp_allow_plaintext:
            raise ValueError("smtp_security=none requires smtp_allow_plaintext=true")

    def _validate_microsoft365(self) -> None:
        tenant = self.m365_tenant_id.strip()
        if not (
            GUID_PATTERN.fullmatch(tenant)
            or HOSTNAME_PATTERN.fullmatch(tenant.lower())
        ):
            raise ValueError("m365_tenant_id must be a tenant GUID or a tenant DNS name")
        if not GUID_PATTERN.fullmatch(self.m365_client_id.strip()):
            raise ValueError("m365_client_id must be a GUID")
        # An empty secret is not a shape error: it is how the admin surface
        # says "keep the stored one". Whether a usable secret ends up being
        # saved is checked against the resulting row, after the merge.
        mailbox = self.m365_mailbox.strip()
        if mailbox and not EMAIL_ADDRESS_PATTERN.fullmatch(mailbox):
            raise ValueError("m365_mailbox must be a valid email address")


# ---------------------------------------------------------------------------
# request context: peer, client, scheme, host
# ---------------------------------------------------------------------------
def _state(request: Request) -> StateStore:
    return request.app.state.state_store


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _proxy(request: Request) -> TrustedProxy:
    return request.app.state.trusted_proxy


def _certificate_backend(request: Request) -> CertificateBackend:
    return request.app.state.certificate_backend


def _peer(request: Request) -> str | None:
    client = request.scope.get("client")
    return str(client[0]) if client else None


# Password failures are refused before anything is burned or written.
PASSWORD_ERRORS = (ValueError, UnicodeEncodeError)


def _validated_password(value: str) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("password must be valid UTF-8") from exc
    if not MIN_PASSWORD_BYTES <= len(encoded) <= MAX_PASSWORD_BYTES:
        raise ValueError("password outside the UTF-8 byte contract")
    return value


def _forwarded(request: Request) -> tuple[str | None, str]:
    """One resolution pass: which client, over which scheme, and why."""
    return _proxy(request).resolve(
        peer=_peer(request),
        real_ip=request.headers.get(REAL_IP_HEADER),
        forwarded_for=request.headers.get(FORWARDED_FOR_HEADER),
        local_proto=request.headers.get(FORWARDED_PROTO_HEADER),
        client_proto=request.headers.get(FORWARDED_CLIENT_PROTO_HEADER),
        fallback=request.url.scheme,
    )


def _client_id(request: Request) -> str:
    client, _scheme_value = _forwarded(request)
    return client or _peer(request) or "unknown"


def _scheme(request: Request) -> str:
    _client, scheme = _forwarded(request)
    return scheme


def require_origin(request: Request) -> None:
    """Exact-Origin check against the authoritative public origin.

    The configured (or standalone-derived) ``public_origin`` is the ONE
    authority an admin mutation may use — neither the Origin nor the
    caller-controlled Host header may pick it. Without a configured origin
    (the documented VPS/proxy default), every mutation fails closed with
    503 instead of falling back to the authority this request claims: no
    first-run, login, recovery or certificate action can ever complete
    under an arbitrary name (DNS rebinding, permissive Host routing).
    """
    configured = _settings(request).public_origin
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=NO_PUBLIC_ORIGIN
        )
    authority = configured.split("://", 1)[1]
    origin = request.headers.get("origin")
    host = (request.headers.get("host") or "").strip().lower()
    if origin is None or origin.strip().lower() != configured or host != authority:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=BAD_ORIGIN)


def _resolve_session(request: Request) -> SessionRecord | None:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        return None
    return _state(request).resolve_session(raw_token)


async def require_session(request: Request) -> SessionRecord:
    session = _resolve_session(request)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTH_REQUIRED,
            headers={"WWW-Authenticate": 'Cookie realm="vysion"'},
        )
    return session


async def require_mutation(request: Request) -> SessionRecord:
    session = await require_session(request)
    presented = request.headers.get(CSRF_HEADER_NAME, "")
    if not presented or not hmac.compare_digest(
        presented.encode("utf-8"), session.csrf_token.encode("utf-8")
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=MISSING_CSRF)
    require_origin(request)
    return session


def _cookie_secure(request: Request) -> bool:
    # A peer outside the trusted proxy list cannot claim https: X-Forwarded-Proto
    # is ignored and the transport truth (http here) wins.
    return _scheme(request) == "https"


def _iso(value: Any) -> str:
    return value.isoformat()


def _session_payload(session: SessionRecord) -> dict[str, str]:
    return {
        "csrf_token": session.csrf_token,
        "created_at": _iso(session.created_at),
        "expires_at": _iso(session.expires_at),
    }


def _signed_in(state: StateStore, request: Request, *, status_code: int) -> JSONResponse:
    ttl = _settings(request).session_ttl_seconds
    raw_token, csrf_token = state.create_session(ttl)
    session = state.resolve_session(raw_token)
    response = JSONResponse(
        {"csrf_token": csrf_token, "expires_at": _iso(session.expires_at)},
        status_code=status_code,
    )
    response.set_cookie(**session_cookie(raw_token, secure=_cookie_secure(request), max_age=ttl))
    return response


def _cleared_cookie_response(payload: dict[str, Any]) -> JSONResponse:
    response = JSONResponse(payload)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


def _rate_limited(request: Request, seconds: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=LOCKED,
        headers={"Retry-After": str(seconds)},
    )


# ---------------------------------------------------------------------------
# body bounds, enforced before anything parses a body
# ---------------------------------------------------------------------------
class AdminBodyLimit:
    """Bound /api/admin mutation bodies before FastAPI reads them."""

    def __init__(self, app: Any, *, max_bytes: int = MAX_ADMIN_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            method = str(scope.get("method", ""))
            path = str(scope.get("path", ""))
            if method in {"POST", "PUT", "PATCH"} and path.startswith("/api/admin/"):
                refusal = self._refusal(scope)
                if refusal is not None:
                    code, detail = refusal
                    body = json.dumps({"detail": detail}).encode("utf-8")
                    await send(
                        {
                            "type": "http.response.start",
                            "status": code,
                            "headers": [
                                (b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode("ascii")),
                                (b"cache-control", b"no-store"),
                            ],
                        }
                    )
                    await send({"type": "http.response.body", "body": body})
                    return
        await self.app(scope, receive, send)

    def _refusal(self, scope: Any) -> tuple[int, str] | None:
        headers = {
            key.decode("latin-1").casefold(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        declared = headers.get("content-length")
        chunked = headers.get("transfer-encoding")
        if declared is None:
            if chunked is not None:
                return (status.HTTP_411_LENGTH_REQUIRED, LENGTH_REQUIRED)
            return None
        if not declared.isdigit():
            return (status.HTTP_400_BAD_REQUEST, BAD_LENGTH)
        if int(declared) > self.max_bytes:
            return (status.HTTP_413_CONTENT_TOO_LARGE, BODY_TOO_LARGE)
        return None


# Pydantic attaches the raw input to every validation error; for a
# model-level refusal that input is the whole body — write-only secrets
# included. Only loc/msg/type/url may ever leave the process.
VALIDATION_ERROR_HIDDEN_KEYS = frozenset({"input", "value", "ctx"})


def install_admin_hardening(app: Any) -> None:
    app.add_middleware(AdminBodyLimit, max_bytes=MAX_ADMIN_BODY_BYTES)

    @app.exception_handler(RequestValidationError)
    async def request_validation_without_echo(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        detail = [
            {
                key: value
                for key, value in error.items()
                if key not in VALIDATION_ERROR_HIDDEN_KEYS
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            {"detail": detail},
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
def build_admin_router() -> APIRouter:
    router = APIRouter(prefix="/api/admin", tags=["admin"])

    @router.get("/status")
    async def admin_status(request: Request) -> dict[str, Any]:
        settings = _settings(request)
        state = _state(request)
        session = _resolve_session(request)
        email = state.email_config()
        return {
            "setup_required": not state.has_admin(),
            "authenticated": session is not None,
            "csrf_token": session.csrf_token if session else None,
            "session_expires_at": _iso(session.expires_at) if session else None,
            "tls_backend": settings.tls_backend,
            "tls_hostname": settings.tls_hostname or None,
            # Recovery needs both a transport and an authoritative origin to
            # build the reset link from; without either it stays hidden.
            "recovery_enabled": bool(
                email is not None and email.recovery_email and settings.public_origin
            ),
            "version": VYSION_VERSION,
        }

    @router.post("/setup", status_code=status.HTTP_201_CREATED)
    async def admin_setup(request: Request, payload: SetupRequest) -> JSONResponse:
        require_origin(request)
        state = _state(request)
        client_scope = f"{SETUP_LOCK_PREFIX}:{_client_id(request)}"
        locked = state.lock_remaining(client_scope)
        if locked:
            raise _rate_limited(request, locked)
        if state.has_admin():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=SETUP_DONE)
        try:
            created = state.create_admin(payload.password)
        except PASSWORD_ERRORS:
            remaining = state.register_failure(
                client_scope,
                threshold=SETUP_LOCK_THRESHOLD,
                lock_seconds=SETUP_LOCK_SECONDS,
            )
            if remaining:
                raise _rate_limited(request, remaining) from None
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=PASSWORD_CONTRACT,
            ) from None
        if not created:
            # Lost the first-run race: another caller already created it.
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=SETUP_DONE)
        state.clear_failures(client_scope)
        return _signed_in(state, request, status_code=status.HTTP_201_CREATED)

    @router.post("/login")
    async def admin_login(request: Request, payload: LoginRequest) -> JSONResponse:
        require_origin(request)
        state = _state(request)
        account_lock = state.lock_remaining(ACCOUNT_LOCK_SCOPE)
        client_scope = f"{CLIENT_LOCK_PREFIX}:{_client_id(request)}"
        client_lock = state.lock_remaining(client_scope)
        if account_lock or client_lock:
            raise _rate_limited(request, max(account_lock or 0, client_lock or 0))
        if not state.has_admin() or not state.verify_password(payload.password):
            if state.has_admin():
                account_lock = state.register_failure(
                    ACCOUNT_LOCK_SCOPE,
                    threshold=ACCOUNT_LOCK_THRESHOLD,
                    lock_seconds=ACCOUNT_LOCK_SECONDS,
                )
                client_lock = state.register_failure(
                    client_scope,
                    threshold=CLIENT_LOCK_THRESHOLD,
                    lock_seconds=CLIENT_LOCK_SECONDS,
                )
                if account_lock or client_lock:
                    raise _rate_limited(request, max(account_lock or 0, client_lock or 0))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_CREDENTIALS
            )
        state.clear_failures(ACCOUNT_LOCK_SCOPE)
        state.clear_failures(client_scope)
        return _signed_in(state, request, status_code=status.HTTP_200_OK)

    @router.post("/logout")
    async def admin_logout(request: Request) -> JSONResponse:
        await require_mutation(request)
        raw_token = request.cookies.get(SESSION_COOKIE_NAME, "")
        if raw_token:
            _state(request).revoke_session(raw_token)
        return _cleared_cookie_response({"status": "closed"})

    @router.get("/session")
    async def admin_session(
        session: Annotated[SessionRecord, Depends(require_session)],
    ) -> dict[str, str]:
        return _session_payload(session)

    @router.get("/sessions")
    async def admin_sessions(
        request: Request,
        session: Annotated[SessionRecord, Depends(require_session)],
    ) -> dict[str, Any]:
        current = session.token_hash
        return {
            "sessions": [
                {
                    "created_at": _iso(record.created_at),
                    "expires_at": _iso(record.expires_at),
                    "current": record.token_hash == current,
                }
                for record in _state(request).list_sessions()
            ]
        }

    @router.post("/sessions/revoke")
    async def admin_revoke_sessions(
        request: Request,
        session: Annotated[SessionRecord, Depends(require_mutation)],
    ) -> JSONResponse:
        revoked = _state(request).revoke_all_sessions()
        return _cleared_cookie_response({"revoked": revoked})

    @router.post("/password")
    async def admin_password(
        request: Request,
        payload: PasswordChangeRequest,
        session: Annotated[SessionRecord, Depends(require_mutation)],
    ) -> JSONResponse:
        state = _state(request)
        locked = state.lock_remaining(ACCOUNT_LOCK_SCOPE)
        if locked:
            raise _rate_limited(request, locked)
        if not state.verify_password(payload.current_password):
            remaining = state.register_failure(
                ACCOUNT_LOCK_SCOPE,
                threshold=ACCOUNT_LOCK_THRESHOLD,
                lock_seconds=ACCOUNT_LOCK_SECONDS,
            )
            if remaining:
                raise _rate_limited(request, remaining)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_CREDENTIALS
            )
        state.clear_failures(ACCOUNT_LOCK_SCOPE)
        try:
            updated = state.set_password(payload.password)
        except PASSWORD_ERRORS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=PASSWORD_CONTRACT,
            ) from None
        if not updated:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=STATE_UNAVAILABLE)
        # set_password revokes every session, including this one.
        return _cleared_cookie_response({"status": "password_updated"})

    # ------------------------------------------------------------------
    # recovery
    # ------------------------------------------------------------------
    @router.post("/recovery/request")
    async def recovery_request(request: Request) -> JSONResponse:
        require_origin(request)
        settings = _settings(request)
        state = _state(request)
        scopes = (
            (f"{RECOVERY_CLIENT_PREFIX}:{_client_id(request)}", RECOVERY_CLIENT_THRESHOLD),
            (RECOVERY_GLOBAL_SCOPE, RECOVERY_GLOBAL_THRESHOLD),
        )
        for scope, threshold in scopes:
            locked = state.register_failure(
                scope, threshold=threshold, lock_seconds=RECOVERY_RATE_SECONDS
            )
            if locked:
                raise _rate_limited(request, locked)
        config = state.email_config()
        if config is None or not config.recovery_email:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=RECOVERY_DOWN
            )
        origin = settings.public_origin
        if not origin:
            # No authoritative address exists to build a reset link from:
            # fail closed rather than borrowing the caller-controlled Host.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=RECOVERY_NO_ORIGIN,
            )
        revision = state.admin_revision()
        if revision is None:
            return JSONResponse({"status": "pending"})
        raw_token = state.create_recovery_token(
            purpose=RECOVERY_PURPOSE,
            ttl_seconds=RECOVERY_TTL_SECONDS,
            revision=revision,
        )
        link = f"{origin}/admin/reset?token={raw_token}"
        body = (
            "Une demande de r\u00e9cup\u00e9ration de l'acc\u00e8s administrateur "
            "Vysion a \u00e9t\u00e9 \u00e9mise.\n\n"
            f"Pour choisir un nouveau mot de passe, ouvrez ce lien :\n{link}\n\n"
            f"Le jeton est \u00e0 usage unique et expire dans {RECOVERY_TTL_SECONDS} s.\n"
            "Si vous n'\u00eates pas \u00e0 l'origine de cette demande, ignorez ce "
            "message.\n"
        )
        mailer = request.app.state.recovery_mailer
        try:
            await asyncio.to_thread(
                mailer.send,
                to=config.recovery_email,
                subject="Vysion - r\u00e9cup\u00e9ration de l'acc\u00e8s administrateur",
                body=body,
            )
        except RecoveryUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=RECOVERY_DOWN
            ) from exc
        return JSONResponse({"status": "pending"})

    @router.post("/recovery/confirm")
    async def recovery_confirm(request: Request, payload: RecoveryConfirmRequest) -> JSONResponse:
        require_origin(request)
        state = _state(request)
        client_scope = f"{RECOVERY_CONFIRM_PREFIX}:{_client_id(request)}"
        locked = state.register_failure(
            client_scope,
            threshold=RECOVERY_CONFIRM_THRESHOLD,
            lock_seconds=RECOVERY_RATE_SECONDS,
        )
        if locked:
            raise _rate_limited(request, locked)
        # Validate the replacement password before the token is consumed.
        try:
            _validated_password(payload.password)
        except PASSWORD_ERRORS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=PASSWORD_CONTRACT,
            ) from None
        revision = state.admin_revision()
        if revision is None or not state.consume_recovery_token(
            payload.token, purpose=RECOVERY_PURPOSE, revision=revision
        ):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=BAD_RECOVERY_TOKEN)
        state.set_password(payload.password)
        state.clear_failures(client_scope)
        # Every session was revoked by set_password, including any local one.
        return _cleared_cookie_response({"status": "password_updated"})

    # -------------------------------------------------------------------------
    # Certificates: standalone TLS only, metadata never crosses the wire.
    # -------------------------------------------------------------------------
    @router.get("/certificates")
    async def certificates_status(
        request: Request,
        _session: Annotated[SessionRecord, Depends(require_session)],
    ) -> dict[str, Any]:
        settings = _settings(request)
        backend = _certificate_backend(request)
        try:
            listing = backend.status()
        except CertificateHelperUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            ) from exc
        return {
            **listing,
            "managed": backend.managed,
            "tls_backend": settings.tls_backend,
            "tls_hostname": settings.tls_hostname or None,
        }

    @router.post("/certificates/validate")
    async def certificates_validate(
        request: Request,
        _session: Annotated[SessionRecord, Depends(require_mutation)],
        certificate: Annotated[UploadFile, File()],
        private_key: Annotated[UploadFile | None, File()] = None,
        passphrase: Annotated[str | None, Form()] = None,
    ) -> dict[str, Any]:
        settings = _settings(request)
        backend = _certificate_backend(request)
        # One refusal block: the mode itself is answered before any hostname
        # or file question, exactly as it was before the backends existed.
        try:
            backend.ensure_available()
            hostname = settings.tls_hostname.strip()
            if not hostname:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT, detail="tls_hostname requis"
                )
            certificate_bytes = await certificate.read(MAX_CERTIFICATE_BYTES + 1)
            if len(certificate_bytes) > MAX_CERTIFICATE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=BODY_TOO_LARGE
                )
            key_bytes: bytes | None = None
            if private_key is not None:
                key_bytes = await private_key.read(MAX_CERTIFICATE_BYTES + 1)
                if len(key_bytes) > MAX_CERTIFICATE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=BODY_TOO_LARGE
                    )
                # An empty part means "not provided" (PKCS#12 needs no key file).
                if not key_bytes:
                    key_bytes = None
            metadata, digest = backend.validate(
                certificate=certificate_bytes,
                private_key=key_bytes,
                hostname=hostname,
                passphrase=passphrase or None,
            )
        except CertificateBackendUnavailable as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except CertificateHelperUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            ) from exc
        except CertificateError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
        if not digest:  # pragma: no cover - validate guarantees staging
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=STATE_UNAVAILABLE
            )
        state = _state(request)
        token = state.create_certificate_ticket(
            session_hash=_session.token_hash,
            content_digest=digest,
            ttl_seconds=CERT_TICKET_TTL_SECONDS,
        )
        return {
            "certificate": metadata.as_dict(),
            "ticket": {"token": token, "expires_in": CERT_TICKET_TTL_SECONDS},
        }

    @router.post("/certificates/activate")
    async def certificates_activate(
        request: Request,
        _session: Annotated[SessionRecord, Depends(require_mutation)],
        payload: CertificateActivateRequest,
    ) -> dict[str, Any]:
        backend = _certificate_backend(request)
        try:
            backend.ensure_available()
            digest = backend.staged_digest()
            if digest is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=NO_STAGING
                )
            state = _state(request)
            if not state.consume_certificate_ticket(
                payload.token,
                session_hash=_session.token_hash,
                content_digest=digest,
            ):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=BAD_TICKET)
            generation, certificate, served = backend.activate(digest)
        except CertificateBackendUnavailable as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except CertificateHelperUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            ) from exc
        except CertificateError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)
            ) from exc
        return {
            "status": "active",
            "generation": generation,
            "certificate": certificate,
            "served_sha256": served,
        }

    # -------------------------------------------------------------------------
    # Email: one section, one selected transport, write-only secrets.
    # -------------------------------------------------------------------------
    def _email_payload(request: Request) -> dict[str, Any]:
        """Public projection only: configured or not, never a configured value."""
        settings = _settings(request)
        state = _state(request)
        config = state.email_config()
        payload = state.email_public_status()
        payload["recovery_enabled"] = bool(
            config is not None and config.recovery_email and settings.public_origin
        )
        return payload

    @router.get("/email")
    async def email_status(
        request: Request,
        _session: Annotated[SessionRecord, Depends(require_session)],
    ) -> dict[str, Any]:
        return _email_payload(request)

    @router.put("/email")
    async def email_update(
        request: Request,
        payload: EmailConfigRequest,
        _session: Annotated[SessionRecord, Depends(require_mutation)],
    ) -> dict[str, Any]:
        state = _state(request)
        current = state.email_config()
        smtp_password = payload.smtp_password.strip()
        client_secret = payload.m365_client_secret.strip()
        # An empty secret keeps the stored one — but only for the transport it
        # belongs to, so a switch can never drag a credential along.
        if current is not None and current.transport == payload.transport:
            if not smtp_password:
                smtp_password = current.smtp_password or ""
            if not client_secret:
                client_secret = current.m365_client_secret or ""
        fields = {
            "transport": payload.transport,
            "from_address": payload.from_address.strip(),
            "recovery_email": payload.recovery_email.strip() or None,
            "timeout_seconds": payload.timeout_seconds,
            "smtp_host": payload.smtp_host.strip().lower() or None,
            "smtp_port": payload.smtp_port,
            "smtp_security": (payload.smtp_security or "starttls"),
            "smtp_username": payload.smtp_username.strip() or None,
            "smtp_password": smtp_password or None,
            "m365_tenant_id": payload.m365_tenant_id.strip() or None,
            "m365_client_id": payload.m365_client_id.strip() or None,
            "m365_client_secret": client_secret or None,
            "m365_mailbox": payload.m365_mailbox.strip() or None,
        }
        # An empty secret field keeps the stored one; the row that comes out
        # of that merge still has to be usable. An unusable row is refused
        # here rather than persisted half-configured, so keeping and saving
        # stay two clearly separated outcomes.
        if not EmailConfig(**fields).complete:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=EMAIL_INCOMPLETE,
            )
        state.set_email_config(**fields)
        return _email_payload(request)

    @router.post("/email/test")
    async def email_test_send(
        request: Request,
        _session: Annotated[SessionRecord, Depends(require_mutation)],
    ) -> dict[str, Any]:
        """Send through the LAST saved configuration, bounded per client."""
        state = _state(request)
        scope = f"{EMAIL_TEST_PREFIX}:{_client_id(request)}"
        locked = state.register_failure(
            scope, threshold=EMAIL_TEST_THRESHOLD, lock_seconds=EMAIL_TEST_RATE_SECONDS
        )
        if locked:
            raise _rate_limited(request, locked)
        config = state.email_config()
        if config is None or not config.complete:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=EMAIL_NOT_CONFIGURED,
            )
        if not config.recovery_email:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=EMAIL_NO_DESTINATION,
            )
        mailer = request.app.state.recovery_mailer
        try:
            await asyncio.to_thread(
                mailer.send,
                to=config.recovery_email,
                subject="Vysion - test du transport d'email",
                body=(
                    "Ce message vérifie que le transport sélectionné dans "
                    "l'administration Vysion fonctionne.\n"
                ),
            )
        except RecoveryUnavailable as exc:
            # The mailer layers only ever raise a fixed or whitelisted
            # message: no credential, no provider body, no address.
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)
            ) from exc
        return {"status": "sent", "transport": config.transport}

    return router

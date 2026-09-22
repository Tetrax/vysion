"""Password, session, proxy-trust and origin primitives for Vysion admin."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
from typing import Any

# Password contract: scrypt parameters are fixed so a tampered record is
# refused instead of silently weakening the KDF.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD_BYTES = 12
MAX_PASSWORD_BYTES = 1024

SESSION_COOKIE_NAME = "vysion_session"
SESSION_TTL_SECONDS = 43_200
CSRF_HEADER_NAME = "x-csrf-token"
FORWARDED_PROTO_HEADER = "x-forwarded-proto"
FORWARDED_FOR_HEADER = "x-forwarded-for"
ALLOWED_FORWARDED_SCHEMES = frozenset({"http", "https"})


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def hash_password(password: Any) -> dict[str, Any]:
    """Hash a password with scrypt; only explicit str input is accepted."""
    if not isinstance(password, str):
        raise ValueError("password must be text")
    encoded = password.encode("utf-8")
    if not MIN_PASSWORD_BYTES <= len(encoded) <= MAX_PASSWORD_BYTES:
        raise ValueError(
            f"password must be between {MIN_PASSWORD_BYTES} and {MAX_PASSWORD_BYTES} UTF-8 bytes"
        )
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        encoded,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return {
        "algorithm": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": _encode(salt),
        "digest": _encode(digest),
    }


def verify_password(password: Any, record: dict[str, Any]) -> bool:
    """Constant-time password check; a malformed record is refused."""
    if not isinstance(password, str):
        return False
    try:
        if record.get("algorithm") != "scrypt":
            raise ValueError("unsupported password algorithm")
        if any(
            record.get(key) != expected
            for key, expected in (
                ("n", SCRYPT_N),
                ("r", SCRYPT_R),
                ("p", SCRYPT_P),
            )
        ):
            raise ValueError("unsupported scrypt parameters")
        salt = base64.b64decode(str(record["salt"]), validate=True)
        expected = base64.b64decode(str(record["digest"]), validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("malformed password record") from exc
    if len(salt) != 16 or len(expected) != SCRYPT_DKLEN:
        raise ValueError("malformed password record")
    if not MIN_PASSWORD_BYTES <= len(password.encode("utf-8")) <= MAX_PASSWORD_BYTES:
        return False
    candidate = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return hmac.compare_digest(candidate, expected)


def token_digest(token: str) -> str:
    """SHA-256 of a bearer-style token: storage never keeps the token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def origin_header_value(scheme: str, host: str) -> str:
    """Build the exact Origin a same-origin browser request must send."""
    return f"{scheme.lower()}://{host.lower()}"


def session_cookie(
    token: str, *, secure: bool, max_age: int = SESSION_TTL_SECONDS
) -> dict[str, Any]:
    """Cookie attributes for the session token (never readable by scripts).

    The mapping is shaped so a route can spread it into
    ``response.set_cookie(...)`` without repeating the security flags.
    """
    return {
        "key": SESSION_COOKIE_NAME,
        "value": token,
        "max_age": max_age,
        "httponly": True,
        "samesite": "strict",
        "path": "/",
        "secure": secure,
    }


class TrustedProxy:
    """Forwarded headers are only believed from explicitly trusted peers."""

    def __init__(self, networks: tuple[Any, ...]) -> None:
        self._networks = networks

    @classmethod
    def parse(cls, value: str) -> TrustedProxy:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("trusted proxy CIDR list must not be empty")
        networks: list[Any] = []
        for part in value.split(","):
            candidate = part.strip()
            if not candidate:
                raise ValueError("trusted proxy CIDR list contains an empty entry")
            try:
                networks.append(ipaddress.ip_network(candidate, strict=False))
            except ValueError as exc:
                raise ValueError(f"invalid trusted proxy CIDR: {candidate}") from exc
        return cls(tuple(networks))

    def _is_trusted(self, address: str | None) -> bool:
        if not address:
            return False
        try:
            parsed = ipaddress.ip_address(address.strip())
        except ValueError:
            return False
        return any(parsed in network for network in self._networks)

    def client_ip(self, peer: str | None, forwarded: str | None) -> str | None:
        """Right-most hop outside the trusted set, only from a trusted peer."""
        if not self._is_trusted(peer):
            return None
        if not forwarded:
            return None
        for hop in reversed(forwarded.split(",")):
            candidate = hop.strip()
            if not candidate:
                return None
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return None
            if not self._is_trusted(candidate):
                return candidate
        return None

    def scheme(self, peer: str | None, forwarded: str | None, *, fallback: str) -> str:
        """Accept only http/https from a trusted peer, else the local truth.

        The local truth can itself be poisoned: a proxy server that passes a
        blank X-Forwarded-Proto through makes uvicorn record an empty scope
        scheme, so an unusable fallback is never trusted either — the
        connection then counts as plain http.
        """
        truth = fallback if fallback in ALLOWED_FORWARDED_SCHEMES else "http"
        if not self._is_trusted(peer):
            return truth
        if forwarded is None:
            return truth
        value = forwarded.strip().lower()
        if value not in ALLOWED_FORWARDED_SCHEMES:
            return truth
        return value

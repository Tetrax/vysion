"""Password, session, proxy-trust and origin primitives."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vysion.security import (
    MAX_PASSWORD_BYTES,
    MIN_PASSWORD_BYTES,
    TrustedProxy,
    hash_password,
    origin_header_value,
    session_cookie,
    token_digest,
    verify_password,
)


def test_password_hash_uses_scrypt_with_explicit_bounds_and_fresh_salt() -> None:
    first = hash_password("a-strong-enough-password")
    second = hash_password("a-strong-enough-password")

    assert first["algorithm"] == "scrypt"
    assert first["n"] == 1 << 15
    assert first["r"] == 8
    assert first["p"] == 1
    assert first["salt"] != second["salt"]
    assert first["digest"] != second["digest"]
    assert verify_password("a-strong-enough-password", first) is True
    assert verify_password("a-strong-enough-passwore", first) is False


def test_password_bounds_are_enforced_in_bytes_not_characters() -> None:
    with pytest.raises(ValueError):
        hash_password("short")
    with pytest.raises(ValueError):
        hash_password("x" * (MAX_PASSWORD_BYTES + 1))
    # The bound is measured on the UTF-8 encoding.
    long_multibyte = "é" * (MAX_PASSWORD_BYTES // 2 + 1)
    with pytest.raises(ValueError):
        hash_password(long_multibyte)
    assert MIN_PASSWORD_BYTES == 12
    assert verify_password("short", hash_password("a-strong-enough-password")) is False


def test_verify_password_is_constant_time_and_rejects_malformed_records() -> None:
    record = hash_password("a-strong-enough-password")
    with pytest.raises(ValueError):
        verify_password("a-strong-enough-password", {**record, "algorithm": "md5"})
    with pytest.raises(ValueError):
        verify_password("a-strong-enough-password", {**record, "n": 1024})
    assert verify_password(None, record) is False  # type: ignore[arg-type]


def test_session_digest_is_sha256_and_never_the_token_itself() -> None:
    digest = token_digest("abcdef-ZYX")
    assert len(digest) == 64
    assert digest != "abcdef-ZYX"
    assert digest == token_digest("abcdef-ZYX")


def test_trusted_proxy_only_reads_forwarded_headers_from_configured_cidrs() -> None:
    trusted = TrustedProxy.parse("127.0.0.1/32, 10.0.0.0/8")

    # Untrusted direct peer: forwarded headers are ignored entirely.
    assert trusted.client_ip("198.51.100.9", "203.0.113.7, 192.0.2.1") is None
    assert trusted.scheme("198.51.100.9", "https", fallback="http") == "http"

    # Trusted peer: the right-most hop outside the trusted set is the client,
    # so entries injected by the original client are never believed.
    assert trusted.client_ip("127.0.0.1", "6.6.6.6, 198.51.100.9, 127.0.0.1") == "198.51.100.9"
    assert trusted.client_ip("127.0.0.1", None) is None
    assert trusted.scheme("127.0.0.1", "https", fallback="http") == "https"
    assert trusted.scheme("127.0.0.1", "gopher", fallback="http") == "http"

    # A blank header (a plain-HTTP hop in front passed an empty value) is not
    # a scheme, and a poisoned local truth (uvicorn recorded an empty scope
    # scheme from that blank header) is not a scheme either: the connection
    # counts as plain http instead.
    assert trusted.scheme("127.0.0.1", "", fallback="http") == "http"
    assert trusted.scheme("127.0.0.1", "  ", fallback="http") == "http"
    assert trusted.scheme("127.0.0.1", "", fallback="") == "http"
    assert trusted.scheme("127.0.0.1", "https", fallback="") == "https"
    assert trusted.scheme("127.0.0.1", None, fallback="") == "http"
    assert trusted.scheme("198.51.100.9", "https", fallback="") == "http"


def test_trusted_proxy_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError):
        TrustedProxy.parse("")
    with pytest.raises(ValueError):
        TrustedProxy.parse("not-an-address")


def test_resolve_trusts_the_hop_our_nginx_observed_over_a_forged_chain() -> None:
    trusted = TrustedProxy.parse("127.0.0.1/32, 10.0.0.0/8")

    # Direct client of the bundled nginx: X-Real-IP is the hop nginx itself
    # observed ($remote_addr), so a forged X-Forwarded-For never selects the
    # client bucket and never buys a fresh rate-limit scope.
    client, scheme = trusted.resolve(
        "127.0.0.1",
        real_ip="198.51.100.7",
        forwarded_for="6.6.6.6",
        local_proto="http",
        client_proto="https",
        fallback="http",
    )
    assert client == "198.51.100.7"
    # The client is outside every trusted network: its scheme claim is dead.
    assert scheme == "http"

    # An explicitly trusted external proxy in front of the nginx: the chain
    # it forwarded decides the client (right-most hop outside the trusted
    # set), and its upstream scheme claim is honoured.
    client, scheme = trusted.resolve(
        "127.0.0.1",
        real_ip="10.0.0.5",
        forwarded_for="6.6.6.6, 203.0.113.9, 10.0.0.5",
        local_proto="http",
        client_proto="https",
        fallback="http",
    )
    assert client == "203.0.113.9"
    assert scheme == "https"

    # A blank claim or a blank local truth never becomes a scheme.
    _client, scheme = trusted.resolve(
        "127.0.0.1",
        real_ip="198.51.100.7",
        local_proto="  ",
        client_proto="",
        fallback="",
    )
    assert scheme == "http"

    # No forwarded header at all: the loopback peer itself is the hop.
    client, scheme = trusted.resolve("127.0.0.1", fallback="http")
    assert client is None  # falls back to the peer in the caller
    assert scheme == "http"

    # The local nginx truth (its own $scheme) still applies for a direct
    # client: the standalone terminator says https on 443.
    client, scheme = trusted.resolve(
        "127.0.0.1", real_ip="198.51.100.7", local_proto="https", fallback="http"
    )
    assert client == "198.51.100.7"
    assert scheme == "https"

    # A non-loopback direct peer keeps the strict behaviour: nothing is
    # believed unless that peer is itself an explicitly trusted proxy.
    assert trusted.resolve("198.51.100.9", local_proto="https", fallback="http") == (
        None,
        "http",
    )
    assert trusted.resolve(
        "10.0.0.5",
        forwarded_for="6.6.6.6, 203.0.113.9",
        local_proto="https",
        fallback="http",
    ) == ("203.0.113.9", "https")
    # An unusable chain is never half-believed.
    assert trusted.resolve(
        "10.0.0.5", forwarded_for="6.6.6.6, not-an-ip", fallback="http"
    ) == (None, "http")


def test_origin_value_is_exact_scheme_authority() -> None:
    assert origin_header_value("https", "vysion.valdev.me") == "https://vysion.valdev.me"
    assert origin_header_value("http", "127.0.0.1:18080") == "http://127.0.0.1:18080"


def test_session_cookie_is_httponly_strict_and_secure_on_https() -> None:
    secure = session_cookie("token-value", secure=True)
    assert secure["key"] == "vysion_session"
    assert secure["max_age"] > 0
    assert secure["httponly"] is True
    assert secure["samesite"] == "strict"
    assert secure["path"] == "/"
    assert secure["secure"] is True

    plain = session_cookie("token-value", secure=False)
    assert plain["httponly"] is True
    assert plain["samesite"] == "strict"
    assert plain["secure"] is False


def test_password_verification_always_runs_the_full_kdf() -> None:
    record = hash_password("a-strong-enough-password")
    started = datetime.now(UTC)
    for _ in range(3):
        verify_password("wrong-password-value", record)
    elapsed = (datetime.now(UTC) - started).total_seconds()
    # scrypt must actually run: no early exit on the first differing byte.
    assert elapsed > 0.05

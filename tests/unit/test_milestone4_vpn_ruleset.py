import pytest

from vysion.audit.rulesets.vpn_crypto import (
    VPN_CRYPTO_RULESET_ID,
    VPN_CRYPTO_RULESET_VERSION,
    is_allowed_vpn_proposal,
    is_denied_vpn_proposal,
    load_vpn_crypto_ruleset,
)


def test_vpn_crypto_ruleset_is_versioned_and_package_loaded() -> None:
    ruleset = load_vpn_crypto_ruleset()

    assert ruleset.id == VPN_CRYPTO_RULESET_ID
    assert ruleset.version == VPN_CRYPTO_RULESET_VERSION
    assert ruleset.allowed_tokens


@pytest.mark.parametrize(
    "proposal",
    [
        "aes256-sha256",
        "AES256-SHA384",
        "aes256-sha512",
        "aes256gcm",
        "aes256gcm-prfsha256",
        "aes256gcm-prfsha384",
        "aes256gcm-prfsha512",
        "chacha20poly1305",
        "chacha20poly1305-prfsha256",
        "chacha20poly1305-prfsha384",
        "chacha20poly1305-prfsha512",
    ],
)
def test_vpn_crypto_ruleset_accepts_supported_fortios_tokens(proposal: str) -> None:
    assert is_allowed_vpn_proposal(proposal)


@pytest.mark.parametrize(
    "proposal",
    [
        "3des-md5",
        "aes128-sha256",
        "aes256-md5",
        "aes256-sha1",
        "aes256gcm-prfmd5",
        "aes256gcm-unknown",
        "unknown-token",
        "aes256-sha256-extra",
        "aes256gcm-prfsha256-extra",
    ],
)
def test_vpn_crypto_ruleset_rejects_weak_or_unknown_full_tokens(proposal: str) -> None:
    assert not is_allowed_vpn_proposal(proposal)


@pytest.mark.parametrize("proposal", ["3des-md5", "AES256-SHA1", "aes256gcm-prfmd5"])
def test_vpn_crypto_ruleset_marks_only_declared_weak_tokens_as_denied(proposal: str) -> None:
    assert is_denied_vpn_proposal(proposal)


def test_vpn_crypto_ruleset_keeps_unknown_tokens_distinct_from_denied_tokens() -> None:
    assert not is_denied_vpn_proposal("unknown-token")

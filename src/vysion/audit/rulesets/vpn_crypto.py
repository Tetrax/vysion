from __future__ import annotations

import json
from importlib import resources

from pydantic import BaseModel, ConfigDict, Field


class VpnCryptoRuleset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: str
    allowed_tokens: frozenset[str] = Field(min_length=1)
    denied_tokens: frozenset[str] = Field(min_length=1)
    allowed_dh_groups: frozenset[int] = Field(min_length=1)
    denied_dh_groups: frozenset[int] = Field(min_length=1)


VPN_CRYPTO_RULESET_ID = "fortigate-vpn-crypto"
VPN_CRYPTO_RULESET_VERSION = "2026-08-13"


def load_vpn_crypto_ruleset() -> VpnCryptoRuleset:
    payload = resources.files("vysion.audit.rulesets").joinpath("vpn_crypto.json").read_text()
    ruleset = VpnCryptoRuleset.model_validate(json.loads(payload))
    if ruleset.id != VPN_CRYPTO_RULESET_ID or ruleset.version != VPN_CRYPTO_RULESET_VERSION:
        raise ValueError("unexpected VPN crypto ruleset identity")
    return ruleset


_RULESET = load_vpn_crypto_ruleset()


def is_allowed_vpn_proposal(proposal: str) -> bool:
    """Match a complete normalized FortiOS proposal token; never parse prefixes."""
    return proposal.casefold() in _RULESET.allowed_tokens


def is_denied_vpn_proposal(proposal: str) -> bool:
    """Match only locally declared weak proposal tokens, never unknown values."""
    return proposal.casefold() in _RULESET.denied_tokens


def is_allowed_vpn_dh_group(group: int) -> bool:
    """Return whether the versioned local policy explicitly accepts a DH group."""
    return group in _RULESET.allowed_dh_groups


def is_denied_vpn_dh_group(group: int) -> bool:
    """Return whether the versioned local policy explicitly rejects a DH group."""
    return group in _RULESET.denied_dh_groups

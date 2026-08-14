from __future__ import annotations

from vysion.audit.models import ProofState
from vysion.audit.parser import FortiGateParser

STRONG_VPN = """\
config vpn ssl settings
    set status disable
end
config vpn ipsec phase1-interface
    edit "branch-vpn"
        set interface "wan1"
        set ike-version 2
        set dhgrp 14 19
        set proposal aes256-sha256 aes256gcm-prfsha384
    next
end
config vpn ipsec phase2-interface
    edit "branch-vpn-p2"
        set phase1name "branch-vpn"
        set dhgrp 14
        set proposal aes256-sha256
    next
end
"""


def test_m4_parser_projects_ssl_and_ipsec_typed_relations() -> None:
    configuration = FortiGateParser().parse(STRONG_VPN)

    assert configuration.ssl_vpn_settings is not None
    assert configuration.ssl_vpn_settings.status == "disable"
    assert configuration.ssl_vpn_settings.proof_state is ProofState.PROVEN
    assert configuration.ssl_vpn_settings.parsed_keys == frozenset({"status"})

    assert len(configuration.ipsec_phase1) == 1
    phase1 = configuration.ipsec_phase1[0]
    assert phase1.name == "branch-vpn"
    assert phase1.interface == "wan1"
    assert phase1.ike_version == 2
    assert phase1.dh_groups == (14, 19)
    assert phase1.proposals == ("aes256-sha256", "aes256gcm-prfsha384")
    assert phase1.proof_state is ProofState.PROVEN

    assert len(configuration.ipsec_phase2) == 1
    phase2 = configuration.ipsec_phase2[0]
    assert phase2.name == "branch-vpn-p2"
    assert phase2.phase1_name == "branch-vpn"
    assert phase2.phase1_reference is not None
    assert phase2.phase1_reference.name == "branch-vpn"
    assert phase2.dh_groups == (14,)
    assert phase2.proposals == ("aes256-sha256",)
    assert phase2.proof_state is ProofState.PROVEN


def test_m4_parser_preserves_mutation_and_duplicate_uncertainty() -> None:
    raw = """\
config vpn ssl settings
    set status disable
    unset status
end
config vpn ipsec phase1-interface
    edit "mutated"
        set interface "wan1"
        set ike-version 2
        unset ike-version
        set dhgrp 14
        append dhgrp 19
        set proposal aes256-sha256
        select proposal aes256gcm
    next
    edit "duplicate"
        set interface "wan1"
        set ike-version 2
        set ike-version 2
        set dhgrp 14
        set proposal aes256-sha256
    next
end
config vpn ipsec phase2-interface
    edit "orphan"
        set phase1name "missing"
        set dhgrp 14
        set proposal aes256-sha256
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.ssl_vpn_settings is not None
    assert configuration.ssl_vpn_settings.status is None
    assert "status" in configuration.ssl_vpn_settings.invalidated_keys
    assert configuration.ssl_vpn_settings.proof_state is ProofState.UNKNOWN

    mutated = configuration.ipsec_phase1[0]
    assert mutated.ike_version is None
    assert mutated.proposals == ()
    assert {"ike-version", "dhgrp", "proposal"} <= mutated.invalidated_keys
    assert mutated.proof_state is ProofState.UNKNOWN

    duplicate = configuration.ipsec_phase1[1]
    assert duplicate.proof_state is ProofState.UNKNOWN
    assert {"interface", "dhgrp", "proposal"} <= duplicate.parsed_keys
    assert "ike-version" in duplicate.invalidated_keys

    orphan = configuration.ipsec_phase2[0]
    assert orphan.phase1_name == "missing"
    assert orphan.phase1_reference is None
    assert orphan.proof_state is ProofState.UNKNOWN


def test_m4_parser_keeps_empty_ssl_settings_unknown() -> None:
    configuration = FortiGateParser().parse("config vpn ssl settings\nend\n")

    assert configuration.ssl_vpn_settings is not None
    assert configuration.ssl_vpn_settings.status is None
    assert configuration.ssl_vpn_settings.proof_state is ProofState.UNKNOWN


def test_m4_parser_rejects_truncated_vpn_sections() -> None:
    raw = """\
config vpn ipsec phase1-interface
    edit "truncated"
        set ike-version 2
"""

    try:
        FortiGateParser().parse(raw)
    except ValueError as exc:
        assert "unsupported or incomplete" in str(exc)
    else:
        raise AssertionError("truncated VPN section must be rejected")

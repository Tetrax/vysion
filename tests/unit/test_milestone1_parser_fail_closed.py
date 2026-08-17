import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditStatus, EvidenceCertainty, ProofState
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


def _finding(raw: str, control_id: str):
    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))
    return next(finding for finding in findings if finding.control_id == control_id)


def test_generic_mutation_after_set_invalidates_the_projected_key() -> None:
    configuration = FortiGateParser().parse(
        """config firewall policy
    edit 10
        set srcintf "lan"
        append srcintf "dmz"
    next
end
"""
    )

    policy = configuration.policies[0]
    assert policy.proof_state is ProofState.UNKNOWN
    assert "srcintf" not in policy.parsed_keys
    section = configuration.document.section("firewall policy")
    assert section is not None
    assert "srcintf" in section.entries[0].invalidated_keys


def test_three_duplicate_generic_directives_remain_ambiguous() -> None:
    configuration = FortiGateParser().parse(
        """config system zone
    edit "internet"
        set interface "wan1"
        set interface "wan2"
        set interface "wan3"
    next
end
"""
    )

    zone = configuration.zones[0]
    assert zone.proof_state is ProofState.UNKNOWN
    assert zone.interfaces == ()
    assert zone.parsed_keys == frozenset()


def test_duplicate_generic_entries_and_sections_never_become_certain() -> None:
    repeated = FortiGateParser().parse(
        """config system interface
    edit "wan1"
    next
    edit "lan"
    next
end
config system zone
    edit "internet"
        set interface "wan1"
    next
end
config system zone
    edit "private"
        set interface "lan"
    next
end
"""
    )
    assert {zone.name for zone in repeated.zones} == {"internet", "private"}
    assert all(zone.proof_state is ProofState.PROVEN for zone in repeated.zones)

    configuration = FortiGateParser().parse(
        """config system zone
    edit "internet"
        set interface "wan1"
    next
    edit "internet"
        set interface "wan2"
    next
end
"""
    )

    sections = [
        section for section in configuration.document.sections if section.name == "system zone"
    ]
    assert len(sections) == 1
    assert all(
        entry.certainty is EvidenceCertainty.AMBIGUOUS
        for section in sections
        for entry in section.entries
    )
    assert all(
        entry.parsed_keys == frozenset()
        and "interface" in entry.invalidated_keys
        for section in sections
        for entry in section.entries
    )
    assert configuration.zones[0].proof_state is ProofState.UNKNOWN

    configuration = FortiGateParser().parse(
        """config system zone
    edit "internet"
        set interface "wan1"
    next
    edit "internet"
        set interface "wan2"
    next
end
"""
    )
    section = configuration.document.section("system zone")
    assert section is not None
    assert all(entry.certainty is EvidenceCertainty.AMBIGUOUS for entry in section.entries)
    assert all(zone.proof_state is ProofState.UNKNOWN for zone in configuration.zones)


def test_truncated_nested_generic_block_is_rejected_fail_closed() -> None:
    with pytest.raises(ValueError, match="unsupported or incomplete"):
        FortiGateParser().parse(
            """config firewall policy
    edit 10
        config match-condition
            edit 1
                set srcintf "lan"
            next
    end
"""
        )


def test_unknown_interface_directive_invalidates_wan_compliance_proof() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
        set future-management ssh
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.UNKNOWN


def test_unknown_nested_interface_section_invalidates_wan_compliance_proof() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
        config vendor-extra
            edit "hidden"
                set allowaccess ssh
            next
        end
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.UNKNOWN


def test_unknown_nested_admin_section_invalidates_mfa_compliance_proof() -> None:
    raw = """config system admin
    edit "secops"
        set two-factor fortitoken
        config vendor-extra
            edit "hidden"
                set two-factor none
            next
        end
    next
end
"""

    assert _finding(raw, "IAM-ADMIN-MFA-001").status is AuditStatus.UNKNOWN


def test_unknown_grandchild_under_gui_dashboard_invalidates_admin_mfa() -> None:
    raw = """config system admin
    edit "secops"
        set two-factor fortitoken
        config gui-dashboard
            edit 1
                set name "safe"
                config widget
                    edit 1
                        set type licinfo
                        config vendor-extra
                            set two-factor none
                        end
                    next
                end
            next
        end
    next
end
"""

    assert _finding(raw, "IAM-ADMIN-MFA-001").status is AuditStatus.UNKNOWN


def test_unknown_nested_global_section_invalidates_hostname_compliance_proof() -> None:
    raw = """config system global
    set hostname safe.example
    config vendor-extra
        set hostname fortigate
    end
end
"""

    assert _finding(raw, "SYS-HOSTNAME-001").status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    "section, directive",
    [
        ("system global", "HOSTNAME"),
        ("system global", '"hostname"'),
        ("SYSTEM GLOBAL", "hostname"),
    ],
)
def test_ambiguous_hostname_spelling_never_produces_pass(
    section: str, directive: str
) -> None:
    raw = f"""config {section}
    set {directive} safe.example
end
"""

    assert _finding(raw, "SYS-HOSTNAME-001").status is AuditStatus.UNKNOWN


def test_explicit_wan_violation_dominates_unknown_interface_directive() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping ssh
        set future-management opaque
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.FAIL


def test_explicit_disabled_mfa_dominates_unknown_nested_admin_section() -> None:
    raw = """config system admin
    edit "admin"
        set two-factor disable
        config vendor-extra
            set opaque value
        end
    next
end
"""

    assert _finding(raw, "IAM-ADMIN-MFA-001").status is AuditStatus.FAIL


def test_explicit_generic_hostname_dominates_unknown_nested_global_section() -> None:
    raw = """config system global
    set hostname fortigate
    config vendor-extra
        set opaque value
    end
end
"""

    assert _finding(raw, "SYS-HOSTNAME-001").status is AuditStatus.FAIL


def test_noncanonical_projected_section_case_cannot_produce_pass() -> None:
    raw = """config SYSTEM INTERFACE
    edit "wan1"
        set role wan
        set allowaccess ping
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.UNKNOWN


def test_noncanonical_projected_key_case_cannot_produce_pass() -> None:
    raw = """config system interface
    edit "wan1"
        set Role wan
        set ALLOWACCESS ping
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.UNKNOWN


def test_unknown_descendant_under_supported_secondaryip_cannot_produce_pass() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
        config secondaryip
            edit 1
                set ip 192.0.2.2/32
                set allowaccess ping
                config vendor-extra
                    edit 1
                        set allowaccess ssh
                    next
                end
            next
        end
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.UNKNOWN


def test_unknown_key_in_projected_m3_namespace_cannot_produce_pass() -> None:
    raw = """config log setting
    set fwpolicy-implicit-log enable
    set mystery disable
end
"""

    assert _finding(raw, "FW-IMPLICIT-DENY-LOG-001").status is AuditStatus.UNKNOWN


def test_explicit_m3_violation_dominates_unknown_projected_key() -> None:
    raw = """config log setting
    set fwpolicy-implicit-log disable
    set mystery opaque
end
"""

    assert _finding(raw, "FW-IMPLICIT-DENY-LOG-001").status is AuditStatus.FAIL


def test_unknown_key_in_disabled_ssl_vpn_cannot_prove_not_applicable() -> None:
    raw = """config vpn ssl settings
    set status disable
    set mystery opaque
end
"""

    assert _finding(raw, "VPN-SSL-001").status is AuditStatus.UNKNOWN


def test_explicit_ikev1_dominates_unknown_projected_key() -> None:
    raw = """config vpn ipsec phase1-interface
    edit "p1"
        set status enable
        set interface "wan1"
        set ike-version 1
        set proposal aes256-sha256
        set dhgrp 14
        set mystery opaque
    next
end
config vpn ipsec phase2-interface
end
"""

    assert _finding(raw, "VPN-IKEV2-001").status is AuditStatus.FAIL

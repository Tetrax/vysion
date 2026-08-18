from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    AuditContext,
    AuditStatus,
    EvidenceCertainty,
    WanSelection,
    WanSelectionKind,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

SIP_ALG_DISABLED = """config system global
    set default-voip-alg-mode kernel-helper-based
end
config system session-helper
    edit 1
        set name ftp
    next
end
"""


def _finding(raw: str):
    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)
    return next(finding for finding in findings if finding.control_id == "NET-SIP-ALG-001")


def test_sip_alg_disabled_is_proven_from_typed_sections() -> None:
    finding = _finding(SIP_ALG_DISABLED)

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_sip_mode_in_system_settings_is_proven() -> None:
    raw = """config system settings
    set default-voip-alg-mode kernel-helper-based
end
config system session-helper
    edit 1
        set name ftp
    next
end
"""

    finding = _finding(raw)

    assert finding.status is AuditStatus.PASS
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_sip_session_helper_entry_with_port_is_still_proven() -> None:
    raw = """config system global
    set default-voip-alg-mode kernel-helper-based
end
config system session-helper
    edit 1
        set name ftp
        set protocol 6
        set port 21
    next
end
"""

    finding = _finding(raw)

    assert finding.status is AuditStatus.PASS


def test_sip_session_helper_is_a_certain_failure() -> None:
    raw = """config system global
    set default-voip-alg-mode kernel-helper-based
end
config system session-helper
    edit 1
        set name sip
    next
end
"""

    finding = _finding(raw)

    assert finding.status is AuditStatus.FAIL
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)
    assert any(item.entry == "1" and item.directive == "name" for item in finding.evidence_items)


def test_sip_default_voip_mode_wrong_value_is_a_certain_failure() -> None:
    raw = """config system global
    set default-voip-alg-mode proxy-based
end
config system session-helper
end
"""

    finding = _finding(raw)

    assert finding.status is AuditStatus.FAIL
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_sip_missing_global_mode_is_unknown() -> None:
    raw = """config system session-helper
    edit 1
        set name ftp
    next
end
"""

    assert _finding(raw).status is AuditStatus.UNKNOWN


def test_sip_explicit_empty_session_helper_can_prove_absence() -> None:
    raw = """config system global
    set default-voip-alg-mode kernel-helper-based
end
config system session-helper
end
"""

    assert _finding(raw).status is AuditStatus.PASS


def test_sip_section_level_directive_is_unknown_not_absence() -> None:
    raw = """config system global
    set default-voip-alg-mode kernel-helper-based
end
config system session-helper
    set name sip
end
"""

    finding = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert all(item.certainty is not EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_sip_repeated_session_helper_sections_are_unknown_not_absence() -> None:
    raw = """config system global
    set default-voip-alg-mode kernel-helper-based
end
config system session-helper
end
config system session-helper
    edit 1
        set name sip
    next
end
"""

    finding = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert all(item.certainty is not EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_sdwan_selected_interface_membership_is_proven_through_registry() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
    next
end
config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set zone "virtual-wan-link"
        next
    end
end
"""
    configuration = FortiGateParser().parse(raw)
    context = AuditContext(
        wan_selections=(
            WanSelection(name="wan1", kind=WanSelectionKind.INTERFACE, interfaces=("wan1",)),
        )
    )

    findings = AuditEngine(default_registry()).run(configuration, context=context)
    finding = next(item for item in findings if item.control_id == "NET-SDWAN-USAGE-001")

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_sdwan_missing_selected_interface_is_a_certain_failure() -> None:
    raw = """config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set zone "virtual-wan-link"
        next
    end
end
"""
    configuration = FortiGateParser().parse(raw)
    context = AuditContext(
        wan_selections=(
            WanSelection(name="wan2", kind=WanSelectionKind.INTERFACE, interfaces=("wan2",)),
        )
    )

    finding = next(
        item
        for item in AuditEngine(default_registry()).run(configuration, context=context)
        if item.control_id == "NET-SDWAN-USAGE-001"
    )

    assert finding.status is AuditStatus.FAIL
    assert [item.name for item in finding.affected_objects] == ["wan2"]


def test_by_sequence_global_label_is_proven_through_registry() -> None:
    raw = """config firewall policy
    edit 10
        set global-label "Internet"
        set srcintf "lan"
        set dstintf "wan1"
    next
end
"""
    configuration = FortiGateParser().parse(raw)

    finding = next(
        item
        for item in AuditEngine(default_registry()).run(configuration)
        if item.control_id == "FW-BY-SEQUENCE-USAGE-001"
    )

    assert finding.status is AuditStatus.PASS
    assert finding.affected_objects[0].name == "10"
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_by_sequence_multi_interface_or_any_is_detected() -> None:
    raw = """config firewall policy
    edit 10
        set srcintf "lan" "dmz"
        set dstintf "wan1"
    next
    edit 20
        set srcintf "lan"
        set dstintf "any"
    next
end
"""
    configuration = FortiGateParser().parse(raw)

    finding = next(
        item
        for item in AuditEngine(default_registry()).run(configuration)
        if item.control_id == "FW-BY-SEQUENCE-USAGE-001"
    )

    assert finding.status is AuditStatus.PASS
    assert {item.name for item in finding.affected_objects} == {"10", "20"}


def test_by_sequence_complete_single_interface_policies_are_a_certain_failure() -> None:
    raw = """config firewall policy
    edit 10
        set srcintf "lan"
        set dstintf "wan1"
    next
end
"""
    configuration = FortiGateParser().parse(raw)

    finding = next(
        item
        for item in AuditEngine(default_registry()).run(configuration)
        if item.control_id == "FW-BY-SEQUENCE-USAGE-001"
    )

    assert finding.status is AuditStatus.FAIL


def test_by_sequence_missing_interface_evidence_is_unknown() -> None:
    raw = """config firewall policy
    edit 10
        set srcintf "lan"
    next
end
"""
    configuration = FortiGateParser().parse(raw)

    finding = next(
        item
        for item in AuditEngine(default_registry()).run(configuration)
        if item.control_id == "FW-BY-SEQUENCE-USAGE-001"
    )

    assert finding.status is AuditStatus.UNKNOWN


def test_ssl_ssh_used_profile_is_proven_through_nested_https() -> None:
    raw = """#config-version=FGT60F-7.4.5-FW-build0000-240101:opmode=0:vdom=0:user=admin
config firewall policy
    edit 10
        set ssl-ssh-profile "deep-inspection"
    next
end
config firewall ssl-ssh-profile
    edit "deep-inspection"
        config https
            set cert-probe-failure allow
        end
    next
end
"""
    configuration = FortiGateParser().parse(raw)

    finding = next(
        item
        for item in AuditEngine(default_registry()).run(configuration)
        if item.control_id == "FW-SSL-SSH-PROFILE-001"
    )

    assert finding.status is AuditStatus.PASS
    assert finding.affected_objects[0].name == "deep-inspection"
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_ssl_ssh_used_nonconforming_profile_is_a_certain_failure() -> None:
    raw = """#config-version=FGT60F-7.4.5-FW-build0000-240101:opmode=0:vdom=0:user=admin
config firewall policy
    edit 10
        set ssl-ssh-profile "deep-inspection"
    next
end
config firewall ssl-ssh-profile
    edit "deep-inspection"
        config https
            set cert-probe-failure block
            set sni-server-cert-check enable
        end
    next
end
"""
    configuration = FortiGateParser().parse(raw)

    finding = next(
        item
        for item in AuditEngine(default_registry()).run(configuration)
        if item.control_id == "FW-SSL-SSH-PROFILE-001"
    )

    assert finding.status is AuditStatus.FAIL


def test_ssl_ssh_unresolved_or_mutated_profile_is_unknown() -> None:
    undefined_raw = """#config-version=FGT60F-7.4.5-FW-build0000-240101:opmode=0:vdom=0:user=admin
config firewall policy
    edit 10
        set ssl-ssh-profile "missing"
    next
end
config firewall ssl-ssh-profile
end
"""
    mutated_raw = """#config-version=FGT60F-7.4.5-FW-build0000-240101:opmode=0:vdom=0:user=admin
config firewall policy
    edit 10
        set ssl-ssh-profile "deep-inspection"
    next
end
config firewall ssl-ssh-profile
    edit "deep-inspection"
        config https
            set cert-probe-failure allow
            unset cert-probe-failure
        end
    next
end
"""

    for raw in (undefined_raw, mutated_raw):
        configuration = FortiGateParser().parse(raw)
        finding = next(
            item
            for item in AuditEngine(default_registry()).run(configuration)
            if item.control_id == "FW-SSL-SSH-PROFILE-001"
        )
        assert finding.status is AuditStatus.UNKNOWN


def test_ssl_ssh_control_is_not_applicable_before_legacy_version_threshold() -> None:
    raw = """#config-version=FGT60F-7.4.4-FW-build0000-240101:opmode=0:vdom=0:user=admin
config firewall policy
end
"""
    configuration = FortiGateParser().parse(raw)

    finding = next(
        item
        for item in AuditEngine(default_registry()).run(configuration)
        if item.control_id == "FW-SSL-SSH-PROFILE-001"
    )

    assert finding.status is AuditStatus.NOT_APPLICABLE
    assert finding.applicability.value == "not_applicable"

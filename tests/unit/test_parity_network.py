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

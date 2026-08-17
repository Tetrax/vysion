from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditStatus, EvidenceCertainty
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

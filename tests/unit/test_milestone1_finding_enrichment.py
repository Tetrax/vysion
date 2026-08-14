from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    Applicability,
    AuditContext,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


def _finding(findings, control_id: str):
    return next(finding for finding in findings if finding.control_id == control_id)


def test_existing_controls_emit_milestone_one_finding_metadata_and_structured_evidence() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping ssh
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))
    wan = _finding(findings, "NET-WAN-MGMT-001")

    assert wan.category == "network"
    assert wan.priority is AuditPriority.P0
    assert wan.severity is AuditSeverity.HIGH
    assert wan.applicability is Applicability.APPLICABLE
    assert wan.affected_objects[0].name == "wan1"
    assert wan.risk is not None
    assert wan.risk.summary
    assert wan.remediation
    assert wan.customer_approval is None
    assert wan.evidence_items[0].line == 4
    assert wan.evidence_items[0].entry == "wan1"


def test_unknown_finding_keeps_applicability_unknown_and_never_approves_customer_action() -> None:
    configuration = FortiGateParser().parse("config system global\nend\n")
    finding = _finding(
        AuditEngine(default_registry()).run(configuration),
        "NET-WAN-MGMT-001",
    )

    assert finding.status is AuditStatus.UNKNOWN
    assert finding.applicability is Applicability.UNKNOWN
    assert finding.customer_approval is None


def test_hostname_pass_has_structured_document_evidence_and_metadata() -> None:
    raw = 'config system global\n    set hostname "edge.example"\nend\n'

    finding = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))[0]

    assert finding.status is AuditStatus.PASS
    assert finding.category == "system"
    assert finding.applicability is Applicability.APPLICABLE
    assert finding.evidence_items
    assert finding.evidence_items[0].section == "system global"
    assert finding.evidence_items[0].directive == "hostname"
    assert finding.evidence_items[0].line == 2


def test_admin_mfa_pass_has_structured_document_evidence_and_metadata() -> None:
    raw = """config system admin
    edit "secops"
        set two-factor fortitoken
    next
end
"""

    finding = _finding(
        AuditEngine(default_registry()).run(FortiGateParser().parse(raw)),
        "IAM-ADMIN-MFA-001",
    )

    assert finding.status is AuditStatus.PASS
    assert finding.category == "identity"
    assert finding.evidence_items
    assert finding.evidence_items[0].entry == "secops"
    assert finding.evidence_items[0].directive == "two-factor"
    assert finding.evidence_items[0].line == 3


def test_declared_wan_context_is_validated_against_interface_projection() -> None:
    raw = """config system interface
    edit "wan1"
        set allowaccess ping https
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    finding = _finding(
        AuditEngine(default_registry()).run(
            configuration,
            AuditContext(selected_wans=("does-not-exist",)),
        ),
        "NET-WAN-MGMT-001",
    )

    assert finding.status is AuditStatus.UNKNOWN
    assert finding.applicability is Applicability.UNKNOWN
    assert "does-not-exist" in " ".join(finding.evidence)


def test_every_unknown_control_result_keeps_applicability_unknown() -> None:
    raw = """config system interface
    edit "wan1"
    next
end
config system admin
    edit "secops"
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    wan = _finding(findings, "NET-WAN-MGMT-001")
    admin_mfa = _finding(findings, "IAM-ADMIN-MFA-001")
    assert wan.status is AuditStatus.UNKNOWN
    assert wan.applicability is Applicability.UNKNOWN
    assert admin_mfa.status is AuditStatus.UNKNOWN
    assert admin_mfa.applicability is Applicability.UNKNOWN

from vysion.audit.models import AuditFinding, AuditStatus


def test_audit_finding_exposes_milestone_one_contract_fields() -> None:
    finding = AuditFinding(
        control_id="NET-WAN-MGMT-001",
        title="Administration WAN",
        status=AuditStatus.FAIL,
        category="network",
        priority="P0",
        severity="high",
        applicability="applicable",
        evidence=("wan1: allowaccess includes ssh",),
        affected_objects=("wan1",),
        risk={"summary": "Exposition WAN", "impact": "administration compromise"},
        message="SSH est exposé.",
        recommendation="Retirer SSH.",
        remediation="Modifier allowaccess puis valider la configuration.",
        customer_approval=True,
    )

    assert finding.category == "network"
    assert finding.priority == "P0"
    assert finding.severity == "high"
    assert finding.applicability == "applicable"
    assert finding.affected_objects[0].name == "wan1"
    assert finding.risk.summary == "Exposition WAN"
    assert finding.remediation.startswith("Modifier")
    assert finding.customer_approval is True
    assert finding.model_config["frozen"] is True

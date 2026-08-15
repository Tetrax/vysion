import pytest

from vysion.audit.models import Applicability, AuditFinding, AuditStatus


def test_not_applicable_finding_never_exposes_pass_status() -> None:
    finding = AuditFinding(
        control_id="TEST-NA-001",
        title="Contrôle non applicable",
        status=AuditStatus.PASS,
        applicability=Applicability.NOT_APPLICABLE,
        message="Le périmètre est explicitement hors sujet.",
    )

    assert finding.status is AuditStatus.NOT_APPLICABLE
    assert finding.applicability is Applicability.NOT_APPLICABLE


def test_not_applicable_status_canonicalizes_applicability() -> None:
    finding = AuditFinding(
        control_id="TEST-NA-002",
        title="Statut non applicable",
        status=AuditStatus.NOT_APPLICABLE,
        applicability=Applicability.APPLICABLE,
        message="Le contrôle est explicitement hors sujet.",
    )

    assert finding.status is AuditStatus.NOT_APPLICABLE
    assert finding.applicability is Applicability.NOT_APPLICABLE


@pytest.mark.parametrize("status", [AuditStatus.FAIL, AuditStatus.ERROR])
def test_explicit_violation_or_error_cannot_be_hidden_as_not_applicable(
    status: AuditStatus,
) -> None:
    with pytest.raises(ValueError, match="FAIL or ERROR"):
        AuditFinding(
            control_id="TEST-CONTRADICTION",
            title="Contradiction",
            status=status,
            applicability=Applicability.NOT_APPLICABLE,
            message="Contradiction explicite.",
        )

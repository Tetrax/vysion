import json
from pathlib import Path

from vysion.audit.models import AuditFinding, AuditStatus
from vysion.reports.presentation import build_presentation, present_finding

CONTROL_IDS = tuple(
    json.loads(
        (Path(__file__).parents[2] / "docs" / "V1_V2_CAPABILITY_MAP.json").read_text()
    )["v2_registry"]["control_ids"]
)


def _finding(control_id: str) -> AuditFinding:
    return AuditFinding(
        control_id=control_id,
        title=f"technical:{control_id}",
        status=AuditStatus.PASS,
        message="ok",
    )


def test_internal_control_id_is_separate_from_v1_display_name() -> None:
    admin = present_finding(_finding("IAM-ADMIN-MFA-001"))
    all_service = present_finding(_finding("FW-INTERNET-ALL-SERVICE-001"))

    assert admin.control_id == "IAM-ADMIN-MFA-001"
    assert admin.title == "technical:IAM-ADMIN-MFA-001"
    assert admin.display_name == (
        "Vérification de la présence de MFA sur les comptes locaux administrateurs et utilisateurs"
    )
    assert all_service.control_id == "FW-INTERNET-ALL-SERVICE-001"
    assert all_service.display_name == (
        "Filtrage des ports au strict minimum pour les flux vers Internet"
    )


def test_presentation_matrix_explains_57_business_points_and_60_engine_controls() -> None:
    findings = tuple(_finding(control_id) for control_id in CONTROL_IDS)
    presentation = build_presentation(findings)

    assert presentation.business_control_count == 57
    assert presentation.engine_control_count == 60
    assert presentation.registered_business_count == 53
    assert presentation.registered_finding_count == 56
    assert presentation.split_extra_finding_count == 3
    assert presentation.v2_only_control_count == 4
    assert len(presentation.business_rows) == 57
    assert len(presentation.v2_only_rows) == 4

    mfa = next(row for row in presentation.business_rows if row.order == 20)
    vpn = next(row for row in presentation.business_rows if row.order == 21)
    one_to_one = next(row for row in presentation.business_rows if row.order == 8)
    assert mfa.relation == "split"
    assert mfa.v2_control_ids == ("IAM-ADMIN-MFA-001", "IAM-LOCAL-USER-MFA-001")
    assert vpn.relation == "split"
    assert vpn.v2_control_ids == ("VPN-IKEV2-001", "VPN-DH-001", "VPN-CRYPTO-001")
    assert one_to_one.relation == "equivalent"
    assert one_to_one.v2_control_ids == ("FW-INTERNET-ALL-SERVICE-001",)

    assert presentation.explanation_lines == (
        "53 capacités V1 produisent 56 findings V2 : deux capacités V1 sont "
        "détaillées en sous-contrôles.",
        "4 contrôles V2 complémentaires sont séparés de la lecture métier V1.",
        "2 capacités V1 disposent d'une implémentation typée hors registre et 2 "
        "sont des projections de données.",
    )

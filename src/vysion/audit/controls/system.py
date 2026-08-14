from vysion.audit.controls._evidence import (
    directive_for,
    evidence_for_directive,
    section_for,
)
from vysion.audit.models import (
    Applicability,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    FortiGateConfiguration,
    RiskAssessment,
)


def check_hostname(configuration: FortiGateConfiguration) -> AuditFinding:
    metadata = {
        "control_id": "SYS-HOSTNAME-001",
        "title": "Hostname explicite",
        "category": "system",
        "priority": AuditPriority.P2,
        "severity": AuditSeverity.MEDIUM,
    }
    normalized = configuration.hostname.strip() if configuration.hostname else ""
    explicit_failure = bool(configuration.hostname is not None and not normalized) or (
        normalized.casefold() == "fortigate"
    )
    evidence_item = evidence_for_directive(
        configuration.document,
        "system global",
        "hostname",
    )
    evidence_is_certain = evidence_item.certainty is EvidenceCertainty.CERTAIN
    section = section_for(configuration.document, "system global")
    explicit_failure_is_certain = bool(
        section is not None and directive_for(section.directives, "hostname") is not None
    )
    if explicit_failure and explicit_failure_is_certain:
        return AuditFinding(
            **metadata,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=(f"hostname: {configuration.hostname or 'absent ou générique'}",),
            evidence_items=(evidence_item,),
            message="Le hostname est absent ou générique.",
            risk=RiskAssessment(
                summary="Identification ambiguë de l'équipement.",
                impact="Mauvaise attribution des actions et de la traçabilité.",
                likelihood="moyenne",
                treatment="Corriger le hostname avant exploitation opérationnelle.",
            ),
            recommendation="Définir un hostname unique et documenté.",
            remediation=(
                "Configurer un hostname conforme à la convention client "
                "puis relancer l'audit."
            ),
        )
    if (
        "system global" not in configuration.parsed_value_sections
        or not evidence_is_certain
    ):
        return AuditFinding(
            **metadata,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("hostname: preuve absente ou invalide",),
            evidence_items=(
                evidence_for_directive(configuration.document, "system global", "hostname"),
            ),
            message="Section system global absente, vide ou sans hostname probant.",
            risk=RiskAssessment(
                summary="L'identification de l'équipement ne peut pas être confirmée.",
                impact="Risque d'associer l'audit au mauvais équipement.",
                likelihood="indéterminée",
                treatment="Obtenir une directive hostname structurée et non ambiguë.",
            ),
            recommendation="Fournir une configuration FortiGate complète.",
            remediation="Rejouer l'export de configuration avec system global et hostname valides.",
        )

    valid = bool(normalized and normalized.casefold() != "fortigate")
    if valid:
        return AuditFinding(
            **metadata,
            status=AuditStatus.PASS,
            applicability=Applicability.APPLICABLE,
            evidence=(f"hostname: {configuration.hostname}",),
            evidence_items=(evidence_item,),
            message="Le hostname est explicite.",
            risk=RiskAssessment(
                summary="Risque résiduel faible d'identification ambiguë.",
                impact="Traçabilité réduite si le nom est modifié sans procédure.",
                likelihood="faible",
                treatment="Surveiller la conformité du nom lors des changements.",
            ),
            recommendation="Conserver un hostname unique et documenté.",
            remediation="Aucune remédiation immédiate; vérifier le nom dans la CMDB.",
        )

    return AuditFinding(
        **metadata,
        status=AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        evidence=(f"hostname: {configuration.hostname or 'absent ou générique'}",),
        evidence_items=(evidence_item,),
        message="Le hostname est absent ou générique.",
        risk=RiskAssessment(
            summary="Identification ambiguë de l'équipement.",
            impact="Mauvaise attribution des actions et de la traçabilité.",
            likelihood="moyenne",
            treatment="Corriger le hostname avant exploitation opérationnelle.",
        ),
        recommendation="Définir un hostname unique et documenté.",
        remediation="Configurer un hostname conforme à la convention client puis relancer l'audit.",
    )

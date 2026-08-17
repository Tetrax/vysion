from __future__ import annotations

from vysion.audit.controls._evidence import evidence_for_directive, evidence_for_section
from vysion.audit.models import (
    Applicability,
    AuditContext,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    FortiGateConfiguration,
    RiskAssessment,
)


def _finding(
    configuration: FortiGateConfiguration,
    *,
    control_id: str,
    title: str,
    section: str,
    directive: str,
    status: AuditStatus,
    message: str,
    recommendation: str,
) -> AuditFinding:
    structural = configuration.document.section(section)
    evidence_item = (
        evidence_for_directive(configuration.document, section, directive)
        if structural is not None
        else evidence_for_section(configuration.document, section)
    )
    return AuditFinding(
        control_id=control_id,
        title=title,
        status=status,
        category="utm",
        priority=AuditPriority.P1,
        severity=AuditSeverity.MEDIUM,
        applicability=(
            Applicability.APPLICABLE
            if status in {AuditStatus.PASS, AuditStatus.FAIL}
            else Applicability.UNKNOWN
        ),
        evidence=(message,),
        evidence_items=(evidence_item,),
        message=message,
        risk=RiskAssessment(
            summary="Un service UTM externe mal paramétré peut réduire la qualité de protection.",
            impact=(
                "Les analyses cloud ou les requêtes FortiGuard peuvent diverger "
                "de la règle legacy."
            ),
            likelihood="moyenne",
            treatment=recommendation,
        ),
        recommendation=recommendation,
        remediation=(
            "Aucune remédiation immédiate."
            if status is AuditStatus.PASS
            else "Corriger la valeur explicite puis relancer l'audit."
        ),
    )


def _certain_value(
    configuration: FortiGateConfiguration, section_name: str, directive_name: str
) -> str | None:
    section = configuration.document.section(section_name)
    if (
        section is None
        or section.certainty is not EvidenceCertainty.CERTAIN
        or section.entries
        or section.children
        or directive_name in section.invalidated_keys
    ):
        return None
    directives = tuple(item for item in section.directives if item.name == directive_name)
    if (
        len(directives) != 1
        or directives[0].mutation
        or directives[0].certainty is not EvidenceCertainty.CERTAIN
        or len(directives[0].tokens) != 1
    ):
        return None
    return directives[0].tokens[0]


def _license_status(context: AuditContext | None) -> AuditStatus | None:
    if context is None or context.utm_license is None or context.operator_provenance is None:
        return AuditStatus.UNKNOWN
    if context.utm_license is False:
        return AuditStatus.FAIL
    return None


def check_fortisandbox_cloud(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    section = "system fortisandbox"
    directive = "sandbox-region"
    license_status = _license_status(context)
    value = _certain_value(configuration, section, directive)
    status = (
        license_status
        if license_status is not None
        else AuditStatus.PASS
        if value == "Europe"
        else AuditStatus.FAIL
        if value is not None
        else AuditStatus.UNKNOWN
    )
    return _finding(
        configuration,
        control_id="UTM-FORTISANDBOX-CLOUD-001",
        title="Région FortiSandbox Cloud",
        section=section,
        directive=directive,
        status=status,
        message=(
            "FortiSandbox Cloud utilise explicitement la région Europe."
            if status is AuditStatus.PASS
            else "La région FortiSandbox Cloud n'est pas conforme ou reste inconnue."
        ),
        recommendation="Utiliser explicitement la région Europe avec une licence UTM sourcée.",
    )


def check_fortiguard_anycast(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    section = "system fortiguard"
    directive = "fortiguard-anycast"
    license_status = _license_status(context)
    value = _certain_value(configuration, section, directive)
    status = (
        license_status
        if license_status is not None
        else AuditStatus.PASS
        if value == "disable"
        else AuditStatus.FAIL
        if value == "enable"
        else AuditStatus.UNKNOWN
    )
    return _finding(
        configuration,
        control_id="UTM-FORTIGUARD-ANYCAST-001",
        title="Désactivation de FortiGuard Anycast",
        section=section,
        directive=directive,
        status=status,
        message=(
            "FortiGuard Anycast est explicitement désactivé."
            if status is AuditStatus.PASS
            else "FortiGuard Anycast est actif ou sa valeur reste inconnue."
        ),
        recommendation="Configurer fortiguard-anycast disable avec une licence UTM sourcée.",
    )

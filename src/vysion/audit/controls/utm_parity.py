from __future__ import annotations

from vysion.audit.controls._evidence import evidence_for_directive, evidence_for_section
from vysion.audit.models import (
    AffectedObject,
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
            Applicability.NOT_APPLICABLE
            if status is AuditStatus.NOT_APPLICABLE
            else Applicability.APPLICABLE
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


def check_mail_filter_usage(configuration: FortiGateConfiguration) -> AuditFinding:
    section_name = "firewall policy"
    directive_name = "emailfilter-profile"
    section = configuration.document.section(section_name)
    violations = []
    uncertainty = section is None or (
        section is not None
        and (
            section.certainty is not EvidenceCertainty.CERTAIN
            or bool(section.directives)
            or bool(section.children)
        )
    )
    if section is not None:
        for entry in section.entries:
            matches = tuple(
                directive
                for directive in entry.directives
                if directive.name == directive_name
            )
            if (
                entry.certainty is not EvidenceCertainty.CERTAIN
                or entry.children
                or directive_name in entry.invalidated_keys
            ):
                uncertainty = True
            if not matches:
                continue
            if (
                len(matches) == 1
                and not matches[0].mutation
                and matches[0].certainty is EvidenceCertainty.CERTAIN
                and len(matches[0].tokens) == 1
                and matches[0].tokens[0]
            ):
                violations.append(entry)
            else:
                uncertainty = True

    if violations:
        status = AuditStatus.FAIL
        applicability = Applicability.APPLICABLE
        evidence = tuple(
            f"policy {entry.name}: emailfilter-profile utilisé" for entry in violations
        )
        evidence_items = tuple(
            evidence_for_directive(
                configuration.document,
                section_name,
                directive_name,
                entry_name=entry.name,
            )
            for entry in violations
        )
        affected = tuple(
            AffectedObject(name=entry.name, object_type="firewall-policy")
            for entry in violations
        )
        message = "Des politiques utilisent explicitement un profil Mail Filter."
    elif section is not None and not section.entries and not uncertainty:
        status = AuditStatus.PASS
        applicability = Applicability.NOT_APPLICABLE
        evidence = ("firewall policy: namespace explicitement vide",)
        evidence_items = (evidence_for_section(configuration.document, section_name),)
        affected = ()
        message = "Aucune politique n’est présente ; le contrôle n’est pas applicable."
    elif uncertainty:
        status = AuditStatus.UNKNOWN
        applicability = Applicability.UNKNOWN
        evidence = ("Usage Mail Filter absent, mais preuve de policy incomplète ou ambiguë",)
        evidence_items = (
            evidence_for_section(
                configuration.document,
                section_name,
                certainty=EvidenceCertainty.AMBIGUOUS,
            ),
        )
        affected = ()
        message = "L’absence d’usage Mail Filter ne peut pas être prouvée."
    else:
        status = AuditStatus.PASS
        applicability = Applicability.APPLICABLE
        evidence = ("Aucun emailfilter-profile dans les politiques certaines",)
        evidence_items = (evidence_for_section(configuration.document, section_name),)
        affected = ()
        message = "Aucune politique certaine n’utilise de profil Mail Filter."

    return AuditFinding(
        control_id="UTM-MAIL-FILTER-USAGE-001",
        title="Absence d’usage Mail Filter",
        status=status,
        category="utm",
        priority=AuditPriority.P1,
        severity=AuditSeverity.MEDIUM,
        applicability=applicability,
        evidence=evidence,
        evidence_items=evidence_items,
        affected_objects=affected,
        message=message,
        risk=RiskAssessment(
            summary="La règle legacy interdit l’usage des profils Mail Filter.",
            impact="Un filtrage mail non prévu peut modifier le traitement des flux SMTP.",
            likelihood="moyenne",
            treatment="Retirer les références Mail Filter des politiques concernées.",
        ),
        recommendation="Ne pas utiliser emailfilter-profile dans les politiques firewall.",
        remediation=(
            "Supprimer les références emailfilter-profile puis relancer l’audit."
            if status is AuditStatus.FAIL
            else "Aucune remédiation immédiate."
        ),
    )

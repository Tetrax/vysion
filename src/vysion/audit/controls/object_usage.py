"""Typed restitution of certainly unused firewall service objects."""

from __future__ import annotations

from vysion.audit.controls._evidence import evidence_for_entry, evidence_for_section
from vysion.audit.controls.references import _indexes, _observations, _service_orphans
from vysion.audit.models import (
    AffectedObject,
    Applicability,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    FortiGateConfiguration,
    ObjectReference,
    RiskAssessment,
)

CONTROL_ID = "CFG-UNUSED-SERVICE-001"
_REQUIRED_SECTIONS = (
    "firewall service custom",
    "firewall service group",
    "firewall policy",
)


def _namespace_complete(configuration: FortiGateConfiguration) -> bool:
    if not configuration.document.valid:
        return False
    for name in _REQUIRED_SECTIONS:
        section = configuration.document.section(name)
        if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
            return False
        if section.directives or section.children:
            return False
        if any(
            entry.certainty is not EvidenceCertainty.CERTAIN
            for entry in section.entries
        ):
            return False
    return True


def _finding(
    configuration: FortiGateConfiguration,
    *,
    status: AuditStatus,
    applicability: Applicability,
    orphaned: tuple[str, ...] = (),
) -> AuditFinding:
    affected = tuple(
        AffectedObject(
            name=name,
            object_type="service",
            reference=ObjectReference(object_type="service", name=name),
        )
        for name in orphaned
    )
    evidence_items = tuple(
        evidence_for_entry(
            configuration.document,
            (
                "firewall service custom"
                if any(item.name == name for item in configuration.service_objects)
                else "firewall service group"
            ),
            name,
        )
        for name in orphaned
    )
    if not evidence_items:
        evidence_items = tuple(
            evidence_for_section(configuration.document, name)
            for name in _REQUIRED_SECTIONS
        )
    certain_result = status in {
        AuditStatus.PASS,
        AuditStatus.FAIL,
        AuditStatus.NOT_APPLICABLE,
    }
    if not certain_result:
        evidence_items = tuple(
            item.model_copy(update={"certainty": EvidenceCertainty.AMBIGUOUS})
            for item in evidence_items
        )

    if status is AuditStatus.FAIL:
        message = "Des objets de service certains ne sont référencés par aucune politique."
        evidence = tuple(f"service {name}: objet non référencé" for name in orphaned)
        summary = "Des objets de service orphelins sont présents."
        likelihood = "moyenne"
        recommendation = "Valider puis supprimer ou rattacher chaque service réellement inutilisé."
        remediation = "Rattacher le service à une politique ou le retirer après approbation."
    elif status is AuditStatus.PASS:
        message = "Tous les objets de service certains sont atteignables depuis une politique."
        evidence = ("services: graphe d'utilisation complet sans objet orphelin",)
        summary = "Les objets de service projetés sont utilisés."
        likelihood = "faible"
        recommendation = "Conserver des relations de service explicites et typées."
        remediation = "Aucune remédiation immédiate."
    elif status is AuditStatus.NOT_APPLICABLE:
        message = "Les namespaces de services sont explicitement complets et vides."
        evidence = ("services: namespaces explicitement vides",)
        summary = "Aucun objet de service n'est applicable."
        likelihood = "faible"
        recommendation = "Réévaluer le contrôle après création d'un service."
        remediation = "Aucune remédiation immédiate."
    else:
        message = "L'utilisation des objets de service ne peut pas être prouvée."
        evidence = ("services: namespace, objet ou résolution incomplet ou ambigu",)
        summary = "Le graphe d'utilisation des services est incomplet ou ambigu."
        likelihood = "indéterminée"
        recommendation = "Fournir des namespaces complets sans collision ni mutation."
        remediation = "Corriger les objets ou références ambigus puis relancer l'audit."

    return AuditFinding(
        control_id=CONTROL_ID,
        title="Objets de service non utilisés",
        status=status,
        category="configuration",
        priority=AuditPriority.P1,
        severity=AuditSeverity.MEDIUM,
        applicability=applicability,
        evidence=evidence,
        evidence_items=evidence_items,
        affected_objects=affected,
        message=message,
        risk=RiskAssessment(
            summary=summary,
            impact="Des objets obsolètes peuvent masquer une dérive de configuration.",
            likelihood=likelihood,
            treatment="Maintenir uniquement les objets nécessaires et prouvés.",
        ),
        recommendation=recommendation,
        remediation=remediation,
    )


def check_unused_service_objects(configuration: FortiGateConfiguration) -> AuditFinding:
    """Report only certainly orphaned services from a complete typed family."""

    if not _namespace_complete(configuration):
        return _finding(
            configuration,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
        )

    services = configuration.service_objects + configuration.service_groups
    if not services:
        return _finding(
            configuration,
            status=AuditStatus.NOT_APPLICABLE,
            applicability=Applicability.NOT_APPLICABLE,
        )

    orphaned, uncertain = _service_orphans(
        configuration,
        _indexes(configuration),
        _observations(configuration),
    )
    if orphaned:
        return _finding(
            configuration,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            orphaned=orphaned,
        )
    if uncertain:
        return _finding(
            configuration,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
        )
    return _finding(
        configuration,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
    )

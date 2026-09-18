"""Typed restitution of certainly unused configuration objects."""

from __future__ import annotations

from collections.abc import Iterator

from vysion.audit.controls._evidence import evidence_for_entry, evidence_for_section
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
    StructuralEntry,
    StructuralSection,
)

CONTROL_ID = "CFG-UNUSED-SERVICE-001"
_REQUIRED_SECTIONS = (
    "firewall service custom",
    "firewall service group",
    "firewall policy",
)
_FAMILY_ALIASES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("address", "adresse", ("firewall address",)),
    ("address-group", "groupe d'adresse", ("firewall addrgrp",)),
    ("vip", "VIP", ("firewall vip",)),
    ("vip-group", "groupe de VIP", ("firewall vipgrp",)),
    ("zone", "zone", ("system zone",)),
    ("user", "utilisateur", ("user local",)),
    ("user-group", "groupe d'utilisateur", ("user group",)),
    ("radius", "connecteur RADIUS", ("user radius",)),
    ("ldap", "connecteur LDAP", ("user ldap",)),
    ("webfilter", "profil Web Filter", ("webfilter profile", "firewall webfilter profile")),
    ("antivirus", "profil Antivirus", ("antivirus profile", "firewall antivirus profile")),
    ("ips", "profil IPS", ("ips sensor", "firewall ips sensor")),
    ("appcontrol", "profil App Control", ("application list", "firewall application list")),
    ("sslssh", "profil SSL/SSH", ("firewall ssl-ssh-profile",)),
    ("dnsfilter", "profil DNS Filter", ("dnsfilter profile", "firewall dnsfilter profile")),
    ("service", "service", ("firewall service custom",)),
    ("service-group", "groupe de services", ("firewall service group",)),
)


def _entry_tokens(entry: StructuralEntry, directive: str) -> tuple[str, ...] | None:
    matches = tuple(
        item
        for item in entry.directives
        if item.name == directive
        and not item.mutation
        and item.certainty is EvidenceCertainty.CERTAIN
    )
    return matches[0].tokens if len(matches) == 1 else None


def _iter_entries(section: StructuralSection) -> Iterator[StructuralEntry]:
    for entry in section.entries:
        yield entry
        for child in entry.children:
            yield from _iter_entries(child)
    for child in section.children:
        yield from _iter_entries(child)


def _section_for(
    configuration: FortiGateConfiguration,
    aliases: tuple[str, ...],
) -> tuple[str, StructuralSection] | None:
    for name in aliases:
        section = configuration.document.section(name)
        if section is not None:
            return name, section
    return None


def _family_objects(
    configuration: FortiGateConfiguration,
) -> tuple[list[tuple[str, str, str, StructuralEntry]], bool, bool]:
    objects: list[tuple[str, str, str, StructuralEntry]] = []
    incomplete = False
    explicit_family = False
    seen_names: set[str] = set()
    for object_type, label, aliases in _FAMILY_ALIASES:
        resolved = _section_for(configuration, aliases)
        if resolved is None:
            continue
        namespace, section = resolved
        explicit_family = True
        if section.certainty is not EvidenceCertainty.CERTAIN and not configuration.complete_backup:
            incomplete = True
            continue
        entries = tuple(_iter_entries(section))
        for entry in entries:
            if entry.invalidated_keys or (
                any(item.mutation for item in entry.directives)
                and not entry.parsed_keys
            ):
                incomplete = True
            key = entry.name.casefold()
            if (
                key in seen_names
                and object_type in {"service", "service-group"}
                and not configuration.complete_backup
            ):
                incomplete = True
            seen_names.add(key)
            resolved_type = object_type
            if namespace == "firewall vip":
                type_tokens = _entry_tokens(entry, "type") or ()
                if any(token.casefold() == "server-load-balance" for token in type_tokens):
                    resolved_type = "virtual-server"
                    label = "Virtual Server"
            objects.append((namespace, resolved_type, label, entry))
    return objects, incomplete, explicit_family


_NON_REFERENCE_DIRECTIVES = frozenset({
    "alias", "comment", "comments", "description", "email-to", "global-label",
    "label", "name", "password", "sms-phone", "timezone", "uuid",
})


def _reference_names(configuration: FortiGateConfiguration) -> set[str]:
    names: set[str] = set()

    def collect_section(section: StructuralSection) -> None:
        for directive in section.directives:
            if (
                not directive.mutation
                and directive.certainty is EvidenceCertainty.CERTAIN
                and directive.name not in _NON_REFERENCE_DIRECTIVES
            ):
                names.update(token.casefold() for token in directive.tokens)
        for entry in section.entries:
            for directive in entry.directives:
                if not directive.mutation and directive.certainty is EvidenceCertainty.CERTAIN:
                    names.update(token.casefold() for token in directive.tokens)
            for child in entry.children:
                collect_section(child)
        for child in section.children:
            collect_section(child)

    for section in configuration.document.sections:
        collect_section(section)
    return names


def _finding(
    configuration: FortiGateConfiguration,
    *,
    status: AuditStatus,
    applicability: Applicability,
    orphaned: tuple[tuple[str, str, str, str], ...] = (),
    namespaces: tuple[str, ...] = (),
) -> AuditFinding:
    affected = tuple(
        AffectedObject(
            name=name,
            object_type=object_type,
            reference=ObjectReference(object_type=object_type, name=name),
        )
        for _, object_type, _, name in orphaned
    )
    evidence_items = tuple(
        evidence_for_entry(configuration.document, namespace, name)
        for namespace, _, _, name in orphaned
    )
    if not evidence_items:
        evidence_items = tuple(
            evidence_for_section(configuration.document, namespace)
            for namespace in namespaces
            if configuration.document.section(namespace) is not None
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
        message = "Des objets de configuration confirmés ne sont référencés par aucun usage actif."
        evidence = tuple(
            f"{label} {name}: objet non référencé" for _, _, label, name in orphaned
        )
        summary = "Des objets de configuration ne sont référencés par aucun usage actif."
        likelihood = "moyenne"
        recommendation = "Valider puis supprimer ou rattacher chaque objet réellement inutilisé."
        remediation = "Rattacher chaque objet à un usage ou le retirer après approbation."
    elif status is AuditStatus.PASS:
        message = (
            "Tous les objets de configuration analysés sont référencés par au "
            "moins un usage actif."
        )
        evidence = ("objets: graphe d'utilisation complet sans objet orphelin",)
        summary = "Les objets de configuration analysés sont utilisés."
        likelihood = "faible"
        recommendation = "Conserver des relations de configuration explicites et typées."
        remediation = "Aucune remédiation immédiate."
    elif status is AuditStatus.NOT_APPLICABLE:
        message = "Les familles d'objets analysées sont explicitement vides."
        evidence = ("objets: familles explicitement vides",)
        summary = "Aucun objet de configuration n'est applicable."
        likelihood = "faible"
        recommendation = "Réévaluer le contrôle après création d'un objet."
        remediation = "Aucune remédiation immédiate."
    else:
        message = "L'utilisation des objets de configuration ne peut pas être établie."
        evidence = ("objets: famille, objet ou résolution incomplet ou ambigu",)
        summary = "L'utilisation des objets de configuration est incomplète ou ambiguë."
        likelihood = "indéterminée"
        recommendation = "Fournir les familles et relations de configuration complètes."
        remediation = "Corriger les objets ou références ambigus puis relancer l'audit."

    return AuditFinding(
        control_id=CONTROL_ID,
        title="Objets de configuration non utilisés",
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
            treatment="Maintenir uniquement les objets nécessaires et utilisés.",
        ),
        recommendation=recommendation,
        remediation=remediation,
    )


def check_unused_service_objects(configuration: FortiGateConfiguration) -> AuditFinding:
    """Report certainly unused object families through the historical control."""

    if not configuration.document.valid:
        return _finding(
            configuration,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
        )
    if not configuration.complete_backup and any(
        configuration.document.section(name) is None for name in _REQUIRED_SECTIONS
    ):
        return _finding(
            configuration,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
        )
    if any(
        (section := configuration.document.section(name)) is not None
        and (
            section.certainty is not EvidenceCertainty.CERTAIN
            or section.directives
            or section.children
        )
        for name in _REQUIRED_SECTIONS
    ):
        return _finding(
            configuration,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
        )

    objects, incomplete, explicit_family = _family_objects(configuration)
    if incomplete:
        return _finding(
            configuration,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
        )
    if not explicit_family:
        return _finding(
            configuration,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
        )

    references = _reference_names(configuration)
    orphaned = tuple(
        (namespace, object_type, label, entry.name)
        for namespace, object_type, label, entry in objects
        if entry.name.casefold() not in references
    )
    if orphaned:
        return _finding(
            configuration,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            orphaned=orphaned,
        )
    if not objects:
        return _finding(
            configuration,
            status=AuditStatus.NOT_APPLICABLE,
            applicability=Applicability.NOT_APPLICABLE,
            namespaces=_REQUIRED_SECTIONS,
        )
    return _finding(
        configuration,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
    )

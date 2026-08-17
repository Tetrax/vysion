from collections.abc import Iterable
from dataclasses import dataclass

from vysion.audit.controls._evidence import evidence_for_directive
from vysion.audit.controls._names import unique_named
from vysion.audit.models import (
    AffectedObject,
    Applicability,
    AuditContext,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    EvidenceItem,
    FortiGateConfiguration,
    Interface,
    ProofState,
    RiskAssessment,
    SecondaryIP,
    WanSelectionKind,
)

_FORBIDDEN_PROTOCOLS = frozenset({"ssh", "http", "https"})


def _metadata() -> dict[str, object]:
    return {
        "control_id": "NET-WAN-MGMT-001",
        "title": "Protocoles d'administration sur interfaces WAN",
        "category": "network",
        "priority": AuditPriority.P0,
        "severity": AuditSeverity.HIGH,
    }


def _risk(summary: str, impact: str, likelihood: str, treatment: str) -> RiskAssessment:
    return RiskAssessment(
        summary=summary,
        impact=impact,
        likelihood=likelihood,
        treatment=treatment,
    )


def _affected(names: Iterable[str]) -> tuple[AffectedObject, ...]:
    return tuple(
        AffectedObject(
            name=name,
            object_type="interface" if ".secondaryip[" not in name else "secondary-ip",
            reference={
                "object_type": "interface" if ".secondaryip[" not in name else "secondary-ip",
                "name": name,
            },
        )
        for name in names
    )


def _interface_is_certain(interface: Interface) -> bool:
    return interface.proof_state.value == "proven" and "allowaccess" in interface.parsed_keys


def _secondary_is_certain(secondary: SecondaryIP) -> bool:
    return secondary.proof_state.value == "proven" and "allowaccess" in secondary.parsed_keys


def _secondary_evidence(
    configuration: FortiGateConfiguration,
    interface_name: str,
    secondary: SecondaryIP,
) -> EvidenceItem:
    section = configuration.document.section("system interface")
    parent = (
        None
        if section is None
        else next(
            (entry for entry in section.entries if entry.name == interface_name),
            None,
        )
    )
    child = None
    if parent is not None:
        child_section = next(
            (item for item in parent.children if item.name.casefold() == "secondaryip"),
            None,
        )
        if child_section is not None:
            child_name = secondary.name.rsplit("[", 1)[-1].rstrip("]")
            child = next(
                (entry for entry in child_section.entries if entry.name == child_name), None
            )
    directives = (
        ()
        if child is None
        else tuple(directive for directive in child.directives if directive.name == "allowaccess")
    )
    directive = directives[0] if len(directives) == 1 else None
    certainty = EvidenceCertainty.CERTAIN
    if (
        section is None
        or parent is None
        or child is None
        or parent.certainty is not EvidenceCertainty.CERTAIN
        or child.certainty is not EvidenceCertainty.CERTAIN
        or len(directives) != 1
        or directives[0].certainty is not EvidenceCertainty.CERTAIN
    ):
        certainty = EvidenceCertainty.AMBIGUOUS
    return EvidenceItem(
        section="system interface",
        entry=secondary.name,
        directive="allowaccess",
        tokens=directive.tokens if directive is not None else (),
        line=(directive.line if directive is not None else child.line if child else None),
        certainty=certainty,
    )


@dataclass(frozen=True)
class _AccessPoint:
    name: str
    protocols: frozenset[str]
    certain: bool
    evidence: EvidenceItem


def _access_points(
    configuration: FortiGateConfiguration,
    interface: Interface,
) -> tuple[_AccessPoint, ...]:
    points = [
        _AccessPoint(
            name=interface.name,
            protocols=frozenset(token.casefold() for token in interface.allowaccess),
            certain=_interface_is_certain(interface),
            evidence=evidence_for_directive(
                configuration.document,
                "system interface",
                "allowaccess",
                entry_name=interface.name,
                certainty=(
                    EvidenceCertainty.CERTAIN
                    if _interface_is_certain(interface)
                    else EvidenceCertainty.AMBIGUOUS
                ),
            ),
        )
    ]
    points.extend(
        _AccessPoint(
            name=secondary.name,
            protocols=frozenset(token.casefold() for token in secondary.allowaccess),
            certain=_secondary_is_certain(secondary),
            evidence=_secondary_evidence(configuration, interface.name, secondary),
        )
        for secondary in interface.secondary_ips
    )
    return tuple(points)


def _context_wans(
    configuration: FortiGateConfiguration,
    context: AuditContext | None,
) -> tuple[tuple[Interface, ...], tuple[str, ...], bool]:
    by_name, interface_collisions = unique_named(configuration.interfaces)
    zones, zone_collisions = unique_named(configuration.zones)
    sdwan_zones, sdwan_collisions = unique_named(configuration.sdwan_zones)
    contradictions = [
        f"Nom d'interface ambigu (insensible à la casse): {name}"
        for name in sorted(interface_collisions)
    ]
    contradictions.extend(
        f"Nom de zone ambigu (insensible à la casse): {name}"
        for name in sorted(zone_collisions)
    )
    contradictions.extend(
        f"Nom de zone SD-WAN ambigu (insensible à la casse): {name}"
        for name in sorted(sdwan_collisions)
    )

    if context is not None and context.wan_selections is not None:
        selected: list[Interface] = []
        selected_names: set[str] = set()
        for selection in context.wan_selections:
            key = selection.name.casefold()
            resolved_names: tuple[str, ...]
            if selection.kind is WanSelectionKind.INTERFACE:
                resolved_names = () if key in interface_collisions else (selection.name,)
            elif selection.kind is WanSelectionKind.ZONE:
                zone = zones.get(key)
                resolved_names = (
                    tuple(reference.name for reference in zone.interfaces)
                    if zone is not None and zone.proof_state is ProofState.PROVEN
                    else ()
                )
            elif selection.kind is WanSelectionKind.SDWAN:
                zone = sdwan_zones.get(key)
                resolved_names = (
                    tuple(reference.name for reference in zone.interfaces)
                    if zone is not None and zone.proof_state is ProofState.PROVEN
                    else ()
                )
            else:
                resolved_names = tuple(
                    interface.name
                    for interface in by_name.values()
                    if interface.role is not None and interface.role.casefold() == "wan"
                )

            if not resolved_names:
                if selection.kind is WanSelectionKind.INTERFACE and key in interface_collisions:
                    contradictions.append(f"WAN déclarée ambiguë: {selection.name}")
                elif selection.kind is WanSelectionKind.ZONE and key in zone_collisions:
                    contradictions.append(f"Zone WAN déclarée ambiguë: {selection.name}")
                elif selection.kind is WanSelectionKind.SDWAN and key in sdwan_collisions:
                    contradictions.append(f"Zone SD-WAN déclarée ambiguë: {selection.name}")
                else:
                    contradictions.append(f"WAN déclarée non résolue: {selection.name}")
                continue

            unresolved = tuple(
                name
                for name in resolved_names
                if name.casefold() not in by_name or name.casefold() in interface_collisions
            )
            if unresolved:
                contradictions.extend(
                    f"WAN déclarée inconnue: {name}" for name in unresolved
                )
                continue

            for resolved_name in resolved_names:
                normalized = resolved_name.casefold()
                if normalized in selected_names:
                    continue
                selected_names.add(normalized)
                selected.append(by_name[normalized])
        return tuple(selected), tuple(dict.fromkeys(contradictions)), True

    if context is not None and context.selected_wans is not None:
        selected: list[Interface] = []
        for declared_name in context.selected_wans:
            key = declared_name.casefold()
            interface = by_name.get(key)
            if interface is None or key in interface_collisions:
                contradictions.append(f"WAN déclarée inconnue ou ambiguë: {declared_name}")
            else:
                selected.append(interface)
        return tuple(selected), tuple(dict.fromkeys(contradictions)), True

    inferred = tuple(
        interface
        for interface in by_name.values()
        if interface.role is not None and interface.role.casefold() == "wan"
    )
    return inferred, tuple(dict.fromkeys(contradictions)), False


def _finding(
    *,
    status: AuditStatus,
    applicability: Applicability,
    evidence: tuple[str, ...],
    evidence_items: tuple[EvidenceItem, ...],
    affected_objects: tuple[AffectedObject, ...],
    message: str,
    risk: RiskAssessment,
    recommendation: str,
    remediation: str,
) -> AuditFinding:
    return AuditFinding(
        **_metadata(),
        status=status,
        applicability=applicability,
        evidence=evidence,
        evidence_items=evidence_items,
        affected_objects=affected_objects,
        message=message,
        risk=risk,
        recommendation=recommendation,
        remediation=remediation,
    )


def _violation_finding(
    violations: Iterable[_AccessPoint],
    extra_evidence: Iterable[str] = (),
) -> AuditFinding:
    points = tuple(violations)
    evidence = tuple(
        f"{point.name}: allowaccess expose "
        f"{', '.join(sorted(point.protocols & _FORBIDDEN_PROTOCOLS))}"
        for point in points
    ) + tuple(extra_evidence)
    return _finding(
        status=AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        evidence=evidence,
        evidence_items=tuple(point.evidence for point in points),
        affected_objects=_affected(point.name for point in points),
        message="Un protocole d'administration interdit est exposé sur une interface WAN.",
        risk=_risk(
            "L'administration HTTP, HTTPS ou SSH est exposée sur une portée WAN.",
            "Compromission potentielle du plan de gestion du pare-feu.",
            "élevée",
            "Retirer les protocoles de gestion des interfaces WAN et limiter "
            "l'administration à un réseau dédié.",
        ),
        recommendation="Retirer SSH, HTTP et HTTPS de allowaccess sur les interfaces WAN.",
        remediation=(
            "Modifier allowaccess sur chaque point exposé puis vérifier "
            "la configuration effective."
        ),
    )


def check_wan_management_access(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    section = configuration.document.section("system interface")
    if section is None or not section.entries:
        return _finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("system interface: namespace absent or empty",),
            evidence_items=(
                evidence_for_directive(
                    configuration.document,
                    "system interface",
                    "allowaccess",
                    certainty=EvidenceCertainty.INVALID,
                ),
            ),
            affected_objects=(),
            message="La portée des interfaces WAN ne peut pas être déterminée.",
            risk=_risk(
                "L'exposition d'administration WAN ne peut pas être déterminée.",
                "Un accès de gestion exposé pourrait rester non détecté.",
                "indéterminée",
                "Obtenir le namespace system interface complet.",
            ),
            recommendation="Fournir une configuration permettant d'identifier les interfaces WAN.",
            remediation="Rejouer l'export avec la section system interface complète.",
        )

    wan_interfaces, contradictions, explicit_selection = _context_wans(configuration, context)
    if contradictions:
        access_points = tuple(
            point
            for interface in wan_interfaces
            for point in _access_points(configuration, interface)
        )
        violations = [
            point
            for point in access_points
            if point.protocols & _FORBIDDEN_PROTOCOLS
        ]
        if violations:
            return _violation_finding(violations, contradictions)
        return _finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=contradictions,
            evidence_items=tuple(
                evidence_for_directive(
                    configuration.document,
                    "system interface",
                    "allowaccess",
                    certainty=EvidenceCertainty.AMBIGUOUS,
                )
                for _ in contradictions
            ),
            affected_objects=_affected(interface.name for interface in wan_interfaces),
            message="La sélection WAN opérateur contient une interface inconnue.",
            risk=_risk(
                "La portée WAN demandée ne peut pas être établie de façon probante.",
                "Une interface déclarée pourrait être omise de l'audit.",
                "indéterminée",
                "Corriger la sélection opérateur ou fournir les interfaces correspondantes.",
            ),
            recommendation="Vérifier les WAN déclarées contre les interfaces de la configuration.",
            remediation=(
                "Corriger le contexte puis relancer l'audit; aucune conclusion n'est émise."
            ),
        )

    if explicit_selection and not wan_interfaces:
        return _finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("WAN déclarées: aucune interface sélectionnée",),
            evidence_items=(
                evidence_for_directive(
                    configuration.document,
                    "system interface",
                    "allowaccess",
                    certainty=EvidenceCertainty.AMBIGUOUS,
                ),
            ),
            affected_objects=(),
            message="Aucune WAN sélectionnée ne peut être auditée.",
            risk=_risk(
                "La portée WAN est vide.",
                "L'exposition de gestion ne peut pas être conclue.",
                "indéterminée",
                "Réconcilier le contexte opérateur avec la configuration.",
            ),
            recommendation="Sélectionner au moins une interface WAN existante.",
            remediation="Corriger les WAN sélectionnées et relancer l'audit.",
        )

    if not wan_interfaces:
        return _finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Aucune interface avec rôle structurel WAN identifiable",),
            evidence_items=(
                evidence_for_directive(
                    configuration.document,
                    "system interface",
                    "role",
                    certainty=EvidenceCertainty.AMBIGUOUS,
                ),
            ),
            affected_objects=(),
            message="Aucune interface WAN structurellement identifiable dans la configuration.",
            risk=_risk(
                "L'exposition WAN ne peut pas être déterminée.",
                "Un accès de gestion pourrait rester non détecté.",
                "indéterminée",
                "Identifier explicitement les interfaces WAN par leur rôle.",
            ),
            recommendation="Fournir le rôle WAN ou une sélection opérateur explicite.",
            remediation=(
                "Ajouter une preuve role wan ou corriger le contexte puis relancer l'audit."
            ),
        )

    access_points = tuple(
        point for interface in wan_interfaces for point in _access_points(configuration, interface)
    )
    violations = [point for point in access_points if point.protocols & _FORBIDDEN_PROTOCOLS]
    uncertain = [point for point in access_points if not point.certain]
    if violations:
        return _violation_finding(violations)
    if uncertain:
        evidence = tuple(f"{point.name}: allowaccess absent ou ambigu" for point in uncertain)
        return _finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=evidence,
            evidence_items=tuple(point.evidence for point in uncertain),
            affected_objects=_affected(point.name for point in access_points),
            message="L'accès d'administration de tous les points WAN ne peut pas être déterminé.",
            risk=_risk(
                "L'exposition de gestion ne peut pas être exclue sur tous les points WAN.",
                "Une directive absente ou ambiguë peut masquer un protocole interdit.",
                "indéterminée",
                "Obtenir une directive allowaccess certaine pour chaque point WAN.",
            ),
            recommendation="Fournir allowaccess pour chaque interface et secondaryip WAN.",
            remediation="Compléter ou corriger l'export puis relancer l'audit avant de conclure.",
        )

    return _finding(
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(
            f"{point.name}: allowaccess sans protocole interdit" for point in access_points
        ),
        evidence_items=tuple(point.evidence for point in access_points),
        affected_objects=_affected(point.name for point in access_points),
        message="Aucun protocole d'administration interdit n'est exposé sur les WAN examinées.",
        risk=_risk(
            "Aucun protocole HTTP, HTTPS ou SSH n'est probant sur les points WAN examinés.",
            "L'exposition couverte par ce contrôle est réduite.",
            "faible",
            "Conserver la restriction et surveiller les changements réseau.",
        ),
        recommendation="Conserver SSH, HTTP et HTTPS désactivés sur les interfaces WAN.",
        remediation=(
            "Aucune remédiation immédiate; contrôler allowaccess lors des changements réseau."
        ),
    )

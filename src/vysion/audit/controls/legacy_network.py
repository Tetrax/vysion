from __future__ import annotations

from vysion.audit.models import (
    Applicability,
    AuditContext,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    EvidenceItem,
    FortiGateConfiguration,
    ProofState,
    RiskAssessment,
    WanSelectionKind,
)

_PROVENANCE = "legacy_v1"
_DEFAULT_V1_RFC6890_POLICY = ("RFC-6890_Unreachable-Subnets",)


def _finding(
    *,
    control_id: str,
    title: str,
    status: AuditStatus,
    message: str,
    evidence: tuple[str, ...],
    evidence_items: tuple[EvidenceItem, ...],
) -> AuditFinding:
    return AuditFinding(
        control_id=control_id,
        title=title,
        status=status,
        category="legacy-network",
        priority=AuditPriority.P1,
        severity=AuditSeverity.HIGH,
        applicability=(
            Applicability.UNKNOWN if status is AuditStatus.UNKNOWN else Applicability.APPLICABLE
        ),
        evidence=evidence,
        evidence_items=evidence_items,
        message=message,
        risk=RiskAssessment(
            summary="La règle réseau historique V1 doit rester observable.",
            impact="Le filtrage réseau attendu peut être absent ou appliqué au mauvais contexte.",
            likelihood="indéterminée" if status is AuditStatus.UNKNOWN else "moyenne",
            treatment="Corriger la configuration ou compléter le contexte opérateur.",
        ),
        recommendation="Aligner la configuration sur la règle historique V1.",
        remediation="Corriger les objets ou routes concernés puis rejouer l’audit.",
        rule_provenance=_PROVENANCE,
    )


def _unknown(control_id: str, title: str, section: str, reason: str) -> AuditFinding:
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.UNKNOWN,
        message=reason,
        evidence=(reason, "provenance: legacy_v1"),
        evidence_items=(
            EvidenceItem(
                section=section,
                directive="legacy-proof",
                tokens=(_PROVENANCE,),
                certainty=EvidenceCertainty.AMBIGUOUS,
            ),
        ),
    )


def _selected_interface_names(
    configuration: FortiGateConfiguration,
    context: AuditContext | None,
) -> tuple[str, ...] | None:
    """Expand typed V1 WAN selections back to physical interface names."""
    if context is None:
        return None
    if context.wan_selections is None:
        return context.selected_wans
    selected: list[str] = []
    for selection in context.wan_selections:
        if selection.kind is WanSelectionKind.INTERFACE:
            selected.append(selection.name)
        else:
            selected.extend(selection.interfaces)
    return tuple(dict.fromkeys(selected))


def _graph_has_cycle(groups: dict[str, object]) -> bool:
    visited: set[str] = set()
    active: set[str] = set()

    def visit(name: str) -> bool:
        if name in active:
            return True
        if name in visited:
            return False
        visited.add(name)
        active.add(name)
        group = groups[name]
        for member in group.members:
            key = member.name.casefold()
            if key in groups and visit(key):
                return True
        active.remove(name)
        return False

    return any(visit(name) for name in groups)


def check_legacy_geo_ip_usage(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    control_id = "NET-GEO-IP-USAGE-001"
    title = "Utilisation du filtrage Geo-IP"
    selected = _selected_interface_names(configuration, context)
    address_section = configuration.document.section("firewall address")
    group_section = configuration.document.section("firewall addrgrp")
    policy_section = configuration.document.section("firewall policy")
    if selected is None or not selected:
        return _unknown(
            control_id,
            title,
            "firewall policy",
            "Aucune sélection WAN n'a été fournie pour évaluer ce point.",
        )
    sections = (address_section, group_section, policy_section)
    if any(
        section is None or section.certainty is not EvidenceCertainty.CERTAIN
        for section in sections
    ):
        return _unknown(
            control_id,
            title,
            "firewall address",
            "Les données nécessaires à l'analyse GEO-IP sont absentes ou ambiguës.",
        )
    objects = {item.name.casefold(): item for item in configuration.address_objects}
    groups = {item.name.casefold(): item for item in configuration.address_groups}
    if (
        len(objects) != len(configuration.address_objects)
        or len(groups) != len(configuration.address_groups)
        or any(
            item.proof_state is not ProofState.PROVEN
            for item in (*objects.values(), *groups.values())
        )
        or _graph_has_cycle(groups)
        or any(policy.proof_state is not ProofState.PROVEN for policy in configuration.policies)
    ):
        return _unknown(
            control_id,
            title,
            "firewall addrgrp",
            "Les objets GEO-IP analysés comportent des incohérences ou des ambiguïtés.",
        )

    geographic = {name for name, item in objects.items() if item.address_type == "geography"}
    changed = True
    while changed:
        changed = False
        for name, group in groups.items():
            if name not in geographic and any(
                member.name.casefold() in geographic for member in group.members
            ):
                geographic.add(name)
                changed = True

    selected_names = {name.casefold() for name in selected}
    matched: list[str] = []
    for policy in configuration.policies:
        sources = {
            reference.name.casefold()
            for reference in policy.object_references
            if reference.relation == "source-address"
        }
        destinations = {
            reference.name.casefold()
            for reference in policy.object_references
            if reference.relation == "destination-address"
        }
        source_interfaces = {item.name.casefold() for item in policy.source_interfaces}
        destination_interfaces = {item.name.casefold() for item in policy.destination_interfaces}
        if (
            sources & geographic
            and (source_interfaces & selected_names or "any" in source_interfaces)
        ) or (
            destinations & geographic
            and (destination_interfaces & selected_names or "any" in destination_interfaces)
        ):
            matched.append(policy.policy_id)

    status = AuditStatus.PASS if matched else AuditStatus.FAIL
    message = (
        "Geo-IP est utilisé sur une policy liée à la sélection WAN."
        if matched
        else "Aucune utilisation Geo-IP n’est détectée sur la sélection WAN."
    )
    return _finding(
        control_id=control_id,
        title=title,
        status=status,
        message=message,
        evidence=((f"policies: {', '.join(matched)}",) if matched else ("aucune policy Geo-IP",)),
        evidence_items=(
            EvidenceItem(section="firewall policy", entry=matched[0] if matched else None),
        ),
    )


def check_legacy_rfc6890_blackhole(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    control_id = "NET-RFC6890-BLACKHOLE-001"
    title = "Route blackhole RFC6890"
    if context is None or context.mpls is None:
        return _unknown(control_id, title, "router static", "Contexte MPLS/L2L non renseigné.")
    policy = context.legacy_v1_rfc6890_policy
    destinations = (
        tuple(policy.destination_objects)
        if policy is not None
        else _DEFAULT_V1_RFC6890_POLICY
    )
    section = configuration.document.section("router static")
    if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
        return _unknown(
            control_id,
            title,
            "router static",
            "Les routes statiques nécessaires ne sont pas disponibles ou sont ambiguës.",
        )
    if any(route.proof_state is not ProofState.PROVEN for route in configuration.static_routes):
        return _unknown(
            control_id,
            title,
            "router static",
            "Des routes statiques sont incohérentes ou ambiguës.",
        )
    destinations = {name.casefold() for name in destinations}
    complete = tuple(
        route
        for route in configuration.static_routes
        if route.destination is not None
        and route.destination.name.casefold() in destinations
        and route.status != "disable"
        and route.blackhole is True
        and route.distance == 254
    )
    passed = bool(complete) is (not context.mpls)
    status = AuditStatus.PASS if passed else AuditStatus.FAIL
    message = (
        "La présence de la route blackhole correspond au contexte MPLS/L2L déclaré."
        if passed
        else "La présence de la route blackhole contredit le contexte MPLS/L2L déclaré."
    )
    return _finding(
        control_id=control_id,
        title=title,
        status=status,
        message=message,
        evidence=(f"route complète: {'oui' if complete else 'non'}", f"mpls/l2l: {context.mpls}"),
        evidence_items=(
            EvidenceItem(
                section="router static",
                entry=complete[0].route_id if complete else None,
                directive="blackhole",
            ),
        ),
    )


check_legacy_geo_ip_usage.control_id = "NET-GEO-IP-USAGE-001"
check_legacy_rfc6890_blackhole.control_id = "NET-RFC6890-BLACKHOLE-001"

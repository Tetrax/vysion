"""Fail-closed Milestone 3 firewall/exposure controls.

Controls consume only the immutable StructuralDocument and typed projections.  No
control in this module parses FortiGate source text or infers WAN state from an
object name.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from vysion.audit.controls._evidence import (
    evidence_for_complete_backup,
    evidence_for_directive,
    evidence_for_section,
)
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
    ObjectReference,
    Policy,
    PortRange,
    ProfileGroup,
    ProofState,
    RiskAssessment,
    Vip,
    VirtualServer,
    WanSelectionKind,
    Zone,
)
from vysion.audit.rulesets.sensitive_protocols import (
    SensitiveProtocolRuleset,
    load_sensitive_protocol_ruleset,
)

_RULESET = load_sensitive_protocol_ruleset()
SENSITIVE_PROTOCOL_RULESET_ID = _RULESET.id
SENSITIVE_PROTOCOL_RULESET_VERSION = _RULESET.version


@dataclass(frozen=True)
class _WanScope:
    selected: bool
    names: frozenset[str]
    unresolved: tuple[str, ...]


@dataclass(frozen=True)
class _PortCoverage:
    known: bool
    tcp: tuple[PortRange, ...] = ()
    udp: tuple[PortRange, ...] = ()


@dataclass(frozen=True)
class _FlowObservation:
    policy: Policy
    coverage: _PortCoverage
    action: str | None
    complete: bool
    applicable: bool | None


_FIREWALL_METADATA = {
    "category": "firewall",
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


def _affected(names: Iterable[str], object_type: str) -> tuple[AffectedObject, ...]:
    return tuple(
        AffectedObject(
            name=name,
            object_type=object_type,
            reference=ObjectReference(object_type=object_type, name=name),
        )
        for name in names
    )


def _finding(
    *,
    control_id: str,
    title: str,
    status: AuditStatus,
    applicability: Applicability,
    evidence: Iterable[str],
    evidence_items: Iterable[EvidenceItem],
    affected_objects: Iterable[AffectedObject],
    message: str,
    risk: RiskAssessment,
    recommendation: str,
    remediation: str,
) -> AuditFinding:
    return AuditFinding(
        **_FIREWALL_METADATA,
        control_id=control_id,
        title=title,
        status=status,
        applicability=applicability,
        evidence=tuple(evidence),
        evidence_items=tuple(evidence_items),
        affected_objects=tuple(affected_objects),
        message=message,
        risk=risk,
        recommendation=recommendation,
        remediation=remediation,
    )


def _section_evidence(
    configuration: FortiGateConfiguration,
    section: str,
    *,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem:
    return evidence_for_section(configuration.document, section, certainty=certainty)


def _directive_evidence(
    configuration: FortiGateConfiguration,
    section: str,
    directive: str,
    *,
    entry: str | None = None,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem:
    return evidence_for_directive(
        configuration.document,
        section,
        directive,
        entry_name=entry,
        certainty=certainty,
    )


def _policy_section(configuration: FortiGateConfiguration):
    return configuration.document.section("firewall policy")


def _interface_by_name(configuration: FortiGateConfiguration) -> dict[str, Interface]:
    result: dict[str, Interface] = {}
    collisions: set[str] = set()
    for interface in configuration.interfaces:
        key = interface.name.casefold()
        if key in result:
            collisions.add(key)
        else:
            result[key] = interface
    for key in collisions:
        result.pop(key, None)
    return result


def _interface_name_collisions(configuration: FortiGateConfiguration) -> frozenset[str]:
    seen: set[str] = set()
    collisions: set[str] = set()
    for interface in configuration.interfaces:
        key = interface.name.casefold()
        if key in seen:
            collisions.add(key)
        else:
            seen.add(key)
    return frozenset(collisions)


def _zone_by_name(zones: Iterable[Zone]) -> dict[str, Zone]:
    result: dict[str, Zone] = {}
    collisions: set[str] = set()
    for zone in zones:
        key = zone.name.casefold()
        if key in result:
            collisions.add(key)
        else:
            result[key] = zone
    for key in collisions:
        result.pop(key, None)
    return result


def _resolved_zone_interfaces(
    zone: Zone,
    interfaces: dict[str, Interface],
) -> tuple[str, ...] | None:
    if zone.proof_state is not ProofState.PROVEN or not zone.interfaces:
        return None
    resolved: list[str] = []
    seen: set[str] = set()
    for reference in zone.interfaces:
        key = reference.name.casefold()
        interface = interfaces.get(key)
        if interface is None or key in seen:
            return None
        seen.add(key)
        resolved.append(getattr(interface, "name", reference.name))
    return tuple(resolved)


def _context_wan_scope(
    configuration: FortiGateConfiguration,
    context: AuditContext | None,
) -> _WanScope:
    interfaces = _interface_by_name(configuration)
    interface_collisions = _interface_name_collisions(configuration)
    zones = _zone_by_name(configuration.zones)
    sdwan_zones = _zone_by_name(configuration.sdwan_zones)
    if context is not None and context.wan_selections is not None:
        names: set[str] = set()
        unresolved: list[str] = []
        for selection in context.wan_selections:
            if selection.kind is WanSelectionKind.INTERFACE:
                resolved = interfaces.get(selection.name.casefold())
                if resolved is None:
                    unresolved.append(selection.name)
                    continue
                names.add(getattr(resolved, "name", selection.name).casefold())
            elif selection.kind in {WanSelectionKind.ZONE, WanSelectionKind.SDWAN}:
                index = zones if selection.kind is WanSelectionKind.ZONE else sdwan_zones
                zone = index.get(selection.name.casefold())
                if zone is None:
                    unresolved.append(selection.name)
                    continue
                resolved_zone_interfaces = _resolved_zone_interfaces(zone, interfaces)
                if resolved_zone_interfaces is None:
                    unresolved.append(selection.name)
                    continue
                names.add(zone.name.casefold())
                names.update(name.casefold() for name in resolved_zone_interfaces)
            else:
                if interface_collisions:
                    unresolved.extend(sorted(interface_collisions))
                names.update(
                    interface.name.casefold()
                    for interface in interfaces.values()
                    if _role(interface) == "wan"
                )
        return _WanScope(selected=True, names=frozenset(names), unresolved=tuple(unresolved))
    if context is None or context.selected_wans is None:
        return _WanScope(selected=False, names=frozenset(), unresolved=())
    names: set[str] = set()
    unresolved: list[str] = []
    for declared in context.selected_wans:
        normalized = declared.casefold()
        interface = interfaces.get(normalized)
        zone = zones.get(normalized)
        if interface is None and zone is None:
            unresolved.append(declared)
            continue
        if zone is not None:
            resolved_zone_interfaces = _resolved_zone_interfaces(zone, interfaces)
            if resolved_zone_interfaces is None:
                unresolved.append(declared)
                continue
            names.add(zone.name.casefold())
            names.update(name.casefold() for name in resolved_zone_interfaces)
        else:
            names.add(getattr(interface, "name", declared).casefold())
    return _WanScope(selected=True, names=frozenset(names), unresolved=tuple(unresolved))


def _role(interface: object) -> str | None:
    value = getattr(interface, "role", None)
    return value.casefold() if isinstance(value, str) else None


def _zone_members_roles(configuration: FortiGateConfiguration, zone_name: str) -> set[str] | None:
    zone = _zone_by_name(configuration.zones).get(zone_name.casefold())
    if zone is None or zone.proof_state is not ProofState.PROVEN or not zone.interfaces:
        return None
    interfaces = _interface_by_name(configuration)
    roles: set[str] = set()
    for reference in zone.interfaces:
        interface = interfaces.get(reference.name.casefold())
        if interface is None or interface.proof_state is not ProofState.PROVEN:
            return None
        interface_role = _role(interface)
        if interface_role is None:
            roles.add("lan")
            continue
        roles.add(interface_role)
    return roles


def _ref_wan_state(
    configuration: FortiGateConfiguration,
    reference: ObjectReference,
    scope: _WanScope,
) -> bool | None:
    name = reference.name.casefold()
    interfaces = _interface_by_name(configuration)
    if name == "any":
        if _interface_name_collisions(configuration):
            return None
        if scope.selected:
            return True if scope.names and not scope.unresolved else None
        return True if any(_role(item) == "wan" for item in interfaces.values()) else None
    if scope.selected:
        if name in scope.names:
            return True
        if name in interfaces and _role(interfaces[name]) == "lan":
            return False
        return None
    interface = interfaces.get(name)
    if interface is not None:
        interface_role = _role(interface)
        if interface_role == "wan":
            return True
        if interface_role == "lan":
            return False
        return None
    roles = _zone_members_roles(configuration, name)
    if roles is None:
        return None
    if roles == {"wan"}:
        return True
    if "wan" not in roles:
        return False
    return None


def _ref_lan_state(
    configuration: FortiGateConfiguration, reference: ObjectReference
) -> bool | None:
    name = reference.name.casefold()
    if name == "any":
        if _interface_name_collisions(configuration):
            return None
        return (
            True
            if any(
                _role(item) == "lan"
                for item in _interface_by_name(configuration).values()
            )
            else None
        )
    interface = _interface_by_name(configuration).get(name)
    if interface is not None:
        interface_role = _role(interface)
        if interface_role == "lan":
            return True
        if interface_role == "wan":
            return False
        return None
    roles = _zone_members_roles(configuration, name)
    if roles is None:
        return None
    if roles == {"lan"}:
        return True
    if "lan" not in roles:
        return False
    return None


def _policy_wan_state(
    configuration: FortiGateConfiguration,
    policy: Policy,
    scope: _WanScope,
) -> bool | None:
    if not policy.destination_interfaces:
        return None
    states = tuple(
        _ref_wan_state(configuration, reference, scope)
        for reference in policy.destination_interfaces
    )
    if any(state is True for state in states):
        return True
    if any(state is None for state in states):
        return None
    return False


def _policy_lan_state(configuration: FortiGateConfiguration, policy: Policy) -> bool | None:
    if not policy.source_interfaces:
        return None
    states = tuple(
        _ref_lan_state(configuration, reference) for reference in policy.source_interfaces
    )
    if any(state is True for state in states):
        return True
    if any(state is None for state in states):
        return None
    return False


def _policy_complete(policy: Policy) -> bool:
    required = {"status", "action", "srcintf", "dstintf", "srcaddr", "dstaddr", "service"}
    return policy.proof_state is ProofState.PROVEN and required <= policy.parsed_keys


def _proves_no_all_from_builtin_https(
    configuration: FortiGateConfiguration,
    policy: Policy,
) -> bool:
    """Use the bounded legacy negative proof for an explicit built-in HTTPS token.

    This control detects the literal ``ALL`` service.  A certain ``HTTPS`` token
    is enough to prove the negative when no custom service namespace can redefine
    or collide with that name.  Other incomplete or unresolved service names stay
    on the fail-closed UNKNOWN path below.
    """
    if (
        policy.action != "accept"
        or policy.proof_state is not ProofState.PROVEN
        or "service" not in policy.parsed_keys
        or not policy.services
        or any(reference.name.casefold() != "https" for reference in policy.services)
    ):
        return False
    for section_name in ("firewall service custom", "firewall service group"):
        section = configuration.document.section(section_name)
        if section is None:
            continue
        if (
            section.certainty is not EvidenceCertainty.CERTAIN
            or section.entries
            or section.children
            or section.directives
        ):
            return False
    return True


def _policy_evidence(
    configuration: FortiGateConfiguration,
    policy: Policy,
    directive: str = "service",
    *,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem:
    return _directive_evidence(
        configuration,
        "firewall policy",
        directive,
        entry=policy.policy_id,
        certainty=certainty,
    )


def check_implicit_deny_log(configuration: FortiGateConfiguration) -> AuditFinding:
    control_id = "FW-IMPLICIT-DENY-LOG-001"
    title = "Journalisation du deny implicite"
    section = configuration.document.section("log setting")
    base_risk = _risk(
        "La journalisation du deny implicite peut être insuffisante.",
        "Les tentatives refusées par défaut peuvent ne pas être traçables.",
        "indéterminée",
        "Fournir une section log setting certaine avec fwpolicy-implicit-log enable.",
    )
    if section is None or configuration.log_setting is None:
        status = (
            AuditStatus.FAIL
            if configuration.complete_backup and section is None
            else AuditStatus.UNKNOWN
        )
        return _finding(
            control_id=control_id,
            title=title,
            status=status,
            applicability=(
                Applicability.APPLICABLE
                if status is AuditStatus.FAIL
                else Applicability.UNKNOWN
            ),
            evidence=("log setting: section ou directive absente",),
            evidence_items=(
                _section_evidence(
                    configuration, "log setting", certainty=EvidenceCertainty.INVALID
                ),
            ),
            affected_objects=(),
            message=(
                "La directive fwpolicy-implicit-log est absente du backup complet."
                if status is AuditStatus.FAIL
                else "La directive fwpolicy-implicit-log n'est pas prouvée."
            ),
            risk=base_risk,
            recommendation="Activer explicitement fwpolicy-implicit-log.",
            remediation="Compléter l'export de log setting puis relancer l'audit.",
        )
    if configuration.log_setting.implicit_deny_log in {"disable", "none"}:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=(
                f"log setting: fwpolicy-implicit-log {configuration.log_setting.implicit_deny_log}",
            ),
            evidence_items=(
                _directive_evidence(configuration, "log setting", "fwpolicy-implicit-log"),
            ),
            affected_objects=(),
            message="La journalisation du deny implicite est explicitement désactivée.",
            risk=_risk(
                "Les refus implicites ne sont pas journalisés.",
                "Une exposition ou tentative bloquée peut ne laisser aucune trace.",
                "élevée",
                "Activer fwpolicy-implicit-log et vérifier les événements générés.",
            ),
            recommendation="Configurer set fwpolicy-implicit-log enable.",
            remediation="Activer la journalisation du deny implicite dans config log setting.",
        )
    if (
        configuration.log_setting.proof_state is not ProofState.PROVEN
        or configuration.log_setting.implicit_deny_log != "enable"
    ):
        status = (
            AuditStatus.FAIL
            if configuration.complete_backup
            and configuration.log_setting.proof_state is ProofState.PROVEN
            and configuration.log_setting.implicit_deny_log is None
            else AuditStatus.UNKNOWN
        )
        return _finding(
            control_id=control_id,
            title=title,
            status=status,
            applicability=(
                Applicability.APPLICABLE
                if status is AuditStatus.FAIL
                else Applicability.UNKNOWN
            ),
            evidence=("fwpolicy-implicit-log: valeur absente, inconnue ou ambiguë",),
            evidence_items=(
                _directive_evidence(configuration, "log setting", "fwpolicy-implicit-log"),
            ),
            affected_objects=(),
            message=(
                "La directive fwpolicy-implicit-log est absente du backup complet."
                if status is AuditStatus.FAIL
                else "La valeur enable de fwpolicy-implicit-log ne peut pas être établie."
            ),
            risk=base_risk,
            recommendation="Fournir une directive fwpolicy-implicit-log enable certaine.",
            remediation="Corriger les mutations ou conflits puis relancer l'audit.",
        )
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=("fwpolicy-implicit-log: enable",),
        evidence_items=(
            _directive_evidence(configuration, "log setting", "fwpolicy-implicit-log"),
        ),
        affected_objects=(),
        message="La journalisation du deny implicite est explicitement activée.",
        risk=_risk(
            "Les refus implicites sont journalisés.",
            "La traçabilité des flux refusés est renforcée.",
            "faible",
            "Conserver l'activation et surveiller les journaux.",
        ),
        recommendation="Conserver fwpolicy-implicit-log enable.",
        remediation="Aucune remédiation immédiate.",
    )


def check_internet_all_service(
    configuration: FortiGateConfiguration, context: AuditContext | None = None
) -> AuditFinding:
    control_id = "FW-INTERNET-ALL-SERVICE-001"
    title = "Services ALL vers Internet"
    section = _policy_section(configuration)
    risk = _risk(
        "Une politique Internet peut autoriser tous les services.",
        "Une compromission interne peut atteindre des services Internet non nécessaires.",
        "élevée",
        "Limiter les services à une allowlist explicitement justifiée.",
    )
    if section is None:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("firewall policy: section absente",),
            evidence_items=(
                _section_evidence(
                    configuration, "firewall policy", certainty=EvidenceCertainty.INVALID
                ),
            ),
            affected_objects=(),
            message="Les politiques Internet ne peuvent pas être déterminées.",
            risk=risk,
            recommendation="Fournir la section firewall policy complète.",
            remediation="Relancer l'export avec les politiques et leurs services.",
        )
    if not section.entries and section.certainty is EvidenceCertainty.CERTAIN:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=("firewall policy: section explicitement vide",),
            evidence_items=(_section_evidence(configuration, "firewall policy"),),
            affected_objects=(),
            message="Aucune politique n'est déclarée dans le namespace firewall policy.",
            risk=_risk(
                "Aucune politique Internet n'est déclarée.",
                "Le contrôle ALL ne s'applique à aucune politique exportée.",
                "faible",
                "Surveiller toute création de politique.",
            ),
            recommendation="Conserver une politique explicitement minimale si nécessaire.",
            remediation="Aucune remédiation immédiate.",
        )

    scope = _context_wan_scope(configuration, context)
    failures: list[Policy] = []
    unknown: list[Policy] = []
    applicable_safe: list[Policy] = []
    for policy in configuration.policies:
        if policy.action == "deny":
            continue
        if policy.status == "disable":
            continue
        if _proves_no_all_from_builtin_https(configuration, policy):
            applicable_safe.append(policy)
            continue
        if policy.action is None or policy.status is None:
            unknown.append(policy)
            continue
        if policy.action != "accept" or policy.status != "enable":
            unknown.append(policy)
            continue
        if not _policy_complete(policy):
            unknown.append(policy)
            continue
        wan_state = _policy_wan_state(configuration, policy, scope)
        if wan_state is False:
            continue
        if wan_state is None:
            unknown.append(policy)
            continue
        services = {reference.name.casefold() for reference in policy.services}
        if not services:
            unknown.append(policy)
        elif "all" in services:
            failures.append(policy)
        elif any(
            not _service_coverage(configuration, reference.name).known
            for reference in policy.services
        ):
            unknown.append(policy)
        else:
            applicable_safe.append(policy)

    if failures:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(
                f"policy {policy.policy_id}: service ALL vers une WAN prouvée"
                for policy in failures
            ),
            evidence_items=tuple(_policy_evidence(configuration, policy) for policy in failures),
            affected_objects=_affected(
                (policy.policy_id for policy in failures), "firewall-policy"
            ),
            message=(
                "Une politique acceptée et activée autorise explicitement ALL "
                "vers une WAN prouvée."
            ),
            risk=risk,
            recommendation="Remplacer ALL par une allowlist de services nécessaire.",
            remediation=(
                "Modifier les politiques acceptées vers Internet puis vérifier "
                "leur portée WAN."
            ),
        )
    if unknown or section.certainty is not EvidenceCertainty.CERTAIN or scope.unresolved:
        evidence = [
            (
                f"policy {policy.policy_id}: preuve action/service/destination incomplète; "
                "services=" + ",".join(reference.name for reference in policy.services)
            )
            for policy in unknown
        ]
        evidence.extend(f"WAN de contexte inconnue: {name}" for name in scope.unresolved)
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=evidence or ("firewall policy: section ambiguë",),
            evidence_items=tuple(
                _policy_evidence(configuration, policy, certainty=EvidenceCertainty.AMBIGUOUS)
                for policy in unknown
            )
            or (
                _section_evidence(
                    configuration, "firewall policy", certainty=EvidenceCertainty.AMBIGUOUS
                ),
            ),
            affected_objects=_affected((policy.policy_id for policy in unknown), "firewall-policy"),
            message=(
                "La portée et les services de toutes les politiques Internet "
                "ne sont pas certains."
            ),
            risk=risk,
            recommendation=(
                "Fournir action, status, service et destination certains pour "
                "chaque politique."
            ),
            remediation=(
                "Corriger les mutations ou compléter le contexte WAN puis "
                "relancer l'audit."
            ),
        )
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE if applicable_safe else Applicability.NOT_APPLICABLE,
        evidence=tuple(
            f"policy {policy.policy_id}: services explicitement bornés"
            for policy in applicable_safe
        )
        or ("Aucune politique acceptée vers WAN avec service ALL",),
        evidence_items=tuple(_policy_evidence(configuration, policy) for policy in applicable_safe)
        or (_section_evidence(configuration, "firewall policy"),),
        affected_objects=_affected(
            (policy.policy_id for policy in applicable_safe), "firewall-policy"
        ),
        message="Aucune politique exportée ne déclare explicitement ALL.",
        risk=_risk(
            "Les services Internet sont bornés par les politiques certaines.",
            "La surface de sortie non nécessaire est réduite.",
            "faible",
            "Maintenir une allowlist documentée.",
        ),
        recommendation="Conserver des services explicitement limités vers les WAN.",
        remediation="Aucune remédiation immédiate.",
    )


def _profile_is_disabled(name: str | None) -> bool:
    return name is not None and name.casefold() in {"none", "disable", "disabled"}


def _profile_index(configuration: FortiGateConfiguration) -> dict[tuple[str, str], object]:
    profiles: dict[tuple[str, str], object] = {}
    collisions: set[tuple[str, str]] = set()
    for profile in configuration.security_profiles:
        if profile.profile_type is not None:
            key = (profile.profile_type.casefold(), profile.name.casefold())
            if key in profiles or key in collisions:
                collisions.add(key)
                profiles.pop(key, None)
            else:
                profiles[key] = profile
    for profile in configuration.utm_profiles:
        key = (profile.profile_type.casefold(), profile.name.casefold())
        if key in profiles or key in collisions:
            collisions.add(key)
            profiles.pop(key, None)
        else:
            profiles[key] = profile
    for key in collisions:
        profiles.pop(key, None)
    return profiles


def _resolvable_direct_profiles(
    configuration: FortiGateConfiguration, policy: Policy
) -> tuple[bool, bool]:
    profiles = _profile_index(configuration)
    if not policy.direct_profile_references:
        return False, False
    unknown = False
    for reference in policy.direct_profile_references:
        if _profile_is_disabled(reference.name):
            return False, False
        profile = profiles.get((reference.object_type.casefold(), reference.name.casefold()))
        if profile is None or profile.proof_state is not ProofState.PROVEN:
            unknown = True
    return (not unknown, unknown)


def _resolvable_profile_group(
    configuration: FortiGateConfiguration, group: ProfileGroup
) -> tuple[bool, bool]:
    profiles = _profile_index(configuration)
    if group.proof_state is not ProofState.PROVEN or not group.profile_references:
        return False, group.proof_state is not ProofState.PROVEN
    unknown = False
    for reference in group.profile_references:
        if _profile_is_disabled(reference.name):
            return False, False
        profile = profiles.get((reference.object_type.casefold(), reference.name.casefold()))
        if profile is None or profile.proof_state is not ProofState.PROVEN:
            unknown = True
    return (not unknown, unknown)


def check_utm_profile_binding(
    configuration: FortiGateConfiguration, context: AuditContext | None = None
) -> AuditFinding:
    control_id = "FW-UTM-PROFILE-BINDING-001"
    title = "Liaison des profils UTM"
    section = _policy_section(configuration)
    risk = _risk(
        "Une politique journalisée UTM peut ne pas appliquer de profils de sécurité.",
        "Des flux Internet peuvent contourner l'inspection attendue.",
        "élevée",
        "Lier explicitement des profils UTM résolubles à chaque politique concernée.",
    )
    if section is None:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("firewall policy: section absente",),
            evidence_items=(
                _section_evidence(
                    configuration, "firewall policy", certainty=EvidenceCertainty.INVALID
                ),
            ),
            affected_objects=(),
            message="Les politiques logtraffic utm ne peuvent pas être déterminées.",
            risk=risk,
            recommendation="Fournir firewall policy et les profils référencés.",
            remediation="Relancer l'export avec les bindings UTM complets.",
        )
    scope = _context_wan_scope(configuration, context)
    groups: dict[str, ProfileGroup] = {}
    group_collisions: set[str] = set()
    for group in configuration.profile_groups:
        key = group.name.casefold()
        if key in groups or key in group_collisions:
            group_collisions.add(key)
            groups.pop(key, None)
        else:
            groups[key] = group
    for key in group_collisions:
        groups.pop(key, None)
    failures: list[Policy] = []
    unknown: list[Policy] = []
    compliant: list[Policy] = []
    for policy in configuration.policies:
        if policy.logtraffic != "utm":
            continue
        if policy.status == "disable" or policy.action == "deny":
            continue
        if policy.action != "accept" or policy.status != "enable":
            unknown.append(policy)
            continue
        wan_state = _policy_wan_state(configuration, policy, scope)
        if wan_state is False:
            continue
        if wan_state is None or not _policy_complete(policy):
            unknown.append(policy)
            continue
        if policy.utm_status in {"disable", "none"}:
            failures.append(policy)
            continue
        if policy.utm_status != "enable":
            if policy.proof_state is ProofState.PROVEN:
                failures.append(policy)
            else:
                unknown.append(policy)
            continue
        if policy.profile_group is not None:
            if _profile_is_disabled(policy.profile_group.name):
                failures.append(policy)
                continue
            group = groups.get(policy.profile_group.name.casefold())
            if group is None:
                unknown.append(policy)
                continue
            valid, uncertain = _resolvable_profile_group(configuration, group)
            if valid:
                compliant.append(policy)
            elif uncertain:
                unknown.append(policy)
            else:
                failures.append(policy)
            continue
        valid, uncertain = _resolvable_direct_profiles(configuration, policy)
        if valid:
            compliant.append(policy)
        elif uncertain:
            unknown.append(policy)
        elif policy.proof_state is ProofState.PROVEN:
            failures.append(policy)
        else:
            unknown.append(policy)

    if failures:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(
                f"policy {policy.policy_id}: binding UTM absent ou désactivé" for policy in failures
            ),
            evidence_items=tuple(
                _policy_evidence(configuration, policy, "utm-status") for policy in failures
            ),
            affected_objects=_affected(
                (policy.policy_id for policy in failures), "firewall-policy"
            ),
            message="Une politique logtraffic utm activée n'a pas de binding UTM valide.",
            risk=risk,
            recommendation="Activer les profils UTM et résoudre chaque référence.",
            remediation="Lier les profils de sécurité directement ou via un profile-group certain.",
        )
    if unknown or section.certainty is not EvidenceCertainty.CERTAIN or scope.unresolved:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=tuple(
                f"policy {policy.policy_id}: binding UTM absent, ambigu ou non résolu"
                for policy in unknown
            )
            or ("Aucune preuve complète des bindings UTM",),
            evidence_items=tuple(
                _policy_evidence(
                    configuration, policy, "utm-status", certainty=EvidenceCertainty.AMBIGUOUS
                )
                for policy in unknown
            )
            or (
                _section_evidence(
                    configuration, "firewall policy", certainty=EvidenceCertainty.AMBIGUOUS
                ),
            ),
            affected_objects=_affected((policy.policy_id for policy in unknown), "firewall-policy"),
            message="Les références UTM ne sont pas toutes résolubles avec certitude.",
            risk=risk,
            recommendation="Fournir des profils UTM et bindings certains.",
            remediation=(
                "Corriger les conflits, mutations ou références absentes puis "
                "relancer l'audit."
            ),
        )
    if not compliant:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=("Aucune politique WAN logtraffic utm applicable",),
            evidence_items=(_section_evidence(configuration, "firewall policy"),),
            affected_objects=(),
            message="Aucune politique logtraffic utm applicable n'est déclarée.",
            risk=_risk(
                "Le contrôle de liaison UTM n'est pas applicable aux politiques exportées.",
                "Aucun flux UTM WAN n'a été identifié.",
                "faible",
                "Réévaluer après toute activation de logtraffic utm.",
            ),
            recommendation="Surveiller les nouvelles politiques logtraffic utm.",
            remediation="Aucune remédiation immédiate.",
        )
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(f"policy {policy.policy_id}: binding UTM résolu" for policy in compliant),
        evidence_items=tuple(
            _policy_evidence(configuration, policy, "utm-status") for policy in compliant
        ),
        affected_objects=_affected((policy.policy_id for policy in compliant), "firewall-policy"),
        message="Les bindings UTM des politiques logtraffic utm sont résolus et actifs.",
        risk=_risk(
            "Les politiques UTM applicables lient des profils résolubles.",
            "L'inspection configurée est traçable.",
            "faible",
            "Maintenir les profils et vérifier leurs changements.",
        ),
        recommendation="Conserver les bindings UTM explicites.",
        remediation="Aucune remédiation immédiate.",
    )


def _check_extintf_any(
    configuration: FortiGateConfiguration,
    *,
    control_id: str,
    title: str,
    objects: tuple[Vip, ...] | tuple[VirtualServer, ...],
    object_type: str,
    expected_type: str,
) -> AuditFinding:
    section = configuration.document.section("firewall vip")
    risk = _risk(
        "Un objet d'exposition peut écouter sur toutes les interfaces externes.",
        "Une publication involontaire augmente la surface Internet.",
        "élevée",
        "Limiter extintf à des interfaces explicitement nécessaires.",
    )
    if section is None:
        if configuration.complete_backup:
            return _finding(
                control_id=control_id,
                title=title,
                status=AuditStatus.PASS,
                applicability=Applicability.NOT_APPLICABLE,
                evidence=(f"backup complet: aucun objet {expected_type}",),
                evidence_items=(evidence_for_complete_backup(),),
                affected_objects=(),
                message=f"Aucun objet {expected_type} n'est déclaré dans le backup complet.",
                risk=_risk(
                    f"Aucun objet {expected_type} n'est applicable.",
                    "La règle extintf any ne s'applique à aucun objet prouvé.",
                    "faible",
                    "Réévaluer après toute création d'objet.",
                ),
                recommendation=f"Surveiller les nouveaux objets {expected_type}.",
                remediation="Aucune remédiation immédiate.",
            )
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("firewall vip: section absente",),
            evidence_items=(
                _section_evidence(
                    configuration, "firewall vip", certainty=EvidenceCertainty.INVALID
                ),
            ),
            affected_objects=(),
            message="Les objets d'exposition ne peuvent pas être déterminés.",
            risk=risk,
            recommendation="Fournir firewall vip complet.",
            remediation="Relancer l'export avec les VIP et virtual servers.",
        )
    if (
        (not section.entries or not objects)
        and section.certainty is EvidenceCertainty.CERTAIN
    ):
        if section.entries and len(configuration.vips) + len(configuration.virtual_servers) != len(
            section.entries
        ):
            status = AuditStatus.UNKNOWN
            applicability = Applicability.UNKNOWN
        else:
            status = AuditStatus.PASS
            applicability = Applicability.NOT_APPLICABLE
        return _finding(
            control_id=control_id,
            title=title,
            status=status,
            applicability=applicability,
            evidence=(f"Aucun objet {expected_type} applicable",),
            evidence_items=(_section_evidence(configuration, "firewall vip"),),
            affected_objects=(),
            message=f"Aucun objet {expected_type} n'est déclaré dans le namespace audité.",
            risk=_risk(
                f"Aucun objet {expected_type} n'est applicable.",
                "La règle extintf any ne s'applique à aucun objet prouvé.",
                "faible",
                "Réévaluer après toute création d'objet.",
            ),
            recommendation=f"Surveiller les nouveaux objets {expected_type}.",
            remediation="Aucune remédiation immédiate.",
        )
    failures: list[Vip | VirtualServer] = []
    unknown: list[Vip | VirtualServer] = []
    safe: list[Vip | VirtualServer] = []
    for item in objects:
        if any(value.casefold() == "any" for value in item.extintf):
            failures.append(item)
        elif item.proof_state is not ProofState.PROVEN or not item.extintf:
            unknown.append(item)
        else:
            safe.append(item)
    if failures:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(f"{object_type} {item.name}: extintf any" for item in failures),
            evidence_items=tuple(
                _directive_evidence(configuration, "firewall vip", "extintf", entry=item.name)
                for item in failures
            ),
            affected_objects=_affected((item.name for item in failures), object_type),
            message=f"Un objet {expected_type} expose explicitement extintf any.",
            risk=risk,
            recommendation="Remplacer extintf any par les interfaces externes nécessaires.",
            remediation="Limiter extintf puis vérifier les objets publiés.",
        )
    if unknown or section.certainty is not EvidenceCertainty.CERTAIN:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=tuple(
                f"{object_type} {item.name}: extintf incomplet ou ambigu" for item in unknown
            )
            or (f"firewall vip: section {expected_type} ambiguë",),
            evidence_items=tuple(
                _directive_evidence(
                    configuration,
                    "firewall vip",
                    "extintf",
                    entry=item.name,
                    certainty=EvidenceCertainty.AMBIGUOUS,
                )
                for item in unknown
            )
            or (
                _section_evidence(
                    configuration, "firewall vip", certainty=EvidenceCertainty.AMBIGUOUS
                ),
            ),
            affected_objects=_affected((item.name for item in unknown), object_type),
            message=f"La restriction extintf des objets {expected_type} n'est pas complète.",
            risk=risk,
            recommendation="Fournir extintf et les champs de l'objet avec certitude.",
            remediation="Corriger les mutations ou compléter les objets puis relancer l'audit.",
        )
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(f"{object_type} {item.name}: extintf explicitement borné" for item in safe),
        evidence_items=tuple(
            _directive_evidence(configuration, "firewall vip", "extintf", entry=item.name)
            for item in safe
        ),
        affected_objects=_affected((item.name for item in safe), object_type),
        message=f"Les objets {expected_type} ont une interface externe explicitement bornée.",
        risk=_risk(
            f"Les objets {expected_type} n'écoutent pas sur any de façon probante.",
            "La surface d'exposition est limitée aux interfaces déclarées.",
            "faible",
            "Maintenir les interfaces externes minimales.",
        ),
        recommendation="Conserver des extintf explicitement limités.",
        remediation="Aucune remédiation immédiate.",
    )


def check_vip_extintf_any(configuration: FortiGateConfiguration) -> AuditFinding:
    return _check_extintf_any(
        configuration,
        control_id="FW-VIP-EXTINTF-ANY-001",
        title="VIP avec extintf any",
        objects=configuration.vips,
        object_type="vip",
        expected_type="VIP",
    )


def check_vserver_extintf_any(configuration: FortiGateConfiguration) -> AuditFinding:
    return _check_extintf_any(
        configuration,
        control_id="FW-VSERVER-EXTINTF-ANY-001",
        title="Virtual server avec extintf any",
        objects=configuration.virtual_servers,
        object_type="virtual-server",
        expected_type="virtual server",
    )


def _range_covers(ranges: tuple[PortRange, ...], target: PortRange) -> bool:
    return any(item.start <= target.start and item.end >= target.end for item in ranges)


def _merge_ranges(values: Iterable[tuple[PortRange, ...]]) -> tuple[PortRange, ...]:
    ordered = sorted(
        (item for ranges in values for item in ranges), key=lambda value: (value.start, value.end)
    )
    merged: list[PortRange] = []
    for item in ordered:
        if merged and item.start <= merged[-1].end + 1:
            merged[-1] = PortRange(start=merged[-1].start, end=max(merged[-1].end, item.end))
        else:
            merged.append(item)
    return tuple(merged)


def _service_coverage(
    configuration: FortiGateConfiguration,
    name: str,
    *,
    seen: frozenset[str] = frozenset(),
) -> _PortCoverage:
    if name.casefold() == "all":
        full_range = (PortRange(start=0, end=65535),)
        return _PortCoverage(known=True, tcp=full_range, udp=full_range)
    if name in seen:
        return _PortCoverage(known=False)
    catalog = configuration.service_objects + configuration.service_groups
    exact = tuple(service for service in catalog if service.name == name)
    if len(exact) == 1:
        service = exact[0]
    elif exact:
        return _PortCoverage(known=False)
    else:
        folded = tuple(service for service in catalog if service.name.casefold() == name.casefold())
        if len(folded) != 1:
            return _PortCoverage(known=False)
        service = folded[0]
    if service.proof_state is not ProofState.PROVEN or service.name in seen:
        return _PortCoverage(known=False)
    if service.members:
        children = tuple(
            _service_coverage(configuration, member.name, seen=seen | {service.name})
            for member in service.members
        )
        if any(not child.known for child in children):
            return _PortCoverage(known=False)
        return _PortCoverage(
            known=True,
            tcp=_merge_ranges(child.tcp for child in children),
            udp=_merge_ranges(child.udp for child in children),
        )
    return _PortCoverage(
        known=True,
        tcp=service.tcp_port_ranges,
        udp=service.udp_port_ranges,
    )


def _policy_coverage(configuration: FortiGateConfiguration, policy: Policy) -> _PortCoverage:
    if not policy.services:
        return _PortCoverage(known=False)
    values = tuple(
        _service_coverage(configuration, reference.name) for reference in policy.services
    )
    if any(not value.known for value in values):
        return _PortCoverage(known=False)
    return _PortCoverage(
        known=True,
        tcp=_merge_ranges(value.tcp for value in values),
        udp=_merge_ranges(value.udp for value in values),
    )


def _ruleset_targets(ruleset: SensitiveProtocolRuleset) -> tuple[tuple[str, PortRange], ...]:
    return tuple(
        (transport.protocol, PortRange(start=item.start, end=item.end))
        for rule in ruleset.protocols
        for transport in rule.transports
        for item in transport.ranges
    )


def _coverage_has_sensitive_flow(
    coverage: _PortCoverage, ruleset: SensitiveProtocolRuleset
) -> bool:
    if not coverage.known:
        return False
    return any(
        _range_covers(coverage.tcp if protocol == "tcp" else coverage.udp, target)
        for protocol, target in _ruleset_targets(ruleset)
    )


def _coverage_covers_all(coverage: _PortCoverage, ruleset: SensitiveProtocolRuleset) -> bool:
    if not coverage.known:
        return False
    return all(
        _range_covers(coverage.tcp if protocol == "tcp" else coverage.udp, target)
        for protocol, target in _ruleset_targets(ruleset)
    )


def check_sensitive_protocol_deny(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    control_id = "FW-SENSITIVE-PROTOCOL-DENY-001"
    title = "Refus explicite des protocoles sensibles"
    section = _policy_section(configuration)
    risk = _risk(
        "Des flux LAN vers WAN peuvent exposer des protocoles d'infrastructure sensibles.",
        (
            "Une exposition de Kerberos, LDAP, RADIUS, SMB ou NetBIOS facilite "
            "une compromission latérale."
        ),
        "élevée",
        "Refuser explicitement chaque port sensible avec un service résolu.",
    )
    if section is None:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("firewall policy: section absente",),
            evidence_items=(
                _section_evidence(
                    configuration, "firewall policy", certainty=EvidenceCertainty.INVALID
                ),
            ),
            affected_objects=(),
            message=(
                f"La couverture {SENSITIVE_PROTOCOL_RULESET_ID} "
                f"{SENSITIVE_PROTOCOL_RULESET_VERSION} est inconnue."
            ),
            risk=risk,
            recommendation="Fournir les politiques LAN vers WAN et leurs services résolus.",
            remediation=(
                "Relancer l'audit avec firewall policy, service custom et "
                "groupes complets."
            ),
        )
    if not section.entries and section.certainty is EvidenceCertainty.CERTAIN:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=("firewall policy: section explicitement vide",),
            evidence_items=(_section_evidence(configuration, "firewall policy"),),
            affected_objects=(),
            message=(
                f"Aucun flux LAN vers WAN à couvrir pour {SENSITIVE_PROTOCOL_RULESET_ID} "
                f"{SENSITIVE_PROTOCOL_RULESET_VERSION}."
            ),
            risk=_risk(
                "Aucune politique LAN vers WAN n'est déclarée.",
                "Le contrôle n'est pas applicable au namespace vide.",
                "faible",
                "Réévaluer après toute création de politique.",
            ),
            recommendation="Surveiller les nouvelles politiques LAN vers WAN.",
            remediation="Aucune remédiation immédiate.",
        )
    scope = _context_wan_scope(configuration, context)
    observations: list[_FlowObservation] = []
    unknown_policies: list[Policy] = []
    for policy in configuration.policies:
        if policy.status == "disable":
            continue
        if policy.action not in {"accept", "deny"} or policy.status != "enable":
            unknown_policies.append(policy)
            continue
        wan_state = _policy_wan_state(configuration, policy, scope)
        lan_state = _policy_lan_state(configuration, policy)
        if wan_state is False or lan_state is False:
            continue
        if wan_state is None or lan_state is None or not _policy_complete(policy):
            unknown_policies.append(policy)
            continue
        coverage = _policy_coverage(configuration, policy)
        observations.append(
            _FlowObservation(
                policy=policy,
                coverage=coverage,
                action=policy.action,
                complete=True,
                applicable=True,
            )
        )

    accepting = [
        observation
        for observation in observations
        if observation.action == "accept"
        and (
            (
                observation.coverage.known
                and _coverage_has_sensitive_flow(observation.coverage, _RULESET)
            )
            or not observation.coverage.known
        )
    ]
    if any(
        observation.coverage.known and _coverage_has_sensitive_flow(observation.coverage, _RULESET)
        for observation in accepting
    ):
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(
                f"policy {observation.policy.policy_id}: accept couvre un flux sensible; "
                f"ruleset {SENSITIVE_PROTOCOL_RULESET_ID}"
                for observation in accepting
                if observation.coverage.known
                and _coverage_has_sensitive_flow(observation.coverage, _RULESET)
            )
            + (f"ruleset-version: {SENSITIVE_PROTOCOL_RULESET_VERSION}",),
            evidence_items=tuple(
                _policy_evidence(configuration, observation.policy)
                for observation in accepting
                if observation.coverage.known
                and _coverage_has_sensitive_flow(observation.coverage, _RULESET)
            ),
            affected_objects=_affected(
                (observation.policy.policy_id for observation in accepting), "firewall-policy"
            ),
            message=(
                "Un accept LAN vers WAN couvre un protocole sensible "
                f"({SENSITIVE_PROTOCOL_RULESET_ID} {SENSITIVE_PROTOCOL_RULESET_VERSION})."
            ),
            risk=risk,
            recommendation=(
                "Remplacer l'accept par un deny explicite couvrant tous les "
                "ports sensibles."
            ),
            remediation=(
                "Créer ou corriger un service résolu puis placer une politique "
                "deny explicite."
            ),
        )
    if (
        section.certainty is not EvidenceCertainty.CERTAIN
        or unknown_policies
        or any(not observation.coverage.known for observation in observations)
    ):
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=tuple(
                f"policy {policy.policy_id}: flux ou service non résolu"
                for policy in unknown_policies
            )
            + tuple(
                f"policy {observation.policy.policy_id}: service object ambigu ou absent"
                for observation in observations
                if not observation.coverage.known
            )
            + (f"ruleset-version: {SENSITIVE_PROTOCOL_RULESET_VERSION}",),
            evidence_items=tuple(
                _policy_evidence(configuration, policy, certainty=EvidenceCertainty.AMBIGUOUS)
                for policy in unknown_policies
            )
            or (
                _section_evidence(
                    configuration, "firewall policy", certainty=EvidenceCertainty.AMBIGUOUS
                ),
            ),
            affected_objects=_affected(
                tuple(policy.policy_id for policy in unknown_policies)
                + tuple(
                    observation.policy.policy_id
                    for observation in observations
                    if not observation.coverage.known
                ),
                "firewall-policy",
            ),
            message=(
                "La couverture complète des flux sensibles est inconnue "
                f"({SENSITIVE_PROTOCOL_RULESET_ID} {SENSITIVE_PROTOCOL_RULESET_VERSION})."
            ),
            risk=risk,
            recommendation=(
                "Résoudre chaque service et fournir action, status, source et "
                "destination."
            ),
            remediation="Corriger les objets mutés ou absents puis relancer l'audit.",
        )
    denies = [observation for observation in observations if observation.action == "deny"]
    if not denies:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=(
                "Aucune politique deny LAN vers WAN certaine ne couvre le ruleset sensible",
                f"ruleset-version: {SENSITIVE_PROTOCOL_RULESET_VERSION}",
            ),
            evidence_items=(
                _section_evidence(
                    configuration, "firewall policy", certainty=EvidenceCertainty.AMBIGUOUS
                ),
            ),
            affected_objects=(),
            message=(
                f"Aucun deny explicite ne prouve la couverture "
                f"{SENSITIVE_PROTOCOL_RULESET_ID}."
            ),
            risk=risk,
            recommendation="Ajouter une politique deny explicite avant les accepts concernés.",
            remediation=(
                "Créer un service contenant les ports du ruleset et le refuser "
                "sur LAN vers WAN."
            ),
        )
    deny_coverage = _PortCoverage(
        known=True,
        tcp=_merge_ranges(observation.coverage.tcp for observation in denies),
        udp=_merge_ranges(observation.coverage.udp for observation in denies),
    )
    if not _coverage_covers_all(deny_coverage, _RULESET):
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=(
                "La couverture deny des ports sensibles est incomplète",
                f"ruleset-version: {SENSITIVE_PROTOCOL_RULESET_VERSION}",
            ),
            evidence_items=tuple(
                _policy_evidence(configuration, observation.policy) for observation in denies
            ),
            affected_objects=_affected(
                (observation.policy.policy_id for observation in denies), "firewall-policy"
            ),
            message=(
                f"La couverture deny n'est pas complète pour {SENSITIVE_PROTOCOL_RULESET_ID} "
                f"{SENSITIVE_PROTOCOL_RULESET_VERSION}."
            ),
            risk=risk,
            recommendation=(
                "Couvrir TCP/UDP 88, 389, TCP 636/445, UDP 1812-1813 et "
                "TCP/UDP 137-139."
            ),
            remediation=(
                "Étendre le service deny avec chaque plage du ruleset puis "
                "relancer l'audit."
            ),
        )
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(
            f"policy {observation.policy.policy_id}: deny couvre le ruleset sensible"
            for observation in denies
        )
        + (f"ruleset-version: {SENSITIVE_PROTOCOL_RULESET_VERSION}",),
        evidence_items=tuple(
            _policy_evidence(configuration, observation.policy) for observation in denies
        ),
        affected_objects=_affected(
            (observation.policy.policy_id for observation in denies), "firewall-policy"
        ),
        message=(
            "Les protocoles sensibles sont refusés explicitement "
            f"({SENSITIVE_PROTOCOL_RULESET_ID} {SENSITIVE_PROTOCOL_RULESET_VERSION})."
        ),
        risk=_risk(
            "Les flux sensibles couverts par le ruleset sont explicitement refusés.",
            "La propagation de protocoles d'infrastructure vers WAN est réduite.",
            "faible",
            "Maintenir la politique deny et son service résolu.",
        ),
        recommendation="Conserver le deny explicite et vérifier l'ordre des politiques.",
        remediation="Aucune remédiation immédiate.",
    )


# Compatibility aliases used by registry consumers that prefer check_* names.
check_fw_implicit_deny_log = check_implicit_deny_log
check_fw_internet_all_service = check_internet_all_service
check_fw_utm_profile_binding = check_utm_profile_binding
check_fw_vip_extintf_any = check_vip_extintf_any
check_fw_vserver_extintf_any = check_vserver_extintf_any
check_fw_sensitive_protocol_deny = check_sensitive_protocol_deny


for _control in (
    check_implicit_deny_log,
    check_internet_all_service,
    check_utm_profile_binding,
    check_vip_extintf_any,
    check_vserver_extintf_any,
    check_sensitive_protocol_deny,
):
    _control.category = "firewall"
    _control.priority = AuditPriority.P0

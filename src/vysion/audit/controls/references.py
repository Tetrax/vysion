"""Fail-closed integrity checks for typed FortiGate object references.

The control in this module consumes only the parser's immutable structural
projection and the typed configuration objects.  It deliberately does not
search or tokenize the original configuration text.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from vysion.audit.controls._evidence import (
    evidence_for_directive,
    evidence_for_entry,
    evidence_for_section,
)
from vysion.audit.models import (
    AffectedObject,
    Applicability,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    EvidenceItem,
    FortiGateConfiguration,
    ObjectReference,
    Policy,
    ProofState,
    RiskAssessment,
    ServiceObject,
)

CONTROL_ID = "CFG-REF-INTEGRITY-001"

_PROFILE_REFERENCE_DIRECTIVES = {
    "webfilter profile": "webfilter-profile",
    "ips sensor": "ips-sensor",
    "antivirus profile": "av-profile",
    "dnsfilter profile": "dnsfilter-profile",
    "application list": "application-list",
    "ssl-ssh-profile": "ssl-ssh-profile",
    "voip profile": "voip-profile",
    "waf profile": "waf-profile",
    "virtual-patch profile": "virtual-patch-profile",
    "file-filter profile": "file-filter-profile",
    "icap profile": "icap-profile",
}
_PROFILE_SECTIONS = {
    "webfilter profile": ("firewall webfilter profile", "webfilter profile"),
    "ips sensor": ("firewall ips sensor", "ips sensor"),
    "antivirus profile": ("firewall antivirus profile", "antivirus profile"),
    "dnsfilter profile": ("firewall dnsfilter profile", "dnsfilter profile"),
    "application list": ("firewall application list", "application list"),
    "ssl-ssh-profile": ("firewall ssl-ssh-profile",),
    "profile-protocol-options": ("firewall profile-protocol-options",),
    "voip profile": ("firewall voip profile",),
    "waf profile": ("firewall waf profile",),
    "virtual-patch profile": ("firewall virtual-patch profile",),
    "file-filter profile": ("firewall file-filter profile",),
    "icap profile": ("firewall icap profile",),
}
_REFERENCE_GRAPH_SECTIONS = (
    "system interface",
    "system zone",
    "system sdwan",
    "firewall service custom",
    "firewall service group",
    "firewall policy",
    "firewall profile-group",
    "firewall vip",
    "firewall vipgrp",
    "vpn ipsec phase1-interface",
    "vpn ipsec phase2-interface",
)


def _compact_section_name(value: str) -> str:
    return "".join(character for character in value.casefold() if character not in " -_")


def _has_noncanonical_reference_section(configuration: FortiGateConfiguration) -> bool:
    expected_names = (
        *_REFERENCE_GRAPH_SECTIONS,
        *(
            section_name
            for aliases in _PROFILE_SECTIONS.values()
            for section_name in aliases
        ),
    )
    expected = set(expected_names)
    compact_expected = tuple(_compact_section_name(name) for name in expected_names)
    for section in configuration.document.sections:
        name = section.name.casefold()
        compact_name = _compact_section_name(name)
        if name in expected:
            continue
        if any(
            name.startswith(expected_name) or compact_name.startswith(expected_compact)
            for expected_name, expected_compact in zip(
                expected_names,
                compact_expected,
                strict=True,
            )
        ):
            return True
    return False


@dataclass(frozen=True)
class _Index:
    objects: dict[str, object]
    collisions: frozenset[str]


@dataclass(frozen=True)
class _Observation:
    reference: ObjectReference
    target_namespace: str
    target_sections: tuple[str, ...]
    source_section: str
    source_entry: str | None
    source_directive: str | None
    source_proven: bool
    label: str


@dataclass(frozen=True)
class _Indexes:
    by_namespace: dict[str, _Index]


def _index(items: Iterable[object]) -> _Index:
    objects: dict[str, object] = {}
    collisions: set[str] = set()
    for item in items:
        name = getattr(item, "name", None)
        if not isinstance(name, str) or not name:
            continue
        key = name.casefold()
        if key in collisions:
            continue
        if key in objects:
            objects.pop(key, None)
            collisions.add(key)
            continue
        objects[key] = item
    return _Index(objects=objects, collisions=frozenset(collisions))


def _index_profiles(configuration: FortiGateConfiguration) -> dict[str, _Index]:
    grouped: dict[str, list[object]] = {}
    for profile in (*configuration.security_profiles, *configuration.utm_profiles):
        profile_type = getattr(profile, "profile_type", None)
        if isinstance(profile_type, str) and profile_type:
            grouped.setdefault(profile_type.casefold(), []).append(profile)
    return {profile_type: _index(items) for profile_type, items in grouped.items()}


def _indexes(configuration: FortiGateConfiguration) -> _Indexes:
    zones = (*configuration.zones, *configuration.sdwan_zones)
    profiles = _index_profiles(configuration)
    by_namespace = {
        "interface": _index(configuration.interfaces),
        "interface-or-zone": _index((*configuration.interfaces, *zones)),
        "service": _index((*configuration.service_objects, *configuration.service_groups)),
        "profile-group": _index(configuration.profile_groups),
        "vip": _index((*configuration.vips, *configuration.virtual_servers)),
        "vip-group": _index(configuration.vip_groups),
        "vip-logical": _index(
            (*configuration.vips, *configuration.virtual_servers, *configuration.vip_groups)
        ),
        "ipsec-phase1": _index(configuration.ipsec_phase1),
    }
    by_namespace.update({f"profile:{name}": index for name, index in profiles.items()})
    return _Indexes(by_namespace=by_namespace)


def _section_is_complete(configuration: FortiGateConfiguration, names: tuple[str, ...]) -> bool:
    document = configuration.document
    if not document.valid or document.certainty is not EvidenceCertainty.CERTAIN:
        return False
    for name in names:
        section = document.section(name)
        if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
            return False
        if any(entry.certainty is not EvidenceCertainty.CERTAIN for entry in section.entries):
            return False
    return True


def _alternative_sections_are_complete(
    configuration: FortiGateConfiguration,
    names: tuple[str, ...],
) -> bool:
    document = configuration.document
    if not names or not document.valid or document.certainty is not EvidenceCertainty.CERTAIN:
        return False
    present = False
    for name in names:
        section = document.section(name)
        if section is None:
            continue
        present = True
        if section.certainty is not EvidenceCertainty.CERTAIN:
            return False
        if any(entry.certainty is not EvidenceCertainty.CERTAIN for entry in section.entries):
            return False
    return present


def _reference_graph_is_explicitly_empty(configuration: FortiGateConfiguration) -> bool:
    if not _section_is_complete(configuration, _REFERENCE_GRAPH_SECTIONS):
        return False
    sections = tuple(configuration.document.section(name) for name in _REFERENCE_GRAPH_SECTIONS)
    return all(section is not None and not section.entries for section in sections)


def _entry_is_certain(
    configuration: FortiGateConfiguration,
    section_name: str,
    entry_name: str | None,
) -> bool:
    document = configuration.document
    if not document.valid or document.certainty is not EvidenceCertainty.CERTAIN:
        return False
    section = document.section(section_name)
    if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
        return False
    if entry_name is None:
        return True
    return any(
        entry.name == entry_name and entry.certainty is EvidenceCertainty.CERTAIN
        for entry in section.entries
    )


def _policy_directive_is_proven(
    configuration: FortiGateConfiguration,
    policy_id: str,
    directive_name: str,
) -> bool:
    document = configuration.document
    if not document.valid or document.certainty is not EvidenceCertainty.CERTAIN:
        return False
    section = document.section("firewall policy")
    if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
        return False
    entry = next((item for item in section.entries if item.name == policy_id), None)
    if entry is None or entry.certainty is not EvidenceCertainty.CERTAIN:
        return False
    if directive_name in entry.invalidated_keys:
        return False
    directives = tuple(item for item in entry.directives if item.name == directive_name)
    return (
        len(directives) == 1
        and directives[0].certainty is EvidenceCertainty.CERTAIN
        and not directives[0].mutation
        and bool(directives[0].tokens)
    )


def _profile_namespace(profile_type: str) -> tuple[str, tuple[str, ...]]:
    normalized = profile_type.casefold()
    return f"profile:{normalized}", _PROFILE_SECTIONS.get(normalized, ())


def _service_section(service: ServiceObject) -> str:
    return (
        "firewall service group"
        if service.service_type.casefold() == "group"
        else "firewall service custom"
    )


def _append_observations(
    observations: list[_Observation],
    references: tuple[ObjectReference, ...],
    *,
    target_namespace: str,
    target_sections: tuple[str, ...],
    source_section: str,
    source_entry: str | None,
    source_directive: str | None,
    source_proven: bool,
    label: str,
) -> None:
    seen: set[str] = set()
    for reference in references:
        key = reference.name.casefold()
        duplicate = key in seen
        seen.add(key)
        observations.append(
            _Observation(
                reference=reference,
                target_namespace=target_namespace,
                target_sections=target_sections,
                source_section=source_section,
                source_entry=source_entry,
                source_directive=source_directive,
                source_proven=source_proven and not duplicate,
                label=label,
            )
        )


def _policy_observations(
    configuration: FortiGateConfiguration,
    observations: list[_Observation],
    policy: Policy,
) -> None:
    _append_observations(
        observations,
        policy.source_interfaces,
        target_namespace="interface-or-zone",
        target_sections=("system interface", "system zone", "system sdwan"),
        source_section="firewall policy",
        source_entry=policy.policy_id,
        source_directive="srcintf",
        source_proven=_policy_directive_is_proven(configuration, policy.policy_id, "srcintf"),
        label=f"policy {policy.policy_id} source interface",
    )
    _append_observations(
        observations,
        policy.destination_interfaces,
        target_namespace="interface-or-zone",
        target_sections=("system interface", "system zone", "system sdwan"),
        source_section="firewall policy",
        source_entry=policy.policy_id,
        source_directive="dstintf",
        source_proven=_policy_directive_is_proven(configuration, policy.policy_id, "dstintf"),
        label=f"policy {policy.policy_id} destination interface",
    )
    _append_observations(
        observations,
        policy.services,
        target_namespace="service",
        target_sections=("firewall service custom", "firewall service group"),
        source_section="firewall policy",
        source_entry=policy.policy_id,
        source_directive="service",
        source_proven=_policy_directive_is_proven(configuration, policy.policy_id, "service"),
        label=f"policy {policy.policy_id} service",
    )
    if policy.profile_group is not None:
        _append_observations(
            observations,
            (policy.profile_group,),
            target_namespace="profile-group",
            target_sections=("firewall profile-group",),
            source_section="firewall policy",
            source_entry=policy.policy_id,
            source_directive="profile-group",
            source_proven=_policy_directive_is_proven(
                configuration, policy.policy_id, "profile-group"
            ),
            label=f"policy {policy.policy_id} profile group",
        )
    for reference in policy.direct_profile_references:
        profile_type = reference.object_type.casefold()
        profile_directive = _PROFILE_REFERENCE_DIRECTIVES.get(profile_type)
        target_namespace, target_sections = _profile_namespace(profile_type)
        _append_observations(
            observations,
            (reference,),
            target_namespace=target_namespace,
            target_sections=target_sections,
            source_section="firewall policy",
            source_entry=policy.policy_id,
            source_directive=profile_directive,
            source_proven=(
                _policy_directive_is_proven(configuration, policy.policy_id, profile_directive)
                if profile_directive is not None
                else False
            ),
            label=f"policy {policy.policy_id} profile",
        )


def _observations(configuration: FortiGateConfiguration) -> tuple[_Observation, ...]:
    observations: list[_Observation] = []
    for zone in (*configuration.zones, *configuration.sdwan_zones):
        source_section = "system zone" if zone in configuration.zones else "system sdwan"
        _append_observations(
            observations,
            zone.interfaces,
            target_namespace="interface",
            target_sections=("system interface",),
            source_section=source_section,
            source_entry=zone.name,
            source_directive="interface",
            source_proven=zone.proof_state is ProofState.PROVEN,
            label=f"zone {zone.name} interface",
        )
    for policy in configuration.policies:
        _policy_observations(configuration, observations, policy)
    for service in (*configuration.service_objects, *configuration.service_groups):
        _append_observations(
            observations,
            service.members,
            target_namespace="service",
            target_sections=("firewall service custom", "firewall service group"),
            source_section=_service_section(service),
            source_entry=service.name,
            source_directive="member",
            source_proven=service.proof_state is ProofState.PROVEN,
            label=f"service {service.name} member",
        )
    for group in configuration.profile_groups:
        for reference in group.profile_references:
            profile_type = reference.object_type.casefold()
            target_namespace, target_sections = _profile_namespace(profile_type)
            _append_observations(
                observations,
                (reference,),
                target_namespace=target_namespace,
                target_sections=target_sections,
                source_section="firewall profile-group",
                source_entry=group.name,
                source_directive=_PROFILE_REFERENCE_DIRECTIVES.get(profile_type),
                source_proven=group.proof_state is ProofState.PROVEN,
                label=f"profile group {group.name} profile",
            )
    for group in configuration.vip_groups:
        _append_observations(
            observations,
            group.members,
            target_namespace="vip",
            target_sections=("firewall vip", "firewall vipgrp"),
            source_section="firewall vipgrp",
            source_entry=group.name,
            source_directive="member",
            source_proven=group.proof_state is ProofState.PROVEN,
            label=f"VIP group {group.name} member",
        )
    for item in (*configuration.vips, *configuration.virtual_servers):
        reference_tokens = tuple(
            ObjectReference(object_type="interface", name=name, relation="vip-extintf")
            for name in item.extintf
        )
        _append_observations(
            observations,
            reference_tokens,
            target_namespace="interface",
            target_sections=("system interface",),
            source_section="firewall vip",
            source_entry=item.name,
            source_directive="extintf",
            source_proven=item.proof_state is ProofState.PROVEN,
            label=f"VIP {item.name} external interface",
        )
    for phase2 in configuration.ipsec_phase2:
        if phase2.phase1_name is None:
            continue
        reference = ObjectReference(
            object_type="ipsec-phase1",
            name=phase2.phase1_name,
            relation="phase2-phase1",
        )
        _append_observations(
            observations,
            (reference,),
            target_namespace="ipsec-phase1",
            target_sections=("vpn ipsec phase1-interface",),
            source_section="vpn ipsec phase2-interface",
            source_entry=phase2.name,
            source_directive="phase1name",
            source_proven=phase2.proof_state is ProofState.PROVEN,
            label=f"IPsec phase2 {phase2.name} phase1",
        )
    return tuple(observations)


def _target_sections_are_complete(
    configuration: FortiGateConfiguration,
    observation: _Observation,
) -> bool:
    if observation.target_namespace.startswith("profile:"):
        return _alternative_sections_are_complete(
            configuration,
            observation.target_sections,
        )
    return _section_is_complete(configuration, observation.target_sections)


def _resolve(
    configuration: FortiGateConfiguration,
    indexes: _Indexes,
    observation: _Observation,
) -> tuple[bool, str]:
    if not observation.source_proven or not observation.reference.name:
        return False, "source evidence is incomplete or ambiguous"
    if not _entry_is_certain(
        configuration,
        observation.source_section,
        observation.source_entry,
    ):
        return False, "source evidence is incomplete or ambiguous"
    if not _target_sections_are_complete(configuration, observation):
        return False, "target namespace is absent or incomplete"
    index = indexes.by_namespace.get(observation.target_namespace)
    if index is None:
        return False, "target namespace is not typed"
    key = observation.reference.name.casefold()
    if key in index.collisions:
        return False, "target name collides after case-folding"
    target = index.objects.get(key)
    if target is None:
        return False, "target object is not defined"
    if getattr(target, "proof_state", ProofState.UNKNOWN) is not ProofState.PROVEN:
        return False, "target object evidence is incomplete or ambiguous"
    return True, "resolved"


def _evidence_item(
    configuration: FortiGateConfiguration,
    observation: _Observation,
    *,
    certain: bool,
) -> EvidenceItem:
    certainty = EvidenceCertainty.CERTAIN if certain else EvidenceCertainty.AMBIGUOUS
    if observation.source_directive is not None:
        return evidence_for_directive(
            configuration.document,
            observation.source_section,
            observation.source_directive,
            entry_name=observation.source_entry,
            certainty=certainty,
        )
    return evidence_for_entry(
        configuration.document,
        observation.source_section,
        observation.source_entry or "<section>",
        certainty=certainty,
    )


def _affected(observations: Iterable[_Observation]) -> tuple[AffectedObject, ...]:
    return tuple(
        AffectedObject(
            name=observation.reference.name,
            object_type=observation.reference.object_type,
            reference=observation.reference,
        )
        for observation in observations
    )


def _service_orphans(
    configuration: FortiGateConfiguration,
    indexes: _Indexes,
    observations: tuple[_Observation, ...],
) -> tuple[tuple[str, ...], bool]:
    """Return certain orphaned services and whether service usage is uncertain.

    Service objects have one typed consumer in the modern model: firewall
    policies, with service groups providing transitive references.  Certain
    orphan findings remain usable even when an unrelated edge is ambiguous;
    the caller applies the documented ``FAIL > UNKNOWN`` precedence.
    """

    if not configuration.service_objects and not configuration.service_groups:
        return (), False
    required = (
        "firewall service custom",
        "firewall service group",
        "firewall policy",
    )
    if not _section_is_complete(configuration, required):
        return (), True

    service_index = indexes.by_namespace["service"]
    uncertain = bool(service_index.collisions)
    unproven_service = False
    for target in service_index.objects.values():
        if getattr(target, "proof_state", ProofState.UNKNOWN) is not ProofState.PROVEN:
            uncertain = True
            unproven_service = True

    service_observations = tuple(
        observation
        for observation in observations
        if observation.target_namespace == "service"
    )
    for observation in service_observations:
        resolved, _reason = _resolve(configuration, indexes, observation)
        if not resolved:
            uncertain = True

    reachable: set[str] = set()
    visiting: set[str] = set()
    cycle = False

    def visit(name: str) -> None:
        nonlocal cycle
        key = name.casefold()
        if key in visiting:
            cycle = True
            return
        if key in reachable:
            return
        target = service_index.objects.get(key)
        if target is None or (
            getattr(target, "proof_state", ProofState.UNKNOWN) is not ProofState.PROVEN
        ):
            return
        visiting.add(key)
        reachable.add(key)
        if isinstance(target, ServiceObject):
            for member in target.members:
                visit(member.name)
        visiting.remove(key)

    certain_policy_roots = {
        observation.reference.name.casefold()
        for observation in service_observations
        if observation.source_section == "firewall policy"
        and _resolve(configuration, indexes, observation)[0]
    }
    for key in certain_policy_roots:
        visit(key)
    if cycle:
        uncertain = True

    if unproven_service:
        orphaned = ()
    else:
        orphaned = tuple(
            getattr(service_index.objects[key], "name", key)
            for key in sorted(set(service_index.objects) - reachable)
            if getattr(service_index.objects[key], "proof_state", ProofState.UNKNOWN)
            is ProofState.PROVEN
        )
    return orphaned, uncertain


def _indexes_have_collisions(indexes: _Indexes) -> bool:
    return any(index.collisions for index in indexes.by_namespace.values())


def _nested_realserver_names_collide(configuration: FortiGateConfiguration) -> bool:
    for virtual_server in configuration.virtual_servers:
        seen: set[str] = set()
        for realserver in virtual_server.realservers:
            key = realserver.name.casefold()
            if key in seen:
                return True
            seen.add(key)
    return False


def _typed_objects(configuration: FortiGateConfiguration) -> tuple[object, ...]:
    return (
        *configuration.interfaces,
        *(
            secondary
            for interface in configuration.interfaces
            for secondary in interface.secondary_ips
        ),
        *configuration.zones,
        *configuration.sdwan_zones,
        *configuration.policies,
        *configuration.service_objects,
        *configuration.service_groups,
        *configuration.profile_groups,
        *configuration.security_profiles,
        *configuration.utm_profiles,
        *configuration.vips,
        *configuration.vip_groups,
        *configuration.virtual_servers,
        *(
            realserver
            for virtual_server in configuration.virtual_servers
            for realserver in virtual_server.realservers
        ),
        *configuration.ipsec_phase1,
        *configuration.ipsec_phase2,
    )


def _has_unproven_typed_objects(configuration: FortiGateConfiguration) -> bool:
    return any(
        getattr(item, "proof_state", ProofState.UNKNOWN) is not ProofState.PROVEN
        for item in _typed_objects(configuration)
    )


def check_reference_integrity(configuration: FortiGateConfiguration) -> AuditFinding:
    observations = _observations(configuration)
    indexes = _indexes(configuration)
    results = tuple(
        (observation, *_resolve(configuration, indexes, observation))
        for observation in observations
    )
    unknown_observations = tuple(item[0] for item in results if not item[1])
    orphaned_services, service_usage_uncertain = _service_orphans(
        configuration,
        indexes,
        observations,
    )
    explicitly_empty = _reference_graph_is_explicitly_empty(configuration)
    noncanonical_reference_section = _has_noncanonical_reference_section(configuration)
    unproven_typed_objects = _has_unproven_typed_objects(configuration)
    collision_uncertain = (
        _indexes_have_collisions(indexes)
        or _nested_realserver_names_collide(configuration)
    )
    certain_violation = bool(orphaned_services)
    graph_uncertain = (
        bool(unknown_observations)
        or noncanonical_reference_section
        or service_usage_uncertain
        or unproven_typed_objects
        or collision_uncertain
    )
    if certain_violation:
        status = AuditStatus.FAIL
        applicability = Applicability.APPLICABLE
    elif graph_uncertain:
        status = AuditStatus.UNKNOWN
        applicability = Applicability.UNKNOWN
    elif explicitly_empty:
        status = AuditStatus.NOT_APPLICABLE
        applicability = Applicability.NOT_APPLICABLE
    elif not observations:
        status = AuditStatus.UNKNOWN
        applicability = Applicability.UNKNOWN
    else:
        status = AuditStatus.PASS
        applicability = Applicability.APPLICABLE

    evidence_items = tuple(
        _evidence_item(configuration, observation, certain=resolved)
        for observation, resolved, _reason in results
    )
    if explicitly_empty:
        evidence_items = tuple(
            evidence_for_section(configuration.document, name)
            for name in _REFERENCE_GRAPH_SECTIONS
        )
    if orphaned_services:
        evidence_items += tuple(
            evidence_for_entry(configuration.document, "firewall service custom", name)
            for name in orphaned_services
            if any(item.name == name for item in configuration.service_objects)
        )
        evidence_items += tuple(
            evidence_for_entry(configuration.document, "firewall service group", name)
            for name in orphaned_services
            if any(item.name == name for item in configuration.service_groups)
        )
    if not evidence_items:
        evidence_items = (
            evidence_for_entry(configuration.document, "firewall policy", "<reference-graph>"),
        )
    if status in {
        AuditStatus.PASS,
        AuditStatus.FAIL,
        AuditStatus.NOT_APPLICABLE,
    }:
        evidence_items = tuple(
            item for item in evidence_items if item.certainty is EvidenceCertainty.CERTAIN
        )

    evidence = tuple(
        f"{observation.label}: {observation.reference.name} — {reason}"
        for observation, _resolved, reason in results
    )
    if orphaned_services:
        evidence += tuple(f"service {name}: object is not referenced" for name in orphaned_services)
    if not evidence:
        evidence = (
            "reference graph: explicitly empty namespaces"
            if explicitly_empty
            else "reference graph: no certain typed relation was observed",
        )

    affected = _affected(
        () if status is AuditStatus.FAIL else unknown_observations
    )
    if orphaned_services:
        affected += tuple(
            AffectedObject(
                name=name,
                object_type="service",
                reference=ObjectReference(object_type="service", name=name),
            )
            for name in orphaned_services
        )

    if status is AuditStatus.NOT_APPLICABLE:
        message = "Les namespaces du graphe de références sont explicitement vides."
        risk = RiskAssessment(
            summary=(
                "Aucune référence de configuration n'est applicable dans les "
                "namespaces fournis."
            ),
            impact="Aucune relation de référence n'est disponible à contrôler dans cet export.",
            likelihood="faible",
            treatment="Réévaluer ce contrôle après l'ajout d'objets ou de politiques.",
        )
        recommendation = "Conserver la vacuité explicite ou documenter les nouveaux objets ajoutés."
        remediation = "Aucune remédiation immédiate."
    elif status is AuditStatus.PASS:
        message = "Les références typées observées sont résolues sans collision."
        risk = RiskAssessment(
            summary="Le graphe de références contrôlé est cohérent.",
            impact="Les relations contrôlées restent traçables vers des objets certains.",
            likelihood="faible",
            treatment="Conserver la résolution typée lors des changements de configuration.",
        )
        recommendation = "Conserver des références explicites et des noms uniques."
        remediation = "Aucune remédiation immédiate."
    elif status is AuditStatus.FAIL:
        message = (
            "Des objets de service certains ne sont référencés par aucune politique: "
            + ", ".join(orphaned_services or ())
            + "."
        )
        risk = RiskAssessment(
            summary="Le graphe contient des objets de service orphelins.",
            impact=(
                "Des objets obsolètes ou mal reliés peuvent rester actifs ou masquer une dérive."
            ),
            likelihood="moyenne",
            treatment="Supprimer ou rattacher les objets après validation du changement.",
        )
        recommendation = (
            "Vérifier chaque objet de service et supprimer les objets réellement inutilisés."
        )
        remediation = (
            "Rattacher les objets nécessaires à une politique ou les retirer après approbation."
        )
    else:
        message = "La résolution des références typées ne peut pas être prouvée de façon certaine."
        risk = RiskAssessment(
            summary="Le graphe de références est incomplet ou ambigu.",
            impact=(
                "Une référence absente, mutée, tronquée ou collisionnée peut échapper à l'audit."
            ),
            likelihood="indéterminée",
            treatment=(
                "Fournir les namespaces et preuves structurelles nécessaires puis rejouer l'audit."
            ),
        )
        recommendation = (
            "Fournir une configuration structurellement complète avec des noms uniques."
        )
        remediation = (
            "Corriger les références absentes ou ambiguës, puis fournir un nouvel export complet."
        )

    return AuditFinding(
        control_id=CONTROL_ID,
        title="Intégrité et résolution des références FortiGate",
        status=status,
        category="configuration",
        priority=AuditPriority.P1,
        severity=AuditSeverity.HIGH,
        applicability=applicability,
        evidence=evidence,
        evidence_items=evidence_items,
        affected_objects=affected,
        message=message,
        risk=risk,
        recommendation=recommendation,
        remediation=remediation,
    )

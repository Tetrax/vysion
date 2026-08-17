from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vysion.audit.controls._evidence import (
    directive_for,
    evidence_for_complete_backup,
    evidence_for_directive,
    evidence_for_section,
)
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
    ExternalObservationStatus,
    FortiGateConfiguration,
    ProofState,
    PsirtObservation,
    RiskAssessment,
    StructuralDirective,
    StructuralEntry,
    WanSelectionKind,
)
from vysion.audit.rulesets.external_services import (
    expected_cti_ipv4,
    expected_cti_resources,
    expected_isdb,
)
from vysion.audit.rulesets.external_services import (
    label as external_ruleset_label,
)


def _entry_directive(entry: StructuralEntry, name: str) -> StructuralDirective | None:
    if name in entry.invalidated_keys:
        return None
    directive = directive_for(entry.directives, name)
    return directive if directive is not None and not directive.defaulted else None


def _tokens_for(entry: StructuralEntry, name: str) -> tuple[str, ...] | None:
    directive = _entry_directive(entry, name)
    return directive.tokens if directive is not None else None


def _wan_names(
    configuration: FortiGateConfiguration,
    context: AuditContext | None,
) -> tuple[frozenset[str], bool]:
    section = configuration.document.section("system interface")
    if section is not None and section.certainty is EvidenceCertainty.CERTAIN:
        entries, entry_collisions = unique_named(section.entries)
        certain_names = frozenset(
            entry.name.casefold()
            for entry in entries.values()
            if entry.certainty is EvidenceCertainty.CERTAIN
        )
    else:
        entry_collisions = frozenset()
        certain_names = frozenset()

    interfaces, interface_collisions = unique_named(configuration.interfaces)
    zones, zone_collisions = unique_named(configuration.zones)
    sdwan_zones, sdwan_collisions = unique_named(configuration.sdwan_zones)
    resolved = not (
        entry_collisions
        or interface_collisions
        or zone_collisions
        or sdwan_collisions
    )
    proven_zone_names = frozenset(
        zone.name.casefold()
        for zone in (*zones.values(), *sdwan_zones.values())
        if zone.proof_state is ProofState.PROVEN
    )

    if context is not None and context.wan_selections is not None:
        selected: set[str] = set()
        for selection in context.wan_selections:
            key = selection.name.casefold()
            if selection.kind is WanSelectionKind.INTERFACE:
                if key not in interfaces or key in interface_collisions:
                    resolved = False
                else:
                    selected.add(key)
            elif selection.kind in {WanSelectionKind.ZONE, WanSelectionKind.SDWAN}:
                index = zones if selection.kind is WanSelectionKind.ZONE else sdwan_zones
                collisions = (
                    zone_collisions
                    if selection.kind is WanSelectionKind.ZONE
                    else sdwan_collisions
                )
                zone = index.get(key)
                if zone is None or key in collisions or zone.proof_state is not ProofState.PROVEN:
                    resolved = False
                    continue
                references = tuple(reference.name.casefold() for reference in zone.interfaces)
                unresolved = tuple(
                    name
                    for name in references
                    if name not in interfaces or name in interface_collisions
                )
                if unresolved or not references:
                    resolved = False
                    continue
                selected.add(key)
                selected.update(references)
            else:
                selected.update(
                    interface.name.casefold()
                    for interface in interfaces.values()
                    if interface.role is not None and interface.role.casefold() == "wan"
                )
        return (
            frozenset(selected),
            bool(selected)
            and resolved
            and selected <= certain_names | proven_zone_names,
        )

    if context is not None and context.selected_wans is not None:
        selected_wans = frozenset(name.casefold() for name in context.selected_wans)
        return (
            selected_wans,
            bool(selected_wans)
            and not selected_wans & interface_collisions
            and selected_wans <= certain_names,
        )

    inferred = frozenset(
        interface.name.casefold()
        for interface in interfaces.values()
        if interface.role is not None
        and interface.role.casefold() == "wan"
        and "role" in interface.parsed_keys
        and interface.name.casefold() in certain_names
    )
    return inferred, bool(inferred) and resolved


def _active_policy_direction(
    entry: StructuralEntry,
    wan_names: frozenset[str],
) -> str | None:
    src = _tokens_for(entry, "srcintf")
    dst = _tokens_for(entry, "dstintf")
    action = _tokens_for(entry, "action")
    status = _tokens_for(entry, "status")
    if (
        src is None
        or dst is None
        or action != ("accept",)
        or status != ("enable",)
    ):
        return None
    src_wan = any(value.casefold() in wan_names for value in src)
    dst_wan = any(value.casefold() in wan_names for value in dst)
    if src_wan == dst_wan:
        return None
    return "incoming" if src_wan else "outgoing"


def _policy_has_unproven_active_wan_scope(
    entry: StructuralEntry,
    wan_names: frozenset[str],
) -> bool:
    src = _tokens_for(entry, "srcintf")
    dst = _tokens_for(entry, "dstintf")
    action = _tokens_for(entry, "action")
    status = _tokens_for(entry, "status")
    if src is None or dst is None or status == ("disable",):
        return False
    src_wan = any(value.casefold() in wan_names for value in src)
    dst_wan = any(value.casefold() in wan_names for value in dst)
    return src_wan != dst_wan and action in {None, ("accept",)} and status != ("enable",)


def _policy_has_unknown_interface(
    configuration: FortiGateConfiguration,
    entry: StructuralEntry,
) -> bool:
    section = configuration.document.section("system interface")
    known = {
        entry.name.casefold()
        for entry in section.entries
        if entry.certainty is EvidenceCertainty.CERTAIN
    } if section is not None and section.certainty is EvidenceCertainty.CERTAIN else set()
    known.update(
        zone.name.casefold()
        for zone in configuration.zones
        if zone.proof_state is ProofState.PROVEN
    )
    for key in ("srcintf", "dstintf"):
        values = _tokens_for(entry, key)
        if values is None or any(value.casefold() not in known for value in values):
            return True
    return False


def _isdb_group_index(
    configuration: FortiGateConfiguration,
) -> tuple[dict[str, tuple[str, ...]], bool]:
    section = configuration.document.section("firewall internet-service-group")
    if section is None:
        return {}, False
    groups: dict[str, tuple[str, ...]] = {}
    collisions: set[str] = set()
    ambiguous = section.certainty is not EvidenceCertainty.CERTAIN
    for entry in section.entries:
        members = _tokens_for(entry, "member")
        key = entry.name.casefold()
        if entry.certainty is EvidenceCertainty.CERTAIN and members:
            if key in groups or key in collisions:
                groups.pop(key, None)
                collisions.add(key)
                ambiguous = True
            else:
                groups[key] = members
        else:
            ambiguous = True
    return groups, ambiguous


def _flow_finding(
    *,
    control_id: str,
    title: str,
    status: AuditStatus,
    evidence: tuple[str, ...],
    evidence_items: tuple[EvidenceItem, ...],
    affected_objects: tuple[AffectedObject, ...],
    message: str,
) -> AuditFinding:
    return AuditFinding(
        control_id=control_id,
        title=title,
        status=status,
        category="network",
        priority=AuditPriority.P0,
        severity=AuditSeverity.HIGH,
        applicability=(
            Applicability.APPLICABLE
            if status in {AuditStatus.PASS, AuditStatus.FAIL}
            else Applicability.UNKNOWN
        ),
        evidence=evidence,
        evidence_items=evidence_items,
        affected_objects=affected_objects,
        message=message,
        risk=RiskAssessment(
            summary=(
                "Un flux WAN insuffisamment filtré peut communiquer "
                "avec une source malveillante."
            ),
            impact="Compromission, exfiltration ou communication avec une infrastructure hostile.",
            likelihood="élevée sur un flux exposé",
            treatment="Appliquer toutes les listes attendues sur chaque politique WAN concernée.",
        ),
        recommendation="Maintenir les listes CTI/ISDB versionnées sur chaque flux WAN.",
        remediation="Corriger les politiques indiquées puis relancer l'audit.",
        customer_approval=None,
    )


def check_cti_wan_flows(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    model = configuration.device_identity.model
    policy_section = configuration.document.section("firewall policy")
    resources_section = configuration.document.section("system external-resource")
    wan_names, wan_proven = _wan_names(configuration, context)
    if (
        not model
        or "model" not in configuration.device_identity.parsed_keys
        or policy_section is None
        or resources_section is None
        or not wan_proven
    ):
        return _flow_finding(
            control_id="NET-CTI-WAN-001",
            title="CTI sur les flux WAN",
            status=AuditStatus.UNKNOWN,
            evidence=("Modèle, ressources CTI, politiques ou interfaces WAN non prouvés.",),
            evidence_items=(),
            affected_objects=(),
            message="Le périmètre CTI ne peut pas être évalué avec certitude.",
        )

    expected_resources = frozenset(expected_cti_resources(model))
    entries_by_name: dict[str, list[StructuralEntry]] = {}
    for entry in resources_section.entries:
        entries_by_name.setdefault(entry.name.casefold(), []).append(entry)
    missing_resources: set[str] = set()
    disabled_resources: set[str] = set()
    unknown_resources: set[str] = set()
    for name in expected_resources:
        matches = entries_by_name.get(name.casefold(), [])
        if not matches:
            if resources_section.certainty is EvidenceCertainty.CERTAIN:
                missing_resources.add(name)
            else:
                unknown_resources.add(name)
            continue
        if len(matches) != 1:
            unknown_resources.add(name)
            continue
        entry = matches[0]
        status = _tokens_for(entry, "status")
        if status == ("disable",):
            disabled_resources.add(name)
        elif status != ("enable",) or entry.certainty is not EvidenceCertainty.CERTAIN:
            unknown_resources.add(name)

    ipv4 = frozenset(expected_cti_ipv4(model))
    weak: list[str] = []
    unknown = bool(
        policy_section.certainty is not EvidenceCertainty.CERTAIN
        or resources_section.certainty is not EvidenceCertainty.CERTAIN
        or unknown_resources
    )
    applicable: list[tuple[StructuralEntry, str]] = []
    for entry in policy_section.entries:
        if _policy_has_unknown_interface(configuration, entry):
            unknown = True
            continue
        direction = _active_policy_direction(entry, wan_names)
        if direction is None:
            if (
                entry.certainty is not EvidenceCertainty.CERTAIN
                or _policy_has_unproven_active_wan_scope(entry, wan_names)
            ):
                unknown = True
            continue
        applicable.append((entry, direction))
        address_key = "srcaddr" if direction == "incoming" else "dstaddr"
        addresses = _tokens_for(entry, address_key)
        if addresses is None:
            unknown = True
        elif not ipv4 <= frozenset(addresses):
            weak.append(entry.name)

    ruleset = external_ruleset_label()
    if missing_resources or disabled_resources or weak:
        details = []
        if missing_resources:
            details.append(f"ressources manquantes: {', '.join(sorted(missing_resources))}")
        if disabled_resources:
            details.append(
                f"ressources désactivées: {', '.join(sorted(disabled_resources))}"
            )
        if weak:
            details.append(f"politiques incomplètes: {', '.join(weak)}")
        return _flow_finding(
            control_id="NET-CTI-WAN-001",
            title="CTI sur les flux WAN",
            status=AuditStatus.FAIL,
            evidence=(f"{ruleset}: {'; '.join(details)}.",),
            evidence_items=tuple(
                evidence_for_section(configuration.document, name)
                for name in ("system external-resource", "firewall policy")
            ),
            affected_objects=tuple(
                AffectedObject(object_type="firewall-policy", name=name) for name in weak
            ),
            message="Le contrat CTI explicite est incomplet.",
        )
    if unknown or not applicable:
        return _flow_finding(
            control_id="NET-CTI-WAN-001",
            title="CTI sur les flux WAN",
            status=AuditStatus.UNKNOWN,
            evidence=(f"{ruleset}: aucune couverture WAN complète et certaine.",),
            evidence_items=(),
            affected_objects=(),
            message="La couverture CTI de tous les flux WAN ne peut pas être prouvée.",
        )
    return _flow_finding(
        control_id="NET-CTI-WAN-001",
        title="CTI sur les flux WAN",
        status=AuditStatus.PASS,
        evidence=(f"{ruleset}: ressources et {len(applicable)} politiques WAN complètes.",),
        evidence_items=tuple(
            evidence_for_section(configuration.document, name)
            for name in ("system external-resource", "firewall policy")
        ),
        affected_objects=tuple(
            AffectedObject(object_type="firewall-policy", name=entry.name)
            for entry, _ in applicable
        ),
        message="Les ressources CTI attendues couvrent chaque flux WAN applicable.",
    )


def check_isdb_wan_flows(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    policy_section = configuration.document.section("firewall policy")
    wan_names, wan_proven = _wan_names(configuration, context)
    if policy_section is None or not wan_proven:
        return _flow_finding(
            control_id="NET-ISDB-WAN-001",
            title="Blocage ISDB entrant et sortant",
            status=AuditStatus.UNKNOWN,
            evidence=("Politiques ou interfaces WAN non prouvées.",),
            evidence_items=(),
            affected_objects=(),
            message="Le périmètre ISDB ne peut pas être établi.",
        )
    weak: list[str] = []
    unknown = policy_section.certainty is not EvidenceCertainty.CERTAIN
    groups, groups_ambiguous = _isdb_group_index(configuration)
    unknown = unknown or groups_ambiguous
    applicable: list[tuple[StructuralEntry, str]] = []
    for entry in policy_section.entries:
        if _policy_has_unknown_interface(configuration, entry):
            unknown = True
            continue
        direction = _active_policy_direction(entry, wan_names)
        if direction is None:
            if (
                entry.certainty is not EvidenceCertainty.CERTAIN
                or _policy_has_unproven_active_wan_scope(entry, wan_names)
            ):
                unknown = True
            continue
        applicable.append((entry, direction))
        key = "internet-service-src-name" if direction == "incoming" else "internet-service-name"
        group_key = (
            "internet-service-src-group"
            if direction == "incoming"
            else "internet-service-group"
        )
        direct_names = _tokens_for(entry, key)
        group_names = _tokens_for(entry, group_key)
        resolved_groups: list[str] = []
        unresolved_group = False
        if group_names is not None:
            for group_name in group_names:
                members = groups.get(group_name.casefold())
                if members is None:
                    unknown = True
                    unresolved_group = True
                else:
                    resolved_groups.extend(members)
        if unresolved_group:
            unknown = True
        elif direct_names is None and group_names is None:
            weak.append(entry.name)
        else:
            names = tuple(direct_names or ()) + tuple(resolved_groups)
            expected = frozenset(expected_isdb(direction))
            if not expected <= frozenset(names):
                weak.append(entry.name)
    ruleset = external_ruleset_label()
    if weak:
        return _flow_finding(
            control_id="NET-ISDB-WAN-001",
            title="Blocage ISDB entrant et sortant",
            status=AuditStatus.FAIL,
            evidence=(f"{ruleset}: politiques ISDB incomplètes: {', '.join(weak)}.",),
            evidence_items=(evidence_for_section(configuration.document, "firewall policy"),),
            affected_objects=tuple(
                AffectedObject(object_type="firewall-policy", name=name) for name in weak
            ),
            message="Au moins une politique WAN omet une liste ISDB attendue.",
        )
    if unknown or not applicable:
        return _flow_finding(
            control_id="NET-ISDB-WAN-001",
            title="Blocage ISDB entrant et sortant",
            status=AuditStatus.UNKNOWN,
            evidence=(f"{ruleset}: couverture ISDB incomplète ou ambiguë.",),
            evidence_items=(),
            affected_objects=(),
            message="La couverture ISDB de tous les flux WAN ne peut pas être prouvée.",
        )
    return _flow_finding(
        control_id="NET-ISDB-WAN-001",
        title="Blocage ISDB entrant et sortant",
        status=AuditStatus.PASS,
        evidence=(f"{ruleset}: {len(applicable)} politiques WAN couvertes.",),
        evidence_items=(evidence_for_section(configuration.document, "firewall policy"),),
        affected_objects=tuple(
            AffectedObject(object_type="firewall-policy", name=entry.name)
            for entry, _ in applicable
        ),
        message="Chaque flux WAN applicable porte toutes les listes ISDB attendues.",
    )


def _ldaps_finding(
    configuration: FortiGateConfiguration,
    *,
    status: AuditStatus,
    applicability: Applicability,
    evidence: tuple[str, ...],
    evidence_items: tuple[EvidenceItem, ...],
    affected_objects: tuple[AffectedObject, ...],
    message: str,
) -> AuditFinding:
    return AuditFinding(
        control_id="IAM-LDAPS-001",
        title="Connecteurs LDAP sécurisés par LDAPS avec certificat CA",
        status=status,
        category="administration",
        priority=AuditPriority.P0,
        severity=AuditSeverity.HIGH,
        applicability=applicability,
        evidence=evidence,
        evidence_items=evidence_items,
        affected_objects=affected_objects,
        message=message,
        risk=RiskAssessment(
            summary="Un connecteur LDAP non chiffré ou non authentifié expose les identifiants.",
            impact="Interception des secrets ou usurpation du serveur d'annuaire.",
            likelihood="élevée sur un réseau compromis",
            treatment=(
                "Imposer LDAPS et une autorité de certification explicite "
                "sur chaque connecteur."
            ),
        ),
        recommendation="Configurer chaque connecteur en LDAPS avec un certificat CA approuvé.",
        remediation="Définir `set secure ldaps` et `set ca-cert` puis relancer l'audit.",
        customer_approval=None,
    )


def check_ldaps_connectors(configuration: FortiGateConfiguration) -> AuditFinding:
    section = configuration.document.section("user ldap")
    if section is None:
        if configuration.complete_backup:
            return _ldaps_finding(
                configuration,
                status=AuditStatus.PASS,
                applicability=Applicability.NOT_APPLICABLE,
                evidence=("Backup complet: namespace user ldap absent.",),
                evidence_items=(evidence_for_complete_backup(),),
                affected_objects=(),
                message="Aucun connecteur LDAP n'est configuré dans le backup complet.",
            )
        return _ldaps_finding(
            configuration,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Namespace user ldap absent.",),
            evidence_items=(evidence_for_section(configuration.document, "user ldap"),),
            affected_objects=(),
            message="L'existence et la sécurité des connecteurs LDAP ne peuvent pas être établies.",
        )
    if not section.entries and section.certainty is EvidenceCertainty.CERTAIN:
        return _ldaps_finding(
            configuration,
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=("Namespace user ldap explicitement vide.",),
            evidence_items=(evidence_for_section(configuration.document, "user ldap"),),
            affected_objects=(),
            message="Aucun connecteur LDAP n'est configuré.",
        )

    weak: list[str] = []
    unknown: list[str] = (
        ["namespace user ldap"]
        if section.certainty is not EvidenceCertainty.CERTAIN
        else []
    )
    items: list[EvidenceItem] = []
    for entry in section.entries:
        secure_directive = (
            directive_for(entry.directives, "secure")
            if "secure" not in entry.invalidated_keys
            else None
        )
        ca_directive = (
            directive_for(entry.directives, "ca-cert")
            if "ca-cert" not in entry.invalidated_keys
            else None
        )
        secure = evidence_for_directive(
            configuration.document,
            "user ldap",
            "secure",
            entry_name=entry.name,
            certainty=(
                EvidenceCertainty.CERTAIN
                if entry.certainty is EvidenceCertainty.CERTAIN
                and secure_directive is not None
                else None
            ),
        )
        ca = evidence_for_directive(
            configuration.document,
            "user ldap",
            "ca-cert",
            entry_name=entry.name,
            certainty=(
                EvidenceCertainty.CERTAIN
                if entry.certainty is EvidenceCertainty.CERTAIN and ca_directive is not None
                else None
            ),
        )
        items.extend((secure, ca))
        secure_value = (
            secure_directive.tokens[0]
            if secure_directive is not None and len(secure_directive.tokens) == 1
            else None
        )
        ca_value = (
            ca_directive.tokens[0].strip()
            if ca_directive is not None and len(ca_directive.tokens) == 1
            else None
        )
        if secure_value in {"disable", "none", "plain"}:
            weak.append(entry.name)
        elif (
            entry.certainty is not EvidenceCertainty.CERTAIN
            or secure.certainty is not EvidenceCertainty.CERTAIN
            or ca.certainty is not EvidenceCertainty.CERTAIN
            or secure_value != "ldaps"
            or not ca_value
        ):
            unknown.append(entry.name)

    if weak:
        return _ldaps_finding(
            configuration,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=(f"Connecteurs non LDAPS: {', '.join(weak)}.",),
            evidence_items=tuple(items),
            affected_objects=tuple(
                AffectedObject(object_type="ldap-connector", name=name) for name in weak
            ),
            message="Au moins un connecteur LDAP est explicitement non sécurisé.",
        )
    if unknown:
        return _ldaps_finding(
            configuration,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=(f"Connecteurs sans preuve LDAPS+CA complète: {', '.join(unknown)}.",),
            evidence_items=tuple(items),
            affected_objects=tuple(
                AffectedObject(object_type="ldap-connector", name=name) for name in unknown
            ),
            message="La sécurité de tous les connecteurs LDAP ne peut pas être prouvée.",
        )
    return _ldaps_finding(
        configuration,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=("Chaque connecteur utilise LDAPS avec un certificat CA explicite.",),
        evidence_items=tuple(items),
        affected_objects=tuple(
            AffectedObject(object_type="ldap-connector", name=entry.name)
            for entry in section.entries
        ),
        message="Tous les connecteurs LDAP sont explicitement sécurisés.",
    )


def _psirt_evidence(
    observation: PsirtObservation | None,
    *,
    certainty: EvidenceCertainty,
) -> EvidenceItem:
    if observation is None:
        tokens = ("missing",)
    else:
        tokens = (
            observation.status.value,
            observation.fortios_version,
            observation.source,
            observation.ruleset_id,
            observation.ruleset_version,
        )
        if observation.observed_at is not None:
            tokens += (str(observation.observed_at),)
    return EvidenceItem(
        section="external-observation",
        directive="fortiguard-psirt",
        tokens=tokens,
        certainty=certainty,
    )


def _psirt_finding(
    *,
    status: AuditStatus,
    applicability: Applicability,
    observation: PsirtObservation | None,
    evidence: tuple[str, ...],
    affected_objects: tuple[AffectedObject, ...],
    message: str,
) -> AuditFinding:
    return AuditFinding(
        control_id="EXT-PSIRT-001",
        title="Vulnérabilités FortiOS via FortiGuard PSIRT",
        status=status,
        category="external-services",
        priority=AuditPriority.P0,
        severity=AuditSeverity.CRITICAL,
        applicability=applicability,
        evidence=evidence,
        evidence_items=(
            _psirt_evidence(
                observation,
                certainty=(
                    EvidenceCertainty.CERTAIN
                    if status in {AuditStatus.PASS, AuditStatus.FAIL}
                    else EvidenceCertainty.INVALID
                ),
            ),
        ),
        affected_objects=affected_objects,
        message=message,
        risk=RiskAssessment(
            summary="Une version FortiOS vulnérable expose l'équipement à des failles publiées.",
            impact="Compromission de l'équipement ou contournement de contrôles de sécurité.",
            likelihood="élevée si un avis applicable est confirmé",
            treatment=(
                "Corréler la version exacte avec une réponse PSIRT complète "
                "puis appliquer le correctif."
            ),
        ),
        recommendation="Maintenir FortiOS sur une version sans avis critique ou élevé applicable.",
        remediation="Planifier la montée de version recommandée et relancer la corrélation PSIRT.",
        customer_approval=None,
    )


def _complete_correlated_observation(
    configuration: FortiGateConfiguration,
    observation: PsirtObservation | None,
) -> bool:
    expected = configuration.device_identity.firmware_version
    now = datetime.now(UTC)
    observed_at = observation.observed_at if observation is not None else None
    observation_is_fresh = bool(
        observed_at is not None
        and observed_at.tzinfo is not None
        and observed_at.utcoffset() is not None
        and now - timedelta(hours=24) <= observed_at <= now
    )
    return bool(
        observation is not None
        and expected
        and "firmware-version" in configuration.device_identity.parsed_keys
        and observation.fortios_version == expected
        and observation.complete
        and observation.source == "https://www.fortiguard.com/psirt"
        and observation.ruleset_id == "fortiguard-psirt-critical-high"
        and observation.ruleset_version == "2026-08-13"
        and observation_is_fresh
    )


def check_fortiguard_psirt(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    observation = context.psirt if context is not None else None
    if not _complete_correlated_observation(configuration, observation):
        if observation is not None and observation.status is ExternalObservationStatus.ERROR:
            evidence = (
                "Vérification externe PSIRT impossible : l'adaptateur a rencontré "
                "une erreur d'exécution ; aucune vulnérabilité ne peut être établie.",
            )
        else:
            evidence = (
                "Observation PSIRT absente, incomplète ou non corrélée à la version FortiOS.",
            )
        return _psirt_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            observation=observation,
            evidence=evidence,
            affected_objects=(),
            message=(
                "La vulnérabilité de la version FortiOS ne peut pas être établie "
                "de façon certaine."
            ),
        )

    assert observation is not None
    ruleset = f"{observation.ruleset_id}@{observation.ruleset_version}"
    vulnerabilities = tuple(
        item.strip() for item in observation.vulnerabilities if item.strip()
    )
    if vulnerabilities:
        return _psirt_finding(
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            observation=observation,
            evidence=(f"{ruleset}: {', '.join(vulnerabilities)}",),
            affected_objects=tuple(
                AffectedObject(object_type="psirt-advisory", name=value)
                for value in vulnerabilities
            ),
            message="Une ou plusieurs vulnérabilités FortiGuard s'appliquent à la version FortiOS.",
        )
    if observation.status is ExternalObservationStatus.FAIL:
        return _psirt_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            observation=observation,
            evidence=(f"{ruleset}: statut FAIL sans vulnérabilité explicite.",),
            affected_objects=(),
            message=(
                "Le statut externe ne contient pas la preuve nécessaire "
                "pour conclure à une violation."
            ),
        )

    if observation.status is ExternalObservationStatus.PASS and not observation.vulnerabilities:
        return _psirt_finding(
            status=AuditStatus.PASS,
            applicability=Applicability.APPLICABLE,
            observation=observation,
            evidence=(f"{ruleset}: aucune vulnérabilité critique ou élevée applicable.",),
            affected_objects=(),
            message=(
                "La réponse PSIRT complète ne signale aucune vulnérabilité "
                "dans le périmètre du ruleset."
            ),
        )

    return _psirt_finding(
        status=AuditStatus.UNKNOWN,
        applicability=Applicability.UNKNOWN,
        observation=observation,
        evidence=(f"{ruleset}: résultat externe non conclusif.",),
        affected_objects=(),
        message="La réponse PSIRT ne permet pas de conclure.",
    )

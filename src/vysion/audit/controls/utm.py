from __future__ import annotations

from collections.abc import Iterable

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
    ProofState,
    RiskAssessment,
    StructuralDirective,
    StructuralEntry,
    StructuralSection,
    UtmProfile,
)
from vysion.audit.rulesets.dnsfilter import (
    dnsfilter_ruleset_label,
    required_dnsfilter_blocklists,
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
    recommendation: str,
    remediation: str,
) -> AuditFinding:
    return AuditFinding(
        control_id=control_id,
        title=title,
        status=status,
        category="utm",
        priority=AuditPriority.P0,
        severity=AuditSeverity.HIGH,
        applicability=applicability,
        evidence=tuple(evidence),
        evidence_items=tuple(evidence_items),
        affected_objects=tuple(affected_objects),
        message=message,
        risk=RiskAssessment(
            summary="Un profil UTM incomplet peut laisser passer des contenus malveillants.",
            impact="La politique peut ne pas appliquer les protections attendues.",
            likelihood="élevée",
            treatment="Corriger les profils réellement utilisés et leurs relations.",
        ),
        recommendation=recommendation,
        remediation=remediation,
        customer_approval=None,
    )


def _license_is_proven(context: AuditContext | None) -> bool:
    return bool(
        context is not None
        and context.utm_license is not None
        and context.operator_provenance is not None
        and context.operator_provenance.source.strip()
    )


def _license_evidence(
    context: AuditContext | None,
    *,
    certainty: EvidenceCertainty,
) -> EvidenceItem:
    source = (
        context.operator_provenance.source
        if context is not None and context.operator_provenance is not None
        else ""
    )
    value = (
        str(context.utm_license).casefold()
        if context is not None and context.utm_license is not None
        else "unknown"
    )
    return EvidenceItem(
        section="operator-context",
        directive="utm-license",
        tokens=(value, source) if source else (value,),
        certainty=certainty,
    )


def check_utm_license(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    del configuration
    proven = _license_is_proven(context)
    if not proven:
        return _finding(
            control_id="UTM-LICENSE-001",
            title="Licence UTM déclarée et traçable",
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Licence UTM absente ou sans provenance opérateur.",),
            evidence_items=(
                _license_evidence(context, certainty=EvidenceCertainty.INVALID),
            ),
            affected_objects=(),
            message="La présence de la licence UTM ne peut pas être établie avec provenance.",
            recommendation="Déclarer l'état de licence avec une source opérateur traçable.",
            remediation="Compléter le contexte d'audit puis relancer l'analyse.",
        )

    assert context is not None
    licensed = context.utm_license is True
    return _finding(
        control_id="UTM-LICENSE-001",
        title="Licence UTM déclarée et traçable",
        status=AuditStatus.PASS if licensed else AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        evidence=(
            f"Licence UTM explicitement déclarée {str(licensed).casefold()} "
            f"par {context.operator_provenance.source}."
        ,),
        evidence_items=(
            _license_evidence(context, certainty=EvidenceCertainty.CERTAIN),
        ),
        affected_objects=(),
        message=(
            "La licence UTM est explicitement déclarée active."
            if licensed
            else "La licence UTM est explicitement déclarée inactive."
        ),
        recommendation=(
            "Conserver la provenance de la déclaration de licence."
            if licensed
            else "Activer ou renouveler la licence UTM requise."
        ),
        remediation=(
            "Aucune remédiation immédiate."
            if licensed
            else "Régulariser la licence puis relancer l'audit."
        ),
    )


def check_utm_autoupdate(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    control_id = "UTM-AUTOUPDATE-001"
    title = "Mises à jour AV/IPS automatiques"
    license_proven = _license_is_proven(context)
    if not license_proven or context is None or context.utm_license is not True:
        return _finding(
            control_id=control_id,
            title=title,
            status=(
                AuditStatus.FAIL
                if license_proven and context is not None and context.utm_license is False
                else AuditStatus.UNKNOWN
            ),
            applicability=(
                Applicability.APPLICABLE
                if license_proven and context is not None and context.utm_license is False
                else Applicability.UNKNOWN
            ),
            evidence=("Licence UTM absente, inactive ou sans provenance.",),
            evidence_items=(
                _license_evidence(
                    context,
                    certainty=(
                        EvidenceCertainty.CERTAIN
                        if license_proven
                        else EvidenceCertainty.INVALID
                    ),
                ),
            ),
            affected_objects=(),
            message="La planification FortiGuard ne peut pas être validée sans licence probante.",
            recommendation="Valider la licence UTM avant la planification des mises à jour.",
            remediation="Compléter le contexte de licence puis relancer l'audit.",
        )

    section = configuration.document.section("system autoupdate schedule")
    structurally_valid = bool(
        section is not None
        and section.certainty is EvidenceCertainty.CERTAIN
        and not section.entries
        and not section.children
    )
    status = (
        _certain_directive(section.directives, "status") if section is not None else None
    )
    frequency = (
        _certain_directive(section.directives, "frequency") if section is not None else None
    )
    evidence_items = tuple(
        EvidenceItem(
            section="system autoupdate schedule",
            directive=name,
            tokens=directive.tokens if directive else (),
            line=directive.line if directive else section.line if section else None,
            certainty=(
                EvidenceCertainty.CERTAIN
                if directive is not None
                else EvidenceCertainty.AMBIGUOUS
                if section is not None
                else EvidenceCertainty.INVALID
            ),
        )
        for name, directive in (("status", status), ("frequency", frequency))
    )
    values_complete = bool(
        status is not None
        and frequency is not None
        and len(status.tokens) == 1
        and len(frequency.tokens) == 1
    )
    status_value = status.tokens[0].casefold() if values_complete and status else None
    frequency_value = (
        frequency.tokens[0].casefold() if values_complete and frequency else None
    )
    explicit_violation = bool(
        values_complete
        and (status_value != "enable" or frequency_value != "automatic")
    )
    if explicit_violation:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=(f"status={status_value}; frequency={frequency_value}",),
            evidence_items=evidence_items,
            affected_objects=(),
            message="Les mises à jour AV/IPS ne sont pas configurées en mode automatique actif.",
            recommendation="Maintenir status enable et frequency automatic.",
            remediation="Activer la planification automatique puis relancer l'audit.",
        )
    if not structurally_valid or not values_complete:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Planification absente, incomplète, mutée ou ambiguë.",),
            evidence_items=evidence_items,
            affected_objects=(),
            message="Le statut et la fréquence des mises à jour ne sont pas tous deux certains.",
            recommendation="Déclarer status enable et frequency automatic explicitement.",
            remediation="Corriger la section autoupdate puis relancer l'audit.",
        )

    assert status_value == "enable" and frequency_value == "automatic"
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=(f"status={status_value}; frequency={frequency_value}",),
        evidence_items=evidence_items,
        affected_objects=(),
        message="Les mises à jour AV/IPS sont explicitement automatiques.",
        recommendation="Maintenir status enable et frequency automatic.",
        remediation="Aucune remédiation immédiate.",
    )


def _entry(section: StructuralSection | None, name: str) -> StructuralEntry | None:
    if section is None:
        return None
    matches = tuple(item for item in section.entries if item.name.casefold() == name.casefold())
    return matches[0] if len(matches) == 1 else None


def _child(entry: StructuralEntry, name: str) -> StructuralSection | None:
    matches = tuple(item for item in entry.children if item.name.casefold() == name.casefold())
    return matches[0] if len(matches) == 1 else None


def _certain_directive(
    directives: tuple[StructuralDirective, ...], name: str
) -> StructuralDirective | None:
    matches = tuple(
        item
        for item in directives
        if item.name == name
        and not item.mutation
        and item.certainty is EvidenceCertainty.CERTAIN
    )
    return matches[0] if len(matches) == 1 else None


def _nested_evidence(
    section_name: str,
    profile: StructuralEntry,
    child_name: str,
    directive_name: str,
) -> EvidenceItem:
    child = _child(profile, child_name)
    directive = _certain_directive(child.directives, directive_name) if child else None
    certainty = (
        directive.certainty
        if directive is not None
        and child is not None
        and child.certainty is EvidenceCertainty.CERTAIN
        and profile.certainty is EvidenceCertainty.CERTAIN
        else EvidenceCertainty.AMBIGUOUS
    )
    return EvidenceItem(
        section=f"{section_name}/{child_name}",
        entry=profile.name,
        directive=directive_name,
        tokens=directive.tokens if directive else (),
        line=directive.line if directive else child.line if child else profile.line,
        certainty=certainty,
    )


def _category_evidence(
    profile_entry: StructuralEntry,
    rule_name: str,
    directive_name: str,
) -> EvidenceItem:
    ftgd = _child(profile_entry, "ftgd-wf")
    filters = None if ftgd is None else next(
        (child for child in ftgd.children if child.name.casefold() == "filters"), None
    )
    rule = _entry(filters, rule_name)
    directive = _certain_directive(rule.directives, directive_name) if rule else None
    certainty = (
        EvidenceCertainty.CERTAIN
        if directive is not None
        and rule is not None
        and filters is not None
        and ftgd is not None
        and all(
            item.certainty is EvidenceCertainty.CERTAIN
            for item in (profile_entry, ftgd, filters, rule, directive)
        )
        else EvidenceCertainty.AMBIGUOUS
    )
    return EvidenceItem(
        section="webfilter profile/ftgd-wf/filters",
        entry=f"{profile_entry.name}/{rule_name}",
        directive=directive_name,
        tokens=directive.tokens if directive else (),
        line=directive.line if directive else rule.line if rule else profile_entry.line,
        certainty=certainty,
    )


def _used_profiles(
    configuration: FortiGateConfiguration,
    profile_type: str,
) -> tuple[tuple[str, ...], bool]:
    names: list[str] = []
    unresolved_relation = False
    for policy in configuration.policies:
        if policy.status == "disable" or policy.action != "accept":
            continue
        for reference in policy.direct_profile_references:
            if reference.object_type == profile_type and reference.name not in names:
                names.append(reference.name)
        if policy.profile_group is not None:
            groups = tuple(
                group
                for group in configuration.profile_groups
                if group.name.casefold() == policy.profile_group.name.casefold()
            )
            if len(groups) != 1 or groups[0].proof_state is not ProofState.PROVEN:
                unresolved_relation = True
                continue
            for reference in groups[0].profile_references:
                if reference.object_type == profile_type and reference.name not in names:
                    names.append(reference.name)
    return tuple(names), unresolved_relation


def _webfilter_is_compliant(profile: UtmProfile) -> bool:
    rules: dict[int, tuple[str | None, str]] = {}
    for rule in profile.category_rules:
        for category in rule.categories:
            rules[category] = (rule.action, rule.name)
    return (
        profile.proof_state is ProofState.PROVEN
        and profile.blocklist_enabled is True
        and profile.error_allow is True
        and rules.get(207, ("missing", ""))[0] is None
        and rules.get(209, (None, ""))[0] == "block"
        and rules.get(210, (None, ""))[0] == "block"
    )


def _webfilter_explicitly_weak(profile: UtmProfile) -> bool:
    rules: dict[int, str | None] = {}
    for rule in profile.category_rules:
        if "category" not in rule.parsed_keys:
            continue
        for category in rule.categories:
            rules[category] = rule.action
    return (
        ("blocklist" in profile.parsed_keys and profile.blocklist_enabled is False)
        or ("options" in profile.parsed_keys and profile.error_allow is False)
        or (207 in rules and rules[207] is not None)
        or (209 in rules and rules[209] != "block")
        or (210 in rules and rules[210] != "block")
    )


def check_webfilter_profiles(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    control_id = "UTM-WEBFILTER-001"
    title = "Conformité des profils WebFilter utilisés"
    used, unresolved_relation = _used_profiles(configuration, "webfilter profile")
    section = configuration.document.section("webfilter profile")
    profiles = {profile.name.casefold(): profile for profile in configuration.utm_profiles}

    if not _license_is_proven(context) or context.utm_license is not True:
        license_proven = _license_is_proven(context)
        return _finding(
            control_id=control_id,
            title=title,
            status=(
                AuditStatus.FAIL
                if license_proven and context is not None and context.utm_license is False
                else AuditStatus.UNKNOWN
            ),
            applicability=(
                Applicability.APPLICABLE
                if license_proven and context is not None and context.utm_license is False
                else Applicability.UNKNOWN
            ),
            evidence=("Licence UTM absente, invalide ou non prouvée.",),
            evidence_items=(
                _license_evidence(
                    context,
                    certainty=(
                        EvidenceCertainty.CERTAIN
                        if license_proven
                        else EvidenceCertainty.INVALID
                    ),
                ),
            ),
            affected_objects=(),
            message="La licence UTM ne permet pas de conclure à la conformité WebFilter.",
            recommendation="Valider la licence UTM avant d'évaluer les profils.",
            remediation="Renseigner un contexte opérateur probant puis relancer l'audit.",
        )
    namespace_invalid = (
        section is None
        or bool(section.directives if section else ())
        or bool(section.children if section else ())
    )
    if namespace_invalid or not used:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Namespace ou relations WebFilter incomplets.",),
            evidence_items=(
                EvidenceItem(
                    section="webfilter profile",
                    line=section.line if section else None,
                    certainty=section.certainty if section else EvidenceCertainty.INVALID,
                ),
            ),
            affected_objects=(),
            message="Les profils WebFilter utilisés ne peuvent pas être établis avec certitude.",
            recommendation="Fournir les profils et leurs liaisons aux politiques.",
            remediation="Compléter l'export ou corriger les références orphelines.",
        )

    assert section is not None
    resolved: list[tuple[UtmProfile, StructuralEntry]] = []
    weak: list[tuple[UtmProfile, StructuralEntry]] = []
    unknown: list[tuple[str, UtmProfile | None, StructuralEntry | None]] = []
    if unresolved_relation:
        unknown.append(("profile-group", None, None))
    for name in used:
        profile = profiles.get(name.casefold())
        profile_entry = _entry(section, name)
        if profile is None or profile_entry is None:
            unknown.append((name, profile, profile_entry))
        elif _webfilter_explicitly_weak(profile):
            weak.append((profile, profile_entry))
        elif not _webfilter_is_compliant(profile):
            unknown.append((name, profile, profile_entry))
        else:
            resolved.append((profile, profile_entry))

    if weak:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(
                f"Profil WebFilter {profile.name}: faiblesse explicitement configurée"
                for profile, _ in weak
            ),
            evidence_items=tuple(
                EvidenceItem(
                    section="webfilter profile",
                    entry=profile.name,
                    line=entry.line,
                    certainty=EvidenceCertainty.CERTAIN,
                )
                for profile, entry in weak
            ),
            affected_objects=tuple(
                AffectedObject(name=profile.name, object_type="webfilter-profile")
                for profile, _ in weak
            ),
            message="Au moins un profil WebFilter utilisé est explicitement non conforme.",
            recommendation=(
                "Bloquer 209/210, préserver 207 sans action et activer les options requises."
            ),
            remediation="Modifier les profils affectés puis relancer l'audit.",
        )
    if unknown:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=tuple(
                f"Profil WebFilter {name}: preuve incomplète ou non résolue."
                for name, _, _ in unknown
            ),
            evidence_items=tuple(
                EvidenceItem(
                    section="webfilter profile",
                    entry=name,
                    line=entry.line if entry else section.line,
                    certainty=(
                        EvidenceCertainty.AMBIGUOUS if entry else EvidenceCertainty.INVALID
                    ),
                )
                for name, _, entry in unknown
            ),
            affected_objects=tuple(
                AffectedObject(name=name, object_type="webfilter-profile")
                for name, _, _ in unknown
            ),
            message="La conformité explicite de chaque exigence WebFilter n'est pas prouvée.",
            recommendation="Corriger les champs absents ou les références non résolues.",
            remediation="Compléter le profil puis relancer l'audit.",
        )

    evidence_items: list[EvidenceItem] = []
    for profile, profile_entry in resolved:
        evidence_items.extend(
            [
                _nested_evidence("webfilter profile", profile_entry, "web", "blocklist"),
                _nested_evidence("webfilter profile", profile_entry, "ftgd-wf", "options"),
            ]
        )
        rule_names = {
            category: rule.name
            for rule in profile.category_rules
            for category in rule.categories
            if category in {207, 209, 210}
        }
        for category in (207, 209, 210):
            evidence_items.append(
                _category_evidence(profile_entry, rule_names[category], "category")
            )
            if category != 207:
                evidence_items.append(
                    _category_evidence(profile_entry, rule_names[category], "action")
                )

    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(
            f"Profil WebFilter {profile.name}: exigences explicites conformes"
            for profile, _ in resolved
        ),
        evidence_items=evidence_items,
        affected_objects=tuple(
            AffectedObject(name=profile.name, object_type="webfilter-profile")
            for profile, _ in resolved
        ),
        message="Tous les profils WebFilter utilisés sont explicitement conformes.",
        recommendation="Conserver les catégories et options sous contrôle de changement.",
        remediation="Aucune remédiation immédiate.",
    )


_REQUIRED_AV_LISTS = frozenset(
    {
        "HASH_CTI_SNS_SHA1",
        "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1",
        "HASH_SNS_SHA256",
    }
)


def _profile_entry_evidence(
    section: StructuralSection,
    entry: StructuralEntry,
    directive_names: tuple[str, ...],
) -> tuple[EvidenceItem, ...]:
    items: list[EvidenceItem] = []
    for name in directive_names:
        directive = _certain_directive(entry.directives, name)
        items.append(
            EvidenceItem(
                section=section.name,
                entry=entry.name,
                directive=name,
                tokens=directive.tokens if directive else (),
                line=directive.line if directive else entry.line,
                certainty=(
                    EvidenceCertainty.CERTAIN
                    if directive and entry.certainty is EvidenceCertainty.CERTAIN
                    else EvidenceCertainty.AMBIGUOUS
                ),
            )
        )
    return tuple(items)


def _category_map(profile: UtmProfile) -> dict[int, str | None]:
    return {
        category: rule.action
        for rule in profile.category_rules
        if "category" in rule.parsed_keys
        for category in rule.categories
    }


def _dnsfilter_state(profile: UtmProfile, required: frozenset[str]) -> AuditStatus:
    lists = frozenset(profile.external_ip_blocklists)
    categories = _category_map(profile)
    explicit_actions = {
        category: rule.action
        for rule in profile.category_rules
        if "category" in rule.parsed_keys and "action" in rule.parsed_keys
        for category in rule.categories
    }
    if "external-ip-blocklist" in profile.parsed_keys and not lists >= required:
        return AuditStatus.FAIL
    if "options" in profile.parsed_keys and profile.error_allow is False:
        return AuditStatus.FAIL
    if any(
        category in explicit_actions and explicit_actions[category] != "block"
        for category in (211, 212)
    ):
        return AuditStatus.FAIL
    if (
        profile.proof_state is ProofState.PROVEN
        and lists >= required
        and profile.error_allow is True
        and {211, 212} <= set(categories)
        and all(explicit_actions.get(category) == "block" for category in (211, 212))
    ):
        return AuditStatus.PASS
    return AuditStatus.UNKNOWN


def check_dnsfilter_profiles(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    control_id = "UTM-DNSFILTER-001"
    title = "Conformité des profils DNS Filter utilisés"
    license_proven = _license_is_proven(context)
    if not license_proven or context is None or context.utm_license is not True:
        return _finding(
            control_id=control_id,
            title=title,
            status=(
                AuditStatus.FAIL
                if license_proven and context is not None and context.utm_license is False
                else AuditStatus.UNKNOWN
            ),
            applicability=(
                Applicability.APPLICABLE
                if license_proven and context is not None and context.utm_license is False
                else Applicability.UNKNOWN
            ),
            evidence=("Licence UTM absente, inactive ou sans provenance.",),
            evidence_items=(
                _license_evidence(
                    context,
                    certainty=(
                        EvidenceCertainty.CERTAIN
                        if license_proven
                        else EvidenceCertainty.INVALID
                    ),
                ),
            ),
            affected_objects=(),
            message="La conformité DNS Filter ne peut pas être conclue sans licence probante.",
            recommendation="Valider la licence UTM et sa provenance.",
            remediation="Compléter le contexte puis relancer l'audit.",
        )

    identity = configuration.device_identity
    model_proven = bool(identity.model and "model" in identity.parsed_keys)
    if not model_proven:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Modèle FortiGate absent, invalide ou contradictoire.",),
            evidence_items=(
                EvidenceItem(
                    section="config-version",
                    directive="model",
                    certainty=EvidenceCertainty.INVALID,
                ),
            ),
            affected_objects=(),
            message="Le ruleset DNS Filter dépend d'un modèle FortiGate certain.",
            recommendation="Fournir un en-tête #config-version unique et valide.",
            remediation="Régénérer l'export complet puis relancer l'audit.",
        )

    assert identity.model is not None
    required = required_dnsfilter_blocklists(identity.model)
    ruleset = dnsfilter_ruleset_label()
    used, unresolved_relation = _used_profiles(configuration, "dnsfilter profile")
    section = configuration.document.section("dnsfilter profile")
    if (
        section is None
        or section.certainty is not EvidenceCertainty.CERTAIN
        or section.directives
        or section.children
        or not used
    ):
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=(f"Namespace ou relations DNS Filter incomplets; ruleset {ruleset}.",),
            evidence_items=(
                EvidenceItem(
                    section="dnsfilter profile",
                    line=section.line if section else None,
                    certainty=(
                        section.certainty if section else EvidenceCertainty.INVALID
                    ),
                ),
            ),
            affected_objects=(),
            message="Les profils DNS Filter réellement utilisés ne sont pas tous établis.",
            recommendation="Fournir les profils et leurs relations aux politiques.",
            remediation="Corriger le namespace ou les références puis relancer l'audit.",
        )

    projected = {
        profile.name.casefold(): profile
        for profile in configuration.utm_profiles
        if profile.profile_type == "dnsfilter profile"
    }
    evaluated: list[tuple[str, AuditStatus, UtmProfile | None, StructuralEntry | None]] = []
    for name in used:
        profile = projected.get(name.casefold())
        entry = _entry(section, name)
        evaluated.append(
            (
                name,
                (
                    _dnsfilter_state(profile, required)
                    if profile is not None and entry is not None
                    else AuditStatus.UNKNOWN
                ),
                profile,
                entry,
            )
        )
    if unresolved_relation:
        evaluated.append(("profile-group", AuditStatus.UNKNOWN, None, None))

    failures = tuple(item for item in evaluated if item[1] is AuditStatus.FAIL)
    unknown = tuple(item for item in evaluated if item[1] is AuditStatus.UNKNOWN)
    if failures:
        status = AuditStatus.FAIL
        selected = failures
        applicability = Applicability.APPLICABLE
        message = "Au moins un profil DNS Filter utilisé est explicitement non conforme."
    elif unknown:
        status = AuditStatus.UNKNOWN
        selected = unknown
        applicability = Applicability.UNKNOWN
        message = "La conformité de chaque profil DNS Filter utilisé n'est pas prouvée."
    else:
        status = AuditStatus.PASS
        selected = tuple(evaluated)
        applicability = Applicability.APPLICABLE
        message = "Tous les profils DNS Filter utilisés sont explicitement conformes."

    evidence_items = tuple(
        EvidenceItem(
            section="dnsfilter profile",
            entry=name,
            directive="external-ip-blocklist",
            tokens=profile.external_ip_blocklists if profile else (),
            line=entry.line if entry else section.line,
            certainty=(
                EvidenceCertainty.CERTAIN
                if state is not AuditStatus.UNKNOWN and entry is not None
                else EvidenceCertainty.AMBIGUOUS
            ),
        )
        for name, state, profile, entry in selected
    )
    return _finding(
        control_id=control_id,
        title=title,
        status=status,
        applicability=applicability,
        evidence=tuple(
            f"Profil {name}: {state.value}; modèle {identity.model}; ruleset {ruleset}"
            for name, state, _, _ in selected
        ),
        evidence_items=evidence_items,
        affected_objects=tuple(
            AffectedObject(name=name, object_type="dnsfilter-profile")
            for name, _, _, _ in selected
        ),
        message=message,
        recommendation=(
            "Conserver les listes attendues, error-allow et les catégories 211/212 bloquées."
        ),
        remediation=(
            "Aucune remédiation immédiate."
            if status is AuditStatus.PASS
            else "Corriger les profils affectés puis relancer l'audit."
        ),
    )


def _antivirus_state(profile: UtmProfile) -> AuditStatus:
    lists = frozenset(profile.external_blocklists)
    analytics_known = "analytics-db" in profile.parsed_keys
    list_all_known = "external-blocklist-enable-all" in profile.parsed_keys
    lists_known = "external-blocklist" in profile.parsed_keys
    if analytics_known and profile.analytics_db_enabled is False:
        return AuditStatus.FAIL
    if (
        list_all_known
        and profile.external_blocklist_all is False
        and lists_known
        and not lists >= _REQUIRED_AV_LISTS
    ):
        return AuditStatus.FAIL
    if (
        lists_known
        and not lists >= _REQUIRED_AV_LISTS
        and profile.external_blocklist_all is not True
    ):
        return AuditStatus.FAIL
    if (
        analytics_known
        and profile.analytics_db_enabled is True
        and (
            (list_all_known and profile.external_blocklist_all is True)
            or (lists_known and lists >= _REQUIRED_AV_LISTS)
        )
        and not profile.invalidated_keys
    ):
        return AuditStatus.PASS
    return AuditStatus.UNKNOWN


def _ips_state(profile: UtmProfile) -> AuditStatus:
    malicious_known = "block-malicious-url" in profile.parsed_keys
    botnet_known = "scan-botnet-connections" in profile.parsed_keys
    if malicious_known and profile.block_malicious_url_enabled is False:
        return AuditStatus.FAIL
    if botnet_known and profile.scan_botnet_connections != "block":
        return AuditStatus.FAIL
    if (
        malicious_known
        and profile.block_malicious_url_enabled is True
        and botnet_known
        and profile.scan_botnet_connections == "block"
        and not profile.invalidated_keys
    ):
        return AuditStatus.PASS
    return AuditStatus.UNKNOWN


def _appcontrol_state(profile: UtmProfile) -> AuditStatus:
    categories = _category_map(profile)
    explicit_actions = {
        category: rule.action
        for rule in profile.category_rules
        if "category" in rule.parsed_keys and "action" in rule.parsed_keys
        for category in rule.categories
    }
    required = {2, 6, 7}
    if any(
        category in explicit_actions and explicit_actions[category] != "block"
        for category in required
    ):
        return AuditStatus.FAIL
    if (
        required <= set(categories)
        and required <= set(explicit_actions)
        and all(explicit_actions[category] == "block" for category in required)
        and profile.proof_state is ProofState.PROVEN
    ):
        return AuditStatus.PASS
    return AuditStatus.UNKNOWN


def _check_simple_profiles(
    configuration: FortiGateConfiguration,
    context: AuditContext | None,
    *,
    control_id: str,
    title: str,
    section_name: str,
    profile_type: str,
    object_type: str,
    directive_names: tuple[str, ...],
    state,
) -> AuditFinding:
    license_state = context.utm_license if context else None
    license_proven = _license_is_proven(context)
    if not license_proven or license_state is not True:
        return _finding(
            control_id=control_id,
            title=title,
            status=(
                AuditStatus.FAIL
                if license_proven and license_state is False
                else AuditStatus.UNKNOWN
            ),
            applicability=(
                Applicability.APPLICABLE
                if license_proven and license_state is False
                else Applicability.UNKNOWN
            ),
            evidence=("Licence UTM absente, invalide ou non prouvée.",),
            evidence_items=(
                _license_evidence(
                    context,
                    certainty=(
                        EvidenceCertainty.CERTAIN
                        if license_proven
                        else EvidenceCertainty.INVALID
                    ),
                ),
            ),
            affected_objects=(),
            message=f"La licence UTM ne permet pas de conclure pour {title}.",
            recommendation="Valider la licence UTM et sa provenance.",
            remediation="Compléter le contexte puis relancer l'audit.",
        )

    used, unresolved_relation = _used_profiles(configuration, profile_type)
    section = configuration.document.section(section_name)
    if section is None or not used or section.directives or section.children:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=(f"Namespace ou relations {section_name} incomplets.",),
            evidence_items=(
                EvidenceItem(
                    section=section_name,
                    line=section.line if section else None,
                    certainty=(
                        section.certainty if section else EvidenceCertainty.INVALID
                    ),
                ),
            ),
            affected_objects=(),
            message="Les profils réellement utilisés ne sont pas tous prouvés.",
            recommendation="Fournir le namespace et les relations aux politiques.",
            remediation="Compléter l'export puis relancer l'audit.",
        )

    projected = {
        profile.name.casefold(): profile
        for profile in configuration.utm_profiles
        if profile.profile_type == profile_type
    }
    evaluated: list[tuple[str, AuditStatus, UtmProfile | None, StructuralEntry | None]] = []
    for name in used:
        profile = projected.get(name.casefold())
        entry = _entry(section, name)
        evaluated.append(
            (
                name,
                (
                    state(profile)
                    if profile is not None and entry is not None
                    else AuditStatus.UNKNOWN
                ),
                profile,
                entry,
            )
        )
    if unresolved_relation:
        evaluated.append(("profile-group", AuditStatus.UNKNOWN, None, None))

    failures = tuple(item for item in evaluated if item[1] is AuditStatus.FAIL)
    unknown = tuple(item for item in evaluated if item[1] is AuditStatus.UNKNOWN)
    if failures:
        status = AuditStatus.FAIL
        selected = failures
        applicability = Applicability.APPLICABLE
        message = f"Au moins un profil {section_name} utilisé est explicitement non conforme."
    elif unknown:
        status = AuditStatus.UNKNOWN
        selected = unknown
        applicability = Applicability.UNKNOWN
        message = f"La conformité de tous les profils {section_name} n'est pas prouvée."
    else:
        status = AuditStatus.PASS
        selected = tuple(evaluated)
        applicability = Applicability.APPLICABLE
        message = f"Tous les profils {section_name} utilisés sont explicitement conformes."

    evidence_items: list[EvidenceItem] = []
    for name, _, _, entry in selected:
        if entry is None:
            evidence_items.append(
                EvidenceItem(
                    section=section_name,
                    entry=name,
                    line=section.line,
                    certainty=EvidenceCertainty.INVALID,
                )
            )
        elif directive_names:
            evidence_items.extend(_profile_entry_evidence(section, entry, directive_names))
        else:
            child = _child(entry, "entries")
            evidence_items.append(
                EvidenceItem(
                    section=f"{section_name}/entries",
                    entry=name,
                    line=child.line if child else entry.line,
                    certainty=(
                        child.certainty if child else EvidenceCertainty.INVALID
                    ),
                )
            )

    return _finding(
        control_id=control_id,
        title=title,
        status=status,
        applicability=applicability,
        evidence=tuple(
            f"Profil {section_name} {name}: {item_status.value}"
            for name, item_status, _, _ in selected
        ),
        evidence_items=evidence_items,
        affected_objects=tuple(
            AffectedObject(name=name, object_type=object_type)
            for name, _, _, _ in selected
        ),
        message=message,
        recommendation="Conserver les exigences explicites sous contrôle de changement.",
        remediation=(
            "Corriger les profils non conformes ou compléter les preuves, puis relancer l'audit."
        ),
    )


def check_antivirus_profiles(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    return _check_simple_profiles(
        configuration,
        context,
        control_id="UTM-ANTIVIRUS-001",
        title="Conformité des profils Antivirus utilisés",
        section_name="antivirus profile",
        profile_type="antivirus profile",
        object_type="antivirus-profile",
        directive_names=(
            "analytics-db",
            "external-blocklist-enable-all",
        ),
        state=_antivirus_state,
    )


def check_ips_profiles(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    return _check_simple_profiles(
        configuration,
        context,
        control_id="UTM-IPS-001",
        title="Conformité des profils IPS utilisés",
        section_name="ips sensor",
        profile_type="ips sensor",
        object_type="ips-profile",
        directive_names=("block-malicious-url", "scan-botnet-connections"),
        state=_ips_state,
    )


def check_appcontrol_profiles(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    return _check_simple_profiles(
        configuration,
        context,
        control_id="UTM-APPCONTROL-001",
        title="Conformité des profils Application Control utilisés",
        section_name="application list",
        profile_type="application list",
        object_type="application-control-profile",
        directive_names=(),
        state=_appcontrol_state,
    )

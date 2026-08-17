from __future__ import annotations

from vysion.audit.controls._evidence import (
    evidence_for_directive,
    evidence_for_sdwan_member,
    evidence_for_section,
    section_for,
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
    ProofState,
    RiskAssessment,
    StructuralDirective,
    StructuralEntry,
    StructuralSection,
    WanSelectionKind,
    Zone,
)

_SESSION_HELPER = "system session-helper"
_SYSTEM_GLOBAL = "system global"


def _finding(
    *,
    status: AuditStatus,
    evidence: tuple[str, ...],
    evidence_items: tuple[EvidenceItem, ...],
    message: str,
    recommendation: str,
    remediation: str,
    risk_summary: str,
) -> AuditFinding:
    return AuditFinding(
        control_id="NET-SIP-ALG-001",
        title="Désactivation du SIP ALG",
        status=status,
        category="network",
        priority=AuditPriority.P1,
        severity=AuditSeverity.HIGH,
        applicability=(
            Applicability.APPLICABLE
            if status in {AuditStatus.PASS, AuditStatus.FAIL}
            else Applicability.UNKNOWN
        ),
        evidence=evidence,
        evidence_items=evidence_items,
        message=message,
        risk=RiskAssessment(
            summary=risk_summary,
            impact="Un ALG SIP actif peut modifier ou exposer le traitement des flux VoIP.",
            likelihood="moyenne",
            treatment=recommendation,
        ),
        recommendation=recommendation,
        remediation=remediation,
    )


def _certain_directives(
    section: StructuralSection | None,
    name: str,
) -> tuple[StructuralDirective, ...]:
    if section is None or name in section.invalidated_keys:
        return ()
    return tuple(directive for directive in section.directives if directive.name == name)


def _one_value(
    section: StructuralSection | None,
    name: str,
) -> tuple[str, StructuralDirective] | None:
    directives = _certain_directives(section, name)
    if len(directives) != 1:
        return None
    directive = directives[0]
    if (
        directive.mutation
        or directive.certainty is not EvidenceCertainty.CERTAIN
        or len(directive.tokens) != 1
    ):
        return None
    return directive.tokens[0].casefold(), directive


def _entry_name(entry: StructuralEntry) -> tuple[str, StructuralDirective] | None:
    directives = tuple(directive for directive in entry.directives if directive.name == "name")
    if len(directives) != 1:
        return None
    directive = directives[0]
    if (
        directive.mutation
        or directive.certainty is not EvidenceCertainty.CERTAIN
        or len(directive.tokens) != 1
    ):
        return None
    return directive.tokens[0].casefold(), directive


def _session_sections(configuration: FortiGateConfiguration) -> tuple[StructuralSection, ...]:
    return tuple(
        section
        for section in configuration.document.sections
        if section.name == _SESSION_HELPER
    )


def _session_state(
    configuration: FortiGateConfiguration,
) -> tuple[bool, bool, tuple[EvidenceItem, ...]]:
    """Return (certain, sip_found, evidence) for the helper namespace."""
    sections = _session_sections(configuration)
    if len(sections) != 1:
        return False, False, tuple(
            evidence_for_section(
                configuration.document,
                _SESSION_HELPER,
                certainty=EvidenceCertainty.AMBIGUOUS,
            )
            for _ in sections or (None,)
        )

    section = sections[0]
    if (
        section.certainty is not EvidenceCertainty.CERTAIN
        or section.children
        or section.directives
    ):
        return False, False, (
            evidence_for_section(
                configuration.document,
                _SESSION_HELPER,
                certainty=EvidenceCertainty.AMBIGUOUS,
            ),
        )

    evidence: list[EvidenceItem] = []
    uncertain = False
    sip_found = False
    for entry in section.entries:
        if (
            entry.certainty is not EvidenceCertainty.CERTAIN
            or entry.children
            or len(entry.directives) != 1
        ):
            uncertain = True
            evidence.append(
                evidence_for_section(
                    configuration.document,
                    _SESSION_HELPER,
                    certainty=EvidenceCertainty.AMBIGUOUS,
                )
            )
            continue
        named = _entry_name(entry)
        if named is None:
            uncertain = True
            evidence.append(
                evidence_for_section(
                    configuration.document,
                    _SESSION_HELPER,
                    certainty=EvidenceCertainty.AMBIGUOUS,
                )
            )
            continue
        value, _ = named
        item = evidence_for_directive(
            configuration.document,
            _SESSION_HELPER,
            "name",
            entry_name=entry.name,
        )
        evidence.append(item)
        if value == "sip":
            sip_found = True

    if uncertain:
        return False, sip_found, tuple(evidence) or (
            evidence_for_section(
                configuration.document,
                _SESSION_HELPER,
                certainty=EvidenceCertainty.AMBIGUOUS,
            ),
        )
    return True, sip_found, tuple(evidence) or (
        evidence_for_section(configuration.document, _SESSION_HELPER),
    )


def check_sip_alg(configuration: FortiGateConfiguration) -> AuditFinding:
    global_section = section_for(configuration.document, _SYSTEM_GLOBAL)
    mode = _one_value(global_section, "default-voip-alg-mode")
    global_certain = bool(
        global_section is not None
        and global_section.certainty is EvidenceCertainty.CERTAIN
        and not global_section.entries
        and not global_section.children
    )
    session_certain, sip_found, session_evidence = _session_state(configuration)

    if sip_found:
        sip_evidence = tuple(item for item in session_evidence if item.entry is not None)
        return _finding(
            status=AuditStatus.FAIL,
            evidence=("system session-helper: name sip",),
            evidence_items=sip_evidence,
            message="Un helper SIP est explicitement présent dans system session-helper.",
            recommendation=(
                "Supprimer le helper SIP et conserver le traitement "
                "kernel-helper-based."
            ),
            remediation="Supprimer l’entrée SIP de system session-helper puis relancer l’audit.",
            risk_summary="Le SIP ALG peut intervenir dans le traitement des flux VoIP.",
        )

    if mode is not None and mode[0] != "kernel-helper-based":
        mode_evidence = evidence_for_directive(
            configuration.document,
            _SYSTEM_GLOBAL,
            "default-voip-alg-mode",
        )
        return _finding(
            status=AuditStatus.FAIL,
            evidence=(f"default-voip-alg-mode: {mode[0]}",),
            evidence_items=(mode_evidence,),
            message="Le mode default-voip-alg-mode n’est pas kernel-helper-based.",
            recommendation="Configurer default-voip-alg-mode kernel-helper-based.",
            remediation="Modifier le mode ALG VoIP puis relancer l’audit.",
            risk_summary="Le mode ALG VoIP explicite n’est pas conforme à la règle legacy.",
        )

    if not global_certain or mode is None or not session_certain:
        unknown_evidence = list(session_evidence)
        if global_section is None:
            unknown_evidence.append(evidence_for_section(configuration.document, _SYSTEM_GLOBAL))
        elif mode is None:
            unknown_evidence.append(
                evidence_for_directive(
                    configuration.document,
                    _SYSTEM_GLOBAL,
                    "default-voip-alg-mode",
                )
            )
        return _finding(
            status=AuditStatus.UNKNOWN,
            evidence=("SIP ALG: preuve structurée incomplète ou ambiguë",),
            evidence_items=tuple(unknown_evidence),
            message="L’absence de SIP ALG ne peut pas être établie avec certitude.",
            recommendation="Fournir system global et system session-helper complets.",
            remediation="Compléter les namespaces VoIP puis relancer l’audit.",
            risk_summary="La configuration SIP ALG reste indéterminée.",
        )

    return _finding(
        status=AuditStatus.PASS,
        evidence=(
            "default-voip-alg-mode: kernel-helper-based",
            "system session-helper: aucun helper sip",
        ),
        evidence_items=(
            evidence_for_directive(
                configuration.document,
                _SYSTEM_GLOBAL,
                "default-voip-alg-mode",
            ),
            *session_evidence,
        ),
        message="SIP ALG est désactivé selon les deux preuves de configuration.",
        recommendation="Conserver le mode kernel-helper-based et l’absence de helper SIP.",
        remediation="Aucune remédiation de configuration immédiate.",
        risk_summary="Aucun helper SIP ni mode ALG proxy n’est prouvé.",
    )


def _sdwan_finding(
    *,
    status: AuditStatus,
    applicability: Applicability,
    evidence: tuple[str, ...],
    evidence_items: tuple[EvidenceItem, ...],
    affected: tuple[str, ...],
    message: str,
    recommendation: str,
) -> AuditFinding:
    return AuditFinding(
        control_id="NET-SDWAN-USAGE-001",
        title="Utilisation du SD-WAN pour les WAN sélectionnées",
        status=status,
        category="network",
        priority=AuditPriority.P1,
        severity=AuditSeverity.MEDIUM,
        applicability=applicability,
        evidence=evidence,
        evidence_items=evidence_items,
        affected_objects=tuple(
            AffectedObject(name=name, object_type="interface") for name in affected
        ),
        message=message,
        risk=RiskAssessment(
            summary="Les interfaces WAN sélectionnées peuvent contourner le SD-WAN.",
            impact=(
                "Une sortie directe peut échapper aux politiques et mécanismes "
                "de résilience SD-WAN."
            ),
            likelihood="moyenne",
            treatment=recommendation,
        ),
        recommendation=recommendation,
        remediation=(
            "Ajouter les interfaces WAN manquantes comme membres SD-WAN, puis relancer l’audit."
            if status is AuditStatus.FAIL
            else "Aucune remédiation immédiate."
        ),
    )


def check_sdwan_usage(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    section = section_for(configuration.document, "system sdwan")
    if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
        return _sdwan_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("system sdwan: section absente ou ambiguë",),
            evidence_items=(
                evidence_for_section(
                    configuration.document,
                    "system sdwan",
                    certainty=EvidenceCertainty.AMBIGUOUS,
                ),
            ),
            affected=(),
            message="La configuration SD-WAN ne peut pas être établie avec certitude.",
            recommendation="Fournir le namespace system sdwan complet.",
        )

    zones: dict[str, Zone] = {}
    collisions: set[str] = set()
    uncertainty = bool(section.directives and not section.children)
    for zone in configuration.sdwan_zones:
        key = zone.name.casefold()
        if key in zones or key in collisions:
            zones.pop(key, None)
            collisions.add(key)
            uncertainty = True
            continue
        zones[key] = zone
        if zone.proof_state is not ProofState.PROVEN:
            uncertainty = True

    members: dict[str, tuple[str, str]] = {}
    for zone in zones.values():
        for interface in zone.interfaces:
            key = interface.name.casefold()
            if key in members:
                uncertainty = True
            else:
                members[key] = (zone.name, interface.name)

    if context is None or context.wan_selections is None:
        return _sdwan_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("WAN sélectionnées: contexte opérateur absent",),
            evidence_items=(
                evidence_for_section(
                    configuration.document,
                    "system sdwan",
                    certainty=EvidenceCertainty.AMBIGUOUS,
                ),
            ),
            affected=(),
            message="Les WAN à couvrir par le SD-WAN ne sont pas connues.",
            recommendation="Sélectionner les WAN via le contexte typé.",
        )

    required: dict[str, str] = {}
    for selection in context.wan_selections:
        if selection.kind is WanSelectionKind.SDWAN:
            continue
        selected_interfaces = selection.interfaces or (selection.name,)
        for interface in selected_interfaces:
            required[interface.casefold()] = interface

    missing = tuple(sorted(required[key] for key in required.keys() - members.keys()))
    member_evidence = tuple(
        item
        for key in sorted(required.keys() & members.keys())
        for item in (
            evidence_for_sdwan_member(
                configuration.document,
                members[key][0],
                members[key][1],
            ),
        )
        if item is not None
    )

    if missing:
        return _sdwan_finding(
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(f"interface WAN hors SD-WAN: {name}" for name in missing),
            evidence_items=member_evidence
            or (evidence_for_section(configuration.document, "system sdwan"),),
            affected=missing,
            message="Des interfaces WAN sélectionnées ne sont pas membres du SD-WAN.",
            recommendation="Intégrer chaque WAN sélectionnée au SD-WAN.",
        )

    if uncertainty or (required and len(member_evidence) != len(required)):
        return _sdwan_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Relations SD-WAN ambiguës, dupliquées ou incomplètes",),
            evidence_items=member_evidence
            or (
                evidence_for_section(
                    configuration.document,
                    "system sdwan",
                    certainty=EvidenceCertainty.AMBIGUOUS,
                ),
            ),
            affected=tuple(required.values()),
            message="L’appartenance de toutes les WAN au SD-WAN n’est pas certaine.",
            recommendation="Corriger les collisions ou mutations du namespace SD-WAN.",
        )

    if not members:
        return _sdwan_finding(
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=("system sdwan: aucun membre certain",),
            evidence_items=(evidence_for_section(configuration.document, "system sdwan"),),
            affected=(),
            message="Le SD-WAN n’est pas configuré avec un membre certain.",
            recommendation="Configurer au moins un membre SD-WAN.",
        )

    return _sdwan_finding(
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(
            f"interface WAN membre SD-WAN: {required[key]}" for key in sorted(required)
        )
        or ("Zone SD-WAN sélectionnée et membres certains",),
        evidence_items=member_evidence
        or (evidence_for_section(configuration.document, "system sdwan"),),
        affected=tuple(required.values()),
        message="Toutes les interfaces WAN sélectionnées sont membres du SD-WAN.",
        recommendation="Conserver cette couverture SD-WAN.",
    )

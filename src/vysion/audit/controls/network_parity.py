from __future__ import annotations

import re

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


def _by_sequence_finding(
    *,
    status: AuditStatus,
    applicability: Applicability,
    evidence: tuple[str, ...],
    evidence_items: tuple[EvidenceItem, ...],
    affected: tuple[str, ...],
    message: str,
) -> AuditFinding:
    return AuditFinding(
        control_id="FW-BY-SEQUENCE-USAGE-001",
        title="Usage des politiques par séquence",
        status=status,
        category="firewall",
        priority=AuditPriority.P1,
        severity=AuditSeverity.LOW,
        applicability=applicability,
        evidence=evidence,
        evidence_items=evidence_items,
        affected_objects=tuple(
            AffectedObject(name=name, object_type="firewall-policy") for name in affected
        ),
        message=message,
        risk=RiskAssessment(
            summary="Le mode d’organisation des politiques influence leur lisibilité.",
            impact="Une organisation non identifiée peut compliquer la revue et l’exploitation.",
            likelihood="faible",
            treatment="Documenter et conserver le mode d’organisation retenu.",
        ),
        recommendation="Documenter l’usage par séquence et vérifier l’ordre des politiques.",
        remediation="Aucune remédiation automatique ; valider l’organisation avec l’opérateur.",
    )


def check_by_sequence_usage(configuration: FortiGateConfiguration) -> AuditFinding:
    section = section_for(configuration.document, "firewall policy")
    if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
        return _by_sequence_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("firewall policy: section absente ou ambiguë",),
            evidence_items=(
                evidence_for_section(
                    configuration.document,
                    "firewall policy",
                    certainty=EvidenceCertainty.AMBIGUOUS,
                ),
            ),
            affected=(),
            message="Le mode d’organisation des politiques ne peut pas être déterminé.",
        )
    if not section.entries and not section.directives and not section.children:
        return _by_sequence_finding(
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=("firewall policy: namespace explicitement vide",),
            evidence_items=(evidence_for_section(configuration.document, "firewall policy"),),
            affected=(),
            message="Aucune politique n’est présente ; le contrôle n’est pas applicable.",
        )

    detections: list[tuple[StructuralEntry, str]] = []
    uncertainty = bool(section.directives or section.children)
    for entry in section.entries:
        if entry.certainty is not EvidenceCertainty.CERTAIN or entry.children:
            uncertainty = True
            continue
        directives = {
            name: tuple(directive for directive in entry.directives if directive.name == name)
            for name in ("global-label", "srcintf", "dstintf")
        }
        if entry.invalidated_keys & directives.keys():
            uncertainty = True
        for name, matches in directives.items():
            if not matches:
                if name in {"srcintf", "dstintf"}:
                    uncertainty = True
                continue
            if (
                len(matches) != 1
                or matches[0].mutation
                or matches[0].certainty is not EvidenceCertainty.CERTAIN
                or not matches[0].tokens
            ):
                uncertainty = True
                continue
            tokens = tuple(token.casefold() for token in matches[0].tokens)
            if name == "global-label" or len(tokens) > 1 or "any" in tokens:
                detections.append((entry, name))

    if detections:
        return _by_sequence_finding(
            status=AuditStatus.PASS,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(
                f"policy {entry.name}: critère by-sequence {name}" for entry, name in detections
            ),
            evidence_items=tuple(
                evidence_for_directive(
                    configuration.document,
                    "firewall policy",
                    name,
                    entry_name=entry.name,
                )
                for entry, name in detections
            ),
            affected=tuple(dict.fromkeys(entry.name for entry, _ in detections)),
            message="Un usage par séquence est prouvé par une politique structurée.",
        )
    if uncertainty:
        return _by_sequence_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Critères global-label/srcintf/dstintf incomplets ou ambigus",),
            evidence_items=(
                evidence_for_section(
                    configuration.document,
                    "firewall policy",
                    certainty=EvidenceCertainty.AMBIGUOUS,
                ),
            ),
            affected=tuple(entry.name for entry in section.entries),
            message="L’absence d’usage par séquence ne peut pas être prouvée.",
        )
    return _by_sequence_finding(
        status=AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        evidence=("Aucun global-label, multi-interface ou any certain",),
        evidence_items=(evidence_for_section(configuration.document, "firewall policy"),),
        affected=tuple(entry.name for entry in section.entries),
        message="Aucun critère legacy d’usage par séquence n’est présent.",
    )


def _ssl_ssh_finding(
    *,
    status: AuditStatus,
    applicability: Applicability,
    evidence: tuple[str, ...],
    evidence_items: tuple[EvidenceItem, ...],
    affected: tuple[str, ...],
    message: str,
) -> AuditFinding:
    return AuditFinding(
        control_id="FW-SSL-SSH-PROFILE-001",
        title="Conformité des profils SSL/SSH utilisés",
        status=status,
        category="firewall",
        priority=AuditPriority.P1,
        severity=AuditSeverity.MEDIUM,
        applicability=applicability,
        evidence=evidence,
        evidence_items=evidence_items,
        affected_objects=tuple(
            AffectedObject(name=name, object_type="ssl-ssh-profile") for name in affected
        ),
        message=message,
        risk=RiskAssessment(
            summary=(
                "Un profil SSL/SSH utilisé peut appliquer un comportement de certificat "
                "inattendu."
            ),
            impact=(
                "L’inspection HTTPS peut bloquer ou traiter différemment des certificats "
                "non vérifiables."
            ),
            likelihood="moyenne",
            treatment="Aligner le sous-bloc https sur la règle legacy validée.",
        ),
        recommendation=(
            "Configurer cert-probe-failure allow ou sni-server-cert-check disable "
            "dans chaque profil utilisé."
        ),
        remediation=(
            "Corriger les profils SSL/SSH concernés puis relancer l’audit."
            if status is AuditStatus.FAIL
            else "Aucune remédiation immédiate."
        ),
    )


def _ssl_ssh_version_state(configuration: FortiGateConfiguration) -> bool | None:
    version = configuration.device_identity.firmware_version
    if version is None:
        return None
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major == 7 and ((minor == 2 and patch >= 11) or (minor == 4 and patch >= 5))


def _nested_evidence(
    *,
    entry: StructuralEntry,
    child: StructuralSection | None,
    directive: StructuralDirective | None,
    certainty: EvidenceCertainty,
) -> EvidenceItem:
    return EvidenceItem(
        section="firewall ssl-ssh-profile -> https",
        entry=entry.name,
        directive=directive.name if directive is not None else None,
        tokens=directive.tokens if directive is not None else (),
        line=(
            directive.line
            if directive is not None
            else child.line
            if child is not None
            else entry.line
        ),
        certainty=certainty,
        defaulted=directive.defaulted if directive is not None else False,
    )


def check_ssl_ssh_profiles(configuration: FortiGateConfiguration) -> AuditFinding:
    version_state = _ssl_ssh_version_state(configuration)
    if version_state is False:
        return _ssl_ssh_finding(
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=(
                "FortiOS "
                f"{configuration.device_identity.firmware_version}: contrôle non applicable",
            ),
            evidence_items=(
                EvidenceItem(
                    section="config-version",
                    tokens=(configuration.device_identity.firmware_version or "",),
                    certainty=EvidenceCertainty.CERTAIN,
                ),
            ),
            affected=(),
            message="La version FortiOS est hors du périmètre exact de la règle legacy.",
        )
    if version_state is None:
        return _ssl_ssh_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Version FortiOS absente ou non interprétable",),
            evidence_items=(
                EvidenceItem(
                    section="config-version",
                    certainty=EvidenceCertainty.INVALID,
                ),
            ),
            affected=(),
            message="L’applicabilité du contrôle SSL/SSH ne peut pas être déterminée.",
        )

    policy_section = section_for(configuration.document, "firewall policy")
    used: dict[str, str] = {}
    uncertainty = policy_section is None or (
        policy_section is not None
        and (
            policy_section.certainty is not EvidenceCertainty.CERTAIN
            or bool(policy_section.directives)
            or bool(policy_section.children)
        )
    )
    policy_evidence: list[EvidenceItem] = []
    if policy_section is not None:
        for entry in policy_section.entries:
            matches = tuple(
                directive
                for directive in entry.directives
                if directive.name == "ssl-ssh-profile"
            )
            if entry.certainty is not EvidenceCertainty.CERTAIN or entry.children:
                uncertainty = True
            if not matches:
                continue
            if (
                len(matches) != 1
                or matches[0].mutation
                or matches[0].certainty is not EvidenceCertainty.CERTAIN
                or len(matches[0].tokens) != 1
                or not matches[0].tokens[0]
            ):
                uncertainty = True
                continue
            name = matches[0].tokens[0]
            key = name.casefold()
            if key in used and used[key] != name:
                uncertainty = True
            used[key] = name
            policy_evidence.append(
                evidence_for_directive(
                    configuration.document,
                    "firewall policy",
                    "ssl-ssh-profile",
                    entry_name=entry.name,
                )
            )

    if not used:
        if uncertainty:
            return _ssl_ssh_finding(
                status=AuditStatus.UNKNOWN,
                applicability=Applicability.UNKNOWN,
                evidence=("Usage des profils SSL/SSH absent ou ambigu",),
                evidence_items=(
                    evidence_for_section(
                        configuration.document,
                        "firewall policy",
                        certainty=EvidenceCertainty.AMBIGUOUS,
                    ),
                ),
                affected=(),
                message="L’absence de profil SSL/SSH utilisé n’est pas certaine.",
            )
        return _ssl_ssh_finding(
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=("Aucun ssl-ssh-profile dans les politiques certaines",),
            evidence_items=(evidence_for_section(configuration.document, "firewall policy"),),
            affected=(),
            message="Aucun profil SSL/SSH n’est utilisé par les politiques.",
        )

    profile_section = section_for(configuration.document, "firewall ssl-ssh-profile")
    if profile_section is None or profile_section.certainty is not EvidenceCertainty.CERTAIN:
        return _ssl_ssh_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Définitions firewall ssl-ssh-profile absentes ou ambiguës",),
            evidence_items=tuple(policy_evidence),
            affected=tuple(used.values()),
            message="Les profils utilisés ne peuvent pas être résolus avec certitude.",
        )

    profiles: dict[str, StructuralEntry] = {}
    collisions: set[str] = set()
    for entry in profile_section.entries:
        key = entry.name.casefold()
        if key in profiles or key in collisions:
            profiles.pop(key, None)
            collisions.add(key)
            uncertainty = True
        else:
            profiles[key] = entry

    violations: list[str] = []
    compliant: list[str] = []
    nested_items: list[EvidenceItem] = []
    for key, display_name in used.items():
        entry = profiles.get(key)
        if entry is None or entry.certainty is not EvidenceCertainty.CERTAIN:
            uncertainty = True
            continue
        https_children = tuple(child for child in entry.children if child.name == "https")
        if len(https_children) > 1 or any(child.name != "https" for child in entry.children):
            uncertainty = True
            continue
        if not https_children:
            violations.append(display_name)
            nested_items.append(
                _nested_evidence(
                    entry=entry,
                    child=None,
                    directive=None,
                    certainty=EvidenceCertainty.CERTAIN,
                )
            )
            continue
        child = https_children[0]
        if (
            child.certainty is not EvidenceCertainty.CERTAIN
            or child.entries
            or child.children
        ):
            uncertainty = True
            continue
        directives = {
            name: tuple(item for item in child.directives if item.name == name)
            for name in ("cert-probe-failure", "sni-server-cert-check")
        }
        accepted: StructuralDirective | None = None
        malformed = False
        for name, matches in directives.items():
            if not matches:
                continue
            if (
                len(matches) != 1
                or matches[0].mutation
                or matches[0].certainty is not EvidenceCertainty.CERTAIN
                or len(matches[0].tokens) != 1
            ):
                malformed = True
                continue
            expected = "allow" if name == "cert-probe-failure" else "disable"
            if matches[0].tokens[0] == expected:
                accepted = matches[0]
        if accepted is not None:
            compliant.append(display_name)
            nested_items.append(
                _nested_evidence(
                    entry=entry,
                    child=child,
                    directive=accepted,
                    certainty=EvidenceCertainty.CERTAIN,
                )
            )
        elif malformed:
            uncertainty = True
        else:
            violations.append(display_name)
            nested_items.append(
                _nested_evidence(
                    entry=entry,
                    child=child,
                    directive=None,
                    certainty=EvidenceCertainty.CERTAIN,
                )
            )

    if violations:
        return _ssl_ssh_finding(
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(f"profil SSL/SSH non conforme: {name}" for name in violations),
            evidence_items=tuple(nested_items),
            affected=tuple(violations),
            message="Des profils SSL/SSH utilisés ne satisfont pas la règle legacy.",
        )
    if uncertainty or len(compliant) != len(used):
        return _ssl_ssh_finding(
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Résolution ou structure des profils SSL/SSH incomplète",),
            evidence_items=tuple(policy_evidence + nested_items),
            affected=tuple(used.values()),
            message="La conformité de tous les profils SSL/SSH utilisés n’est pas certaine.",
        )
    return _ssl_ssh_finding(
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(f"profil SSL/SSH conforme: {name}" for name in compliant),
        evidence_items=tuple(nested_items),
        affected=tuple(compliant),
        message="Tous les profils SSL/SSH utilisés satisfont la règle legacy.",
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

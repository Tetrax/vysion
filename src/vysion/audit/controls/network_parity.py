from __future__ import annotations

from vysion.audit.controls._evidence import (
    evidence_for_directive,
    evidence_for_section,
    section_for,
)
from vysion.audit.models import (
    Applicability,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    EvidenceItem,
    FortiGateConfiguration,
    RiskAssessment,
    StructuralDirective,
    StructuralEntry,
    StructuralSection,
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

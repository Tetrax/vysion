"""Fail-closed Milestone 4 VPN controls.

The controls consume only typed VPN projections and structured evidence.  They do
not inspect or parse the uploaded configuration text.
"""

from __future__ import annotations

from collections.abc import Iterable

from vysion.audit.controls._evidence import (
    evidence_for_complete_backup,
    evidence_for_directive,
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
    IpsecPhase1,
    IpsecPhase2,
    ProofState,
    RiskAssessment,
    StructuralSection,
)
from vysion.audit.rulesets.vpn_crypto import (
    VPN_CRYPTO_RULESET_ID,
    VPN_CRYPTO_RULESET_VERSION,
    is_allowed_vpn_proposal,
)

_VPN_METADATA = {
    "category": "vpn",
    "priority": AuditPriority.P0,
    "severity": AuditSeverity.HIGH,
}
_PHASE1_SECTION = "vpn ipsec phase1-interface"
_PHASE2_SECTION = "vpn ipsec phase2-interface"


def _risk(summary: str, impact: str, likelihood: str, treatment: str) -> RiskAssessment:
    return RiskAssessment(
        summary=summary,
        impact=impact,
        likelihood=likelihood,
        treatment=treatment,
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
        **_VPN_METADATA,
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
        customer_approval=None,
    )


def _affected(names: Iterable[str], object_type: str) -> tuple[AffectedObject, ...]:
    return tuple(AffectedObject(name=name, object_type=object_type) for name in names)


def _directive(
    configuration: FortiGateConfiguration,
    section: str,
    name: str,
    *,
    entry: str | None = None,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem:
    return evidence_for_directive(
        configuration.document,
        section,
        name,
        entry_name=entry,
        certainty=certainty,
    )


def _section(
    configuration: FortiGateConfiguration,
    name: str,
    *,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem:
    return evidence_for_section(configuration.document, name, certainty=certainty)


def _ambiguous_or_invalid_section(
    configuration: FortiGateConfiguration,
    name: str,
) -> EvidenceItem:
    return _section(
        configuration,
        name,
        certainty=(
            EvidenceCertainty.AMBIGUOUS
            if configuration.document.section(name) is not None
            else EvidenceCertainty.INVALID
        ),
    )


def _ipsec_sections(
    configuration: FortiGateConfiguration,
):
    phase1 = configuration.document.section(_PHASE1_SECTION)
    phase2 = configuration.document.section(_PHASE2_SECTION)
    if configuration.complete_backup and phase1 is None and phase2 is None:
        return (
            StructuralSection(name=_PHASE1_SECTION, line=1),
            StructuralSection(name=_PHASE2_SECTION, line=1),
        )
    return phase1, phase2


def _ipsec_namespace(
    configuration: FortiGateConfiguration,
) -> tuple[AuditStatus | None, Applicability | None]:
    phase1_section, phase2_section = _ipsec_sections(configuration)
    if phase1_section is None or phase2_section is None:
        return AuditStatus.UNKNOWN, Applicability.UNKNOWN
    sections_certain = (
        phase1_section.certainty is EvidenceCertainty.CERTAIN
        and phase2_section.certainty is EvidenceCertainty.CERTAIN
    )
    if sections_certain and not phase1_section.entries and not phase2_section.entries:
        return AuditStatus.PASS, Applicability.NOT_APPLICABLE

    phases = (*configuration.ipsec_phase1, *configuration.ipsec_phase2)
    all_explicitly_disabled = bool(phases) and all(
        phase.status == "disable"
        and "status" in phase.parsed_keys
        and "status" not in phase.invalidated_keys
        for phase in phases
    )
    if sections_certain and all_explicitly_disabled:
        return AuditStatus.PASS, Applicability.NOT_APPLICABLE
    return None, None


def _ipsec_not_applicable_evidence(
    configuration: FortiGateConfiguration,
) -> tuple[EvidenceItem, ...]:
    if (
        configuration.complete_backup
        and configuration.document.section(_PHASE1_SECTION) is None
        and configuration.document.section(_PHASE2_SECTION) is None
    ):
        return (evidence_for_complete_backup(),)
    phases = (
        (_PHASE1_SECTION, configuration.ipsec_phase1),
        (_PHASE2_SECTION, configuration.ipsec_phase2),
    )
    disabled = tuple(
        _directive(configuration, section, "status", entry=phase.name)
        for section, items in phases
        for phase in items
        if phase.status == "disable" and "status" in phase.parsed_keys
    )
    if disabled:
        return disabled
    return (
        _section(configuration, _PHASE1_SECTION),
        _section(configuration, _PHASE2_SECTION),
    )


def _status_disabled(status: str | None) -> bool:
    return status == "disable"


def _phase1_items(configuration: FortiGateConfiguration) -> tuple[IpsecPhase1, ...]:
    return tuple(item for item in configuration.ipsec_phase1 if not _status_disabled(item.status))


def _phase1_by_name(configuration: FortiGateConfiguration) -> dict[str, IpsecPhase1]:
    return {
        item.name.casefold(): item
        for item in configuration.ipsec_phase1
        if not _status_disabled(item.status)
    }


def _phase2_items(configuration: FortiGateConfiguration) -> tuple[IpsecPhase2, ...]:
    phase1_by_name = _phase1_by_name(configuration)
    return tuple(
        item
        for item in configuration.ipsec_phase2
        if not _status_disabled(item.status)
        and (
            item.phase1_name is None
            or item.phase1_name.casefold()
            not in {
                name for name, phase1 in phase1_by_name.items() if _status_disabled(phase1.status)
            }
        )
    )


def _ssl_risk() -> RiskAssessment:
    return _risk(
        "Le périmètre SSL-VPN peut exposer un accès distant non nécessaire.",
        "Une exposition SSL-VPN non justifiée augmente la surface d'accès distant.",
        "élevée",
        "Désactiver explicitement SSL-VPN lorsqu'il n'est pas requis et documenter tout usage.",
    )


def check_ssl_vpn(configuration: FortiGateConfiguration) -> AuditFinding:
    control_id = "VPN-SSL-001"
    title = "État et usage explicites du SSL-VPN"
    settings = configuration.ssl_vpn_settings
    section = configuration.document.section("vpn ssl settings")
    if settings is None or section is None:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("vpn ssl settings: section absente",),
            evidence_items=(_ambiguous_or_invalid_section(configuration, "vpn ssl settings"),),
            affected_objects=(),
            message="L'état SSL-VPN ne peut pas être établi sans la section explicite.",
            risk=_ssl_risk(),
            recommendation="Fournir vpn ssl settings et un statut explicite.",
            remediation="Compléter l'export puis relancer l'audit.",
        )

    usage_keys = {"source-interface", "source-address", "default-portal"}
    certain_usage = usage_keys & set(settings.parsed_keys)
    status_certain = "status" in settings.parsed_keys
    status = settings.status

    if status_certain and status == "disable":
        if certain_usage:
            return _finding(
                control_id=control_id,
                title=title,
                status=AuditStatus.UNKNOWN,
                applicability=Applicability.UNKNOWN,
                evidence=(
                    "SSL-VPN désactivé mais des directives d'usage explicites subsistent",
                ),
                evidence_items=(
                    _directive(configuration, "vpn ssl settings", "status"),
                    *tuple(
                        _directive(configuration, "vpn ssl settings", key)
                        for key in sorted(certain_usage)
                    ),
                ),
                affected_objects=_affected(("ssl-vpn",), "ssl-vpn"),
                message=(
                    "Le statut disable contredit des directives d'usage conservées; "
                    "l'absence effective d'exposition n'est pas prouvée."
                ),
                risk=_ssl_risk(),
                recommendation=(
                    "Retirer les directives d'usage résiduelles ou fournir une preuve "
                    "autoritaire de l'état effectif."
                ),
                remediation=(
                    "Nettoyer source-interface, source-address et default-portal, "
                    "puis relancer l'audit."
                ),
            )
        if (
            settings.proof_state is not ProofState.PROVEN
            or section.certainty is not EvidenceCertainty.CERTAIN
        ):
            return _finding(
                control_id=control_id,
                title=title,
                status=AuditStatus.UNKNOWN,
                applicability=Applicability.UNKNOWN,
                evidence=(
                    "SSL-VPN désactivé mais la section contient une structure ambiguë",
                ),
                evidence_items=(
                    _directive(
                        configuration,
                        "vpn ssl settings",
                        "status",
                        certainty=EvidenceCertainty.CERTAIN,
                    ),
                    _ambiguous_or_invalid_section(configuration, "vpn ssl settings"),
                ),
                affected_objects=(),
                message=(
                    "Le statut disable est explicite, mais la section ne prouve pas "
                    "une absence complète d'utilisation SSL-VPN."
                ),
                risk=_ssl_risk(),
                recommendation="Corriger la structure ambiguë avant de conclure.",
                remediation="Fournir une section vpn ssl settings complète et certaine.",
            )
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=("vpn ssl settings: status disable explicite",),
            evidence_items=(_directive(configuration, "vpn ssl settings", "status"),),
            affected_objects=(),
            message="Le SSL-VPN est explicitement désactivé et aucune utilisation n'est prouvée.",
            risk=_risk(
                "Le SSL-VPN n'est pas exposé par la configuration prouvée.",
                "La surface d'accès distant SSL est réduite.",
                "faible",
                "Conserver le statut disable si le service reste inutilisé.",
            ),
            recommendation="Conserver set status disable tant que SSL-VPN n'est pas requis.",
            remediation="Aucune remédiation immédiate.",
        )

    if (status_certain and status == "enable") or certain_usage:
        evidence_items = []
        if status_certain and status == "enable":
            evidence_items.append(_directive(configuration, "vpn ssl settings", "status"))
        for key in sorted(certain_usage):
            evidence_items.append(_directive(configuration, "vpn ssl settings", key))
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=("SSL-VPN explicitement activé ou configuré",),
            evidence_items=tuple(evidence_items),
            affected_objects=_affected(("ssl-vpn",), "ssl-vpn"),
            message="Une activation ou une utilisation SSL-VPN est explicitement présente.",
            risk=_ssl_risk(),
            recommendation="Désactiver SSL-VPN si aucun besoin approuvé n'existe.",
            remediation="Appliquer set status disable et retirer les directives d'usage inutiles.",
        )

    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.UNKNOWN,
        applicability=Applicability.UNKNOWN,
        evidence=("vpn ssl settings: statut absent, invalide ou ambigu",),
        evidence_items=(
            _directive(
                configuration,
                "vpn ssl settings",
                "status",
                certainty=EvidenceCertainty.AMBIGUOUS,
            ),
        ),
        affected_objects=(),
        message="Le statut SSL-VPN ne permet pas de conclure sans supposer une valeur FortiOS.",
        risk=_ssl_risk(),
        recommendation="Fournir un statut SSL-VPN explicite et non contradictoire.",
        remediation="Corriger les mutations ou compléter la section puis relancer l'audit.",
    )


def _ike_risk() -> RiskAssessment:
    return _risk(
        "Un tunnel IPsec peut négocier une version IKE insuffisamment robuste.",
        "La négociation cryptographique peut être rétrogradée vers une version ancienne.",
        "élevée",
        "Utiliser explicitement IKEv2 sur chaque phase 1 applicable.",
    )


def check_ikev2(configuration: FortiGateConfiguration) -> AuditFinding:
    control_id = "VPN-IKEV2-001"
    title = "Version IKEv2 explicite des phases 1"
    phase1_section, phase2_section = _ipsec_sections(configuration)
    if phase1_section is None or phase2_section is None:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Les deux namespaces IPsec ne sont pas présents.",),
            evidence_items=tuple(
                _ambiguous_or_invalid_section(configuration, name)
                for name, section in (
                    (_PHASE1_SECTION, phase1_section),
                    (_PHASE2_SECTION, phase2_section),
                )
                if section is None
            ),
            affected_objects=(),
            message="La version IKE ne peut pas être conclue sans les namespaces IPsec complets.",
            risk=_ike_risk(),
            recommendation="Fournir les sections phase1-interface et phase2-interface.",
            remediation="Compléter l'export puis relancer l'audit.",
        )
    namespace_status, namespace_applicability = _ipsec_namespace(configuration)
    if namespace_status is AuditStatus.PASS:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.PASS,
            applicability=namespace_applicability or Applicability.NOT_APPLICABLE,
            evidence=("Aucune phase IPsec applicable dans les namespaces explicitement vides.",),
            evidence_items=_ipsec_not_applicable_evidence(configuration),
            affected_objects=(),
            message="Aucune phase 1 IPsec applicable n'est déclarée.",
            risk=_risk(
                "Aucun tunnel IPsec applicable n'est présent.",
                "La règle de version IKE ne s'applique à aucun tunnel.",
                "faible",
                "Réévaluer après toute création de tunnel.",
            ),
            recommendation="Surveiller les nouvelles phases 1 IPsec.",
            remediation="Aucune remédiation immédiate.",
        )

    items = _phase1_items(configuration)
    failures = [
        item for item in items if "ike-version" in item.parsed_keys and item.ike_version != 2
    ]
    if failures:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(
                f"phase1 {item.name}: ike-version {item.ike_version}" for item in failures
            ),
            evidence_items=tuple(
                _directive(configuration, _PHASE1_SECTION, "ike-version", entry=item.name)
                for item in failures
            ),
            affected_objects=_affected((item.name for item in failures), "ipsec-phase1"),
            message="Au moins une phase 1 utilise explicitement une version IKE différente de 2.",
            risk=_ike_risk(),
            recommendation="Configurer set ike-version 2 sur chaque phase 1 applicable.",
            remediation="Remplacer les versions IKE faibles puis relancer l'audit.",
        )
    unknown = [item for item in items if "ike-version" not in item.parsed_keys]
    if unknown or phase1_section.certainty is not EvidenceCertainty.CERTAIN:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=tuple(
                f"phase1 {item.name}: ike-version absente ou ambiguë" for item in unknown
            )
            or ("phase1-interface: section ambiguë",),
            evidence_items=tuple(
                _directive(
                    configuration,
                    _PHASE1_SECTION,
                    "ike-version",
                    entry=item.name,
                    certainty=EvidenceCertainty.AMBIGUOUS,
                )
                for item in unknown
            )
            or (_section(configuration, _PHASE1_SECTION, certainty=EvidenceCertainty.AMBIGUOUS),),
            affected_objects=_affected((item.name for item in unknown), "ipsec-phase1"),
            message="Une ou plusieurs phases 1 ne portent pas une version IKEv2 certaine.",
            risk=_ike_risk(),
            recommendation="Fournir ike-version 2 explicitement sur toutes les phases 1.",
            remediation="Corriger les valeurs absentes, mutées ou ambiguës.",
        )
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(f"phase1 {item.name}: ike-version 2" for item in items),
        evidence_items=tuple(
            _directive(configuration, _PHASE1_SECTION, "ike-version", entry=item.name)
            for item in items
        ),
        affected_objects=_affected((item.name for item in items), "ipsec-phase1"),
        message="Toutes les phases 1 applicables utilisent explicitement IKEv2.",
        risk=_risk(
            "Les phases 1 applicables sont explicitement en IKEv2.",
            "La négociation n'est pas rétrogradée par ce contrôle.",
            "faible",
            "Maintenir ike-version 2 et contrôler les changements.",
        ),
        recommendation="Conserver ike-version 2 sur toutes les phases 1.",
        remediation="Aucune remédiation immédiate.",
    )


def _dh_risk() -> RiskAssessment:
    return _risk(
        "Un groupe Diffie-Hellman faible peut réduire la résistance d'un tunnel IPsec.",
        "La sécurité des échanges de clés peut être insuffisante.",
        "élevée",
        "Utiliser uniquement des groupes DH explicitement supérieurs ou égaux à 14.",
    )


def _group_evidence(
    configuration: FortiGateConfiguration,
    section: str,
    item: IpsecPhase1 | IpsecPhase2,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem:
    return _directive(configuration, section, "dhgrp", entry=item.name, certainty=certainty)


def check_dh_groups(configuration: FortiGateConfiguration) -> AuditFinding:
    control_id = "VPN-DH-001"
    title = "Groupes DH IPsec supérieurs ou égaux à 14"
    phase1_section, phase2_section = _ipsec_sections(configuration)
    if phase1_section is None or phase2_section is None:
        missing = tuple(
            _ambiguous_or_invalid_section(configuration, name)
            for name, section in (
                (_PHASE1_SECTION, phase1_section),
                (_PHASE2_SECTION, phase2_section),
            )
            if section is None
        )
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("Un seul namespace IPsec est présent; aucun défaut FortiOS n'est supposé.",),
            evidence_items=missing,
            affected_objects=(),
            message="Les groupes DH ne peuvent pas être évalués avec un namespace IPsec absent.",
            risk=_dh_risk(),
            recommendation="Fournir les deux sections IPsec complètes.",
            remediation="Compléter l'export puis relancer l'audit.",
        )
    namespace_status, namespace_applicability = _ipsec_namespace(configuration)
    if namespace_status is AuditStatus.PASS:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.PASS,
            applicability=namespace_applicability or Applicability.NOT_APPLICABLE,
            evidence=("Les deux namespaces IPsec sont explicitement vides.",),
            evidence_items=_ipsec_not_applicable_evidence(configuration),
            affected_objects=(),
            message="Aucun groupe DH IPsec applicable n'est déclaré.",
            risk=_risk(
                "Aucun tunnel IPsec applicable n'est présent.",
                "Le contrôle DH ne s'applique à aucun tunnel.",
                "faible",
                "Réévaluer après toute création de tunnel.",
            ),
            recommendation="Surveiller les nouveaux tunnels IPsec.",
            remediation="Aucune remédiation immédiate.",
        )

    phase1_items = _phase1_items(configuration)
    phase2_items = _phase2_items(configuration)
    failures: list[tuple[str, IpsecPhase1 | IpsecPhase2]] = []
    unknown: list[tuple[str, IpsecPhase1 | IpsecPhase2]] = []
    for item in phase1_items:
        if "dhgrp" not in item.parsed_keys:
            unknown.append((_PHASE1_SECTION, item))
        elif any(group < 14 for group in item.dh_groups):
            failures.append((_PHASE1_SECTION, item))
    for item in phase2_items:
        if "dhgrp" in item.parsed_keys and any(group < 14 for group in item.dh_groups):
            failures.append((_PHASE2_SECTION, item))
        elif "dhgrp" not in item.parsed_keys or item.phase1_reference is None:
            unknown.append((_PHASE2_SECTION, item))

    if failures:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(
                f"{item.name}: groupe DH inférieur à 14 ({', '.join(map(str, item.dh_groups))})"
                for _, item in failures
            ),
            evidence_items=tuple(
                _group_evidence(configuration, section, item) for section, item in failures
            ),
            affected_objects=_affected((item.name for _, item in failures), "ipsec-phase"),
            message="Au moins un groupe DH explicite est inférieur à 14.",
            risk=_dh_risk(),
            recommendation=(
                "Retirer les groupes DH faibles et conserver uniquement "
                "des groupes >= 14."
            ),
            remediation="Modifier dhgrp sur les phases concernées puis relancer l'audit.",
        )
    if (
        unknown
        or phase1_section.certainty is not EvidenceCertainty.CERTAIN
        or phase2_section.certainty is not EvidenceCertainty.CERTAIN
    ):
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=tuple(
                f"{item.name}: groupe DH ou relation phase1 ambiguë" for _, item in unknown
            )
            or ("Les groupes DH ne sont pas tous certains.",),
            evidence_items=tuple(
                _group_evidence(configuration, section, item, EvidenceCertainty.AMBIGUOUS)
                for section, item in unknown
            )
            or (_section(configuration, _PHASE2_SECTION, certainty=EvidenceCertainty.AMBIGUOUS),),
            affected_objects=_affected((item.name for _, item in unknown), "ipsec-phase"),
            message=(
                "Les groupes DH ne sont pas tous présents, entiers et "
                "rattachés avec certitude."
            ),
            risk=_dh_risk(),
            recommendation="Fournir dhgrp explicite et résoudre chaque phase 2 vers une phase 1.",
            remediation="Corriger les mutations, valeurs non entières ou rattachements orphelins.",
        )
    safe = [
        (section, item)
        for section, items in ((_PHASE1_SECTION, phase1_items), (_PHASE2_SECTION, phase2_items))
        for item in items
    ]
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(f"{item.name}: groupes DH >= 14" for _, item in safe),
        evidence_items=tuple(
            _group_evidence(configuration, section, item) for section, item in safe
        ),
        affected_objects=_affected((item.name for _, item in safe), "ipsec-phase"),
        message=(
            "Tous les groupes DH IPsec applicables sont explicitement "
            "supérieurs ou égaux à 14."
        ),
        risk=_risk(
            "Les groupes DH applicables respectent le seuil minimal.",
            "La résistance de l'échange de clés est renforcée.",
            "faible",
            "Maintenir le seuil DH14 et surveiller les changements.",
        ),
        recommendation="Conserver uniquement des groupes DH >= 14.",
        remediation="Aucune remédiation immédiate.",
    )


def _crypto_risk() -> RiskAssessment:
    return _risk(
        "Une proposition IPsec faible ou inconnue peut réduire la confidentialité et l'intégrité.",
        "Un tunnel peut négocier un chiffrement ou une authentification insuffisante.",
        "élevée",
        "Utiliser exclusivement les propositions du ruleset VPN versionné.",
    )


def check_vpn_crypto(configuration: FortiGateConfiguration) -> AuditFinding:
    control_id = "VPN-CRYPTO-001"
    title = "Propositions cryptographiques IPsec approuvées"
    phase1_section, phase2_section = _ipsec_sections(configuration)
    ruleset_label = f"{VPN_CRYPTO_RULESET_ID}@{VPN_CRYPTO_RULESET_VERSION}"
    if phase1_section is None or phase2_section is None:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=(f"ruleset {ruleset_label}; namespace IPsec incomplet",),
            evidence_items=tuple(
                _ambiguous_or_invalid_section(configuration, name)
                for name, section in (
                    (_PHASE1_SECTION, phase1_section),
                    (_PHASE2_SECTION, phase2_section),
                )
                if section is None
            ),
            affected_objects=(),
            message=(
                "Les propositions ne peuvent pas être évaluées avec le "
                f"ruleset {ruleset_label}."
            ),
            risk=_crypto_risk(),
            recommendation="Fournir les deux sections IPsec et leurs propositions explicites.",
            remediation="Compléter l'export puis relancer l'audit.",
        )
    namespace_status, namespace_applicability = _ipsec_namespace(configuration)
    if namespace_status is AuditStatus.PASS:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.PASS,
            applicability=namespace_applicability or Applicability.NOT_APPLICABLE,
            evidence=(f"ruleset {ruleset_label}; namespaces IPsec explicitement vides",),
            evidence_items=_ipsec_not_applicable_evidence(configuration),
            affected_objects=(),
            message=f"Aucune proposition IPsec applicable; ruleset {ruleset_label}.",
            risk=_risk(
                "Aucun tunnel IPsec applicable n'est présent.",
                "Le contrôle cryptographique ne s'applique à aucun tunnel.",
                "faible",
                "Réévaluer après toute création de tunnel.",
            ),
            recommendation="Surveiller les nouvelles propositions IPsec.",
            remediation="Aucune remédiation immédiate.",
        )

    phase1_items = _phase1_items(configuration)
    phase2_items = _phase2_items(configuration)
    failures: list[tuple[str, IpsecPhase1 | IpsecPhase2, str]] = []
    unknown: list[tuple[str, IpsecPhase1 | IpsecPhase2]] = []
    for item in phase1_items:
        if "proposal" not in item.parsed_keys:
            unknown.append((_PHASE1_SECTION, item))
        else:
            failures.extend(
                (_PHASE1_SECTION, item, proposal)
                for proposal in item.proposals
                if not is_allowed_vpn_proposal(proposal)
            )
    for item in phase2_items:
        if "proposal" in item.parsed_keys:
            failures.extend(
                (_PHASE2_SECTION, item, proposal)
                for proposal in item.proposals
                if not is_allowed_vpn_proposal(proposal)
            )
        else:
            unknown.append((_PHASE2_SECTION, item))
        if item.phase1_reference is None and (_PHASE2_SECTION, item) not in unknown:
            unknown.append((_PHASE2_SECTION, item))

    if failures:
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(
                f"{item.name}: proposition explicite non autorisée "
                f"{proposal}; ruleset {ruleset_label}"
                for _, item, proposal in failures
            ),
            evidence_items=tuple(
                _directive(configuration, section, "proposal", entry=item.name)
                for section, item, _ in failures
            ),
            affected_objects=_affected((item.name for _, item, _ in failures), "ipsec-phase"),
            message=f"Au moins une proposition IPsec est faible ou inconnue selon {ruleset_label}.",
            risk=_crypto_risk(),
            recommendation=(
                "Remplacer chaque proposition par un token complet "
                "approuvé par le ruleset."
            ),
            remediation="Modifier proposal sur les phases concernées puis relancer l'audit.",
        )
    if (
        unknown
        or phase1_section.certainty is not EvidenceCertainty.CERTAIN
        or phase2_section.certainty is not EvidenceCertainty.CERTAIN
    ):
        return _finding(
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=tuple(
                f"{item.name}: proposition absente, ambiguë ou phase2 "
                f"orpheline; ruleset {ruleset_label}"
                for _, item in unknown
            )
            or (f"ruleset {ruleset_label}; propositions incomplètes",),
            evidence_items=tuple(
                _directive(
                    configuration,
                    section,
                    "proposal",
                    entry=item.name,
                    certainty=EvidenceCertainty.AMBIGUOUS,
                )
                for section, item in unknown
            )
            or (_section(configuration, _PHASE2_SECTION, certainty=EvidenceCertainty.AMBIGUOUS),),
            affected_objects=_affected((item.name for _, item in unknown), "ipsec-phase"),
            message=(
                "Toutes les propositions IPsec ne sont pas certaines; "
                f"ruleset {ruleset_label}."
            ),
            risk=_crypto_risk(),
            recommendation=(
                "Fournir des propositions complètes et résoudre les "
                "rattachements phase2."
            ),
            remediation="Corriger les mutations, absences et relations orphelines.",
        )
    safe = [
        (section, item)
        for section, items in ((_PHASE1_SECTION, phase1_items), (_PHASE2_SECTION, phase2_items))
        for item in items
    ]
    return _finding(
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(
            f"{item.name}: propositions approuvées; ruleset {ruleset_label}" for _, item in safe
        ),
        evidence_items=tuple(
            _directive(configuration, section, "proposal", entry=item.name)
            for section, item in safe
        ),
        affected_objects=_affected((item.name for _, item in safe), "ipsec-phase"),
        message=f"Toutes les propositions IPsec applicables sont approuvées par {ruleset_label}.",
        risk=_risk(
            "Les propositions IPsec applicables sont couvertes par le ruleset versionné.",
            "La confidentialité et l'intégrité négociées sont bornées par les tokens approuvés.",
            "faible",
            "Conserver les propositions approuvées et la version du ruleset.",
        ),
        recommendation="Conserver uniquement les propositions du ruleset VPN versionné.",
        remediation="Aucune remédiation immédiate.",
    )

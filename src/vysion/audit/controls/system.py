from vysion.audit.controls._evidence import (
    directive_for,
    evidence_for_directive,
    section_for,
)
from vysion.audit.models import (
    Applicability,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    FortiGateConfiguration,
    RiskAssessment,
)


def check_hostname(configuration: FortiGateConfiguration) -> AuditFinding:
    metadata = {
        "control_id": "SYS-HOSTNAME-001",
        "title": "Hostname explicite",
        "category": "system",
        "priority": AuditPriority.P2,
        "severity": AuditSeverity.MEDIUM,
    }
    normalized = configuration.hostname.strip() if configuration.hostname else ""
    explicit_failure = bool(configuration.hostname is not None and not normalized) or (
        normalized.casefold() == "fortigate"
    )
    evidence_item = evidence_for_directive(
        configuration.document,
        "system global",
        "hostname",
    )
    evidence_is_certain = evidence_item.certainty is EvidenceCertainty.CERTAIN
    section = section_for(configuration.document, "system global")
    explicit_failure_is_certain = bool(
        section is not None and directive_for(section.directives, "hostname") is not None
    )
    if explicit_failure and explicit_failure_is_certain:
        return AuditFinding(
            **metadata,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=(f"hostname: {configuration.hostname or 'absent ou générique'}",),
            evidence_items=(evidence_item,),
            message="Le hostname est absent ou générique.",
            risk=RiskAssessment(
                summary="Identification ambiguë de l'équipement.",
                impact="Mauvaise attribution des actions et de la traçabilité.",
                likelihood="moyenne",
                treatment="Corriger le hostname avant exploitation opérationnelle.",
            ),
            recommendation="Définir un hostname unique et documenté.",
            remediation=(
                "Configurer un hostname conforme à la convention client puis relancer l'audit."
            ),
        )
    if "system global" not in configuration.parsed_value_sections or not evidence_is_certain:
        return AuditFinding(
            **metadata,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("hostname: preuve absente ou invalide",),
            evidence_items=(
                evidence_for_directive(configuration.document, "system global", "hostname"),
            ),
            message="Section system global absente, vide ou sans hostname probant.",
            risk=RiskAssessment(
                summary="L'identification de l'équipement ne peut pas être confirmée.",
                impact="Risque d'associer l'audit au mauvais équipement.",
                likelihood="indéterminée",
                treatment="Obtenir une directive hostname structurée et non ambiguë.",
            ),
            recommendation="Fournir une configuration FortiGate complète.",
            remediation="Rejouer l'export de configuration avec system global et hostname valides.",
        )

    valid = bool(normalized and normalized.casefold() != "fortigate")
    if valid:
        return AuditFinding(
            **metadata,
            status=AuditStatus.PASS,
            applicability=Applicability.APPLICABLE,
            evidence=(f"hostname: {configuration.hostname}",),
            evidence_items=(evidence_item,),
            message="Le hostname est explicite.",
            risk=RiskAssessment(
                summary="Risque résiduel faible d'identification ambiguë.",
                impact="Traçabilité réduite si le nom est modifié sans procédure.",
                likelihood="faible",
                treatment="Surveiller la conformité du nom lors des changements.",
            ),
            recommendation="Conserver un hostname unique et documenté.",
            remediation="Aucune remédiation immédiate; vérifier le nom dans la CMDB.",
        )

    return AuditFinding(
        **metadata,
        status=AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        evidence=(f"hostname: {configuration.hostname or 'absent ou générique'}",),
        evidence_items=(evidence_item,),
        message="Le hostname est absent ou générique.",
        risk=RiskAssessment(
            summary="Identification ambiguë de l'équipement.",
            impact="Mauvaise attribution des actions et de la traçabilité.",
            likelihood="moyenne",
            treatment="Corriger le hostname avant exploitation opérationnelle.",
        ),
        recommendation="Définir un hostname unique et documenté.",
        remediation="Configurer un hostname conforme à la convention client puis relancer l'audit.",
    )


def _certain_revision_value(section, name: str) -> str | None:
    if section is None or name in section.invalidated_keys:
        return None
    directives = tuple(
        directive
        for directive in section.directives
        if directive.name == name
        and not directive.mutation
        and directive.certainty is EvidenceCertainty.CERTAIN
    )
    if len(directives) != 1 or len(directives[0].tokens) != 1:
        return None
    return directives[0].tokens[0].casefold()


def check_automatic_revision_backups(configuration: FortiGateConfiguration) -> AuditFinding:
    metadata = {
        "control_id": "SYS-BACKUP-AUTO-001",
        "title": "Sauvegardes automatiques des révisions FortiGate",
        "category": "system",
        "priority": AuditPriority.P1,
        "severity": AuditSeverity.HIGH,
    }
    directive_names = (
        "revision-backup-on-logout",
        "revision-image-auto-backup",
    )
    section = section_for(configuration.document, "system global")
    values = {name: _certain_revision_value(section, name) for name in directive_names}
    complete_section = bool(
        configuration.complete_backup
        and configuration.document.valid
        and configuration.document.certainty is EvidenceCertainty.CERTAIN
        and section is not None
        and section.certainty is EvidenceCertainty.CERTAIN
    )
    disabled = tuple(name for name, value in values.items() if value == "disable")
    evidence_items = tuple(
        evidence_for_directive(
            configuration.document,
            "system global",
            name,
            certainty=(
                EvidenceCertainty.CERTAIN
                if values[name] == "disable"
                else EvidenceCertainty.CERTAIN
                if complete_section and values[name] is None
                else None
            ),
        )
        for name in directive_names
    )
    if disabled:
        disabled_text = ", ".join(
            {
                "revision-backup-on-logout": "sauvegarde à la déconnexion d'un administrateur",
                "revision-image-auto-backup": "sauvegarde automatique avant mise à jour",
            }.get(name, name)
            for name in disabled
        )
        return AuditFinding(
            **metadata,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(f"{name}: disable" for name in disabled),
            evidence_items=evidence_items,
            message=f"Une sauvegarde automatique de révision est désactivée : {disabled_text}.",
            risk=RiskAssessment(
                summary=(
                    "Une partie des révisions FortiGate peut ne pas être "
                    "sauvegardée automatiquement."
                ),
                impact="Une révision peut être perdue après une modification ou une déconnexion.",
                likelihood="élevée",
                treatment="Activer les deux options de sauvegarde automatique.",
            ),
            recommendation="Activer les deux options de sauvegarde automatique de révision.",
            remediation=(
                "Activer les deux options de sauvegarde automatique de révision "
                "puis vérifier leur prise en compte."
            ),
        )
    if complete_section and all(values[name] is None for name in directive_names):
        return AuditFinding(
            **metadata,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(f"{name}: absent" for name in directive_names),
            evidence_items=evidence_items,
            message=(
                "Les deux sauvegardes automatiques de révision sont absentes de la "
                "configuration."
            ),
            risk=RiskAssessment(
                summary=(
                    "Une partie des révisions FortiGate peut ne pas être "
                    "sauvegardée automatiquement."
                ),
                impact="Une révision peut être perdue après une modification ou une déconnexion.",
                likelihood="élevée",
                treatment="Activer les deux options de sauvegarde automatique.",
            ),
            recommendation="Activer les deux options de sauvegarde automatique de révision.",
            remediation=(
                "Activer les deux options de sauvegarde automatique de révision "
                "puis vérifier leur prise en compte."
            ),
        )
    enabled = (
        configuration.document.valid
        and configuration.document.certainty is EvidenceCertainty.CERTAIN
        and section is not None
        and section.certainty is EvidenceCertainty.CERTAIN
        and all(values[name] == "enable" for name in directive_names)
    )
    if enabled:
        return AuditFinding(
            **metadata,
            status=AuditStatus.PASS,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(f"{name}: enable" for name in directive_names),
            evidence_items=evidence_items,
            message="Les deux sauvegardes automatiques de révision sont activées.",
            risk=RiskAssessment(
                summary="Les révisions peuvent être sauvegardées automatiquement.",
                impact="Risque résiduel réduit de perte de révision locale.",
                likelihood="faible",
                treatment="Conserver les deux options activées.",
            ),
            recommendation="Conserver les deux options de sauvegarde automatique activées.",
            remediation="Aucune remédiation immédiate; vérifier ce réglage lors des changements.",
        )
    return AuditFinding(
        **metadata,
        status=AuditStatus.UNKNOWN,
        applicability=Applicability.UNKNOWN,
        evidence=("Sauvegardes automatiques: preuve structurelle incomplète.",),
        evidence_items=evidence_items,
        message=(
            "Les deux options de sauvegarde automatique de révision n'ont pas pu "
            "être établies."
        ),
        risk=RiskAssessment(
            summary="La sauvegarde automatique des révisions ne peut pas être confirmée.",
            impact="Une révision peut ne pas être récupérable après une modification.",
            likelihood="indéterminée",
            treatment="Obtenir les deux options de sauvegarde avec une valeur établie.",
        ),
        recommendation="Fournir une configuration complète avec les deux options de sauvegarde.",
        remediation="Vérifier les deux options de sauvegarde puis relancer l'audit.",
    )

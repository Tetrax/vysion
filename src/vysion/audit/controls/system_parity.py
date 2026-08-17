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
    FortiGateConfiguration,
    RiskAssessment,
    StructuralDirective,
    StructuralSection,
)


def _directives(section: StructuralSection | None, name: str) -> tuple[StructuralDirective, ...]:
    if section is None or name in section.invalidated_keys:
        return ()
    return tuple(directive for directive in section.directives if directive.name == name)


def _certain_value(
    section: StructuralSection | None,
    name: str,
) -> tuple[str, StructuralDirective] | None:
    directives = _directives(section, name)
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


def _finding(
    *,
    control_id: str = "SYS-AUTO-INSTALL-USB-001",
    title: str = "Auto-installation USB FortiGate",
    status: AuditStatus,
    evidence: tuple[str, ...],
    evidence_items,
    message: str,
    recommendation: str,
    remediation: str = (
        "Configurer auto-install-config disable et auto-install-image disable, "
        "puis relancer l’audit."
    ),
    risk_summary: str = (
        "Une auto-installation USB active peut modifier la configuration ou "
        "l’image FortiGate."
    ),
) -> AuditFinding:
    return AuditFinding(
        control_id=control_id,
        title=title,
        status=status,
        category="system",
        priority=AuditPriority.P1,
        severity=AuditSeverity.HIGH,
        applicability=(
            Applicability.APPLICABLE
            if status in {AuditStatus.PASS, AuditStatus.FAIL}
            else Applicability.UNKNOWN
        ),
        evidence=evidence,
        evidence_items=tuple(evidence_items),
        message=message,
        risk=RiskAssessment(
            summary=risk_summary,
            impact=(
                "Une configuration d’administration ou de démarrage insuffisamment "
                "maîtrisée peut augmenter l’exposition opérationnelle."
            ),
            likelihood="moyenne",
            treatment=recommendation,
        ),
        recommendation=recommendation,
        remediation=remediation,
    )


def _section_is_certain_leaf(section: StructuralSection | None) -> bool:
    return bool(
        section is not None
        and section.certainty is EvidenceCertainty.CERTAIN
        and not section.entries
        and not section.children
    )


def check_auto_install_usb(configuration: FortiGateConfiguration) -> AuditFinding:
    section_name = "system auto-install"
    section = section_for(configuration.document, section_name)
    directive_names = ("auto-install-config", "auto-install-image")
    section_evidence = evidence_for_section(configuration.document, section_name)

    if section is None:
        return _finding(
            status=AuditStatus.UNKNOWN,
            evidence=("system auto-install: namespace absent",),
            evidence_items=(section_evidence,),
            message="La section system auto-install est absente; son état ne peut pas être prouvé.",
            recommendation="Fournir une section system auto-install complète.",
        )

    if not _section_is_certain_leaf(section):
        return _finding(
            status=AuditStatus.UNKNOWN,
            evidence=("system auto-install: structure incomplète ou ambiguë",),
            evidence_items=tuple(
                evidence_for_directive(configuration.document, section_name, name)
                for name in directive_names
            ),
            message="La section system auto-install contient une structure non prouvée.",
            recommendation=(
                "Fournir uniquement les directives system auto-install canoniques "
                "et complètes."
            ),
        )

    values = {name: _certain_value(section, name) for name in directive_names}
    certain_values = {name: value[0] for name, value in values.items() if value is not None}
    enabled = tuple(name for name, value in certain_values.items() if value == "enable")
    if enabled:
        return _finding(
            status=AuditStatus.FAIL,
            evidence=tuple(f"{name}: enable" for name in enabled),
            evidence_items=tuple(
                evidence_for_directive(configuration.document, section_name, name)
                for name in enabled
            ),
            message="Une option d’auto-installation USB est explicitement activée.",
            recommendation="Désactiver toutes les options auto-install USB.",
        )

    unknown_values = tuple(
        name
        for name, value in values.items()
        if value is None or value[0] not in {"enable", "disable"}
    )
    if unknown_values:
        return _finding(
            status=AuditStatus.UNKNOWN,
            evidence=tuple(
                f"{name}: preuve absente ou valeur non supportée" for name in unknown_values
            ),
            evidence_items=tuple(
                evidence_for_directive(configuration.document, section_name, name)
                for name in directive_names
            ),
            message="Les deux directives auto-install USB ne sont pas prouvées.",
            recommendation=(
                "Fournir les deux directives avec une valeur enable ou disable "
                "certaine."
            ),
        )

    return _finding(
        status=AuditStatus.PASS,
        evidence=tuple(f"{name}: disable" for name in directive_names),
        evidence_items=tuple(
            evidence_for_directive(configuration.document, section_name, name)
            for name in directive_names
        ),
        message="L’auto-installation USB de la configuration et de l’image est désactivée.",
        recommendation="Conserver les deux mécanismes auto-install explicitement désactivés.",
    )


def check_fortimanager_sync(configuration: FortiGateConfiguration) -> AuditFinding:
    section_name = "system central-management"
    section = section_for(configuration.document, section_name)
    if section is None:
        return _finding(
            control_id="SYS-FORTIMANAGER-SYNC-001",
            title="Synchronisation FortiManager",
            status=AuditStatus.UNKNOWN,
            evidence=("system central-management: namespace absent",),
            evidence_items=(evidence_for_section(configuration.document, section_name),),
            message=(
                "La configuration central-management est absente; la synchronisation "
                "ne peut pas être prouvée."
            ),
            recommendation="Fournir la section system central-management complète.",
            remediation=(
                "Configurer central-management selon la politique d’administration, "
                "puis relancer l’audit."
            ),
            risk_summary="L’état de rattachement à un FortiManager ne peut pas être confirmé.",
        )
    if not _section_is_certain_leaf(section):
        return _finding(
            control_id="SYS-FORTIMANAGER-SYNC-001",
            title="Synchronisation FortiManager",
            status=AuditStatus.UNKNOWN,
            evidence=("system central-management: structure incomplète ou ambiguë",),
            evidence_items=(
                evidence_for_directive(configuration.document, section_name, "type"),
                evidence_for_directive(configuration.document, section_name, "fmg"),
            ),
            message="La section central-management contient une structure non prouvée.",
            recommendation=(
                "Fournir uniquement les directives central-management canoniques "
                "et complètes."
            ),
            remediation="Corriger ou compléter central-management avant de relancer l’audit.",
            risk_summary="Le rattachement d’administration centrale ne peut pas être déterminé.",
        )

    type_value = _certain_value(section, "type")
    if type_value is None:
        return _finding(
            control_id="SYS-FORTIMANAGER-SYNC-001",
            title="Synchronisation FortiManager",
            status=AuditStatus.UNKNOWN,
            evidence=("system central-management: type absent ou ambigu",),
            evidence_items=(evidence_for_directive(configuration.document, section_name, "type"),),
            message="Le type de central-management n’est pas prouvé.",
            recommendation="Fournir une directive type certaine.",
            remediation=(
                "Configurer type fortimanager, fortiguard ou une valeur explicitement "
                "supportée."
            ),
            risk_summary="Le mode d’administration centrale reste indéterminé.",
        )

    mode, _ = type_value
    if mode == "fortimanager":
        fmg_value = _certain_value(section, "fmg")
        if fmg_value is None or not fmg_value[0].strip():
            return _finding(
                control_id="SYS-FORTIMANAGER-SYNC-001",
                title="Synchronisation FortiManager",
                status=AuditStatus.UNKNOWN,
                evidence=("type: fortimanager", "fmg: preuve absente ou ambiguë"),
                evidence_items=(
                    evidence_for_directive(configuration.document, section_name, "type"),
                    evidence_for_directive(configuration.document, section_name, "fmg"),
                ),
                message="Le mode FortiManager est indiqué mais le serveur n’est pas prouvé.",
                recommendation="Fournir une directive fmg unique et certaine.",
                remediation="Configurer le serveur FortiManager puis relancer l’audit.",
                risk_summary="Le rattachement FortiManager est incomplet.",
            )
        return _finding(
            control_id="SYS-FORTIMANAGER-SYNC-001",
            title="Synchronisation FortiManager",
            status=AuditStatus.PASS,
            evidence=("type: fortimanager", f"fmg: {fmg_value[0]}"),
            evidence_items=(
                evidence_for_directive(configuration.document, section_name, "type"),
                evidence_for_directive(configuration.document, section_name, "fmg"),
            ),
            message="Le FortiGate est configuré pour un FortiManager explicite.",
            recommendation="Vérifier périodiquement l’état runtime de la synchronisation.",
            remediation="Aucune remédiation de configuration immédiate.",
            risk_summary="Le rattachement FortiManager est explicitement configuré.",
        )

    if mode == "fortiguard":
        return _finding(
            control_id="SYS-FORTIMANAGER-SYNC-001",
            title="Synchronisation FortiManager",
            status=AuditStatus.PASS,
            evidence=("type: fortiguard",),
            evidence_items=(evidence_for_directive(configuration.document, section_name, "type"),),
            message=(
                "Le FortiGate est configuré pour FortiGuard/FortiCloud plutôt que "
                "pour un FortiManager."
            ),
            recommendation="Vérifier que ce mode correspond au modèle d’administration retenu.",
            remediation="Aucune remédiation de configuration immédiate.",
            risk_summary=(
                "Un mode central explicite est configuré, mais il ne s’agit pas "
                "d’un FortiManager."
            ),
        )

    if mode in {"none", "disable", "local"}:
        return _finding(
            control_id="SYS-FORTIMANAGER-SYNC-001",
            title="Synchronisation FortiManager",
            status=AuditStatus.FAIL,
            evidence=(f"type: {mode}",),
            evidence_items=(evidence_for_directive(configuration.document, section_name, "type"),),
            message="Aucun rattachement FortiManager ou FortiCloud n’est configuré.",
            recommendation="Configurer le mode central-management approuvé par la politique.",
            remediation=(
                "Configurer type fortimanager avec un serveur fmg explicite, puis "
                "relancer l’audit."
            ),
            risk_summary="L’équipement n’est pas rattaché à une administration centrale prouvée.",
        )

    return _finding(
        control_id="SYS-FORTIMANAGER-SYNC-001",
        title="Synchronisation FortiManager",
        status=AuditStatus.UNKNOWN,
        evidence=(f"type: {mode}: valeur non supportée",),
        evidence_items=(evidence_for_directive(configuration.document, section_name, "type"),),
        message="La valeur central-management observée n’est pas interprétable avec certitude.",
        recommendation="Fournir une valeur central-management documentée et supportée.",
        remediation="Vérifier la version FortiOS et compléter la projection avant de conclure.",
        risk_summary="Le mode de synchronisation ne peut pas être classé.",
    )


def check_fortianalyzer_sync(configuration: FortiGateConfiguration) -> AuditFinding:
    classic_name = "log fortianalyzer setting"
    cloud_name = "log fortianalyzer-cloud setting"
    classic = section_for(configuration.document, classic_name)
    cloud = section_for(configuration.document, cloud_name)

    if classic is None and cloud is None:
        return _finding(
            control_id="SYS-FORTIANALYZER-SYNC-001",
            title="Synchronisation FortiAnalyzer",
            status=AuditStatus.UNKNOWN,
            evidence=("FortiAnalyzer: namespaces absents",),
            evidence_items=(
                evidence_for_section(configuration.document, classic_name),
                evidence_for_section(configuration.document, cloud_name),
            ),
            message="Aucune configuration FortiAnalyzer n’est présente dans le backup.",
            recommendation="Fournir les paramètres FortiAnalyzer ou FortiAnalyzer Cloud.",
            remediation="Configurer un FortiAnalyzer approuvé puis relancer l’audit.",
            risk_summary="La journalisation centralisée FortiAnalyzer ne peut pas être confirmée.",
        )

    if (classic is not None and not _section_is_certain_leaf(classic)) or (
        cloud is not None and not _section_is_certain_leaf(cloud)
    ):
        return _finding(
            control_id="SYS-FORTIANALYZER-SYNC-001",
            title="Synchronisation FortiAnalyzer",
            status=AuditStatus.UNKNOWN,
            evidence=("FortiAnalyzer: structure incomplète ou ambiguë",),
            evidence_items=tuple(
                item
                for section_name, section in ((classic_name, classic), (cloud_name, cloud))
                if section is not None
                for item in (
                    evidence_for_directive(configuration.document, section_name, "status"),
                    evidence_for_directive(configuration.document, section_name, "server"),
                )
            ),
            message="La configuration FortiAnalyzer contient une structure non prouvée.",
            recommendation="Fournir des sections FortiAnalyzer canoniques et complètes.",
            remediation="Corriger la structure puis relancer l’audit.",
            risk_summary="L’état de journalisation centralisée ne peut pas être déterminé.",
        )

    classic_status = _certain_value(classic, "status") if classic is not None else None
    classic_server = _certain_value(classic, "server") if classic is not None else None
    cloud_status = _certain_value(cloud, "status") if cloud is not None else None

    if classic_status is not None and classic_status[0] == "enable":
        if classic_server is not None and classic_server[0].strip():
            return _finding(
                control_id="SYS-FORTIANALYZER-SYNC-001",
                title="Synchronisation FortiAnalyzer",
                status=AuditStatus.PASS,
                evidence=("status: enable", f"server: {classic_server[0]}"),
                evidence_items=(
                    evidence_for_directive(configuration.document, classic_name, "status"),
                    evidence_for_directive(configuration.document, classic_name, "server"),
                ),
                message="Le FortiGate est configuré pour un FortiAnalyzer explicite.",
                recommendation="Vérifier périodiquement l’état runtime de la synchronisation.",
                remediation="Aucune remédiation de configuration immédiate.",
                risk_summary="La journalisation FortiAnalyzer est explicitement configurée.",
            )
        if cloud_status is not None and cloud_status[0] == "enable":
            return _finding(
                control_id="SYS-FORTIANALYZER-SYNC-001",
                title="Synchronisation FortiAnalyzer",
                status=AuditStatus.PASS,
                evidence=("FortiAnalyzer Cloud: status enable",),
                evidence_items=(
                    evidence_for_directive(configuration.document, cloud_name, "status"),
                ),
                message="Le FortiGate est configuré pour FortiAnalyzer Cloud.",
                recommendation="Vérifier périodiquement l’état runtime de la synchronisation.",
                remediation="Aucune remédiation de configuration immédiate.",
                risk_summary="La journalisation FortiAnalyzer Cloud est explicitement configurée.",
            )
        return _finding(
            control_id="SYS-FORTIANALYZER-SYNC-001",
            title="Synchronisation FortiAnalyzer",
            status=AuditStatus.UNKNOWN,
            evidence=("status: enable", "server: preuve absente ou ambiguë"),
            evidence_items=(
                evidence_for_directive(configuration.document, classic_name, "status"),
                evidence_for_directive(configuration.document, classic_name, "server"),
            ),
            message="FortiAnalyzer est activé mais son serveur n’est pas prouvé.",
            recommendation="Fournir une directive server unique et certaine.",
            remediation="Configurer le serveur FortiAnalyzer puis relancer l’audit.",
            risk_summary="La destination de journalisation centralisée est incomplète.",
        )

    if cloud_status is not None and cloud_status[0] == "enable":
        return _finding(
            control_id="SYS-FORTIANALYZER-SYNC-001",
            title="Synchronisation FortiAnalyzer",
            status=AuditStatus.PASS,
            evidence=("FortiAnalyzer Cloud: status enable",),
            evidence_items=(evidence_for_directive(configuration.document, cloud_name, "status"),),
            message="Le FortiGate est configuré pour FortiAnalyzer Cloud.",
            recommendation="Vérifier périodiquement l’état runtime de la synchronisation.",
            remediation="Aucune remédiation de configuration immédiate.",
            risk_summary="La journalisation FortiAnalyzer Cloud est explicitement configurée.",
        )

    if (
        classic_status is not None
        and classic_status[0] == "disable"
        and (cloud_status is None or cloud_status[0] == "disable")
    ):
        evidence_items = [evidence_for_directive(configuration.document, classic_name, "status")]
        evidence = ["FortiAnalyzer: status disable"]
        if cloud_status is not None and cloud_status[0] == "disable":
            evidence_items.append(
                evidence_for_directive(configuration.document, cloud_name, "status")
            )
            evidence.append("FortiAnalyzer Cloud: status disable")
        return _finding(
            control_id="SYS-FORTIANALYZER-SYNC-001",
            title="Synchronisation FortiAnalyzer",
            status=AuditStatus.FAIL,
            evidence=tuple(evidence),
            evidence_items=tuple(evidence_items),
            message="Aucun FortiAnalyzer actif n’est configuré.",
            recommendation="Activer un FortiAnalyzer ou FortiAnalyzer Cloud approuvé.",
            remediation=(
                "Configurer status enable et la destination correspondante, puis "
                "relancer l’audit."
            ),
            risk_summary="Les journaux ne sont pas envoyés vers un FortiAnalyzer configuré.",
        )

    return _finding(
        control_id="SYS-FORTIANALYZER-SYNC-001",
        title="Synchronisation FortiAnalyzer",
        status=AuditStatus.UNKNOWN,
        evidence=("FortiAnalyzer: état absent, ambigu ou non supporté",),
        evidence_items=tuple(
            item
            for section_name, section in ((classic_name, classic), (cloud_name, cloud))
            if section is not None
            for item in (
                evidence_for_directive(configuration.document, section_name, "status"),
                evidence_for_directive(configuration.document, section_name, "server"),
            )
        ),
        message="L’état FortiAnalyzer ne peut pas être classé avec certitude.",
        recommendation="Fournir des directives FortiAnalyzer explicites et supportées.",
        remediation="Vérifier la version FortiOS et compléter la projection avant de conclure.",
        risk_summary="La journalisation centralisée reste indéterminée.",
    )


def check_admin_https_port(configuration: FortiGateConfiguration) -> AuditFinding:
    section_name = "system global"
    section = section_for(configuration.document, section_name)
    if section is None:
        return _finding(
            control_id="SYS-ADMIN-HTTPS-PORT-001",
            title="Port HTTPS d’administration personnalisé",
            status=AuditStatus.UNKNOWN,
            evidence=("system global: namespace absent",),
            evidence_items=(evidence_for_section(configuration.document, section_name),),
            message="Le port d’administration n’est pas prouvé.",
            recommendation="Fournir une section system global complète.",
            remediation="Configurer admin-sport puis relancer l’audit.",
            risk_summary="Le port HTTPS d’administration ne peut pas être confirmé.",
        )
    if not _section_is_certain_leaf(section):
        return _finding(
            control_id="SYS-ADMIN-HTTPS-PORT-001",
            title="Port HTTPS d’administration personnalisé",
            status=AuditStatus.UNKNOWN,
            evidence=("system global: structure incomplète ou ambiguë",),
            evidence_items=(
                evidence_for_directive(configuration.document, section_name, "admin-sport"),
            ),
            message="La section system global contient une structure non prouvée.",
            recommendation="Fournir une section system global canonique et complète.",
            remediation="Corriger la structure puis relancer l’audit.",
            risk_summary="Le port HTTPS d’administration reste indéterminé.",
        )

    value = _certain_value(section, "admin-sport")
    if value is None or not value[0].isdecimal():
        return _finding(
            control_id="SYS-ADMIN-HTTPS-PORT-001",
            title="Port HTTPS d’administration personnalisé",
            status=AuditStatus.UNKNOWN,
            evidence=("admin-sport: valeur absente ou non numérique",),
            evidence_items=(
                evidence_for_directive(configuration.document, section_name, "admin-sport"),
            ),
            message="La valeur admin-sport ne permet pas de prouver le port d’administration.",
            recommendation="Fournir une valeur admin-sport numérique unique.",
            remediation="Corriger admin-sport puis relancer l’audit.",
            risk_summary="Le port HTTPS d’administration ne peut pas être classé.",
        )

    port = int(value[0])
    evidence_item = evidence_for_directive(configuration.document, section_name, "admin-sport")
    if port == 443:
        return _finding(
            control_id="SYS-ADMIN-HTTPS-PORT-001",
            title="Port HTTPS d’administration personnalisé",
            status=AuditStatus.FAIL,
            evidence=("admin-sport: 443",),
            evidence_items=(evidence_item,),
            message="Le port HTTPS d’administration conserve la valeur par défaut 443.",
            recommendation=(
                "Choisir un port HTTPS d’administration personnalisé conforme à la politique."
            ),
            remediation="Configurer un admin-sport personnalisé puis relancer l’audit.",
            risk_summary="Le port d’administration par défaut facilite les scans opportunistes.",
        )

    return _finding(
        control_id="SYS-ADMIN-HTTPS-PORT-001",
        title="Port HTTPS d’administration personnalisé",
        status=AuditStatus.PASS,
        evidence=(f"admin-sport: {port}",),
        evidence_items=(evidence_item,),
        message="Le port HTTPS d’administration est personnalisé.",
        recommendation="Conserver ce port et limiter son exposition par réseau de gestion.",
        remediation="Aucune remédiation de configuration immédiate.",
        risk_summary="Le port HTTPS d’administration n’utilise pas la valeur par défaut.",
    )

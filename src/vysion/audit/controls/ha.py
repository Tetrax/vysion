from __future__ import annotations

from vysion.audit.controls._evidence import evidence_for_directive, evidence_for_section
from vysion.audit.models import (
    Applicability,
    AuditContext,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    FortiGateConfiguration,
    ProofState,
    RiskAssessment,
)

_HA_SECTION = "system ha"


def _ha_finding(
    configuration: FortiGateConfiguration,
    *,
    control_id: str,
    title: str,
    status: AuditStatus,
    keys: tuple[str, ...],
    evidence: tuple[str, ...],
    message: str,
    recommendation: str,
    remediation: str,
) -> AuditFinding:
    return AuditFinding(
        control_id=control_id,
        title=title,
        status=status,
        category="ha",
        priority=AuditPriority.P1,
        severity=AuditSeverity.HIGH,
        applicability=(
            Applicability.APPLICABLE
            if status in {AuditStatus.PASS, AuditStatus.FAIL}
            else Applicability.UNKNOWN
        ),
        evidence=evidence,
        evidence_items=(
            tuple(
                evidence_for_directive(configuration.document, _HA_SECTION, key)
                for key in keys
            )
            if keys
            else (evidence_for_section(configuration.document, _HA_SECTION),)
        ),
        message=message,
        risk=RiskAssessment(
            summary="La continuité du cluster dépend d'une configuration HA certaine.",
            impact=(
                "Une configuration incomplète peut interrompre les sessions "
                "lors d'un basculement."
            ),
            likelihood="moyenne",
            treatment=recommendation,
        ),
        recommendation=recommendation,
        remediation=remediation,
    )


def check_ha_session_pickup(configuration: FortiGateConfiguration) -> AuditFinding:
    control_id = "HA-SESSION-PICKUP-001"
    title = "Conservation des sessions lors du basculement HA"
    settings = configuration.ha_settings
    required = (
        "session-pickup",
        "session-pickup-connectionless",
        "session-pickup-expectation",
    )
    if (
        settings is None
        or settings.proof_state is not ProofState.PROVEN
        or not set(required) <= set(settings.parsed_keys)
    ):
        return _ha_finding(
            configuration,
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            keys=(),
            evidence=("system ha: preuve session-pickup incomplète ou ambiguë",),
            message="Les trois options de reprise de session ne sont pas prouvées.",
            recommendation="Fournir un bloc system ha complet avec les trois options explicites.",
            remediation="Compléter la configuration HA puis relancer l'audit.",
        )
    values = (
        settings.session_pickup,
        settings.session_pickup_connectionless,
        settings.session_pickup_expectation,
    )
    if any(value == "disable" for value in values):
        return _ha_finding(
            configuration,
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            keys=required,
            evidence=("Au moins une option session-pickup est explicitement désactivée.",),
            message="La reprise de toutes les catégories de sessions n'est pas activée.",
            recommendation="Activer les trois options session-pickup.",
            remediation="Configurer les trois directives sur enable puis relancer l'audit.",
        )
    if not all(value == "enable" for value in values):
        return _ha_finding(
            configuration,
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            keys=required,
            evidence=("Une option session-pickup porte une valeur non canonique.",),
            message="La reprise des sessions ne peut pas être conclue.",
            recommendation="Utiliser uniquement enable ou disable explicitement.",
            remediation="Corriger la valeur non canonique puis relancer l'audit.",
        )
    return _ha_finding(
        configuration,
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        keys=required,
        evidence=("Les trois options session-pickup sont explicitement activées.",),
        message="La reprise de session HA est configurée selon la règle legacy.",
        recommendation="Conserver les trois options sur enable.",
        remediation="Aucune remédiation immédiate.",
    )


def check_ha_heartbeat_redundancy(configuration: FortiGateConfiguration) -> AuditFinding:
    settings = configuration.ha_settings
    common = {
        "control_id": "HA-HEARTBEAT-REDUNDANCY-001",
        "title": "Redondance des interfaces heartbeat HA",
    }
    if (
        settings is None
        or settings.proof_state is not ProofState.PROVEN
        or "hbdev" not in settings.parsed_keys
    ):
        return _ha_finding(
            configuration,
            **common,
            status=AuditStatus.UNKNOWN,
            keys=(),
            evidence=("system ha: hbdev absent, invalide ou ambigu",),
            message="La redondance heartbeat ne peut pas être établie.",
            recommendation="Fournir une directive hbdev canonique et complète.",
            remediation="Configurer les interfaces heartbeat puis relancer l'audit.",
        )
    count = len(settings.heartbeat_interfaces)
    status = AuditStatus.PASS if count >= 2 else AuditStatus.FAIL
    return _ha_finding(
        configuration,
        **common,
        status=status,
        keys=("hbdev",),
        evidence=(f"Nombre d'interfaces heartbeat certaines: {count}",),
        message=(
            "Au moins deux interfaces heartbeat sont configurées."
            if status is AuditStatus.PASS
            else "Une seule interface heartbeat est configurée."
        ),
        recommendation="Conserver au moins deux chemins heartbeat distincts.",
        remediation=(
            "Aucune remédiation immédiate."
            if status is AuditStatus.PASS
            else "Ajouter un second chemin heartbeat puis relancer l'audit."
        ),
    )


def check_ha_override(configuration: FortiGateConfiguration) -> AuditFinding:
    settings = configuration.ha_settings
    common = {"control_id": "HA-OVERRIDE-001", "title": "Politique override du cluster HA"}
    if (
        settings is None
        or settings.proof_state is not ProofState.PROVEN
        or "override" not in settings.parsed_keys
    ):
        return _ha_finding(
            configuration,
            **common,
            status=AuditStatus.UNKNOWN,
            keys=(),
            evidence=("system ha: override absent, invalide ou ambigu",),
            message="La politique override ne peut pas être établie.",
            recommendation="Fournir une directive override explicite.",
            remediation="Compléter le bloc HA puis relancer l'audit.",
        )
    if settings.override == "disable":
        status = AuditStatus.PASS
        keys = ("override",)
    elif settings.override == "enable":
        if "override-wait-time" not in settings.parsed_keys:
            status = AuditStatus.FAIL
            keys = ("override",)
        else:
            status = (
                AuditStatus.PASS
                if settings.override_wait_time == 30
                else AuditStatus.FAIL
            )
            keys = ("override", "override-wait-time")
    else:
        return _ha_finding(
            configuration,
            **common,
            status=AuditStatus.UNKNOWN,
            keys=("override",),
            evidence=("override porte une valeur non canonique",),
            message="La politique override ne peut pas être interprétée.",
            recommendation="Utiliser enable ou disable explicitement.",
            remediation="Corriger override puis relancer l'audit.",
        )
    return _ha_finding(
        configuration,
        **common,
        status=status,
        keys=keys,
        evidence=(
            "override désactivé"
            if settings.override == "disable"
            else f"override activé; attente: {settings.override_wait_time}"
        ,),
        message=(
            "La politique override respecte la règle legacy."
            if status is AuditStatus.PASS
            else "Override actif sans attente exacte de 30 secondes."
        ),
        recommendation="Désactiver override ou fixer override-wait-time à 30 secondes.",
        remediation=(
            "Aucune remédiation immédiate."
            if status is AuditStatus.PASS
            else "Corriger la politique override puis relancer l'audit."
        ),
    )


def check_ha_cabling_redundancy(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    common = {
        "control_id": "HA-CABLING-REDUNDANCY-001",
        "title": "Redondance physique du câblage HA",
    }
    settings = configuration.ha_settings
    observation = context.ha_cabling_redundancy if context is not None else None
    provenance = context.operator_provenance if context is not None else None
    if settings is None or settings.proof_state is not ProofState.PROVEN:
        observation = None
    if observation is None or provenance is None:
        return _ha_finding(
            configuration,
            **common,
            status=AuditStatus.UNKNOWN,
            keys=(),
            evidence=("Observation opérateur du câblage HA absente ou non sourcée.",),
            message="Le backup ne permet pas de prouver la redondance physique.",
            recommendation=(
                "Renseigner une observation opérateur sourcée après inspection physique."
            ),
            remediation="Inspecter le câblage puis relancer l'audit avec son contexte.",
        )
    status = AuditStatus.PASS if observation else AuditStatus.FAIL
    return _ha_finding(
        configuration,
        **common,
        status=status,
        keys=("group-name",),
        evidence=("Observation opérateur sourcée de la redondance physique.",),
        message=(
            "La redondance physique HA est confirmée par l'opérateur."
            if observation
            else "L'opérateur confirme l'absence de redondance physique HA."
        ),
        recommendation="Maintenir deux chemins physiques indépendants.",
        remediation=(
            "Aucune remédiation immédiate."
            if observation
            else "Ajouter un chemin physique indépendant puis refaire l'inspection."
        ),
    )

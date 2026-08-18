from datetime import UTC, datetime

from vysion.audit.models import (
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
    ScheduleCounts,
)

CONTROL_ID = "FW-LEGACY-SCHEDULE-INVENTORY-001"


def _result(
    status: AuditStatus, message: str, counts: ScheduleCounts | None = None
) -> AuditFinding:
    applicability = (
        Applicability.NOT_APPLICABLE
        if status is AuditStatus.NOT_APPLICABLE
        else Applicability.UNKNOWN
        if status is AuditStatus.UNKNOWN
        else Applicability.APPLICABLE
    )
    evidence = (
        f"always: {counts.always}",
        f"active: {counts.active}",
        f"expired: {counts.expired}",
        "provenance: legacy_v1",
    ) if counts else (message, "provenance: legacy_v1")
    return AuditFinding(
        control_id=CONTROL_ID,
        title="Inventaire des schedules de policies",
        status=status,
        category="firewall-policy",
        priority=AuditPriority.P1,
        severity=AuditSeverity.MEDIUM,
        applicability=applicability,
        evidence=evidence,
        evidence_items=(
            EvidenceItem(
                section="firewall policy",
                directive="schedule-counts",
                tokens=tuple(evidence[:3]),
                certainty=(
                    EvidenceCertainty.AMBIGUOUS
                    if status is AuditStatus.UNKNOWN
                    else EvidenceCertainty.CERTAIN
                ),
            ),
        ),
        message=message,
        risk=RiskAssessment(
            summary="Une policy peut rester liée à une fenêtre temporelle expirée.",
            impact="Le comportement temporel attendu de la règle n'est plus assuré.",
            likelihood="indéterminée" if status is AuditStatus.UNKNOWN else "moyenne",
            treatment="Corriger ou remplacer le schedule expiré.",
        ),
        recommendation="Maintenir uniquement des schedules actifs sur les policies.",
        remediation="Mettre à jour le schedule puis rejouer l'audit avec un instant explicite.",
        rule_provenance="legacy_v1",
        schedule_counts=counts,
    )


def check_legacy_schedule_inventory(
    configuration: FortiGateConfiguration, context: AuditContext | None = None
) -> AuditFinding:
    policy_section = configuration.document.section("firewall policy")
    if policy_section is None or policy_section.certainty is not EvidenceCertainty.CERTAIN:
        return _result(AuditStatus.UNKNOWN, "Namespace firewall policy absent ou ambigu.")
    if not policy_section.entries:
        return _result(
            AuditStatus.NOT_APPLICABLE,
            "Le namespace firewall policy est certainement vide.",
            ScheduleCounts(always=1, active=0, expired=0),
        )
    reference = (
        context.schedule_reference_instant
        if context is not None
        else datetime.now(UTC)
        if configuration.complete_backup
        else None
    )
    if reference is None:
        return _result(AuditStatus.UNKNOWN, "Instant de référence opérateur absent.")

    objects = (
        *configuration.onetime_schedules,
        *configuration.recurring_schedules,
        *configuration.schedule_groups,
    )
    names = [item.name.casefold() for item in objects]
    schedule_sections = tuple(
        configuration.document.section(name)
        for name in (
            "firewall schedule onetime",
            "firewall schedule recurring",
            "firewall schedule group",
        )
    )
    if (
        len(names) != len(set(names))
        or any(item.proof_state is not ProofState.PROVEN for item in objects)
        or any(
            section is not None and section.certainty is not EvidenceCertainty.CERTAIN
            for section in schedule_sections
        )
        or any(
            policy.proof_state is not ProofState.PROVEN
            or "schedule" not in policy.parsed_keys
            or policy.schedule is None
            for policy in configuration.policies
        )
    ):
        return _result(AuditStatus.UNKNOWN, "Schedule ou policy muté, ambigu ou incomplet.")

    onetime = {item.name.casefold(): item for item in configuration.onetime_schedules}
    recurring = {item.name.casefold() for item in configuration.recurring_schedules}
    groups = {item.name.casefold(): item for item in configuration.schedule_groups}
    visiting: set[str] = set()
    visited: set[str] = set()

    def cyclic(name: str) -> bool:
        if name in visiting:
            return True
        if name in visited or name not in groups:
            return False
        visiting.add(name)
        if any(cyclic(member.name.casefold()) for member in groups[name].members):
            return True
        visiting.remove(name)
        visited.add(name)
        return False

    if any(cyclic(name) for name in groups):
        return _result(AuditStatus.UNKNOWN, "Cycle dans les groupes de schedules.")

    def state(name: str) -> str | None:
        key = name.casefold()
        if key in recurring:
            return "active"
        if key in onetime:
            end = onetime[key].end
            if end is None:
                return None
            localized_end = end.replace(tzinfo=reference.tzinfo)
            return "expired" if localized_end < reference else "active"
        if key in groups:
            member_states = [state(member.name) for member in groups[key].members]
            if not member_states or any(value is None for value in member_states):
                return None
            return "expired" if "expired" in member_states else "active"
        return None

    always = 1
    active = expired = 0
    for policy in configuration.policies:
        if policy.schedule.casefold() == "always":
            always += 1
            continue
        resolved = state(policy.schedule)
        if resolved is None:
            return _result(AuditStatus.UNKNOWN, "Référence schedule inconnue ou incomplète.")
        if resolved == "expired":
            expired += 1
        else:
            active += 1
    counts = ScheduleCounts(always=always, active=active, expired=expired)
    return _result(
        AuditStatus.FAIL if expired else AuditStatus.PASS,
        "Au moins un schedule utilisé est expiré."
        if expired
        else "Tous les schedules utilisés sont actifs ou always.",
        counts,
    )


check_legacy_schedule_inventory.control_id = CONTROL_ID

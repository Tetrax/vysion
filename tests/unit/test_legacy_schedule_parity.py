from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext, AuditStatus
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

CONTROL_ID = "FW-LEGACY-SCHEDULE-INVENTORY-001"


def _finding(raw: str, context: AuditContext | None = None):
    configuration = FortiGateParser().parse(raw)
    return next(
        finding
        for finding in AuditEngine(default_registry()).run(configuration, context=context)
        if finding.control_id == CONTROL_ID
    )


def _config(schedule: str, definitions: str) -> str:
    return f"""#config-version=FGT100F-7.4.3-FW-build1-1
{definitions}
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "{schedule}"
    next
end
"""


def test_real_parser_projection_control_registry_pass_and_canonical_counts() -> None:
    raw = _config(
        "office-hours",
        """config firewall schedule recurring
    edit "office-hours"
        set day monday tuesday
    next
end""",
    )
    context = AuditContext(
        schedule_reference_instant=datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
    )

    configuration = FortiGateParser().parse(raw)
    assert configuration.recurring_schedules[0].name == "office-hours"
    finding = _finding(raw, context)

    assert finding.status is AuditStatus.PASS
    assert finding.rule_provenance == "legacy_v1"
    assert finding.schedule_counts.model_dump() == {"always": 1, "active": 1, "expired": 0}
    assert finding.model_dump(mode="json")["schedule_counts"]["always"] == 1


def test_expired_onetime_member_makes_group_and_control_fail() -> None:
    raw = _config(
        "mixed-group",
        """config firewall schedule onetime
    edit "past"
        set end 11:59 2026/08/18
    next
end
config firewall schedule recurring
    edit "weekly"
        set day monday
    next
end
config firewall schedule group
    edit "mixed-group"
        set member "past" "weekly"
    next
end""",
    )

    finding = _finding(
        raw,
        AuditContext(schedule_reference_instant=datetime(2026, 8, 18, 12, 0, tzinfo=UTC)),
    )

    assert finding.status is AuditStatus.FAIL
    assert finding.schedule_counts.model_dump() == {"always": 1, "active": 0, "expired": 1}


@pytest.mark.parametrize(
    ("definitions", "schedule"),
    [
        ("", "missing"),
        ("config firewall schedule recurring\n edit x\n  append day monday\n next\nend", "x"),
    ],
)
def test_unknown_reference_or_mutation_is_unknown(definitions: str, schedule: str) -> None:
    finding = _finding(
        _config(schedule, definitions),
        AuditContext(schedule_reference_instant=datetime(2026, 8, 18, 12, 0, tzinfo=UTC)),
    )
    assert finding.status is AuditStatus.UNKNOWN


def test_missing_reference_instant_is_unknown_and_naive_instant_is_rejected() -> None:
    raw = _config(
        "window",
        "config firewall schedule onetime\n edit window\n  set end 12:30 2026/08/18\n next\nend",
    )
    assert _finding(raw).status is AuditStatus.UNKNOWN
    with pytest.raises(ValidationError):
        AuditContext(schedule_reference_instant=datetime(2026, 8, 18, 12, 0))


def test_certainly_empty_policy_namespace_is_not_applicable() -> None:
    finding = _finding(
        "#config-version=FGT100F-7.4.3-FW-build1-1\nconfig firewall policy\nend\n",
        AuditContext(schedule_reference_instant=datetime(2026, 8, 18, 12, 0, tzinfo=UTC)),
    )
    assert finding.status is AuditStatus.NOT_APPLICABLE


def test_registry_appends_schedule_control_with_stable_unique_id() -> None:
    ids = [getattr(control, "control_id", "") for control in default_registry()]
    assert ids[-1] == CONTROL_ID
    assert len(ids) == 51
    declared_ids = [control_id for control_id in ids if control_id]
    assert len(declared_ids) == len(set(declared_ids))

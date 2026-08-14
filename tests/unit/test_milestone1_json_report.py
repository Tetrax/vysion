from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.audit.models import AuditContext
from vysion.reports.json_report import JsonAuditReport


def test_json_audit_report_is_schema_v2_and_contains_context() -> None:
    created_at = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
    report = JsonAuditReport(
        report_id=uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=5),
        source_name="synthetic.conf",
        fortiguard=FortiGuardResult(status=FortiGuardStatus.UNKNOWN, detail="synthetic"),
        context=AuditContext(client="Client synthétique", site="Paris-lab"),
        findings=(),
    )

    assert report.schema_version == 2
    assert report.context.client == "Client synthétique"
    payload = report.model_dump(mode="json")
    assert payload["schema_version"] == 2
    assert payload["context"]["ha"] is None


def test_json_audit_report_defaults_context_to_explicit_unknown() -> None:
    created_at = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
    report = JsonAuditReport(
        report_id=uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=5),
        source_name="synthetic.conf",
        fortiguard=FortiGuardResult(status=FortiGuardStatus.UNKNOWN, detail="synthetic"),
        findings=(),
    )

    assert report.context == AuditContext()
    assert report.context.ha is None

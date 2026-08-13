from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.reports.json_report import JsonAuditReport
from vysion.storage.reports import JsonReportStore


def make_report(created_at: datetime) -> JsonAuditReport:
    return JsonAuditReport(
        report_id=uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(seconds=60),
        source_name="synthetic.conf",
        fortiguard=FortiGuardResult(
            status=FortiGuardStatus.UNKNOWN,
            detail="synthetic",
        ),
        findings=(),
    )


def test_store_purges_expired_reports_during_initialization(tmp_path: Path) -> None:
    created = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    report = make_report(created)
    initial = JsonReportStore(tmp_path, clock=lambda: created)
    path = initial.save(report)

    JsonReportStore(tmp_path, clock=lambda: created + timedelta(seconds=61))

    assert not path.exists()


def test_store_purges_expired_reports_before_saving_a_new_report(tmp_path: Path) -> None:
    current = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    store = JsonReportStore(tmp_path, clock=lambda: current)
    expired_path = store.save(make_report(current))

    current += timedelta(seconds=61)
    store.save(make_report(current))

    assert not expired_path.exists()
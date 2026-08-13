from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.config import Settings
from vysion.reports.json_report import JsonAuditReport


def test_application_upload_limit_cannot_exceed_nginx_edge_limit() -> None:
    with pytest.raises(ValidationError):
        Settings(max_upload_bytes=5 * 1024 * 1024 + 1)


def test_json_report_rejects_naive_timestamps() -> None:
    with pytest.raises(ValidationError):
        JsonAuditReport(
            report_id=uuid4(),
            created_at=datetime(2026, 8, 12, 12, 0),
            expires_at=datetime(2026, 8, 12, 13, 0),
            source_name="synthetic.conf",
            fortiguard=FortiGuardResult(
                status=FortiGuardStatus.UNKNOWN,
                detail="synthetic",
            ),
            findings=(),
        )


def test_json_report_normalizes_aware_timestamps_to_utc() -> None:
    offset = timezone(timedelta(hours=2))
    report = JsonAuditReport(
        report_id=uuid4(),
        created_at=datetime(2026, 8, 12, 14, 0, tzinfo=offset),
        expires_at=datetime(2026, 8, 12, 15, 0, tzinfo=offset),
        source_name="synthetic.conf",
        fortiguard=FortiGuardResult(
            status=FortiGuardStatus.UNKNOWN,
            detail="synthetic",
        ),
        findings=(),
    )

    assert report.created_at == datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    assert report.created_at.tzinfo is UTC
    assert report.expires_at == datetime(2026, 8, 12, 13, 0, tzinfo=UTC)
    assert report.expires_at.tzinfo is UTC


def test_json_report_rejects_expiration_not_after_creation() -> None:
    timestamp = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)

    with pytest.raises(ValidationError):
        JsonAuditReport(
            report_id=uuid4(),
            created_at=timestamp,
            expires_at=timestamp,
            source_name="synthetic.conf",
            fortiguard=FortiGuardResult(
                status=FortiGuardStatus.UNKNOWN,
                detail="synthetic",
            ),
            findings=(),
        )
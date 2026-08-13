from datetime import UTC, datetime, timedelta
from io import BytesIO
from uuid import uuid4

from openpyxl import load_workbook

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.audit.models import AuditFinding, AuditStatus
from vysion.reports.json_report import JsonAuditReport
from vysion.reports.xlsx_report import render_xlsx


def test_xlsx_treats_user_controlled_values_as_text_not_formulas() -> None:
    created_at = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    report = JsonAuditReport(
        report_id=uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=5),
        source_name='=WEBSERVICE("https://invalid.example")',
        fortiguard=FortiGuardResult(
            status=FortiGuardStatus.UNKNOWN,
            detail="@malicious",
        ),
        findings=(
            AuditFinding(
                control_id="SAFE-001",
                title="+cmd",
                status=AuditStatus.UNKNOWN,
                message="-1+1",
            ),
        ),
    )

    workbook = load_workbook(BytesIO(render_xlsx(report)), read_only=False, data_only=False)
    summary = workbook["Synthèse"]
    controls = workbook["Contrôles"]

    for cell in (summary["B2"], summary["B6"], controls["B2"], controls["D2"]):
        assert cell.data_type == "s"
        assert isinstance(cell.value, str)
        assert cell.value.startswith("'")

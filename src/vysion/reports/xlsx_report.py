from io import BytesIO

from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter

from vysion.reports.json_report import JsonAuditReport


def spreadsheet_text(value: str) -> str:
    if value.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def render_xlsx(report: JsonAuditReport) -> bytes:
    workbook = Workbook()
    summary = workbook.active
    if summary is None:
        raise RuntimeError("workbook has no active worksheet")
    summary.title = "Synthèse"
    summary_rows = (
        ("Identifiant", str(report.report_id)),
        ("Source", spreadsheet_text(report.source_name)),
        ("Créé le", report.created_at.isoformat()),
        ("Expire le", report.expires_at.isoformat()),
        ("FortiGuard", report.fortiguard.status.value),
        ("Détail FortiGuard", spreadsheet_text(report.fortiguard.detail)),
    )
    for row in summary_rows:
        summary.append(row)
    for cell in summary["A"]:
        cell.font = Font(bold=True)
    summary.column_dimensions["A"].width = 22
    summary.column_dimensions["B"].width = 48

    controls = workbook.create_sheet("Contrôles")
    headers = ("Contrôle", "Titre", "Statut", "Constat", "Risque", "Recommandation")
    controls.append(headers)
    for cell in controls[1]:
        cell.font = Font(bold=True)
    controls.freeze_panes = "A2"
    controls.auto_filter.ref = "A1:F1"

    for finding in report.findings:
        controls.append(
            (
                spreadsheet_text(finding.control_id),
                spreadsheet_text(finding.title),
                finding.status.value,
                spreadsheet_text(finding.message),
                spreadsheet_text(finding.risk or ""),
                spreadsheet_text(finding.recommendation or ""),
            )
        )
    for index, width in enumerate((22, 32, 12, 48, 42, 48), start=1):
        controls.column_dimensions[get_column_letter(index)].width = width

    output = BytesIO()
    workbook.save(output)
    return output.getvalue()

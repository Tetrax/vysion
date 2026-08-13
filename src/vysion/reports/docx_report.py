from io import BytesIO

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH

from vysion.reports.json_report import JsonAuditReport


def render_docx(report: JsonAuditReport) -> bytes:
    document = Document()
    document.core_properties.title = "Rapport d’audit Vysion"
    document.core_properties.subject = "Audit de configuration FortiGate"
    document.core_properties.author = "Vysion"
    document.core_properties.created = report.created_at
    document.core_properties.modified = report.created_at

    title = document.add_heading("Rapport d’audit Vysion", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    metadata = document.add_table(rows=0, cols=2)
    metadata.alignment = WD_TABLE_ALIGNMENT.CENTER
    for label, value in (
        ("Identifiant", str(report.report_id)),
        ("Source", report.source_name),
        ("Créé le", report.created_at.isoformat()),
        ("Expire le", report.expires_at.isoformat()),
        ("FortiGuard", report.fortiguard.status.value),
        ("Détail FortiGuard", report.fortiguard.detail),
    ):
        cells = metadata.add_row().cells
        cells[0].text = label
        cells[1].text = value

    document.add_heading("Résultats", level=1)
    findings = document.add_table(rows=1, cols=5)
    findings.style = "Table Grid"
    findings.alignment = WD_TABLE_ALIGNMENT.CENTER
    for cell, value in zip(
        findings.rows[0].cells,
        ("Contrôle", "Titre", "Statut", "Constat", "Recommandation"),
        strict=True,
    ):
        cell.text = value

    for finding in report.findings:
        cells = findings.add_row().cells
        values = (
            finding.control_id,
            finding.title,
            finding.status.value,
            finding.message,
            finding.recommendation or "—",
        )
        for cell, value in zip(cells, values, strict=True):
            cell.text = value

    output = BytesIO()
    document.save(output)
    return output.getvalue()

from io import BytesIO

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH

from vysion.audit.models import AffectedObject, EvidenceItem, RiskAssessment
from vysion.reports.json_report import JsonAuditReport


def _display(value: object) -> str:
    if value is None or value == "":
        return "Non renseigné"
    return str(value)


def _context_rows(report: JsonAuditReport) -> tuple[tuple[str, str], ...]:
    context = report.context
    provenance = context.operator_provenance
    return (
        ("Client", _display(context.client)),
        ("Site", _display(context.site)),
        ("WAN sélectionnées", _display(", ".join(context.selected_wans or ()) or None)),
        ("HA", _display(context.ha)),
        ("MPLS", _display(context.mpls)),
        ("Licence UTM", _display(context.utm_license)),
        ("Provenance", _display(provenance.source if provenance else None)),
        ("Opérateur", _display(provenance.operator if provenance else None)),
        ("Méthode", _display(provenance.method if provenance else None)),
    )


def _evidence_text(items: tuple[EvidenceItem, ...]) -> str:
    if not items:
        return "Non renseigné"
    return "\n".join(
        ": ".join(
            part
            for part in (
                item.section,
                item.entry,
                item.directive,
                " ".join(item.tokens) or None,
                f"ligne {item.line}" if item.line else None,
                item.certainty.value,
            )
            if part
        )
        for item in items
    )


def _objects_text(objects: tuple[AffectedObject, ...]) -> str:
    return ", ".join(f"{item.object_type}: {item.name}" for item in objects) or "Non renseigné"


def _risk_text(risk: RiskAssessment | None) -> str:
    if risk is None:
        return "Non renseigné"
    return "\n".join(
        part
        for part in (
            risk.summary,
            f"Impact: {risk.impact}" if risk.impact else None,
            f"Probabilité: {risk.likelihood}" if risk.likelihood else None,
            f"Traitement: {risk.treatment}" if risk.treatment else None,
        )
        if part
    )


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
        *_context_rows(report),
    ):
        cells = metadata.add_row().cells
        cells[0].text = label
        cells[1].text = value

    document.add_heading("Résultats", level=1)
    headers = (
        "Contrôle",
        "Titre",
        "Catégorie",
        "Priorité",
        "Sévérité",
        "Applicabilité",
        "Statut",
        "Constat",
        "Preuve structurée",
        "Objets affectés",
        "Risque",
        "Recommandation",
        "Remédiation",
        "Approbation client",
    )
    findings = document.add_table(rows=1, cols=len(headers))
    findings.style = "Table Grid"
    findings.alignment = WD_TABLE_ALIGNMENT.CENTER
    for cell, value in zip(findings.rows[0].cells, headers, strict=True):
        cell.text = value

    for finding in report.findings:
        cells = findings.add_row().cells
        values = (
            finding.control_id,
            finding.title,
            finding.category,
            finding.priority.value,
            finding.severity.value,
            finding.applicability.value,
            finding.status.value,
            finding.message,
            _evidence_text(finding.evidence_items),
            _objects_text(finding.affected_objects),
            _risk_text(finding.risk),
            finding.recommendation or "Non renseigné",
            finding.remediation or "Non renseigné",
            _display(finding.customer_approval),
        )
        for cell, value in zip(cells, values, strict=True):
            cell.text = value

    output = BytesIO()
    document.save(output)
    return output.getvalue()

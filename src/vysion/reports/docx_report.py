from io import BytesIO

from docx import Document
from docx.document import Document as DocumentType
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

from vysion.audit.models import AuditStatus
from vysion.reports.json_report import JsonAuditReport
from vysion.reports.views import context_rows, display, domain_label, finding_views, status_counts

STATUS_COLORS = {
    "PASS": "008A4B",
    "FAIL": "C62828",
    "UNKNOWN": "B26A00",
    "NOT_APPLICABLE": "5E6A71",
    "ERROR": "7B1FA2",
}


def _set_cell_shading(cell, fill: str) -> None:
    properties = cell._tc.get_or_add_tcPr()
    shading = properties.find(qn("w:shd"))
    if shading is None:
        shading = OxmlElement("w:shd")
        properties.append(shading)
    shading.set(qn("w:fill"), fill)


def _set_cell_text(cell, text: object, *, bold: bool = False, color: str | None = None) -> None:
    cell.text = ""
    paragraph = cell.paragraphs[0]
    run = paragraph.add_run(display(text))
    run.bold = bold
    if color:
        run.font.color.rgb = RGBColor.from_string(color)
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER


def _table(document: DocumentType, headers: tuple[str, ...], rows: tuple[tuple[object, ...], ...]):
    table = document.add_table(rows=1, cols=len(headers))
    table.style = "Light Shading Accent 1"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for cell, header in zip(table.rows[0].cells, headers, strict=True):
        _set_cell_text(cell, header, bold=True, color="FFFFFF")
        _set_cell_shading(cell, "183B56")
    for row in rows:
        cells = table.add_row().cells
        for cell, value in zip(cells, row, strict=True):
            _set_cell_text(cell, value)
    return table


def _status_paragraph(document: DocumentType, status: AuditStatus | str) -> None:
    value = status.value if isinstance(status, AuditStatus) else str(status)
    paragraph = document.add_paragraph()
    run = paragraph.add_run(f"Résultat : {value}")
    run.bold = True
    run.font.color.rgb = RGBColor.from_string(STATUS_COLORS.get(value, "183B56"))


def _configure_document(document: DocumentType, report: JsonAuditReport) -> None:
    section = document.sections[0]
    section.top_margin = Inches(0.65)
    section.bottom_margin = Inches(0.65)
    section.left_margin = Inches(0.7)
    section.right_margin = Inches(0.7)
    normal = document.styles["Normal"]
    normal.font.name = "Aptos"
    normal.font.size = Pt(9)
    document.styles["Title"].font.name = "Aptos Display"
    document.styles["Title"].font.color.rgb = RGBColor.from_string("183B56")
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run(
        f"Vysion — rapport confidentiel — {report.report_id}"
    ).font.size = Pt(8)


def _add_cover(document: DocumentType, report: JsonAuditReport) -> None:
    document.add_paragraph().add_run("VYSION").bold = True
    title = document.add_paragraph(style="Title")
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.add_run("Rapport d’audit Vysion")
    subtitle = document.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.add_run("FortiGate · restitution client et technique").italic = True
    document.add_paragraph()
    _table(
        document,
        ("Fiche audit", "Valeur"),
        (
            ("Client", report.context.client or "Non renseigné"),
            ("Site", report.context.site or "Non renseigné"),
            ("Équipement", report.equipment.hostname or "Non renseigné"),
            ("Modèle", report.equipment.model or "Non renseigné"),
            (
                "Numéro de série",
                report.context.serial_number or report.equipment.serial_number or "Non renseigné",
            ),
            ("Version FortiOS", report.equipment.firmware_version or "Non renseigné"),
            ("Source configuration", report.source_name),
            ("Rapport", str(report.report_id)),
            ("Date", report.created_at.strftime("%d/%m/%Y %H:%M UTC")),
        ),
    )
    document.add_paragraph()
    document.add_heading("Confidentialité", level=2)
    confidentiality = document.add_paragraph()
    confidentiality.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = confidentiality.add_run(
        "CONFIDENTIALITÉ — Diffusion restreinte au destinataire de l’audit"
    )
    run.bold = True
    run.font.color.rgb = RGBColor.from_string("C62828")
    document.add_paragraph(
        "Ce document contient des informations de configuration et de sécurité. "
        "Toute reproduction ou diffusion doit être autorisée par le propriétaire de l’équipement."
    ).alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_page_break()


def _add_context(document: DocumentType, report: JsonAuditReport) -> None:
    document.add_heading("Contexte", level=1)
    document.add_paragraph(
        "Les informations ci-dessous proviennent de la configuration analysée et "
        "du contexte opérateur saisi. "
        "Une valeur non renseignée reste volontairement distincte d’une valeur conforme."
    )
    _table(document, ("Information", "Valeur"), context_rows(report))
    document.add_heading("Échelle de risque", level=2)
    _table(
        document,
        ("Niveau", "Lecture client"),
        (
            ("Critique", "Compromission ou indisponibilité majeure ; traitement prioritaire."),
            ("Élevé", "Exposition importante nécessitant une remédiation planifiée rapidement."),
            ("Moyen", "Risque significatif à réduire dans le cycle de durcissement."),
            ("Faible / information", "Amélioration ou suivi sans impact immédiat démontré."),
            (
                "UNKNOWN",
                "Les preuves disponibles ne permettent pas de conclure ; "
                "ne pas assimiler à PASS.",
            ),
        ),
    )


def _add_summary(document: DocumentType, report: JsonAuditReport) -> None:
    document.add_heading("Synthèse", level=1)
    counts = status_counts(report)
    _table(
        document,
        ("Statut", "Nombre"),
        tuple(
            (status, counts.get(status, 0))
            for status in ("FAIL", "PASS", "UNKNOWN", "NOT_APPLICABLE", "ERROR")
        ),
    )
    failing = [view for view in finding_views(report) if view.finding.status is AuditStatus.FAIL]
    if failing:
        document.add_paragraph(
            f"{len(failing)} point(s) nécessite(nt) une action de remédiation. "
            "La synthèse client ci-dessous expose le problème, l’impact et l’action recommandée ; "
            "les preuves sont conservées dans la vue technique."
        )
    else:
        document.add_paragraph("Aucun contrôle en échec n’a été relevé dans le périmètre analysé.")
    _table(
        document,
        ("ID", "Problème", "Impact", "Risque", "Action recommandée"),
        tuple(
            (
                view.finding.control_id,
                view.client_problem,
                view.impact,
                view.risk_description,
                view.recommendation,
            )
            for view in failing
        ),
    )


def _add_risk_table(document: DocumentType, report: JsonAuditReport) -> None:
    document.add_heading("Tableau récapitulatif final des risques", level=1)
    risk_views = [view for view in finding_views(report) if view.finding.status is AuditStatus.FAIL]
    _table(
        document,
        (
            "ID",
            "Point audité",
            "Description du risque",
            "Vraisemblance",
            "Impact",
            "Complexité correction",
            "Remédiation",
        ),
        tuple(
            (
                view.finding.control_id,
                view.finding.title,
                view.risk_description,
                view.likelihood,
                view.impact,
                view.correction_complexity,
                view.remediation,
            )
            for view in risk_views
        ),
    )


def _add_finding_detail(document: DocumentType, view) -> None:
    finding = view.finding
    document.add_heading(f"{finding.control_id} — {finding.title}", level=2)
    document.add_paragraph("Vue client").runs[0].bold = True
    _table(
        document,
        ("Problème", "Impact", "Risque", "Action recommandée"),
        ((view.client_problem, view.impact, view.risk_description, view.recommendation),),
    )
    _status_paragraph(document, finding.status)
    document.add_paragraph("Vue technique").runs[0].bold = True
    _table(
        document,
        ("Champ", "Valeur"),
        (
            ("ID", finding.control_id),
            ("Catégorie", finding.category),
            ("Priorité", finding.priority.value),
            ("Sévérité", finding.severity.value),
            ("Applicabilité", finding.applicability.value),
            ("Preuve technique", view.proof),
            ("Objets concernés", view.objects),
            ("Complexité correction", view.correction_complexity),
            ("Recommandation", view.recommendation),
            ("Remédiation", view.remediation),
            ("Approbation client", display(finding.customer_approval)),
        ),
    )


def render_docx(report: JsonAuditReport) -> bytes:
    document = Document()
    _configure_document(document, report)
    _add_cover(document, report)
    _add_context(document, report)
    document.add_page_break()
    _add_summary(document, report)
    document.add_page_break()
    document.add_heading("Détail des contrôles", level=1)
    last_domain = None
    for index, view in enumerate(finding_views(report)):
        if index:
            document.add_page_break()
        current_domain = domain_label(view.finding)
        if current_domain != last_domain:
            document.add_heading(current_domain, level=2)
            last_domain = current_domain
        _add_finding_detail(document, view)
    document.add_page_break()
    _add_risk_table(document, report)
    document.add_paragraph()
    document.add_paragraph(
        f"FortiGuard : {report.fortiguard.status.value} — {report.fortiguard.detail}"
    )
    output = BytesIO()
    document.save(output)
    return output.getvalue()

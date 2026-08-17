from io import BytesIO

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from vysion.audit.models import AffectedObject, EvidenceItem, RiskAssessment
from vysion.reports.json_report import JsonAuditReport
from vysion.reports.views import (
    action_views,
    context_rows,
    finding_views,
    status_counts,
)


def spreadsheet_text(value: object) -> str:
    text = "Non renseigné" if value is None or value == "" else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return f"'{text}"
    return text


def evidence_text_legacy(items: tuple[EvidenceItem, ...]) -> str:
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
                "defaulted" if item.defaulted else "explicit",
            )
            if part
        )
        for item in items
    )


def objects_text_legacy(objects: tuple[AffectedObject, ...]) -> str:
    return ", ".join(f"{item.object_type}: {item.name}" for item in objects) or "Non renseigné"


def risk_text_legacy(risk: RiskAssessment | None) -> str:
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


def _style_sheet(sheet, *, filter_columns: int | None = None) -> None:
    sheet.freeze_panes = "A2"
    if filter_columns:
        sheet.auto_filter.ref = f"A1:{get_column_letter(filter_columns)}1"
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="183B56")
        cell.alignment = Alignment(wrap_text=True, vertical="top")
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")


def _append_context_sheet(workbook: Workbook, report: JsonAuditReport) -> None:
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
        *tuple((label, spreadsheet_text(value)) for label, value in context_rows(report)),
    )
    for row in summary_rows:
        summary.append(row)
    for cell in summary["A"]:
        cell.font = Font(bold=True)
    for row in summary.iter_rows():
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
    summary.column_dimensions["A"].width = 28
    summary.column_dimensions["B"].width = 72


def _append_legacy_control_sheets(workbook: Workbook, report: JsonAuditReport) -> None:
    controls = workbook.create_sheet("Contrôles")
    controls.append(("Contrôle", "Titre", "Statut", "Constat", "Risque", "Recommandation"))
    for view in finding_views(report):
        finding = view.finding
        controls.append(
            (
                spreadsheet_text(finding.control_id),
                spreadsheet_text(finding.title),
                spreadsheet_text(finding.status.value),
                spreadsheet_text(finding.message),
                spreadsheet_text(risk_text_legacy(finding.risk)),
                spreadsheet_text(finding.recommendation),
            )
        )
    _style_sheet(controls, filter_columns=6)
    for index, width in enumerate((22, 32, 12, 48, 60, 48), start=1):
        controls.column_dimensions[get_column_letter(index)].width = width

    enriched = workbook.create_sheet("Contrôles enrichis")
    headers = (
        "Contrôle",
        "Titre",
        "Catégorie",
        "Priorité",
        "Sévérité",
        "Applicabilité",
        "Statut",
        "Constat",
        "Preuve",
        "Objets affectés",
        "Risque",
        "Recommandation",
        "Remédiation",
        "Approbation client",
    )
    enriched.append(headers)
    for view in finding_views(report):
        finding = view.finding
        enriched.append(
            tuple(
                spreadsheet_text(value)
                for value in (
                    finding.control_id,
                    finding.title,
                    finding.category,
                    finding.priority.value,
                    finding.severity.value,
                    finding.applicability.value,
                    finding.status.value,
                    finding.message,
                    view.proof,
                    objects_text_legacy(finding.affected_objects),
                    risk_text_legacy(finding.risk),
                    finding.recommendation,
                    finding.remediation,
                    finding.customer_approval,
                )
            )
        )
    _style_sheet(enriched, filter_columns=14)
    for index, width in enumerate(
        (22, 32, 18, 12, 14, 18, 12, 48, 70, 40, 70, 48, 60, 20),
        start=1,
    ):
        enriched.column_dimensions[get_column_letter(index)].width = width


def _append_audit_configuration(workbook: Workbook, report: JsonAuditReport) -> None:
    sheet = workbook.create_sheet("Audit configuration")
    sheet.append(
        (
            "ID",
            "Contrôle",
            "Catégorie",
            "Résultat",
            "Conformité",
            "Risque",
            "Recommandation",
            "Remédiation",
        )
    )
    conformity = {
        "PASS": "Conforme",
        "FAIL": "Non conforme",
        "UNKNOWN": "À qualifier",
        "NOT_APPLICABLE": "Hors périmètre",
        "ERROR": "Erreur",
    }
    for view in finding_views(report):
        finding = view.finding
        sheet.append(
            tuple(
                spreadsheet_text(value)
                for value in (
                    finding.control_id,
                    finding.title,
                    finding.category,
                    finding.status.value,
                    conformity[finding.status.value],
                    view.risk_description,
                    view.recommendation,
                    view.remediation,
                )
            )
        )
    _style_sheet(sheet, filter_columns=8)
    for index, width in enumerate((22, 36, 20, 14, 18, 60, 52, 60), start=1):
        sheet.column_dimensions[get_column_letter(index)].width = width


def _append_actions_sheet(
    workbook: Workbook,
    report: JsonAuditReport,
    title: str,
    approval: bool,
) -> None:
    sheet = workbook.create_sheet(title)
    sheet.append(
        (
            "ID",
            "Point audité",
            "Risque",
            "Impact",
            "Vraisemblance",
            "Action recommandée",
            "Remédiation",
        )
    )
    for view in action_views(report, approval):
        sheet.append(
            tuple(
                spreadsheet_text(value)
                for value in (
                    view.finding.control_id,
                    view.finding.title,
                    view.risk_description,
                    view.impact,
                    view.likelihood,
                    view.recommendation,
                    view.remediation,
                )
            )
        )
    _style_sheet(sheet, filter_columns=7)
    for index, width in enumerate((22, 36, 60, 24, 24, 52, 60), start=1):
        sheet.column_dimensions[get_column_letter(index)].width = width


def _append_statistics_sheet(workbook: Workbook, report: JsonAuditReport) -> None:
    sheet = workbook.create_sheet("Statistiques")
    sheet.append(("Indicateur", "Valeur"))
    counts = status_counts(report)
    sheet.append(("Total contrôles", len(report.findings)))
    for status in ("FAIL", "PASS", "UNKNOWN", "NOT_APPLICABLE", "ERROR"):
        sheet.append((f"Statut {status}", counts.get(status, 0)))
    match_statistics = report.context.rule_match_statistics
    sheet.append(
        (
            "Règles sans match (observation opérateur)",
            match_statistics.unmatched_rules if match_statistics else "Non renseigné",
        )
    )
    sheet.append(
        (
            "Source règles sans match",
            spreadsheet_text(match_statistics.source) if match_statistics else "Non renseigné",
        )
    )
    sheet.append(
        (
            "Méthode règles sans match",
            spreadsheet_text(match_statistics.method) if match_statistics else "Non renseigné",
        )
    )
    categories: dict[str, int] = {}
    for finding in report.findings:
        categories[finding.category] = categories.get(finding.category, 0) + 1
    for category, count in sorted(categories.items()):
        sheet.append((f"Catégorie {category}", count))
    _style_sheet(sheet)
    sheet.column_dimensions["A"].width = 32
    sheet.column_dimensions["B"].width = 18


def _append_accounts_sheet(workbook: Workbook, report: JsonAuditReport) -> None:
    sheet = workbook.create_sheet("Comptes")
    sheet.append(("Nom", "Type", "MFA / 2FA", "Peer authentication"))
    for account in report.accounts:
        sheet.append(
            (
                spreadsheet_text(account.name),
                spreadsheet_text(account.kind),
                spreadsheet_text(account.two_factor),
                spreadsheet_text(account.peer_auth),
            )
        )
    _style_sheet(sheet, filter_columns=4)
    for index, width in enumerate((30, 24, 20, 24), start=1):
        sheet.column_dimensions[get_column_letter(index)].width = width


def _append_equipment_sheet(workbook: Workbook, report: JsonAuditReport) -> None:
    sheet = workbook.create_sheet("Métadonnées équipement")
    equipment = report.equipment
    rows = (
        ("Hostname", equipment.hostname),
        ("Modèle", equipment.model),
        ("Version FortiOS", equipment.firmware_version),
        ("Numéro de série", equipment.serial_number or report.context.serial_number),
        ("Interfaces", ", ".join(equipment.interface_names)),
        ("Zones", ", ".join(equipment.zone_names)),
        ("Zones SD-WAN", ", ".join(equipment.sdwan_zone_names)),
        ("Relations interface → zone", "\n".join(equipment.interface_zone_relations)),
    )
    for row in rows:
        sheet.append(tuple(spreadsheet_text(value) for value in row))
    sheet.column_dimensions["A"].width = 32
    sheet.column_dimensions["B"].width = 72
    for cell in sheet["A"]:
        cell.font = Font(bold=True)
    for row in sheet.iter_rows():
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")


def render_xlsx(report: JsonAuditReport) -> bytes:
    workbook = Workbook()
    _append_context_sheet(workbook, report)
    _append_legacy_control_sheets(workbook, report)
    _append_audit_configuration(workbook, report)
    _append_actions_sheet(workbook, report, "Actions sans accord", approval=False)
    _append_actions_sheet(workbook, report, "Actions avec accord", approval=True)
    _append_statistics_sheet(workbook, report)
    _append_accounts_sheet(workbook, report)
    _append_equipment_sheet(workbook, report)

    output = BytesIO()
    workbook.save(output)
    return output.getvalue()

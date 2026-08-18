from collections import Counter
from dataclasses import dataclass

from vysion.audit.models import AffectedObject, AuditFinding, EvidenceItem, RiskAssessment
from vysion.reports.json_report import JsonAuditReport

DOMAIN_LABELS = {
    "system": "Système",
    "administration": "Administration / Identity",
    "identity": "Administration / Identity",
    "iam": "Administration / Identity",
    "network": "Réseau",
    "firewall": "Firewall",
    "vpn": "VPN",
    "utm": "UTM",
    "wifi": "Wi-Fi",
}


def domain_label(finding: AuditFinding) -> str:
    prefix = finding.control_id.split("-")[0].casefold()
    return DOMAIN_LABELS.get(finding.category.casefold(), DOMAIN_LABELS.get(prefix, "Autre"))


def display(value: object) -> str:
    if value is None or value == "":
        return "Non renseigné"
    return str(value)


def evidence_text(finding: AuditFinding) -> str:
    structured_items = list(finding.evidence_items)
    structured_items.extend(
        item
        for item in finding.evidence
        if isinstance(item, EvidenceItem) and item not in structured_items
    )
    structured = "\n".join(
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
        for item in structured_items
    )
    legacy = "\n".join(str(item) for item in finding.evidence if isinstance(item, str))
    return "\n".join(item for item in (structured, legacy) if item) or "Non renseigné"


def objects_text(objects: tuple[AffectedObject, ...]) -> str:
    return ", ".join(f"{item.object_type}: {item.name}" for item in objects) or "Non renseigné"


def risk_text(risk: RiskAssessment | None) -> str:
    if risk is None:
        return "Non renseigné"
    return "\n".join(
        part
        for part in (
            risk.summary,
            f"Impact: {risk.impact}" if risk.impact else None,
            f"Vraisemblance: {risk.likelihood}" if risk.likelihood else None,
            f"Traitement: {risk.treatment}" if risk.treatment else None,
        )
        if part
    ) or "Non renseigné"


@dataclass(frozen=True)
class FindingView:
    finding: AuditFinding
    risk_description: str
    impact: str
    likelihood: str
    correction_complexity: str
    proof: str
    objects: str

    @classmethod
    def from_finding(cls, finding: AuditFinding) -> "FindingView":
        risk = finding.risk
        return cls(
            finding=finding,
            risk_description=risk.summary if risk else finding.message,
            impact=display(risk.impact if risk else None),
            likelihood=display(risk.likelihood if risk else None),
            correction_complexity=display(risk.treatment if risk else None),
            proof=evidence_text(finding),
            objects=objects_text(finding.affected_objects),
        )

    @property
    def client_problem(self) -> str:
        return self.finding.message

    @property
    def recommendation(self) -> str:
        return display(self.finding.recommendation)

    @property
    def remediation(self) -> str:
        return display(self.finding.remediation)


def finding_views(report: JsonAuditReport) -> tuple[FindingView, ...]:
    return tuple(FindingView.from_finding(finding) for finding in report.findings)


def status_counts(report: JsonAuditReport) -> Counter[str]:
    return Counter(finding.status.value for finding in report.findings)


def severity_counts(report: JsonAuditReport) -> Counter[str]:
    return Counter(finding.severity.value for finding in report.findings)


def category_counts(report: JsonAuditReport) -> Counter[str]:
    return Counter(finding.category for finding in report.findings)


def context_rows(report: JsonAuditReport) -> tuple[tuple[str, str], ...]:
    context = report.context
    license_details = context.utm_license_details
    provenance = context.operator_provenance
    license_value = None
    if license_details is not None:
        license_value = license_details.status.value if license_details.status else None
        if license_details.expiration_date:
            license_value = (
                f"{license_value or 'Non renseigné'} — "
                f"{license_details.expiration_date.isoformat()}"
            )
    elif context.utm_license is not None:
        license_value = "active" if context.utm_license else "inactive"
    selected = context.wan_selections or ()
    selected_text = ", ".join(f"{item.kind.value}: {item.name}" for item in selected)
    if not selected_text:
        selected_text = ", ".join(context.selected_wans or ())
    return (
        ("Client", display(context.client)),
        ("Site", display(context.site)),
        ("Numéro de série", display(context.serial_number or report.equipment.serial_number)),
        ("Hostname", display(report.equipment.hostname)),
        ("Modèle", display(report.equipment.model)),
        ("Version FortiOS", display(report.equipment.firmware_version)),
        ("Interfaces", display(", ".join(report.equipment.interface_names) or None)),
        ("Zones", display(", ".join(report.equipment.zone_names) or None)),
        ("Zones SD-WAN", display(", ".join(report.equipment.sdwan_zone_names) or None)),
        (
            "Relations interface → zone",
            display("\n".join(report.equipment.interface_zone_relations) or None),
        ),
        ("Uptime", display(context.uptime)),
        ("Commentaire contexte", display(context.operator_comment)),
        (
            "Règles sans match",
            display(
                context.rule_match_statistics.unmatched_rules
                if context.rule_match_statistics
                else None
            ),
        ),
        (
            "Source règles sans match",
            display(
                context.rule_match_statistics.source
                if context.rule_match_statistics
                else None
            ),
        ),
        (
            "Méthode règles sans match",
            display(
                context.rule_match_statistics.method
                if context.rule_match_statistics
                else None
            ),
        ),
        ("WAN sélectionnées", display(selected_text or None)),
        ("HA", display(context.ha)),
        ("MPLS/L2L", display(context.mpls)),
        ("Licence UTM", display(license_value)),
        (
            "Provenance licence UTM",
            display(license_details.provenance if license_details else None),
        ),
        ("Opérateur réseau", display(context.operator)),
        ("Provenance contexte", display(provenance.source if provenance else None)),
        ("Opérateur de saisie", display(provenance.operator if provenance else None)),
        ("Méthode", display(provenance.method if provenance else None)),
    )


def action_views(report: JsonAuditReport, approval: bool) -> tuple[FindingView, ...]:
    return tuple(
        view
        for view in finding_views(report)
        if view.finding.status.value == "FAIL"
        and (
            view.finding.customer_approval is True
            if approval
            else view.finding.customer_approval is not True
        )
    )

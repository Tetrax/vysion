from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

from openpyxl import load_workbook

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    AffectedObject,
    Applicability,
    AuditContext,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    ContextProvenance,
    EvidenceItem,
    RiskAssessment,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry
from vysion.reports.docx_report import render_docx
from vysion.reports.json_report import EquipmentMetadata, JsonAuditReport
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


def _enriched_report() -> JsonAuditReport:
    created_at = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    return JsonAuditReport(
        report_id=uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=5),
        source_name="=customer-source",
        fortiguard=FortiGuardResult(
            status=FortiGuardStatus.UNKNOWN,
            detail="@fixture",
        ),
        context=AuditContext(
            selected_wans=("wan1",),
            operator_provenance=ContextProvenance(source="operator-form", operator="analyst"),
            client="+client",
            site="-site",
            ha=None,
            mpls=False,
            utm_license=True,
        ),
        equipment=EquipmentMetadata(
            hostname="fgt-paris",
            policy_count=12,
            policy_enabled_count=9,
            policy_disabled_count=2,
            policy_status_unknown_count=1,
            service_object_count=8,
            vip_count=3,
            security_profile_count=6,
            ipsec_tunnel_count=2,
            ssl_vpn_configured=True,
            ha_configured=False,
        ),
        findings=(
            AuditFinding(
                control_id="NET-WAN-MGMT-001",
                title="=WAN management",
                status=AuditStatus.FAIL,
                category="network",
                priority=AuditPriority.P0,
                severity=AuditSeverity.HIGH,
                applicability=Applicability.APPLICABLE,
                evidence=("=legacy evidence",),
                evidence_items=(
                    EvidenceItem(
                        section="system interface",
                        entry="wan1",
                        directive="allowaccess",
                        tokens=("ping", "ssh"),
                        line=3,
                    ),
                ),
                affected_objects=(AffectedObject(name="wan1", object_type="interface"),),
                message="-message",
                risk=RiskAssessment(
                    summary="@risk",
                    impact="impact",
                    likelihood="high",
                    treatment="treat",
                ),
                recommendation="+recommendation",
                remediation="remediation",
                customer_approval=None,
            ),
        ),
    )


def test_docx_renders_context_and_all_enriched_finding_fields_from_json_report() -> None:
    with ZipFile(BytesIO(render_docx(_enriched_report()))) as package:
        document = package.read("word/document.xml").decode("utf-8")

    for value in (
        "operator-form",
        "analyst",
        "client",
        "site",
        "wan1",
        "network",
        "P0",
        "high",
        "applicable",
        "allowaccess",
        "interface",
        "@risk",
        "impact",
        "high",
        "treat",
        "+recommendation",
        "remediation",
        "Non renseigné",
    ):
        assert value in document


def test_xlsx_renders_context_and_all_enriched_finding_fields_as_safe_text() -> None:
    workbook = load_workbook(
        BytesIO(render_xlsx(_enriched_report())),
        read_only=False,
        data_only=False,
    )

    assert workbook.sheetnames[:3] == ["Synthèse", "Contrôles", "Contrôles enrichis"]
    assert {
        "Audit configuration",
        "Actions sans accord",
        "Actions avec accord",
        "Statistiques",
        "Comptes",
        "Métadonnées équipement",
        "Inventaire configuration",
    } <= set(workbook.sheetnames)
    context_values = [cell.value for row in workbook["Synthèse"].iter_rows() for cell in row]
    assert "operator-form" in context_values
    assert "analyst" in context_values
    assert "wan1" in context_values
    controls = list(workbook["Contrôles enrichis"].iter_rows(values_only=True))
    assert controls[0] == (
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
    row = controls[1]
    assert row[2:7] == ("network", "P0", "high", "applicable", "FAIL")
    assert "allowaccess" in row[8]
    assert "wan1" in row[9]
    assert "@risk" in row[10]
    assert row[13] == "Non renseigné"
    assert workbook["Actions sans accord"]["A2"].value == "NET-WAN-MGMT-001"
    assert workbook["Actions avec accord"].max_row == 1
    inventory = dict(
        workbook["Inventaire configuration"].iter_rows(values_only=True)
    )
    assert inventory["Règles firewall"] == 12
    assert inventory["Règles firewall actives (explicites)"] == 9
    assert inventory["Règles firewall désactivées (explicites)"] == 2
    assert inventory["Règles firewall statut inconnu"] == 1
    assert inventory["Objets service"] == 8
    assert inventory["VIP / groupes VIP / virtual servers"] == 3
    assert inventory["Profils de sécurité"] == 6
    assert inventory["Tunnels IPsec phase 1"] == 2
    assert inventory["SSL-VPN configuré"] == "Oui"
    assert inventory["HA configuré"] == "Non"

    for sheet in workbook.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.startswith(("=", "+", "-", "@")):
                    raise AssertionError(f"formula-like cell was not escaped: {cell.coordinate}")


def test_legacy_evidence_item_is_rendered_across_docx_and_xlsx() -> None:
    finding = _enriched_report().findings[0].model_copy(
        update={
            "evidence": (
                EvidenceItem(
                    section="system interface",
                    entry="wan1",
                    directive="allowaccess",
                    tokens=("https",),
                    line=42,
                ),
            ),
            "evidence_items": (),
        }
    )
    report = _enriched_report().model_copy(update={"findings": (finding,)})

    with ZipFile(BytesIO(render_docx(report))) as package:
        document = package.read("word/document.xml").decode("utf-8")
    assert "allowaccess" in document
    assert "ligne 42" in document

    workbook = load_workbook(BytesIO(render_xlsx(report)), data_only=False)
    proof = workbook["Contrôles enrichis"]["I2"].value
    assert isinstance(proof, str)
    assert "allowaccess" in proof
    assert "ligne 42" in proof


def test_m5_json_docx_xlsx_share_all_finding_ids() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "anonymized_fortigate_export.conf"
    configuration = FortiGateParser().parse(fixture.read_text(encoding="utf-8"))
    findings = AuditEngine(default_registry()).run(configuration)
    created_at = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
    report = JsonAuditReport(
        report_id=uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=5),
        source_name=fixture.name,
        fortiguard=FortiGuardResult(
            status=FortiGuardStatus.UNKNOWN,
            detail="fixture",
        ),
        findings=tuple(findings),
    )

    json_ids = [finding.control_id for finding in report.findings]
    assert len(json_ids) == 40
    assert {"NET-CTI-WAN-001", "NET-ISDB-WAN-001"}.isdisjoint(json_ids)
    assert json_ids[-24:] == [
        "UTM-LICENSE-001",
        "UTM-AUTOUPDATE-001",
        "UTM-DNSFILTER-001",
        "UTM-WEBFILTER-001",
        "UTM-ANTIVIRUS-001",
        "UTM-IPS-001",
        "UTM-APPCONTROL-001",
        "IAM-LDAPS-001",
        "EXT-PSIRT-001",
        "SYS-BACKUP-AUTO-001",
        "CFG-REF-INTEGRITY-001",
        "SYS-AUTO-INSTALL-USB-001",
        "SYS-FORTIMANAGER-SYNC-001",
        "SYS-FORTIANALYZER-SYNC-001",
        "SYS-ADMIN-HTTPS-PORT-001",
        "NET-SIP-ALG-001",
        "HA-SESSION-PICKUP-001",
        "HA-HEARTBEAT-REDUNDANCY-001",
        "HA-OVERRIDE-001",
        "HA-CABLING-REDUNDANCY-001",
        "UTM-FORTISANDBOX-CLOUD-001",
        "UTM-FORTIGUARD-ANYCAST-001",
        "NET-SDWAN-USAGE-001",
        "FW-BY-SEQUENCE-USAGE-001",
    ]

    with ZipFile(BytesIO(render_docx(report))) as package:
        document = package.read("word/document.xml").decode("utf-8")
    assert all(control_id in document for control_id in json_ids)

    workbook = load_workbook(BytesIO(render_xlsx(report)), read_only=True, data_only=True)
    xlsx_ids = [
        row[0]
        for row in list(workbook["Contrôles"].iter_rows(values_only=True))[1:]
    ]
    assert xlsx_ids == json_ids

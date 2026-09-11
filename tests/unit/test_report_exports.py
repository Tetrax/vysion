import re
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
from vysion.reports.business_text import business_text_for, client_result_for
from vysion.reports.docx_report import render_docx
from vysion.reports.json_report import JsonAuditReport
from vysion.reports.presentation import build_presentation, present_finding
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


def test_docx_renders_v1_client_language_without_engine_fields() -> None:
    finding = (
        _enriched_report()
        .findings[0]
        .model_copy(update={"remediation": "Retirer admin des namespaces concernés"})
    )
    report = _enriched_report().model_copy(update={"findings": (finding,)})
    with ZipFile(BytesIO(render_docx(report))) as package:
        document = package.read("word/document.xml").decode("utf-8")

    assert "Audit de configuration" in document
    assert "Point audité :" in document
    assert "Résultat :" in document
    assert "NON CONFORME" in document
    for value in (
        "operator-form",
        "analyst",
        "P0",
        "applicable",
        "allowaccess",
        "@risk",
        "+recommendation",
        "evidence_items",
        "line=3",
        "namespace",
    ):
        assert value not in document


def test_client_exports_use_v1_display_name_and_v1_v2_matrix() -> None:
    finding = AuditFinding(
        control_id="IAM-ADMIN-MFA-001",
        title="IAM-ADMIN-MFA-001",
        status=AuditStatus.FAIL,
        message="Compte sans MFA",
    )
    presented = present_finding(finding)
    report = _enriched_report().model_copy(
        update={
            "findings": (presented,),
            "presentation": build_presentation((finding,)),
        }
    )

    with ZipFile(BytesIO(render_docx(report))) as package:
        document = package.read("word/document.xml").decode("utf-8")
    assert "MFA pour les comptes admins et utilisateurs" in document
    assert "IAM-ADMIN-MFA-001" not in document

    workbook = load_workbook(BytesIO(render_xlsx(report)), read_only=True, data_only=True)
    client_controls = list(workbook["Contrôles"].iter_rows(values_only=True))
    assert client_controls[1][0] == "IAM-ADMIN-MFA-001"
    assert client_controls[1][1] == "MFA des administrateurs"
    matrix_rows = list(workbook["Matrice V1-V2"].iter_rows(values_only=True))
    assert matrix_rows[0] == (
        "Contrôle V1",
        "Libellé métier V1",
        "Contrôle(s) V2 correspondant(s)",
        "Relation",
        "Classification",
        "Résultat client",
    )
    assert any(row[1] == "MFA des administrateurs" for row in matrix_rows[1:])


def test_guest_client_wording_hides_internal_namespace_evidence() -> None:
    finding = AuditFinding(
        control_id="IAM-GUEST-ACCOUNT-001",
        title="Absence du compte guest",
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=("compte guest absent des namespaces certains",),
        message="Le compte par défaut guest est absent des namespaces certains.",
    )

    assert client_result_for(finding) == (
        "Le compte guest n'a pas été détecté dans la configuration analysée."
    )

    report = _enriched_report().model_copy(update={"findings": (finding,)})
    with ZipFile(BytesIO(render_docx(report))) as package:
        document = package.read("word/document.xml").decode("utf-8")

    assert "Le compte guest n'a pas été détecté dans la configuration analysée." not in document
    forbidden = (
        "namespace",
        "parser",
        "projection",
        "proof_state",
        "ambiguous",
        "defaulted",
        "control_id",
        "provenance",
        "evidence",
        "internal",
        "typed projection",
        "line number",
        "JSON",
        "engine",
        "registry",
    )
    assert all(
        re.search(rf"\b{re.escape(term)}\b", document, flags=re.IGNORECASE) is None
        for term in forbidden
    )


def test_docx_hides_not_applicable_findings_from_the_business_body() -> None:
    applicable = _enriched_report().findings[0]
    not_applicable = AuditFinding(
        control_id="VPN-SSL-001",
        title="État et usage explicites du SSL-VPN",
        status=AuditStatus.NOT_APPLICABLE,
        applicability=Applicability.NOT_APPLICABLE,
        message="Le VPN SSL n'est pas utilisé.",
    )
    pass_finding = AuditFinding(
        control_id="NET-SDWAN-USAGE-001",
        title="Utilisation du SD-WAN",
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        message="Le SD-WAN est correctement utilisé.",
    )
    unknown_finding = AuditFinding(
        control_id="NET-GEO-IP-USAGE-001",
        title="Utilisation de la GEO-IP",
        status=AuditStatus.UNKNOWN,
        applicability=Applicability.APPLICABLE,
        message="La configuration GEO-IP ne permet pas de conclure.",
    )
    report = _enriched_report().model_copy(
        update={"findings": (applicable, pass_finding, unknown_finding, not_applicable)}
    )

    with ZipFile(BytesIO(render_docx(report))) as package:
        document = package.read("word/document.xml").decode("utf-8")

    assert "Durcissement accès administration à votre Fortigate" in document
    assert "Utilisation du SD-WAN" in document
    assert "Utilisation de la GEO-IP" in document
    assert "Utilisation du VPN SSL" in document
    assert "NON APPLICABLE" in document


def test_docx_uses_v1_business_prose_and_detected_values() -> None:
    finding = AuditFinding(
        control_id="FW-INTERNET-ALL-SERVICE-001",
        title="Services ALL vers Internet",
        status=AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        affected_objects=(AffectedObject(name="23", object_type="policy"),),
        message=(
            "Tous les ports sont ouverts dans la règle ID : 23. "
            "(fortigate-sensitive-protocols 2026-08-13)"
        ),
        risk=RiskAssessment(
            summary="Une politique Internet peut autoriser tous les services.",
            impact="SIGNIFICATIF",
            likelihood="TRÈS VRAISEMBLABLE",
            treatment="RAISONNABLE",
        ),
        recommendation="Remplacer ALL par une allowlist de services nécessaire.",
        remediation="Limiter les services autorisés vers Internet.",
    )
    report = _enriched_report().model_copy(update={"findings": (finding,)})

    with ZipFile(BytesIO(render_docx(report))) as package:
        document = package.read("word/document.xml").decode("utf-8")

    assert "Filtrage des ports au strict minimum pour les flux vers Internet." in document
    assert "Tous les ports sont ouverts dans la règle ID : 23." in document
    assert "Ouvrir trop de ports sur un pare-feu expose le réseau" in document
    assert "fortigate-sensitive-protocols" not in document
    assert "Vérification de la bonne pratique suivante" not in document
    assert "met en évidence une non-conformité nécessitant une action corrective" not in document


def test_xlsx_renders_context_and_all_enriched_finding_fields_as_safe_text() -> None:
    workbook = load_workbook(
        BytesIO(render_xlsx(_enriched_report())),
        read_only=False,
        data_only=False,
    )

    assert workbook.sheetnames == [
        "Synthèse",
        "Contrôles",
        "Contrôles enrichis",
        "Matrice V1-V2",
    ]
    context_values = [cell.value for row in workbook["Synthèse"].iter_rows() for cell in row]
    assert "operator-form" in context_values
    assert "analyst" in context_values
    assert "wan1" in context_values
    controls = list(workbook["Contrôles enrichis"].iter_rows(values_only=True))
    assert controls[0] == (
        "Contrôle V2 (interne)",
        "Libellé métier V1",
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

    for sheet in workbook.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.startswith(("=", "+", "-", "@")):
                    raise AssertionError(f"formula-like cell was not escaped: {cell.coordinate}")


def test_structured_evidence_item_stays_in_xlsx_not_client_docx() -> None:
    finding = (
        _enriched_report()
        .findings[0]
        .model_copy(
            update={
                "evidence": (),
                "evidence_items": (
                    EvidenceItem(
                        section="system interface",
                        entry="wan1",
                        directive="allowaccess",
                        tokens=("https",),
                        line=42,
                    ),
                ),
            }
        )
    )
    report = _enriched_report().model_copy(update={"findings": (finding,)})

    with ZipFile(BytesIO(render_docx(report))) as package:
        document = package.read("word/document.xml").decode("utf-8")
    assert "allowaccess" not in document
    assert "ligne 42" not in document

    workbook = load_workbook(BytesIO(render_xlsx(report)), data_only=False)
    proof = workbook["Contrôles enrichis"]["I2"].value
    assert isinstance(proof, str)
    assert "allowaccess" in proof
    assert "ligne 42" in proof


def test_m5_json_xlsx_keep_finding_ids_but_docx_is_client_facing() -> None:
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
    assert len(json_ids) == 60
    assert {"NET-CTI-WAN-001", "NET-ISDB-WAN-001"}.isdisjoint(json_ids)
    assert json_ids[-44:] == [
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
        "UTM-MAIL-FILTER-USAGE-001",
        "FW-SSL-SSH-PROFILE-001",
        "CFG-UNUSED-SERVICE-001",
        "IAM-LEGACY-ADMIN-001",
        "IAM-LEGACY-PKI-REMOVAL-001",
        "IAM-LEGACY-PKI-PRESENCE-001",
        "NET-LEGACY-ADMIN-LOOPBACK-001",
        "DNS-LEGACY-DATABASE-001",
        "NET-GEO-IP-USAGE-001",
        "NET-RFC6890-BLACKHOLE-001",
        "FW-LEGACY-SCHEDULE-INVENTORY-001",
        "WIFI-FORTIAP-OBSOLETE-001",
        "WIFI-SSID-LIMIT-001",
        "WIFI-RADIO2-40MHZ-001",
        "WIFI-DARRP-001",
        "WIFI-FREQUENCY-HANDOFF-001",
        "WIFI-TIM-001",
        "WIFI-BAND-001",
        "WIFI-CHANNELS-001",
        "WIFI-SHORT-GUARD-INTERVAL-001",
    ]

    with ZipFile(BytesIO(render_docx(report))) as package:
        document = package.read("word/document.xml").decode("utf-8")
    assert all(control_id not in document for control_id in json_ids)
    assert all(business_text_for(finding) is not None for finding in report.findings)
    assert all(
        finding.title not in document
        for finding in report.findings
        if finding.status is AuditStatus.NOT_APPLICABLE
    )
    assert "Vérification de la bonne pratique suivante" not in document
    assert "met en évidence une non-conformité nécessitant une action corrective" not in document

    workbook = load_workbook(BytesIO(render_xlsx(report)), read_only=True, data_only=True)
    xlsx_ids = [row[0] for row in list(workbook["Contrôles"].iter_rows(values_only=True))[1:]]
    assert xlsx_ids == json_ids

from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

from docx import Document

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry
from vysion.reports.docx_report import render_docx
from vysion.reports.json_report import JsonAuditReport
from vysion.reports.presentation import build_presentation, present_findings

CONFIGURATION = Path("/home/hermes/.hermes/attachments/FW-AVR-01_7-2_1639_202608121044.conf")


def _real_report() -> JsonAuditReport:
    configuration = FortiGateParser().parse(CONFIGURATION.read_text(encoding="utf-8"))
    findings = tuple(AuditEngine(default_registry()).run(configuration, AuditContext()))
    presented = present_findings(findings)
    created_at = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
    return JsonAuditReport(
        report_id=uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=5),
        source_name=CONFIGURATION.name,
        context=AuditContext(),
        device_identity=configuration.device_identity,
        fortiguard=FortiGuardResult(
            status=FortiGuardStatus.UNKNOWN,
            detail="fixture",
        ),
        findings=presented,
        presentation=build_presentation(findings, configuration, AuditContext()),
    )


def test_docx_uses_the_v1_document_order_and_keeps_ssl_vpn_na() -> None:
    document = Document(BytesIO(render_docx(_real_report())))
    headings = [
        paragraph.text.strip()
        for paragraph in document.paragraphs
        if paragraph.style.name.startswith("Heading")
    ]

    expected = [
        "3. Audit de configuration",
        "3.1 Audit - Système",
        "3.1.1 Version Fortigate",
        "3.1.2 Modèle Fortigate",
        "3.1.3 Sauvegardes automatiques des révisions FortiGate",
        "3.1.4 Objets sans référence",
        "3.1.5 Auto-installation USB FortiGate",
        "3.1.6 Synchronisation FortiManager",
        "3.1.7 Synchronisation FortiAnalyzer",
        "3.1.8 Port HTTPS d'administration personnalisé",
        "3.2 Audit - Administration et comptes",
        "3.2.1 Protocoles d'administration sur interfaces WAN",
        "3.2.2 MFA des administrateurs",
        "3.3 Audit - Réseaux et flux",
        "3.3.1 Journalisation du deny implicite",
        "3.3.2 Services ALL vers Internet",
        "3.3.3 Refus explicite des protocoles sensibles",
        "3.3.4 Désactivation SIP ALG",
        "3.3.5 Utilisation du SD-WAN pour les WAN sélectionnées",
        "3.4 Audit - Cluster",
        "3.5 Audit - Connexions distantes VPN",
        "3.5.1 Utilisation du VPN SSL",
        "3.6 Audit - Profils de sécurité UTM",
        "3.6.1 Licence UTM",
        "3.6.2 Mises à jour AV/IPS",
    ]
    positions = [headings.index(value) for value in expected]
    assert positions == sorted(positions)
    assert "NON APPLICABLE" in "\n".join(paragraph.text for paragraph in document.paragraphs)


def test_docx_keeps_the_v1_logo_placeholder_without_client_logo() -> None:
    document = Document(BytesIO(render_docx(_real_report())))
    body = "\n".join(paragraph.text for paragraph in document.paragraphs)

    assert "LOGO CLIENT si existe" in body


def test_docx_inserts_a_client_logo_when_one_is_available() -> None:
    logo = Path(__file__).parents[2] / "src" / "vysion" / "reports" / "assets" / "cluster.png"
    document = Document(BytesIO(render_docx(_real_report(), client_logo_path=logo)))
    body = "\n".join(paragraph.text for paragraph in document.paragraphs)

    assert "LOGO CLIENT si existe" not in body
    assert len(document.inline_shapes) >= 5


def test_docx_embeds_v1_business_diagrams_in_the_report_body() -> None:
    with ZipFile(BytesIO(render_docx(_real_report()))) as package:
        document_xml = package.read("word/document.xml").decode("utf-8")

    assert document_xml.count("<pic:pic") >= 4

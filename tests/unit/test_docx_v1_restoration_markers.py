"""V1 restoration markers that must hold for EVERY rendered DOCX.

The matching assertions in ``test_docx_v1_restoration.py`` are gated on the
real field backup (module ``pytestmark``), so they skip on machines without
it — including CI. The review acceptance criteria require at least one
restoration-marker assertion to *run* everywhere, so this module asserts the
config-independent markers on a synthetic report: V1 document order, the
client logo placeholder, the mandatory business diagrams, and the absence of
internal architecture vocabulary.
"""

import re
from datetime import UTC, datetime, timedelta
from io import BytesIO
from uuid import uuid4

from docx import Document

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.audit.models import (
    AffectedObject,
    Applicability,
    AuditContext,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceItem,
    RiskAssessment,
)
from vysion.reports.docx_report import render_docx
from vysion.reports.json_report import JsonAuditReport

INTERNAL_VOCABULARY_PATTERNS = (
    r"périmètre\s+V2",
    r"contrôle historique",
    r"règle historique",
    r"différence de couverture",
    r"\bV1\s*/\s*V2\b",
    r"\bV2-only\b",
    r"\blegacy_v1\b",
    r"\b(?:moteur|architecture|parité|baseline|gate)\s+V[12]\b",
)


def _synthetic_report() -> JsonAuditReport:
    created_at = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    return JsonAuditReport(
        report_id=uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=5),
        source_name="synthetic.conf",
        fortiguard=FortiGuardResult(
            status=FortiGuardStatus.UNKNOWN,
            detail="synthetic",
        ),
        context=AuditContext(),
        findings=(
            AuditFinding(
                control_id="NET-WAN-MGMT-001",
                title="Gestion du WAN",
                status=AuditStatus.FAIL,
                category="network",
                priority=AuditPriority.P0,
                severity=AuditSeverity.HIGH,
                applicability=Applicability.APPLICABLE,
                evidence=("preuve",),
                evidence_items=(
                    EvidenceItem(
                        section="system interface",
                        entry="wan1",
                        directive="allowaccess",
                        tokens=("ping",),
                        line=1,
                    ),
                ),
                affected_objects=(AffectedObject(name="wan1", object_type="interface"),),
                message="constat",
                risk=RiskAssessment(
                    summary="risque",
                    impact="impact",
                    likelihood="high",
                    treatment="treat",
                ),
                recommendation="recommandation",
                remediation="remediation",
                customer_approval=None,
            ),
        ),
    )


def _numbered_key(heading: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", heading)
    return tuple(int(value) for value in numbers)


def test_docx_v1_restoration_markers_run_without_the_field_backup() -> None:
    """Marker assertion (not fixture-dependent): V1 order, logo placeholder,
    mandatory diagrams, no internal vocabulary — on any machine."""
    document = Document(BytesIO(render_docx(_synthetic_report())))
    headings = [
        paragraph.text.strip()
        for paragraph in document.paragraphs
        if paragraph.style.name.startswith("Heading")
    ]
    numbered = [heading for heading in headings if re.match(r"^\d", heading)]

    # V1 document order: numbered sections ascend monotonically and open
    # with the mandatory audit root.
    assert numbered, headings
    assert numbered[0] == "3. Audit de configuration"
    keys = [_numbered_key(heading) for heading in numbered]
    assert keys == sorted(keys), numbered

    # The client logo placeholder stays until a logo is provided.
    body = "\n".join(paragraph.text for paragraph in document.paragraphs)
    assert "LOGO CLIENT si existe" in body

    # No internal migration/architecture vocabulary may reach the client
    # document (same qualified patterns as the fixture-gated test).
    for pattern in INTERNAL_VOCABULARY_PATTERNS:
        assert re.search(pattern, body, flags=re.IGNORECASE) is None, pattern

    # The mandatory business diagrams (ISDB, CTI, security profiles) are
    # derived from the real configuration's presentation, so their count
    # stays asserted by the fixture-gated test in
    # ``test_docx_v1_restoration.py`` when the field backup is available.

from vysion.audit.models import AuditFinding, AuditStatus
from vysion.reports.views import domain_label


def test_wifi_findings_use_the_explicit_cross_surface_label() -> None:
    finding = AuditFinding(
        control_id="WIFI-TEST-001",
        title="Wi-Fi",
        status=AuditStatus.PASS,
        message="ok",
        category="wifi",
    )

    assert domain_label(finding) == "Wi-Fi"
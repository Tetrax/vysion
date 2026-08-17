from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditStatus, EvidenceCertainty
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

AUTO_INSTALL_DISABLED = """config system auto-install
    set auto-install-config disable
    set auto-install-image disable
end
"""


FORTIMANAGER_CONFIGURED = """config system central-management
    set type fortimanager
    set fmg "fmgr.example"
end
"""


FORTIANALYZER_CONFIGURED = """config log fortianalyzer setting
    set status enable
    set server "faz.example"
end
"""


ADMIN_PORT_CUSTOM = """config system global
    set admin-sport 8443
end
"""


def _finding(raw: str, control_id: str):
    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)
    return next(finding for finding in findings if finding.control_id == control_id)


def test_auto_install_usb_disabled_is_proven_from_typed_section() -> None:
    finding = _finding(AUTO_INSTALL_DISABLED, "SYS-AUTO-INSTALL-USB-001")

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)
    assert {item.directive for item in finding.evidence_items} == {
        "auto-install-config",
        "auto-install-image",
    }


def test_fortimanager_sync_is_proven_from_typed_section() -> None:
    finding = _finding(FORTIMANAGER_CONFIGURED, "SYS-FORTIMANAGER-SYNC-001")

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)
    assert {item.directive for item in finding.evidence_items} == {"type", "fmg"}


def test_fortianalyzer_sync_is_proven_from_typed_section() -> None:
    finding = _finding(FORTIANALYZER_CONFIGURED, "SYS-FORTIANALYZER-SYNC-001")

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)
    assert {item.directive for item in finding.evidence_items} == {"status", "server"}


def test_auto_install_usb_explicit_enable_fails_with_certain_evidence() -> None:
    raw = """config system auto-install
    set auto-install-config enable
    set auto-install-image disable
end
"""

    finding = _finding(raw, "SYS-AUTO-INSTALL-USB-001")

    assert finding.status is AuditStatus.FAIL
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)
    assert {item.directive for item in finding.evidence_items} == {"auto-install-config"}


def test_auto_install_usb_missing_directive_is_unknown() -> None:
    raw = """config system auto-install
    set auto-install-config disable
end
"""

    finding = _finding(raw, "SYS-AUTO-INSTALL-USB-001")

    assert finding.status is AuditStatus.UNKNOWN


def test_fortimanager_without_server_is_unknown() -> None:
    raw = """config system central-management
    set type fortimanager
end
"""

    finding = _finding(raw, "SYS-FORTIMANAGER-SYNC-001")

    assert finding.status is AuditStatus.UNKNOWN


def test_fortimanager_explicit_none_fails() -> None:
    raw = """config system central-management
    set type none
end
"""

    finding = _finding(raw, "SYS-FORTIMANAGER-SYNC-001")

    assert finding.status is AuditStatus.FAIL
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_fortianalyzer_explicit_disable_fails() -> None:
    raw = """config log fortianalyzer setting
    set status disable
end
"""

    finding = _finding(raw, "SYS-FORTIANALYZER-SYNC-001")

    assert finding.status is AuditStatus.FAIL
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_fortianalyzer_enable_without_server_is_unknown() -> None:
    raw = """config log fortianalyzer setting
    set status enable
end
"""

    finding = _finding(raw, "SYS-FORTIANALYZER-SYNC-001")

    assert finding.status is AuditStatus.UNKNOWN


def test_fortianalyzer_cloud_enable_is_pass() -> None:
    raw = """config log fortianalyzer-cloud setting
    set status enable
end
"""

    finding = _finding(raw, "SYS-FORTIANALYZER-SYNC-001")

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_admin_https_custom_port_is_proven_from_system_global() -> None:
    finding = _finding(ADMIN_PORT_CUSTOM, "SYS-ADMIN-HTTPS-PORT-001")

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)
    assert {item.directive for item in finding.evidence_items} == {"admin-sport"}


def test_admin_https_default_port_fails_with_certain_evidence() -> None:
    raw = """config system global
    set admin-sport 443
end
"""

    finding = _finding(raw, "SYS-ADMIN-HTTPS-PORT-001")

    assert finding.status is AuditStatus.FAIL
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_admin_https_missing_or_multivalue_port_is_unknown() -> None:
    missing = _finding("config system global\nend\n", "SYS-ADMIN-HTTPS-PORT-001")
    multivalue = _finding(
        "config system global\n    set admin-sport 8443 9443\nend\n",
        "SYS-ADMIN-HTTPS-PORT-001",
    )

    assert missing.status is AuditStatus.UNKNOWN
    assert multivalue.status is AuditStatus.UNKNOWN

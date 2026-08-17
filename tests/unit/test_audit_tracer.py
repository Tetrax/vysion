import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditStatus
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

CONTROL_IDS = (
    "SYS-HOSTNAME-001",
    "NET-WAN-MGMT-001",
    "IAM-ADMIN-MFA-001",
    "IAM-LOCAL-USER-MFA-001",
    "IAM-DEFAULT-ADMIN-001",
    "IAM-GUEST-ACCOUNT-001",
    "FW-IMPLICIT-DENY-LOG-001",
    "FW-INTERNET-ALL-SERVICE-001",
    "FW-UTM-PROFILE-BINDING-001",
    "FW-VIP-EXTINTF-ANY-001",
    "FW-VSERVER-EXTINTF-ANY-001",
    "FW-SENSITIVE-PROTOCOL-DENY-001",
    "VPN-SSL-001",
    "VPN-IKEV2-001",
    "VPN-DH-001",
    "VPN-CRYPTO-001",
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
)

SYNTHETIC_CONFIG = """\
# Synthetic fixture created for Vysion v2
config system global
    set hostname "vysion-lab.example"
    set admin-sport 8443
end
config system interface
    edit "wan1"
        set ip 192.0.2.10 255.255.255.0
        set role wan
        set allowaccess ping ssh
    next
end
config system admin
    edit "secops"
        set two-factor fortitoken
    next
end
config user local
end
"""


def _findings(raw: str):
    return AuditEngine(default_registry()).run(FortiGateParser().parse(raw))


def _finding(raw: str, control_id: str):
    return next(finding for finding in _findings(raw) if finding.control_id == control_id)


def test_representative_configuration_crosses_parser_registry_and_typed_engine() -> None:
    configuration = FortiGateParser().parse(SYNTHETIC_CONFIG)

    findings = AuditEngine(default_registry()).run(configuration)

    assert configuration.hostname == "vysion-lab.example"
    assert tuple(finding.control_id for finding in findings) == CONTROL_IDS
    statuses = {finding.control_id: finding.status for finding in findings}
    assert statuses == {
        control_id: (
            {
                "SYS-HOSTNAME-001": AuditStatus.PASS,
                "NET-WAN-MGMT-001": AuditStatus.FAIL,
                "IAM-ADMIN-MFA-001": AuditStatus.PASS,
                "IAM-LOCAL-USER-MFA-001": AuditStatus.NOT_APPLICABLE,
                "IAM-DEFAULT-ADMIN-001": AuditStatus.PASS,
                "IAM-GUEST-ACCOUNT-001": AuditStatus.PASS,
                "SYS-ADMIN-HTTPS-PORT-001": AuditStatus.PASS,
            }.get(control_id, AuditStatus.UNKNOWN)
        )
        for control_id in CONTROL_IDS
    }
    assert _finding(SYNTHETIC_CONFIG, "NET-WAN-MGMT-001").evidence == (
        "wan1: allowaccess expose ssh",
    )


def test_parser_rejects_non_fortigate_text() -> None:
    with pytest.raises(ValueError, match="Aucun parseur compatible trouvé"):
        FortiGateParser().parse("this is not a FortiGate configuration")


def test_parser_rejects_truncated_configuration() -> None:
    raw = 'config system global\n    set hostname "truncated.example"\n'

    with pytest.raises(ValueError, match="unsupported or incomplete"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "config system interface\nnext\nend\n",
        'config system interface\nedit "wan1"\nend\n',
        "config system global\nend\nend\n",
        "config system global\nend\narbitrary trailing garbage\n",
    ],
)
def test_parser_rejects_unbalanced_or_out_of_scope_structure(raw: str) -> None:
    with pytest.raises(ValueError):
        FortiGateParser().parse(raw)


def test_parser_rejects_unbalanced_edit_quote() -> None:
    raw = 'config system interface\n    edit "wan1\n    next\nend\n'

    with pytest.raises(ValueError, match="malformed edit directive"):
        FortiGateParser().parse(raw)


def test_frozen_findings_do_not_expose_mutable_evidence() -> None:
    findings = _findings(SYNTHETIC_CONFIG)

    assert isinstance(findings[0].evidence, tuple)


def test_missing_audited_sections_produce_unknown_instead_of_pass() -> None:
    findings = _findings('config system global\n    set hostname "partial.example"\nend\n')

    assert [finding.status for finding in findings] == [AuditStatus.PASS] + [
        AuditStatus.UNKNOWN
    ] * (len(CONTROL_IDS) - 1)


def test_empty_audited_sections_produce_unknown() -> None:
    raw = """config system global
end
config system interface
end
config system admin
end
config user local
end
"""

    statuses = {finding.control_id: finding.status for finding in _findings(raw)}
    passing = {
        "IAM-DEFAULT-ADMIN-001",
        "IAM-GUEST-ACCOUNT-001",
    }
    assert all(
        status
        is (
            AuditStatus.NOT_APPLICABLE
            if control_id == "IAM-LOCAL-USER-MFA-001"
            else AuditStatus.PASS
            if control_id in passing
            else AuditStatus.UNKNOWN
        )
        for control_id, status in statuses.items()
    )


def test_global_section_without_hostname_is_unknown() -> None:
    raw = """config system global
    set admin-sport 8443
end
"""

    assert _findings(raw)[0].status is AuditStatus.UNKNOWN


@pytest.mark.parametrize("hostname", ["fortigate", "FORTIGATE"])
def test_generic_hostname_is_fail(hostname: str) -> None:
    raw = f"config system global\n    set hostname {hostname}\nend\n"

    assert _findings(raw)[0].status is AuditStatus.FAIL


@pytest.mark.parametrize(
    "hostname",
    ["edge01", "edge-01", "edge-01.example", "FGT100F-A1"],
)
def test_valid_hostname_syntax_is_accepted(hostname: str) -> None:
    raw = f"config system global\n    set hostname {hostname}\nend\n"

    assert FortiGateParser().parse(raw).hostname == hostname


@pytest.mark.parametrize(
    "hostname",
    ["fortigate;", "fortigate/extra", "-edge01", "edge01-", "edge..01"],
)
def test_malformed_hostname_is_rejected(hostname: str) -> None:
    raw = f"config system global\n    set hostname {hostname}\nend\n"

    with pytest.raises(ValueError, match="invalid hostname value"):
        FortiGateParser().parse(raw)


def test_duplicate_audited_directive_is_rejected() -> None:
    raw = """config system interface
    edit "wan1"
        set allowaccess ssh
        set allowaccess ping
    next
end
"""

    with pytest.raises(ValueError, match="duplicate directive"):
        FortiGateParser().parse(raw)


def test_unknown_allowaccess_value_is_not_used_as_proof() -> None:
    raw = """config system interface
    edit "wan1"
        set allowaccess ping future-protocol
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.UNKNOWN


def test_wan_interface_without_allowaccess_is_unknown() -> None:
    raw = """config system interface
    edit "wan1"
        set ip 192.0.2.1 255.255.255.0
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.UNKNOWN


def test_explicit_wan_with_https_is_fail() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping https
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.FAIL


def test_explicit_wan_with_ssh_is_fail() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping ssh
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.FAIL


def test_missing_admin_mfa_is_unknown() -> None:
    raw = """config system admin
    edit "admin"
        set accprofile super_admin
    next
end
"""

    assert _finding(raw, "IAM-ADMIN-MFA-001").status is AuditStatus.UNKNOWN


@pytest.mark.parametrize("method", ["fortitoken", "email", "sms"])
def test_supported_admin_mfa_is_pass(method: str) -> None:
    raw = f"""config system admin
    edit "admin"
        set two-factor {method}
    next
end
"""

    assert _finding(raw, "IAM-ADMIN-MFA-001").status is AuditStatus.PASS


@pytest.mark.parametrize("method", ["none", "disable"])
def test_explicitly_disabled_admin_mfa_is_fail(method: str) -> None:
    raw = f"""config system admin
    edit "admin"
        set two-factor {method}
    next
end
"""

    assert _finding(raw, "IAM-ADMIN-MFA-001").status is AuditStatus.FAIL


def test_unknown_mfa_method_is_unknown() -> None:
    raw = """config system admin
    edit "admin"
        set two-factor future-method
    next
end
"""

    assert _finding(raw, "IAM-ADMIN-MFA-001").status is AuditStatus.UNKNOWN


def test_secondary_ip_access_is_audited_while_unrelated_sections_are_ignored() -> None:
    raw = """config system interface
    edit "wan1"
        set vdom root
        set role wan
        set allowaccess ping https
        set description "Valeur Unicode — ignorée"
        config secondaryip
            edit 1
                set allowaccess ssh
            next
        end
    next
end
config firewall policy
    edit 1
        set action accept
        config unrelated-child
            edit 1
                set arbitrary value
            next
        end
    next
end
"""

    assert _finding(raw, "NET-WAN-MGMT-001").status is AuditStatus.FAIL


def test_nested_audited_section_is_rejected() -> None:
    raw = """config vendor-wrapper
    config system interface
        edit "wan1"
            set allowaccess ssh
        next
    end
end
"""

    with pytest.raises(ValueError, match="ambiguous or nested audited section"):
        FortiGateParser().parse(raw)

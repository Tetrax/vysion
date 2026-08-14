import pytest

from vysion.audit.controls.external_services import check_cti_wan_flows
from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditStatus
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


def finding(raw: str, control_id: str):
    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))
    return next(item for item in findings if item.control_id == control_id)


@pytest.mark.parametrize(
    ("raw", "control_id"),
    [
        ('config "system global"\n    set hostname safe.example\nend\n', "SYS-HOSTNAME-001"),
        (
            'config "system interface"\n'
            '    edit "wan1"\n'
            "        set role wan\n"
            "        set allowaccess ping\n"
            "    next\nend\n",
            "NET-WAN-MGMT-001",
        ),
    ],
)
def test_quoted_audited_section_never_produces_pass(raw: str, control_id: str) -> None:
    assert finding(raw, control_id).status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    "dashboard_body",
    [
        "                set two-factor none\n",
        (
            '                set name "safe"\n'
            "                config widget\n"
            "                    edit 1\n"
            "                        set two-factor none\n"
            "                    next\n"
            "                end\n"
        ),
    ],
)
def test_unknown_dashboard_or_widget_key_invalidates_admin_mfa(
    dashboard_body: str,
) -> None:
    raw = (
        "config system admin\n"
        '    edit "secops"\n'
        "        set two-factor fortitoken\n"
        "        config gui-dashboard\n"
        "            edit 1\n"
        f"{dashboard_body}"
        "            next\n"
        "        end\n"
        "    next\n"
        "end\n"
    )
    assert finding(raw, "IAM-ADMIN-MFA-001").status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    "directives",
    [
        "set protocol ICMP extra\n        set tcp-portrange 443",
        'set protocol ALL\n        set tcp-portrange ""',
        "set tcp-portrange 443\n        set protocol-number 6 7",
    ],
)
def test_malformed_protocol_cardinality_or_empty_port_is_unknown(directives: str) -> None:
    raw = f'''config firewall service custom
    edit "synthetic"
        {directives}
    next
end
'''
    assert FortiGateParser().parse(raw).service_objects[0].proof_state.value == "unknown"


@pytest.mark.parametrize(
    ("raw", "control_id"),
    [
        (
            '''config vpn ipsec phase1-interface
    edit "P1"
        set interface "wan1"
        set ike-version 2
        set proposal aes256-sha256
        set dhgrp 14
    next
    edit "p1"
        set interface "wan1"
        set ike-version 2
        set proposal aes256-sha256
        set dhgrp 14
    next
end
config vpn ipsec phase2-interface
    edit "P2"
        set phase1name "P1"
        set pfs enable
        set proposal aes256-sha256
        set dhgrp 14
    next
end
''',
            "VPN-DH-001",
        ),
        (
            '''config user local
    edit "Bob"
        set type password
        set two-factor fortitoken
    next
    edit "bob"
        set type password
        set two-factor fortitoken
    next
end
''',
            "IAM-LOCAL-USER-MFA-001",
        ),
        (
            '''config user ldap
    edit "LDAP"
        set secure ldaps
        set ca-cert "ca"
    next
    edit "ldap"
        set secure ldaps
        set ca-cert "ca"
    next
end
''',
            "IAM-LDAPS-001",
        ),
    ],
)
def test_casefold_entry_collision_never_produces_pass(raw: str, control_id: str) -> None:
    assert finding(raw, control_id).status is AuditStatus.UNKNOWN


def test_cti_unknown_wan_interface_proof_is_unknown() -> None:
    resources = (
        "IPV4_CTI_SNS", "IPV4_SNS", "HASH_CTI_SNS_SHA1", "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1", "HASH_SNS_SHA256", "FQDN_SNS", "URL_SNS",
        "FQDN_CTI_SNS", "URL_CTI_SNS",
    )
    resource_entries = "".join(
        f'    edit "{name}"\n        set status enable\n    next\n' for name in resources
    )
    raw = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
        "config system interface\n"
        '    edit "wan1"\n'
        "        set role wan\n"
        "        set allowaccess ping\n"
        "        config vendor-extra\n"
        "            set allowaccess ssh\n"
        "        end\n"
        "    next\n"
        '    edit "lan"\n'
        "        set role lan\n"
        "        set allowaccess ping\n"
        "    next\n"
        "end\n"
        "config system external-resource\n"
        f"{resource_entries}"
        "end\n"
        "config firewall policy\n"
        "    edit 1\n"
        '        set srcintf "wan1"\n'
        '        set dstintf "lan"\n'
        '        set srcaddr "IPV4_CTI_SNS" "IPV4_SNS"\n'
        '        set dstaddr "all"\n'
        "        set action accept\n"
        "        set status enable\n"
        "    next\n"
        "end\n"
    )
    assert check_cti_wan_flows(FortiGateParser().parse(raw)).status is AuditStatus.UNKNOWN


def test_multi_vdom_hidden_policy_prevents_top_level_safe_pass() -> None:
    raw = '''config system interface
    edit "wan1"
        set role wan
    next
    edit "lan1"
        set role lan
    next
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
end
config firewall policy
    edit 1
        set srcintf "lan1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status enable
        set schedule "always"
        set service "HTTPS"
    next
end
config vdom
    edit "A"
        config firewall policy
            edit 99
                set srcintf "lan1"
                set dstintf "wan1"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set status enable
                set schedule "always"
                set service "ALL"
            next
        end
    next
    edit "B"
        config firewall policy
            edit 100
                set srcintf "lan1"
                set dstintf "wan1"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set status enable
                set schedule "always"
                set service "ALL"
            next
        end
    next
end
'''
    assert finding(raw, "FW-INTERNET-ALL-SERVICE-001").status is AuditStatus.UNKNOWN

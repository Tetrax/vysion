from pathlib import Path

import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    AuditContext,
    AuditStatus,
    ContextProvenance,
    EvidenceCertainty,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "anonymized_fortigate_export.conf"


def _finding(findings, control_id: str):
    return next(finding for finding in findings if finding.control_id == control_id)


def test_anonymized_realistic_fortigate_export_is_audited() -> None:
    configuration = FortiGateParser().parse(_FIXTURE.read_text(encoding="utf-8"))

    findings = AuditEngine(default_registry()).run(
        configuration,
        context=AuditContext(
            utm_license=True,
            operator_provenance=ContextProvenance(
                source="anonymized-fixture",
                method="explicit-test-context",
            ),
        ),
    )

    assert configuration.hostname == "edge-lab.example"
    assert [interface.name for interface in configuration.interfaces] == ["wan1", "port1"]
    assert configuration.administrators[0].two_factor == "fortitoken"
    assert configuration.zones[0].name == "trusted"
    assert configuration.zones[0].interfaces[0].name == "port1"
    assert configuration.local_users[0].name == "vpn-demo-user"
    assert configuration.local_users[0].two_factor == "fortitoken"
    assert configuration.security_profiles[0].name == "certificate-inspection-demo"
    assert configuration.policies[0].source_interfaces[0].name == "trusted"
    assert any(
        reference.name == "example-documentation-net" and reference.relation == "source-address"
        for reference in configuration.policies[0].object_references
    )
    statuses = {finding.control_id: finding.status for finding in findings}
    assert len(statuses) == 40
    assert statuses == {
        finding.control_id: (
            AuditStatus.FAIL
            if finding.control_id == "FW-BY-SEQUENCE-USAGE-001"
            else AuditStatus.NOT_APPLICABLE
            if finding.control_id == "VPN-SSL-001"
            else AuditStatus.UNKNOWN
            if finding.control_id in {
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
            }
            else AuditStatus.PASS
        )
        for finding in findings
    }


def test_utf8_bom_is_accepted() -> None:
    raw = "\ufeffconfig system global\n    set hostname edge-lab.example\nend\n"

    configuration = FortiGateParser().parse(raw)

    assert configuration.hostname == "edge-lab.example"


def test_unicode_in_comments_and_unused_values_is_accepted() -> None:
    raw = """# Export synthétique — équipe sécurité
config system interface
    edit "wan1"
        set allowaccess ping
        set description "Accès opérateur — générique"
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.interfaces[0].allowaccess == frozenset({"ping"})


def test_fortios_global_nonprobative_directives_do_not_invalidate_hostname() -> None:
    raw = """config system global
    set hostname edge-synthetic.example
    set admin-server-cert "synthetic-cert"
    set alias "Synthetic edge"
    set allow-traffic-redirect disable
    set cli-audit-log enable
    set fortitoken-cloud-region global
    set gui-auto-upgrade-setup-warning disable
    set gui-certificates enable
    set gui-display-hostname enable
    set gui-replacement-message-groups enable
    set gui-wireless-opensecurity disable
    set ipv6-allow-traffic-redirect disable
    set ldapconntimeout 5000
    set management-ip 192.0.2.1 255.255.255.255
    set remoteauthtimeout 5
    set reset-sessionless-tcp disable
    set rest-api-key-url-query disable
    set revision-backup-on-logout enable
    set revision-image-auto-backup enable
    set sslvpn-web-mode disable
    set strict-dirty-session-check enable
    set switch-controller enable
    set virtual-switch-vlan enable
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)

    assert configuration.device_identity.hostname == "edge-synthetic.example"
    section = configuration.document.section("system global")
    assert section is not None
    assert section.certainty.value == "certain"
    assert _finding(findings, "SYS-HOSTNAME-001").status is AuditStatus.PASS


def test_fortios_interface_metadata_keeps_multiple_interfaces_certain() -> None:
    raw = """config system interface
    edit "wan-synthetic"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set allowaccess ping ssh
        set role wan
        set snmp-index 1
        set device-identification enable
        set status up
        set mode static
        set interface "port-synthetic"
        set vlanid 100
        set dhcp-relay-service disable
        set dhcp-relay-ip "192.0.2.10"
        set src-check enable
        set mtu-override enable
        set mtu 1400
        set tcp-mss 1360
        set estimated-upstream-bandwidth 100000
        set estimated-downstream-bandwidth 100000
    next
    edit "lan-synthetic"
        set vdom "root"
        set ip 198.51.100.1 255.255.255.0
        set allowaccess ping
        set role lan
        set snmp-index 2
        set type physical
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)
    section = configuration.document.section("system interface")

    assert section is not None
    assert section.certainty.value == "certain"
    assert [item.name for item in configuration.interfaces] == [
        "wan-synthetic",
        "lan-synthetic",
    ]
    assert all(item.proof_state.value == "proven" for item in configuration.interfaces)
    assert _finding(findings, "NET-WAN-MGMT-001").status is AuditStatus.FAIL


def test_fortios_admin_dashboard_and_metadata_preserve_mfa_certainty() -> None:
    raw = """config system admin
    edit "secops-synthetic"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC SYNTHETIC
        set old-password ENC SYNTHETIC
        set trusthost1 192.0.2.0 255.255.255.0
        set gui-ignore-release-overview-version "7.4.0"
        set two-factor fortitoken
        config gui-dashboard
            edit 1
                set name "Synthetic status"
                config widget
                    edit 1
                        set type licinfo
                    next
                end
            next
        end
    next
    edit "peer-synthetic"
        set accprofile "super_admin"
        set vdom "root"
        set peer-auth enable
        set peer-group "synthetic-peers"
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)
    section = configuration.document.section("system admin")

    assert section is not None
    assert section.certainty.value == "certain"
    assert all(entry.certainty.value == "certain" for entry in section.entries)
    assert _finding(findings, "IAM-ADMIN-MFA-001").status is AuditStatus.PASS


def test_fortios_local_user_password_metadata_preserves_explicit_mfa() -> None:
    raw = """config user local
    edit "synthetic-user"
        set type password
        set passwd ENC SYNTHETIC
        set passwd-time 2026-01-01 00:00:00
        set two-factor fortitoken
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)
    section = configuration.document.section("user local")

    assert section is not None
    assert section.certainty.value == "certain"
    assert section.entries[0].certainty.value == "certain"
    assert _finding(findings, "IAM-LOCAL-USER-MFA-001").status is AuditStatus.PASS


def test_fortios_disabled_ssl_vpn_with_retained_settings_is_deterministic() -> None:
    raw = """config vpn ssl settings
    set status disable
    set source-interface "wan-synthetic"
    set algorithm high
    set auth-timeout 28800
    set banned-cipher SHA1
    set default-portal "web-access"
    set dns-server1 192.0.2.53
    set dns-server2 198.51.100.53
    set dns-suffix "synthetic.example"
    set idle-timeout 300
    set port 10443
    set servercert "synthetic-cert"
    set source-address "all"
    set source-address6 "all"
    set ssl-min-proto-ver tls1-2
    set tunnel-ip-pools "synthetic-pool"
    config authentication-rule
        edit 1
            set groups "synthetic-group"
            set portal "full-access"
        next
    end
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)
    section = configuration.document.section("vpn ssl settings")
    finding = _finding(findings, "VPN-SSL-001")

    assert section is not None
    assert section.certainty.value == "certain"
    assert configuration.ssl_vpn_settings is not None
    assert configuration.ssl_vpn_settings.status == "disable"
    assert finding.status is AuditStatus.UNKNOWN
    assert finding.applicability.value == "unknown"


@pytest.mark.parametrize(
    "extra_directive",
    [
        "set add-route enable",
        'set comments "Synthetic tunnel"',
        "set dpd on-idle",
        "set dpd-retryinterval 20",
        "set keylife 28800",
        "set local-gw 192.0.2.1",
        'set localid "synthetic-local"',
        "set mode aggressive",
        "set nattraversal enable",
        "set net-device enable",
        "set npu-offload enable",
        'set peerid "synthetic-peer"',
        "set peertype any",
        "set psksecret ENC SYNTHETIC",
        "set remote-gw 198.51.100.10",
        'set remotegw-ddns "vpn.synthetic.example"',
        "set type static",
    ],
)
def test_fortios_phase1_metadata_preserves_strong_ipsec_proof(
    extra_directive: str,
) -> None:
    raw = f"""config vpn ipsec phase1-interface
    edit "phase1-synthetic"
        set status enable
        set interface "wan-synthetic"
        set ike-version 2
        set proposal aes256-sha256
        set dhgrp 14
        {extra_directive}
    next
end
config vpn ipsec phase2-interface
    edit "phase2-synthetic"
        set status enable
        set phase1name "phase1-synthetic"
        set pfs enable
        set proposal aes256-sha256
        set dhgrp 14
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)

    assert configuration.ipsec_phase1[0].proof_state.value == "proven"
    assert _finding(findings, "VPN-IKEV2-001").status is AuditStatus.PASS
    assert _finding(findings, "VPN-DH-001").status is AuditStatus.PASS
    assert _finding(findings, "VPN-CRYPTO-001").status is AuditStatus.PASS


@pytest.mark.parametrize(
    "extra_directive",
    [
        "set auto-negotiate enable",
        "set dst-addr-type subnet",
        'set dst-name "synthetic-destination"',
        "set dst-start-ip 198.51.100.10",
        "set dst-subnet 198.51.100.0 255.255.255.0",
        "set keepalive enable",
        "set keylifeseconds 3600",
        "set route-overlap use-new",
        "set src-addr-type subnet",
        'set src-name "synthetic-source"',
        "set src-subnet 192.0.2.0 255.255.255.0",
    ],
)
def test_fortios_phase2_metadata_preserves_strong_ipsec_proof(
    extra_directive: str,
) -> None:
    raw = f"""config vpn ipsec phase1-interface
    edit "phase1-synthetic"
        set status enable
        set interface "wan-synthetic"
        set ike-version 2
        set proposal aes256-sha256
        set dhgrp 14
    next
end
config vpn ipsec phase2-interface
    edit "phase2-synthetic"
        set status enable
        set phase1name "phase1-synthetic"
        set pfs enable
        set proposal aes256-sha256
        set dhgrp 14
        {extra_directive}
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)

    assert configuration.ipsec_phase2[0].proof_state.value == "proven"
    assert _finding(findings, "VPN-DH-001").status is AuditStatus.PASS
    assert _finding(findings, "VPN-CRYPTO-001").status is AuditStatus.PASS


def test_fortios_multiline_quoted_policy_metadata_is_one_directive() -> None:
    raw = """config firewall policy
    edit 1
        set name "Synthetic
policy"
        set comments "First synthetic line
Second synthetic line."
        set srcintf "lan-synthetic"
        set dstintf "wan-synthetic"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status enable
        set schedule "always"
        set service "ALL"
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    section = configuration.document.section("firewall policy")

    assert section is not None
    assert section.certainty.value == "certain"
    assert section.entries[0].certainty.value == "certain"
    assert configuration.policies[0].proof_state.value == "proven"


def test_fortios_escaped_backslash_service_name_resolves_from_policy() -> None:
    raw = r"""config firewall service custom
    edit "SYNTHETIC\\1234-5678"
        set tcp-portrange 1234-5678
    next
end
config firewall policy
    edit 1
        set srcintf "lan-synthetic"
        set dstintf "wan-synthetic"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status enable
        set schedule "always"
        set service "SYNTHETIC\\1234-5678"
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.service_objects[0].proof_state.value == "proven"
    assert configuration.policies[0].proof_state.value == "proven"
    assert configuration.policies[0].services[0].name == configuration.service_objects[0].name


@pytest.mark.parametrize(
    "extra_directive",
    [
        "set auto-asic-offload enable",
        "set dstaddr-negate enable",
        'set global-label "Synthetic global"',
        "set disclaimer disable",
        'set dlp-profile "synthetic-dlp"',
        'set emailfilter-profile "synthetic-email"',
        'set fsso-groups "synthetic-fsso"',
        'set groups "synthetic-group"',
        "set inspection-mode proxy",
        "set internet-service-src enable",
        "set ippool enable",
        'set label "Synthetic label"',
        "set logtraffic-start enable",
        "set match-vip enable",
        "set nat enable",
        "set np-acceleration enable",
        'set per-ip-shaper "synthetic-shaper"',
        'set poolname "synthetic-pool"',
        'set profile-protocol-options "synthetic-options"',
        "set session-ttl 3600",
        "set tcp-mss-receiver 1360",
        "set tcp-mss-sender 1360",
        'set users "synthetic-user"',
        "set uuid 00000000-0000-0000-0000-000000000001",
    ],
)
def test_fortios_policy_metadata_preserves_policy_proof(extra_directive: str) -> None:
    raw = f"""config firewall policy
    edit 1
        set srcintf "lan-synthetic"
        set dstintf "wan-synthetic"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status enable
        set schedule "always"
        set service "ALL"
        {extra_directive}
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    section = configuration.document.section("firewall policy")

    assert section is not None
    assert section.certainty.value == "certain"
    assert configuration.policies[0].proof_state.value == "proven"


@pytest.mark.parametrize(
    "extra_directive",
    [
        'set category "Synthetic"',
        'set comment "Synthetic service"',
        "set icmpcode 0",
        "set icmptype 8",
        "set protocol TCP/UDP/SCTP",
        "set proxy enable",
        "set uuid 00000000-0000-0000-0000-000000000002",
    ],
)
def test_fortios_custom_service_metadata_preserves_service_proof(
    extra_directive: str,
) -> None:
    raw = f"""config firewall service custom
    edit "service-synthetic"
        set tcp-portrange 8443
        {extra_directive}
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    section = configuration.document.section("firewall service custom")

    assert section is not None
    assert section.certainty.value == "certain"
    assert configuration.service_objects[0].proof_state.value == "proven"


def test_fortios_service_destination_and_source_port_ranges_are_projected() -> None:
    raw = """config firewall service custom
    edit "service-synthetic"
        set tcp-portrange 8443:1024-65535
    next
end
"""

    service = FortiGateParser().parse(raw).service_objects[0]

    assert service.proof_state.value == "proven"
    assert tuple((item.start, item.end) for item in service.tcp_port_ranges) == ((8443, 8443),)


def test_malformed_fortios_source_port_range_never_proves_service() -> None:
    raw = """config firewall service custom
    edit "service-synthetic"
        set tcp-portrange 8443:not-a-range
    next
end
"""

    assert FortiGateParser().parse(raw).service_objects[0].proof_state.value == "unknown"


@pytest.mark.parametrize(
    "protocol_directives",
    [
        "set protocol IP\n        set protocol-number 6",
        "set protocol ALL",
    ],
)
def test_malformed_source_port_range_cannot_be_masked_by_protocol(
    protocol_directives: str,
) -> None:
    raw = f"""config firewall service custom
    edit "service-synthetic"
        set tcp-portrange 8443:not-a-range
        {protocol_directives}
    next
end
"""

    assert FortiGateParser().parse(raw).service_objects[0].proof_state.value == "unknown"


@pytest.mark.parametrize(
    "protocol_directives",
    [
        "set protocol IP\n        set protocol-number 6\n        set udp-portrange 53",
        "set protocol ICMP\n        set tcp-portrange 443",
    ],
)
def test_incompatible_protocol_and_port_range_never_proves_service(
    protocol_directives: str,
) -> None:
    raw = f"""config firewall service custom
    edit "service-synthetic"
        {protocol_directives}
    next
end
"""

    assert FortiGateParser().parse(raw).service_objects[0].proof_state.value == "unknown"


def test_protocol_number_without_ip_protocol_stays_unknown() -> None:
    raw = """config firewall service custom
    edit "service-synthetic"
        set tcp-portrange 8443
        set protocol-number 6
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.service_objects[0].proof_state.value == "unknown"


@pytest.mark.parametrize(
    ("section_name", "base_directives", "extra_directive"),
    [
        (
            "firewall service group",
            'set member "HTTPS"',
            'set comment "Synthetic service group"',
        ),
        (
            "firewall service group",
            'set member "HTTPS"',
            "set uuid 00000000-0000-0000-0000-000000000003",
        ),
        (
            "firewall vip",
            'set extintf "wan-synthetic"\n'
            "        set extip 192.0.2.10\n"
            '        set mappedip "198.51.100.10"',
            "set portforward enable",
        ),
        (
            "firewall vip",
            'set extintf "wan-synthetic"\n'
            "        set extip 192.0.2.10\n"
            '        set mappedip "198.51.100.10"',
            "set extport 443",
        ),
        (
            "firewall vip",
            'set extintf "wan-synthetic"\n'
            "        set extip 192.0.2.10\n"
            '        set mappedip "198.51.100.10"',
            "set mappedport 8443",
        ),
        (
            "firewall vip",
            'set extintf "wan-synthetic"\n'
            "        set extip 192.0.2.10\n"
            '        set mappedip "198.51.100.10"',
            "set protocol tcp",
        ),
        (
            "firewall vip",
            'set extintf "wan-synthetic"\n'
            "        set extip 192.0.2.10\n"
            '        set mappedip "198.51.100.10"',
            'set comment "Synthetic VIP"',
        ),
        (
            "firewall vip",
            'set extintf "wan-synthetic"\n'
            "        set extip 192.0.2.10\n"
            '        set mappedip "198.51.100.10"',
            "set uuid 00000000-0000-0000-0000-000000000004",
        ),
        (
            "firewall vipgrp",
            'set member "vip-synthetic"',
            'set interface "wan-synthetic"',
        ),
        (
            "firewall vipgrp",
            'set member "vip-synthetic"',
            "set uuid 00000000-0000-0000-0000-000000000005",
        ),
        (
            "system zone",
            'set interface "lan-synthetic"',
            "set intrazone allow",
        ),
    ],
)
def test_fortios_firewall_and_zone_metadata_preserve_structural_certainty(
    section_name: str,
    base_directives: str,
    extra_directive: str,
) -> None:
    raw = f"""config {section_name}
    edit "object-synthetic"
        {base_directives}
        {extra_directive}
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    section = configuration.document.section(section_name)

    assert section is not None
    assert section.certainty.value == "certain"
    assert section.entries[0].certainty.value == "certain"


def test_fortios_secondary_ip_canonical_case_and_multiple_entries_are_certain() -> None:
    raw = """config system interface
    edit "wan-synthetic"
        set ip 192.0.2.1 255.255.255.0
        set allowaccess ping
        set role wan
        set secondary-IP enable
        config secondaryip
            edit 1
                set ip 192.0.2.2 255.255.255.255
                set allowaccess ping
            next
            edit 2
                set ip 192.0.2.3 255.255.255.255
                set allowaccess ping
            next
        end
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    section = configuration.document.section("system interface")

    assert section is not None
    assert section.certainty.value == "certain"
    assert section.entries[0].certainty.value == "certain"
    assert len(section.entries[0].children[0].entries) == 2


@pytest.mark.parametrize("key", ["icmpcode", "icmptype", "tcp-portrange", "udp-portrange"])
def test_fortios_unset_known_service_key_is_a_certain_absence(key: str) -> None:
    raw = f"""config firewall service custom
    edit "service-synthetic"
        set protocol ICMP
        unset {key}
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    section = configuration.document.section("firewall service custom")

    assert section is not None
    assert section.certainty.value == "certain"
    assert section.entries[0].certainty.value == "certain"
    assert key not in section.entries[0].parsed_keys
    assert key not in section.entries[0].invalidated_keys


@pytest.mark.parametrize(
    ("protocol", "protocol_number", "expected_tcp", "expected_udp"),
    [
        ("ICMP", None, (), ()),
        ("ICMP6", None, (), ()),
        ("IP", "47", (), ()),
        ("IP", "50", (), ()),
        ("IP", "51", (), ()),
        ("IP", "89", (), ()),
        ("ALL", None, ((0, 65535),), ((0, 65535),)),
    ],
)
def test_fortios_non_port_service_protocols_have_deterministic_coverage(
    protocol: str,
    protocol_number: str | None,
    expected_tcp: tuple[tuple[int, int], ...],
    expected_udp: tuple[tuple[int, int], ...],
) -> None:
    number = f"set protocol-number {protocol_number}" if protocol_number else ""
    raw = f"""config firewall service custom
    edit "service-synthetic"
        set protocol {protocol}
        {number}
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    service = configuration.service_objects[0]

    assert service.proof_state.value == "proven"
    assert service.protocol == protocol.casefold()
    assert service.protocol_number == (
        int(protocol_number) if protocol_number is not None else None
    )
    assert tuple((item.start, item.end) for item in service.tcp_port_ranges) == expected_tcp
    assert tuple((item.start, item.end) for item in service.udp_port_ranges) == expected_udp


def test_case_distinct_fortios_service_names_resolve_exactly_or_stay_unknown() -> None:
    from vysion.audit.controls.firewall import _service_coverage

    raw = """config firewall service custom
    edit "CaseX"
        set protocol ICMP
    next
    edit "casex"
        set protocol ALL
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    section = configuration.document.section("firewall service custom")
    exact_safe = _service_coverage(configuration, "CaseX")
    exact_all = _service_coverage(configuration, "casex")
    folded_ambiguous = _service_coverage(configuration, "CASEX")

    assert section is not None
    assert section.certainty.value == "certain"
    assert all(entry.certainty.value == "certain" for entry in section.entries)
    assert exact_safe.known is True
    assert exact_safe.tcp == () and exact_safe.udp == ()
    assert exact_all.known is True
    assert exact_all.tcp and exact_all.udp
    assert folded_ambiguous.known is False


def test_fortios_unset_unknown_service_key_remains_ambiguous() -> None:
    raw = """config firewall service custom
    edit "service-synthetic"
        set tcp-portrange 443
        unset mystery
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    section = configuration.document.section("firewall service custom")

    assert section is not None
    assert section.certainty.value == "ambiguous"
    assert section.entries[0].certainty.value == "ambiguous"


def test_fortios_ldap_metadata_does_not_hide_explicit_ldaps_and_ca() -> None:
    raw = """config user ldap
    edit "ldap-synthetic"
        set server "192.0.2.10"
        set cnid "uid"
        set dn "dc=synthetic,dc=example"
        set type regular
        set username "cn=synthetic"
        set password ENC SYNTHETIC
        set password-expiry-warning enable
        set password-renewal enable
        set port 636
        set server-identity-check enable
        set source-ip 192.0.2.1
        set secure ldaps
        set ca-cert "synthetic-ca"
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)
    section = configuration.document.section("user ldap")

    assert section is not None
    assert section.certainty.value == "certain"
    assert section.entries[0].certainty.value == "certain"
    assert _finding(findings, "IAM-LDAPS-001").status is AuditStatus.PASS


def test_documented_defaults_apply_only_to_complete_fortigate_backups() -> None:
    raw = """#config-version=FGT60E-7.4.8-FW-build0000-000000:opmode=0:vdom=0:user=admin
#buildno=0000
#global_vdom=1
#conf_file_ver=1
config system admin
    edit "secops-synthetic"
        set accprofile "super_admin"
    next
end
config user local
    edit "user-synthetic"
        set type password
    next
end
config vpn ssl settings
    set source-interface "wan-synthetic"
end
config vpn ipsec phase1-interface
    edit "vpn-synthetic"
        set interface "wan-synthetic"
        set proposal aes256-sha256
    next
end
config vpn ipsec phase2-interface
    edit "vpn-synthetic-p2"
        set phase1name "vpn-synthetic"
        set proposal aes256-sha256
    next
end
config firewall policy
    edit 1
        set srcintf "lan-synthetic"
        set dstintf "wan-synthetic"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = {
        item.control_id: item for item in AuditEngine(default_registry()).run(configuration)
    }

    assert configuration.complete_backup is True
    assert configuration.administrators[0].two_factor == "disable"
    assert configuration.administrators[0].defaulted_keys == {"two-factor", "peer-auth"}
    assert configuration.local_users[0].two_factor == "disable"
    assert configuration.local_users[0].defaulted_keys == {"two-factor"}
    assert configuration.ssl_vpn_settings is not None
    assert configuration.ssl_vpn_settings.status == "enable"
    assert configuration.ssl_vpn_settings.defaulted_keys == {"status"}
    assert configuration.policies[0].status == "enable"
    assert configuration.policies[0].defaulted_keys == {"status"}
    assert configuration.ipsec_phase1[0].ike_version == 1
    assert configuration.ipsec_phase1[0].dh_groups == (14,)
    assert configuration.ipsec_phase1[0].defaulted_keys == {"ike-version", "dhgrp"}
    assert configuration.ipsec_phase2[0].pfs == "enable"
    assert configuration.ipsec_phase2[0].dh_groups == (14,)
    assert configuration.ipsec_phase2[0].defaulted_keys == {"pfs", "dhgrp"}
    assert findings["IAM-ADMIN-MFA-001"].status is AuditStatus.FAIL
    assert findings["IAM-LOCAL-USER-MFA-001"].status is AuditStatus.FAIL
    assert findings["VPN-SSL-001"].status is AuditStatus.FAIL
    assert findings["VPN-IKEV2-001"].status is AuditStatus.FAIL
    assert findings["VPN-DH-001"].status is AuditStatus.PASS
    assert findings["VPN-CRYPTO-001"].status is AuditStatus.PASS


@pytest.mark.parametrize(
    ("buildno", "global_vdom", "conf_file_ver"),
    [
        ("not-a-build", "1", "1"),
        ("0000", "garbage", "1"),
        ("0000", "1", "garbage"),
    ],
)
def test_invalid_backup_markers_never_enable_complete_backup_absence_passes(
    buildno: str, global_vdom: str, conf_file_ver: str
) -> None:
    raw = f"""#config-version=FGT60E-7.4.8-FW-build0000-000000:opmode=0:vdom=0:user=admin
#buildno={buildno}
#global_vdom={global_vdom}
#conf_file_ver={conf_file_ver}
config system global
    set hostname edge-synthetic.example
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = {
        item.control_id: item
        for item in AuditEngine(default_registry()).run(configuration)
    }

    assert configuration.complete_backup is False
    assert findings["IAM-LOCAL-USER-MFA-001"].status is AuditStatus.UNKNOWN


def test_unsupported_firmware_never_enables_complete_backup_absence_passes() -> None:
    raw = """#config-version=FGT60E-6.4.0-FW-build0000-000000:opmode=0:vdom=0:user=admin
#buildno=0000
#global_vdom=1
#conf_file_ver=1
config system global
    set hostname edge-synthetic.example
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = {
        item.control_id: item
        for item in AuditEngine(default_registry()).run(configuration)
    }

    assert configuration.complete_backup is False
    assert findings["IAM-LOCAL-USER-MFA-001"].status is AuditStatus.UNKNOWN


def test_backup_markers_inside_configuration_never_prove_complete_backup() -> None:
    raw = """#config-version=FGT60E-7.4.8-FW-build0000-000000:opmode=0:vdom=0:user=admin
config system global
    set hostname edge-safe.example
#conf_file_ver=1
#buildno=0000
#global_vdom=1
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = {
        item.control_id: item
        for item in AuditEngine(default_registry()).run(configuration)
    }

    assert configuration.complete_backup is False
    assert findings["IAM-LOCAL-USER-MFA-001"].status is AuditStatus.UNKNOWN


def test_absent_optional_namespaces_are_not_applicable_in_complete_backup() -> None:
    raw = """#config-version=FGT60E-7.2.16-FW-build0000-000000:opmode=0:vdom=0:user=admin
#buildno=0000
#global_vdom=1
#conf_file_ver=1
config system global
    set hostname edge-synthetic.example
end
config system admin
    edit "secops-synthetic"
        set two-factor fortitoken
    next
end
"""

    findings = {
        item.control_id: item
        for item in AuditEngine(default_registry()).run(FortiGateParser().parse(raw))
    }
    expected_not_applicable = {
        "IAM-LOCAL-USER-MFA-001",
        "IAM-GUEST-ACCOUNT-001",
        "FW-VIP-EXTINTF-ANY-001",
        "FW-VSERVER-EXTINTF-ANY-001",
        "VPN-IKEV2-001",
        "VPN-DH-001",
        "VPN-CRYPTO-001",
        "IAM-LDAPS-001",
    }

    for control_id in expected_not_applicable:
        finding = findings[control_id]
        assert finding.status is AuditStatus.NOT_APPLICABLE
        assert finding.applicability.value == "not_applicable"
        assert finding.evidence_items
        assert all(item.certainty.value == "certain" for item in finding.evidence_items)
        assert any(item.directive == "complete-backup" for item in finding.evidence_items)


def test_repeated_projected_sections_with_disjoint_objects_are_merged() -> None:
    raw = """config firewall service custom
    edit "SYNTH-A"
        set tcp-portrange 443
    next
end
config firewall service custom
    edit "SYNTH-B"
        set udp-portrange 53
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert {item.name for item in configuration.service_objects} == {"SYNTH-A", "SYNTH-B"}
    assert all(item.proof_state.value == "proven" for item in configuration.service_objects)


def test_single_vdom_is_projected_without_losing_scope() -> None:
    raw = """config vdom
    edit "SYNTH-ONLY"
        config firewall service custom
            edit "SYNTH-HTTPS"
                set tcp-portrange 443
            next
        end
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert tuple(item.name for item in configuration.service_objects) == ("SYNTH-HTTPS",)
    assert configuration.service_objects[0].proof_state.value == "proven"


def test_multiple_vdoms_remain_structural_and_business_unknown() -> None:
    raw = """#config-version=FGT60E-7.4.8-FW-build0000-000000:opmode=0:vdom=1:user=admin
#buildno=0000
#global_vdom=1
#conf_file_ver=1
config vdom
    edit "SYNTH-A"
        config firewall vip
            edit "SYNTH-VIP-A"
                set extintf "any"
            next
        end
    next
    edit "SYNTH-B"
        config firewall vip
            edit "SYNTH-VIP-B"
                set extintf "port1"
            next
        end
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)

    assert configuration.document.section("vdom") is not None
    assert configuration.document.section("firewall vip") is None
    assert configuration.vips == ()
    assert configuration.complete_backup is False
    assert _finding(findings, "FW-VIP-EXTINTF-ANY-001").status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    "control_id",
    [
        "FW-INTERNET-ALL-SERVICE-001",
        "FW-SENSITIVE-PROTOCOL-DENY-001",
        "FW-VIP-EXTINTF-ANY-001",
        "FW-VSERVER-EXTINTF-ANY-001",
    ],
)
def test_ambiguous_empty_firewall_namespace_never_passes(control_id: str) -> None:
    namespace = (
        "firewall vip"
        if "VIP" in control_id or "VSERVER" in control_id
        else "firewall policy"
    )
    raw = f"""config {namespace}
    config vendor-extra
    end
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert _finding(findings, control_id).status is AuditStatus.UNKNOWN


def test_casefold_colliding_zones_do_not_prove_policy_scope() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
    next
    edit "lan1"
        set role lan
        set allowaccess ping
    next
end
config system zone
    edit "internet"
        set interface "wan1"
    next
    edit "INTERNET"
        set interface "lan1"
    next
end
config firewall policy
    edit 1
        set srcintf "lan1"
        set dstintf "internet"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status enable
        set service "ALL"
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert _finding(findings, "FW-INTERNET-ALL-SERVICE-001").status is AuditStatus.UNKNOWN


def test_extra_keys_in_audited_entries_are_ignored() -> None:
    raw = """config system admin
    edit "secops"
        set accprofile "super_admin"
        set vdom "root"
        set two-factor fortitoken
        set email-to "secops@example.invalid"
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.administrators[0].two_factor == "fortitoken"


@pytest.mark.parametrize(
    "dangerous",
    [
        "\x00",
        "\x01",
        "\x1f",
        "\x7f",
        "\x85",
        "\u200b",
        "\u2028",
        "\u2029",
        "\u202e",
        "\ufeff",
    ],
)
def test_dangerous_control_characters_are_rejected(dangerous: str) -> None:
    raw = f"# invalid{dangerous}separator\nconfig system global\nend\n"

    with pytest.raises(ValueError, match="invalid .*character|invalid line separator"):
        FortiGateParser().parse(raw)


def test_no_identifiable_wan_interface_is_unknown() -> None:
    raw = """config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert _finding(findings, "NET-WAN-MGMT-001").status is AuditStatus.UNKNOWN


def test_missing_admin_mfa_directive_is_unknown() -> None:
    raw = """config system admin
    edit "secops"
        set accprofile "super_admin"
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert _finding(findings, "IAM-ADMIN-MFA-001").status is AuditStatus.UNKNOWN


def test_nested_subsection_does_not_become_parent_evidence() -> None:
    raw = """config system interface
    edit "wan1"
        config secondaryip
            edit 1
                set allowaccess ping ssh
            next
        end
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert _finding(findings, "NET-WAN-MGMT-001").status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    ("section", "entry", "known_value", "mutation", "finding_index"),
    [
        ("system global", "", "set hostname edge-lab.example", "unset hostname", 0),
        (
            "system interface",
            'edit "wan1"',
            "set allowaccess ping",
            "append allowaccess ssh",
            1,
        ),
        (
            "system admin",
            'edit "secops"',
            "set two-factor fortitoken",
            "unset two-factor",
            2,
        ),
    ],
)
def test_uninterpreted_audited_mutation_is_unknown(
    section: str,
    entry: str,
    known_value: str,
    mutation: str,
    finding_index: int,
) -> None:
    suffix = "\n    next" if entry else ""
    raw = f"config {section}\n    {entry}\n        {known_value}\n        {mutation}{suffix}\nend\n"

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[finding_index].status is AuditStatus.UNKNOWN


def test_interface_role_wan_is_used_as_identification_evidence() -> None:
    raw = """config system interface
    edit "port1"
        set role wan
        set allowaccess ping
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert _finding(findings, "NET-WAN-MGMT-001").status is AuditStatus.PASS


@pytest.mark.parametrize(
    "raw",
    [
        "config system global\n    set hostname edge\\q\nend\n",
        'config system global\n    set hostname "edge"lab.example\nend\n',
        'config system interface\n    edit "wan"1\n    next\nend\n',
    ],
)
def test_ambiguous_lexical_transformations_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match="malformed .* directive|invalid hostname value"):
        FortiGateParser().parse(raw)


def test_duplicate_top_level_audited_section_is_rejected() -> None:
    raw = """config system global
    set hostname first.example
end
config system global
    set hostname second.example
end
"""

    with pytest.raises(ValueError, match="duplicate audited section"):
        FortiGateParser().parse(raw)


def test_duplicate_audited_entry_is_rejected_fail_closed() -> None:
    raw = """config system interface
    edit "wan1"
        set allowaccess ping https
    next
    edit "wan1"
        set allowaccess ping https
    next
end
"""

    with pytest.raises(ValueError, match="duplicate audited entry"):
        FortiGateParser().parse(raw)


def test_edit_in_system_global_is_rejected() -> None:
    raw = """config system global
    edit "unexpected"
        set hostname fabricated.example
    next
end
"""

    with pytest.raises(ValueError, match="unsupported edit in audited section"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize("hostname", ['""', '"   "', '" fortigate "', '" FORTIGATE "'])
def test_explicit_blank_or_generic_hostname_is_fail(hostname: str) -> None:
    raw = f"config system global\n    set hostname {hostname}\nend\n"

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[0].status is AuditStatus.FAIL


def test_explicit_admin_mfa_failure_takes_precedence_over_unknown() -> None:
    raw = """config system admin
    edit "known-failure"
        set two-factor none
    next
    edit "unknown-state"
        set accprofile super_admin
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert _finding(findings, "IAM-ADMIN-MFA-001").status is AuditStatus.FAIL
    assert _finding(findings, "IAM-ADMIN-MFA-001").evidence == (
        "administrateur sans MFA: known-failure",
    )


def test_non_audited_entry_names_are_not_lexically_interpreted() -> None:
    raw = """config firewall address
    edit "unused'O\\bject"
        set comment "Valeur Unicode — ignorée"
    next
end
config system global
    set hostname edge-lab.example
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.hostname == "edge-lab.example"


@pytest.mark.parametrize(
    ("namespace", "directive"),
    [
        ("firewall address", 'set subnet "192.0.2.0" "255.255.255.0"'),
        ("firewall addrgrp", 'set member "SYNTH-A" "SYNTH-B"'),
        ("system sdwan", "set status enable"),
    ],
)
def test_nonprojected_requested_namespaces_remain_structurally_valid(
    namespace: str, directive: str
) -> None:
    raw = f"""config {namespace}
    edit "SYNTH-ONE"
        {directive}
    next
    edit "SYNTH-TWO"
        {directive}
    next
end
"""

    section = FortiGateParser().parse(raw).document.section(namespace)

    assert section is not None
    assert section.certainty is EvidenceCertainty.CERTAIN
    assert tuple(entry.name for entry in section.entries) == ("SYNTH-ONE", "SYNTH-TWO")
    assert all(entry.certainty is EvidenceCertainty.CERTAIN for entry in section.entries)


@pytest.mark.parametrize(
    "hidden_section",
    [
        "config system interface extra\n",
        "config system interface;\n",
        "config system interface-extra\n",
        "config system interface.extra\n",
        "config system interface/extra\n",
        "config system interface_extra\n",
        "config system interfaces\n",
        "config systeminterface\n",
        "config ignored wrapper\n    config system interface\n",
    ],
)
def test_ambiguous_or_nested_audited_sections_are_rejected(hidden_section: str) -> None:
    hidden_end = "    end\nend\n" if hidden_section.startswith("config ignored") else "end\n"
    raw = (
        hidden_section
        + '    edit "wan-hidden"\n'
        + "        set allowaccess ssh\n"
        + "    next\n"
        + hidden_end
        + "config system interface\n"
        + '    edit "wan1"\n'
        + "        set allowaccess ping https\n"
        + "    next\n"
        + "end\n"
    )

    with pytest.raises(ValueError, match="ambiguous or nested audited section"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "directive",
    [
        "set allowaccess ssh",
        "append allowaccess ssh",
        "unset allowaccess",
        'append "allowaccess" ssh',
    ],
)
def test_directives_outside_audited_entries_are_rejected(directive: str) -> None:
    raw = f"""config system interface
    {directive}
    edit "wan1"
        set allowaccess ping https
    next
end
"""

    with pytest.raises(ValueError, match="directive outside audited entry"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize("invalidating_directive", ["set hostname", 'unset "hostname"'])
def test_later_invalid_hostname_directive_removes_stale_pass(
    invalidating_directive: str,
) -> None:
    raw = f"""config system global
    set hostname safe.example
    {invalidating_directive}
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)

    assert configuration.hostname is None
    assert findings[0].status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    ("raw", "finding_index"),
    [
        (
            """config system interface
    edit "wan-hidden"
        SET allowaccess ssh
    next
    edit "wan1"
        set allowaccess ping https
    next
end
""",
            1,
        ),
        (
            """config system global
    set hostname safe.example
    set "hostname" fortigate
end
""",
            0,
        ),
    ],
)
def test_keyword_case_or_quoted_audited_key_never_preserves_pass(
    raw: str,
    finding_index: int,
) -> None:
    try:
        findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))
    except ValueError:
        return

    assert findings[finding_index].status is not AuditStatus.PASS


@pytest.mark.parametrize(
    "section",
    [
        "system-interface",
        "system.interface",
        "system/interface",
        "system_interface",
    ],
)
def test_separator_lookalikes_of_audited_sections_are_rejected(section: str) -> None:
    raw = f"""config {section}
    edit "wan-hidden"
        set allowaccess ssh
    next
end
config system interface
    edit "wan1"
        set allowaccess ping https
    next
end
"""

    with pytest.raises(ValueError, match="ambiguous or nested audited section"):
        FortiGateParser().parse(raw)


def test_reserved_directive_lookalike_after_proof_is_rejected() -> None:
    raw = """config system global
    set hostname safe.example
    setx hostname fortigate
end
"""

    with pytest.raises(ValueError, match="ambiguous directive"):
        FortiGateParser().parse(raw)

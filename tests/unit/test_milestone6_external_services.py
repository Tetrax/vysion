from datetime import UTC, datetime, timedelta

import pytest

from vysion.audit.controls.external_services import (
    check_cti_wan_flows,
    check_fortiguard_psirt,
    check_isdb_wan_flows,
    check_ldaps_connectors,
)
from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    AuditContext,
    AuditStatus,
    ExternalObservationStatus,
    PsirtObservation,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


def configuration(version: str = "7.2.9"):
    return FortiGateParser().parse(
        f"#config-version=FGT60E-{version}-FW-build0000-000000:opmode=0:vdom=0:user=admin\n"
        "config system global\n    set hostname edge-fw\nend\n"
    )


def observation(
    status: ExternalObservationStatus,
    *,
    version: str = "7.2.9",
    vulnerabilities: tuple[str, ...] = (),
) -> PsirtObservation:
    return PsirtObservation(
        status=status,
        fortios_version=version,
        vulnerabilities=vulnerabilities,
        source="https://www.fortiguard.com/psirt",
        ruleset_id="fortiguard-psirt-critical-high",
        ruleset_version="2026-08-13",
        observed_at=datetime.now(UTC) - timedelta(minutes=1),
        complete=True,
    )


def ldap(*entries: str) -> str:
    return "config user ldap\n" + "".join(entries) + "end\n"


def ldap_entry(name: str, *directives: str) -> str:
    body = "\n".join(f"        {directive}" for directive in directives)
    return f'    edit "{name}"\n{body}\n    next\n'


def wan_interfaces() -> str:
    return '''config system interface
    edit "wan1"
        set ip 192.0.2.1/24
        set role wan
    next
    edit "lan"
        set ip 10.0.0.1/24
        set role lan
    next
end
'''


def external_resources(*names: str, disabled: tuple[str, ...] = ()) -> str:
    entries = "".join(
        f'    edit "{name}"\n        set status '
        f'{"disable" if name in disabled else "enable"}\n    next\n'
        for name in names
    )
    return "config system external-resource\n" + entries + "end\n"


def policy(
    policy_id: int,
    src: str,
    dst: str,
    *,
    srcaddr: tuple[str, ...] = ("all",),
    dstaddr: tuple[str, ...] = ("all",),
    isdb_src: tuple[str, ...] = (),
    isdb_dst: tuple[str, ...] = (),
    isdb_src_group: str | None = None,
    isdb_dst_group: str | None = None,
) -> str:
    def quote(values: tuple[str, ...]) -> str:
        return " ".join(f'"{value}"' for value in values)
    extra = ""
    if isdb_src:
        extra += f"        set internet-service-src-name {quote(isdb_src)}\n"
    if isdb_dst:
        extra += f"        set internet-service-name {quote(isdb_dst)}\n"
    if isdb_src_group:
        extra += f'        set internet-service-src-group "{isdb_src_group}"\n'
    if isdb_dst_group:
        extra += f'        set internet-service-group "{isdb_dst_group}"\n'
    return (
        f"    edit {policy_id}\n"
        f'        set srcintf "{src}"\n'
        f'        set dstintf "{dst}"\n'
        f"        set srcaddr {quote(srcaddr)}\n"
        f"        set dstaddr {quote(dstaddr)}\n"
        "        set action accept\n"
        "        set status enable\n"
        f"{extra}"
        "    next\n"
    )


def wan_policies(*entries: str) -> str:
    return "config firewall policy\n" + "".join(entries) + "end\n"


def isdb_groups(**groups: tuple[str, ...]) -> str:
    entries = "".join(
        f'    edit "{name}"\n        set member '
        f'{" ".join(chr(34) + value + chr(34) for value in members)}\n    next\n'
        for name, members in groups.items()
    )
    return "config firewall internet-service-group\n" + entries + "end\n"


def test_m6_isdb_casefold_group_collision_is_unknown() -> None:
    incoming = (
        "VPN-Anonymous.VPN", "Tor-Relay.Node", "Tor-Exit.Node", "Spam-Spamming.Server",
        "Proxy-Proxy.Server", "Phishing-Phishing.Server", "Malicious-Malicious.Server",
        "Botnet-C&C.Server",
    )
    outgoing = (
        "VPN-Anonymous.VPN", "Tor-Relay.Node", "Spam-Spamming.Server",
        "Proxy-Proxy.Server", "Phishing-Phishing.Server", "Malicious-Malicious.Server",
        "Botnet-C&C.Server", "Blockchain-Crypto.Mining.Pool",
    )
    raw = (
        wan_interfaces()
        + isdb_groups(Safe=("incomplete",), safe=incoming)
        + wan_policies(
            policy(1, "wan1", "lan", isdb_src_group="SAFE"),
            policy(2, "lan", "wan1", isdb_dst=outgoing),
        )
    )

    assert check_isdb_wan_flows(FortiGateParser().parse(raw)).status is AuditStatus.UNKNOWN


def test_m6_cti_complete_resources_and_wan_flows_pass() -> None:
    cti = (
        "IPV4_CTI_SNS",
        "IPV4_SNS",
        "HASH_CTI_SNS_SHA1",
        "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1",
        "HASH_SNS_SHA256",
        "FQDN_SNS",
        "URL_SNS",
        "FQDN_CTI_SNS",
        "URL_CTI_SNS",
    )
    ipv4 = ("IPV4_CTI_SNS", "IPV4_SNS")
    raw = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
        + wan_interfaces()
        + external_resources(*cti)
        + wan_policies(
            policy(1, "wan1", "lan", srcaddr=ipv4),
            policy(2, "lan", "wan1", dstaddr=ipv4),
        )
    )

    assert check_cti_wan_flows(FortiGateParser().parse(raw)).status is AuditStatus.PASS


def test_m6_cti_resource_casefold_collision_is_unknown_but_unique_fold_resolves() -> None:
    cti = (
        "IPV4_CTI_SNS", "IPV4_SNS", "HASH_CTI_SNS_SHA1", "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1", "HASH_SNS_SHA256", "FQDN_SNS", "URL_SNS",
        "FQDN_CTI_SNS", "URL_CTI_SNS",
    )
    ipv4 = ("IPV4_CTI_SNS", "IPV4_SNS")
    policies = wan_policies(
        policy(1, "wan1", "lan", srcaddr=ipv4),
        policy(2, "lan", "wan1", dstaddr=ipv4),
    )
    canonical = external_resources(*cti)
    collision = canonical.replace(
        "end\n",
        '    edit "ipv4_cti_sns"\n        set status disable\n    next\nend\n',
    )
    unique_fold = external_resources(*(name.lower() for name in cti))
    prefix = "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n" + wan_interfaces()

    assert (
        check_cti_wan_flows(FortiGateParser().parse(prefix + collision + policies)).status
        is AuditStatus.UNKNOWN
    )
    assert (
        check_cti_wan_flows(FortiGateParser().parse(prefix + unique_fold + policies)).status
        is AuditStatus.PASS
    )


def test_m6_cti_policy_defaulted_status_is_unknown_not_active() -> None:
    cti = (
        "IPV4_CTI_SNS",
        "IPV4_SNS",
        "HASH_CTI_SNS_SHA1",
        "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1",
        "HASH_SNS_SHA256",
        "FQDN_SNS",
        "URL_SNS",
        "FQDN_CTI_SNS",
        "URL_CTI_SNS",
    )
    raw = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
        "#buildno=1\n"
        "#global_vdom=1\n"
        "#conf_file_ver=1\n"
        + wan_interfaces()
        + external_resources(*cti)
        + wan_policies(
            policy(
                1,
                "wan1",
                "lan",
                srcaddr=("IPV4_CTI_SNS", "IPV4_SNS"),
            ).replace("        set status enable\n", "")
        )
    )

    assert check_cti_wan_flows(FortiGateParser().parse(raw)).status is AuditStatus.UNKNOWN


def test_m6_cti_missing_explicit_flow_object_fails_but_unknown_relation_is_unknown() -> None:
    cti = (
        "IPV4_CTI_SNS", "IPV4_SNS", "HASH_CTI_SNS_SHA1", "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1", "HASH_SNS_SHA256", "FQDN_SNS", "URL_SNS",
        "FQDN_CTI_SNS", "URL_CTI_SNS",
    )
    weak = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
        + wan_interfaces() + external_resources(*cti)
        + wan_policies(policy(1, "wan1", "lan", srcaddr=("IPV4_SNS",)))
    )
    unknown = external_resources(*cti) + wan_policies(policy(1, "mystery", "lan"))

    assert check_cti_wan_flows(FortiGateParser().parse(weak)).status is AuditStatus.FAIL
    assert check_cti_wan_flows(FortiGateParser().parse(unknown)).status is AuditStatus.UNKNOWN


def test_m6_cti_disabled_resource_fails_and_unknown_policy_prevents_pass() -> None:
    cti = (
        "IPV4_CTI_SNS", "IPV4_SNS", "HASH_CTI_SNS_SHA1", "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1", "HASH_SNS_SHA256", "FQDN_SNS", "URL_SNS",
        "FQDN_CTI_SNS", "URL_CTI_SNS",
    )
    ipv4 = ("IPV4_CTI_SNS", "IPV4_SNS")
    disabled = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n" + wan_interfaces()
        + external_resources(*cti, disabled=("IPV4_CTI_SNS",))
        + wan_policies(policy(1, "wan1", "lan", srcaddr=ipv4))
    )
    mixed = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n" + wan_interfaces()
        + external_resources(*cti)
        + wan_policies(
            policy(1, "wan1", "lan", srcaddr=ipv4),
            policy(2, "mystery", "lan", srcaddr=ipv4),
        )
    )

    assert check_cti_wan_flows(FortiGateParser().parse(disabled)).status is AuditStatus.FAIL
    assert check_cti_wan_flows(FortiGateParser().parse(mixed)).status is AuditStatus.UNKNOWN


def test_m6_cti_ambiguous_present_resources_are_unknown_not_missing() -> None:
    cti = (
        "IPV4_CTI_SNS",
        "IPV4_SNS",
        "HASH_CTI_SNS_SHA1",
        "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1",
        "HASH_SNS_SHA256",
        "FQDN_SNS",
        "URL_SNS",
        "FQDN_CTI_SNS",
        "URL_CTI_SNS",
    )
    ipv4 = ("IPV4_CTI_SNS", "IPV4_SNS")
    resources = external_resources(*cti).replace(
        "    next\n",
        "        set mystery opaque\n    next\n",
    )
    raw = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
        + wan_interfaces()
        + resources
        + wan_policies(
            policy(1, "wan1", "lan", srcaddr=ipv4),
            policy(2, "lan", "wan1", dstaddr=ipv4),
        )
    )

    assert check_cti_wan_flows(FortiGateParser().parse(raw)).status is AuditStatus.UNKNOWN


def test_m6_cti_explicit_disabled_resource_dominates_unknown_key() -> None:
    cti = (
        "IPV4_CTI_SNS",
        "IPV4_SNS",
        "HASH_CTI_SNS_SHA1",
        "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1",
        "HASH_SNS_SHA256",
        "FQDN_SNS",
        "URL_SNS",
        "FQDN_CTI_SNS",
        "URL_CTI_SNS",
    )
    ipv4 = ("IPV4_CTI_SNS", "IPV4_SNS")
    resources = external_resources(*cti, disabled=("IPV4_CTI_SNS",)).replace(
        "    next\n",
        "        set mystery opaque\n    next\n",
    )
    raw = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
        + wan_interfaces()
        + resources
        + wan_policies(policy(1, "wan1", "lan", srcaddr=ipv4))
    )

    assert check_cti_wan_flows(FortiGateParser().parse(raw)).status is AuditStatus.FAIL


def test_m6_isdb_complete_bidirectional_wan_flows_pass_and_missing_fails() -> None:
    incoming = (
        "VPN-Anonymous.VPN", "Tor-Relay.Node", "Tor-Exit.Node", "Spam-Spamming.Server",
        "Proxy-Proxy.Server", "Phishing-Phishing.Server", "Malicious-Malicious.Server",
        "Botnet-C&C.Server",
    )
    outgoing = (
        "VPN-Anonymous.VPN", "Tor-Relay.Node", "Spam-Spamming.Server",
        "Proxy-Proxy.Server", "Phishing-Phishing.Server", "Malicious-Malicious.Server",
        "Botnet-C&C.Server", "Blockchain-Crypto.Mining.Pool",
    )
    complete = wan_interfaces() + wan_policies(
        policy(1, "wan1", "lan", isdb_src=incoming),
        policy(2, "lan", "wan1", isdb_dst=outgoing),
    )
    weak = wan_interfaces() + wan_policies(
        policy(1, "wan1", "lan", isdb_src=incoming[:-1])
    )

    assert check_isdb_wan_flows(FortiGateParser().parse(complete)).status is AuditStatus.PASS
    assert check_isdb_wan_flows(FortiGateParser().parse(weak)).status is AuditStatus.FAIL


def test_m6_isdb_resolves_groups_and_orphan_group_is_unknown() -> None:
    incoming = (
        "VPN-Anonymous.VPN", "Tor-Relay.Node", "Tor-Exit.Node", "Spam-Spamming.Server",
        "Proxy-Proxy.Server", "Phishing-Phishing.Server", "Malicious-Malicious.Server",
        "Botnet-C&C.Server",
    )
    complete = wan_interfaces() + isdb_groups(block_in=incoming) + wan_policies(
        policy(1, "wan1", "lan", isdb_src_group="block_in")
    )
    orphan = wan_interfaces() + wan_policies(
        policy(1, "wan1", "lan", isdb_src_group="missing")
    )

    assert check_isdb_wan_flows(FortiGateParser().parse(complete)).status is AuditStatus.PASS
    assert check_isdb_wan_flows(FortiGateParser().parse(orphan)).status is AuditStatus.UNKNOWN


def test_m6_ldaps_all_connectors_secure_with_ca_pass() -> None:
    raw = ldap(
        ldap_entry("ldap-a", "set secure ldaps", 'set ca-cert "Corp-CA"'),
        ldap_entry("ldap-b", "set secure ldaps", 'set ca-cert "Backup-CA"'),
    )

    finding = check_ldaps_connectors(FortiGateParser().parse(raw))

    assert finding.status is AuditStatus.PASS
    assert all(item.certainty.value == "certain" for item in finding.evidence_items)


def test_m6_ldaps_explicit_insecure_or_missing_ca_fails() -> None:
    insecure = check_ldaps_connectors(
        FortiGateParser().parse(ldap(ldap_entry("ldap-a", "set secure disable")))
    )
    no_ca = check_ldaps_connectors(
        FortiGateParser().parse(ldap(ldap_entry("ldap-a", "set secure ldaps")))
    )

    assert insecure.status is AuditStatus.FAIL
    assert no_ca.status is AuditStatus.UNKNOWN


def test_m6_ldaps_explicit_violation_dominates_unknown_connector() -> None:
    raw = ldap(
        ldap_entry("weak", "set secure disable"),
        ldap_entry("unknown", "set secure ldaps", "unset ca-cert"),
    )

    assert check_ldaps_connectors(FortiGateParser().parse(raw)).status is AuditStatus.FAIL


def test_m6_ldaps_absent_namespace_is_unknown_but_explicit_empty_is_not_applicable() -> None:
    missing = check_ldaps_connectors(FortiGateParser().parse("config system global\nend\n"))
    empty = check_ldaps_connectors(FortiGateParser().parse(ldap()))

    assert missing.status is AuditStatus.UNKNOWN
    assert empty.status is AuditStatus.NOT_APPLICABLE
    assert empty.applicability.value == "not_applicable"


def test_registry_preserves_existing_prefix_and_appends_parity_controls() -> None:
    expected_ids = (
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
        "UTM-MAIL-FILTER-USAGE-001",
        "FW-SSL-SSH-PROFILE-001",
    )
    configuration = FortiGateParser().parse("config system global\nend\n")

    registered_ids = tuple(
        finding.control_id for finding in AuditEngine(default_registry()).run(configuration)
    )

    assert registered_ids == expected_ids
    assert len(registered_ids) == 42
    assert registered_ids[-15:] == (
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
    )


@pytest.mark.parametrize("secure_value", ["unknown", "starttls"])
def test_m6_ldaps_unrecognized_or_non_ldaps_secure_value_is_unknown(secure_value: str) -> None:
    raw = ldap(ldap_entry("ldap-a", f"set secure {secure_value}", 'set ca-cert "Corp-CA"'))

    finding = check_ldaps_connectors(FortiGateParser().parse(raw))

    assert finding.status is AuditStatus.UNKNOWN


def test_m6_ldaps_case_variant_secure_value_cannot_pass() -> None:
    raw = ldap(ldap_entry("ldap-a", "set secure LDAPS", 'set ca-cert "Corp-CA"'))

    assert check_ldaps_connectors(FortiGateParser().parse(raw)).status is AuditStatus.UNKNOWN


def test_m6_ldaps_case_variant_directive_key_cannot_pass() -> None:
    raw = ldap(ldap_entry("ldap-a", "set Secure ldaps", 'set ca-cert "Corp-CA"'))

    assert check_ldaps_connectors(FortiGateParser().parse(raw)).status is AuditStatus.UNKNOWN


def test_m6_ldaps_nested_lookalike_evidence_cannot_pass() -> None:
    raw = """config user ldap
    edit "ldap-a"
        set secure ldaps
        set ca-cert "Corp-CA"
        config nested
            edit "lookalike"
                set secure ldaps
                set ca-cert "Nested-CA"
            next
        end
    next
end
"""

    assert check_ldaps_connectors(FortiGateParser().parse(raw)).status is AuditStatus.UNKNOWN


def test_m6_psirt_complete_correlated_clean_observation_passes() -> None:
    finding = check_fortiguard_psirt(
        configuration(),
        context=AuditContext(psirt=observation(ExternalObservationStatus.PASS)),
    )

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert "fortiguard-psirt-critical-high" in " ".join(finding.evidence)


def test_m6_psirt_explicit_vulnerabilities_fail() -> None:
    finding = check_fortiguard_psirt(
        configuration(),
        context=AuditContext(
            psirt=observation(
                ExternalObservationStatus.FAIL,
                vulnerabilities=("FG-IR-24-001 / CVE-2024-0001",),
            )
        ),
    )

    assert finding.status is AuditStatus.FAIL
    assert finding.affected_objects
    assert "CVE-2024-0001" in " ".join(finding.evidence)


@pytest.mark.parametrize(
    "context",
    [
        None,
        AuditContext(),
        AuditContext(psirt=observation(ExternalObservationStatus.UNKNOWN)),
        AuditContext(psirt=observation(ExternalObservationStatus.ERROR)),
        AuditContext(psirt=observation(ExternalObservationStatus.PASS, version="7.4.1")),
        AuditContext(
            psirt=PsirtObservation(
                status=ExternalObservationStatus.PASS,
                fortios_version="7.2.9",
                source="https://www.fortiguard.com/psirt",
                ruleset_id="fortiguard-psirt-critical-high",
                ruleset_version="2026-08-13",
                observed_at=None,
                complete=True,
            )
        ),
    ],
)
def test_m6_psirt_absent_incomplete_or_uncorrelated_is_unknown(
    context: AuditContext | None,
) -> None:
    assert check_fortiguard_psirt(configuration(), context=context).status is AuditStatus.UNKNOWN


def test_m6_psirt_fail_requires_explicit_vulnerability_evidence() -> None:
    context = AuditContext(psirt=observation(ExternalObservationStatus.FAIL))

    assert check_fortiguard_psirt(configuration(), context=context).status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    "observed_at",
    [
        datetime.now(UTC) - timedelta(hours=25),
        datetime.now(UTC) + timedelta(minutes=5),
        datetime.now().replace(microsecond=0),
    ],
)
def test_m6_psirt_stale_future_or_naive_observation_is_unknown(
    observed_at: datetime,
) -> None:
    current = observation(ExternalObservationStatus.PASS).model_copy(
        update={"observed_at": observed_at}
    )

    finding = check_fortiguard_psirt(configuration(), AuditContext(psirt=current))

    assert finding.status is AuditStatus.UNKNOWN


def test_m6_psirt_lookalike_https_source_is_unknown() -> None:
    current = observation(ExternalObservationStatus.PASS).model_copy(
        update={"source": "https://example.invalid/fortiguard.com/psirt"}
    )

    assert (
        check_fortiguard_psirt(configuration(), AuditContext(psirt=current)).status
        is AuditStatus.UNKNOWN
    )


def test_m6_ldaps_unknown_directive_cannot_pass() -> None:
    raw = ldap(
        ldap_entry(
            "ldap-a",
            "set secure ldaps",
            'set ca-cert "Corp-CA"',
            "set mystery value",
        )
    )

    assert check_ldaps_connectors(FortiGateParser().parse(raw)).status is AuditStatus.UNKNOWN


def test_m6_nested_ldap_namespace_is_rejected_fail_closed() -> None:
    raw = """config vendor-wrapper
    config user ldap
        edit "hidden"
            set secure disable
        next
    end
end
config user ldap
    edit "safe"
        set secure ldaps
        set ca-cert "Corp-CA"
    next
end
"""

    with pytest.raises(ValueError, match="nested projected section"):
        FortiGateParser().parse(raw)


def test_m6_psirt_explicit_vulnerability_dominates_pass_status() -> None:
    current = observation(
        ExternalObservationStatus.PASS,
        vulnerabilities=("CVE-2026-1234",),
    ).model_copy(update={"observed_at": datetime.now(UTC)})

    finding = check_fortiguard_psirt(configuration(), AuditContext(psirt=current))

    assert finding.status is AuditStatus.FAIL


def test_m6_psirt_arbitrary_ruleset_is_unknown() -> None:
    current = observation(ExternalObservationStatus.PASS).model_copy(
        update={"ruleset_id": "arbitrary", "observed_at": datetime.now(UTC)}
    )

    finding = check_fortiguard_psirt(configuration(), AuditContext(psirt=current))

    assert finding.status is AuditStatus.UNKNOWN


def test_m6_multi_interface_wan_policy_is_audited_not_ignored() -> None:
    cti = (
        "IPV4_CTI_SNS",
        "IPV4_SNS",
        "HASH_CTI_SNS_SHA1",
        "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1",
        "HASH_SNS_SHA256",
        "FQDN_SNS",
        "URL_SNS",
        "FQDN_CTI_SNS",
        "URL_CTI_SNS",
    )
    incoming = (
        "VPN-Anonymous.VPN",
        "Tor-Relay.Node",
        "Tor-Exit.Node",
        "Spam-Spamming.Server",
        "Proxy-Proxy.Server",
        "Phishing-Phishing.Server",
        "Malicious-Malicious.Server",
        "Botnet-C&C.Server",
    )
    raw = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
        + """config system interface
    edit "wan1"
        set role wan
    next
    edit "lan"
        set role lan
    next
    edit "dmz"
        set role lan
    next
end
"""
        + external_resources(*cti)
        + wan_policies(
            policy(
                1,
                "wan1",
                "lan",
                srcaddr=("IPV4_CTI_SNS", "IPV4_SNS"),
                isdb_src=incoming,
            ),
            """    edit 2
        set srcintf "wan1" "dmz"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status enable
    next
""",
        )
    )
    parsed = FortiGateParser().parse(raw)

    assert check_cti_wan_flows(parsed).status is AuditStatus.FAIL
    assert check_isdb_wan_flows(parsed).status is AuditStatus.FAIL


def test_m6_wan_policy_without_explicit_enabled_status_cannot_pass() -> None:
    cti = (
        "IPV4_CTI_SNS",
        "IPV4_SNS",
        "HASH_CTI_SNS_SHA1",
        "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1",
        "HASH_SNS_SHA256",
        "FQDN_SNS",
        "URL_SNS",
        "FQDN_CTI_SNS",
        "URL_CTI_SNS",
    )
    incoming = (
        "VPN-Anonymous.VPN",
        "Tor-Relay.Node",
        "Tor-Exit.Node",
        "Spam-Spamming.Server",
        "Proxy-Proxy.Server",
        "Phishing-Phishing.Server",
        "Malicious-Malicious.Server",
        "Botnet-C&C.Server",
    )
    raw = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
        + wan_interfaces()
        + external_resources(*cti)
        + "config firewall policy\n"
        + """    edit 1
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "IPV4_CTI_SNS" "IPV4_SNS"
        set dstaddr "all"
        set action accept
        set internet-service-src-name """
        + " ".join(f'"{name}"' for name in incoming)
        + "\n    next\nend\n"
    )
    parsed = FortiGateParser().parse(raw)

    assert check_cti_wan_flows(parsed).status is AuditStatus.UNKNOWN
    assert check_isdb_wan_flows(parsed).status is AuditStatus.UNKNOWN

    complete_policy = policy(
        2,
        "wan1",
        "lan",
        srcaddr=("IPV4_CTI_SNS", "IPV4_SNS"),
        isdb_src=incoming,
    )
    mixed_raw = raw.replace(
        "config firewall policy\n",
        "config firewall policy\n" + complete_policy,
    )
    mixed = FortiGateParser().parse(mixed_raw)

    assert check_cti_wan_flows(mixed).status is AuditStatus.UNKNOWN
    assert check_isdb_wan_flows(mixed).status is AuditStatus.UNKNOWN


def test_m6_explicit_weak_wan_policy_dominates_unknown_projected_key() -> None:
    cti = (
        "IPV4_CTI_SNS",
        "IPV4_SNS",
        "HASH_CTI_SNS_SHA1",
        "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1",
        "HASH_SNS_SHA256",
        "FQDN_SNS",
        "URL_SNS",
        "FQDN_CTI_SNS",
        "URL_CTI_SNS",
    )
    weak_policy = policy(1, "wan1", "lan", srcaddr=("IPV4_SNS",)).replace(
        "    next\n",
        "        set mystery opaque\n    next\n",
    )
    raw = (
        "#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
        + wan_interfaces()
        + external_resources(*cti)
        + wan_policies(weak_policy)
    )
    parsed = FortiGateParser().parse(raw)

    assert check_cti_wan_flows(parsed).status is AuditStatus.FAIL
    assert check_isdb_wan_flows(parsed).status is AuditStatus.FAIL

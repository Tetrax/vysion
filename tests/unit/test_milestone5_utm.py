from __future__ import annotations

from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext, AuditStatus, ContextProvenance
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


def audit(
    raw: str,
    *,
    licensed: bool | None = True,
    provenance: bool = True,
):
    configuration = FortiGateParser().parse(raw)
    context = AuditContext(
        utm_license=licensed,
        operator_provenance=(
            ContextProvenance(source="unit-test", method="explicit-context")
            if provenance
            else None
        ),
    )
    return {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(configuration, context=context)
    }


def policy_with(*directives: str) -> str:
    body = "\n".join(f"        {directive}" for directive in directives)
    return f"""config firewall policy
    edit 1
        set status enable
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
{body}
    next
end
"""


def test_m5_utm_license_true_with_provenance_passes() -> None:
    finding = audit("config system global\nend\n")["UTM-LICENSE-001"]

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty.value == "certain" for item in finding.evidence_items)


def test_m5_utm_license_false_with_provenance_fails() -> None:
    assert audit("config system global\nend\n", licensed=False)[
        "UTM-LICENSE-001"
    ].status is AuditStatus.FAIL


def test_m5_utm_license_missing_or_without_provenance_is_unknown() -> None:
    raw = "config system global\nend\n"

    assert audit(raw, licensed=None)["UTM-LICENSE-001"].status is AuditStatus.UNKNOWN
    assert audit(raw, licensed=True, provenance=False)[
        "UTM-LICENSE-001"
    ].status is AuditStatus.UNKNOWN


def autoupdate(*directives: str) -> str:
    body = "\n".join(f"    {directive}" for directive in directives)
    return f"config system autoupdate schedule\n{body}\nend\n"


def test_m5_autoupdate_explicit_automatic_passes() -> None:
    finding = audit(autoupdate("set status enable", "set frequency automatic"))[
        "UTM-AUTOUPDATE-001"
    ]

    assert finding.status is AuditStatus.PASS
    assert {item.directive for item in finding.evidence_items} == {"status", "frequency"}


def test_m5_autoupdate_explicit_disable_or_nonautomatic_fails() -> None:
    assert audit(autoupdate("set status disable", "set frequency automatic"))[
        "UTM-AUTOUPDATE-001"
    ].status is AuditStatus.FAIL
    assert audit(autoupdate("set status enable", "set frequency daily"))[
        "UTM-AUTOUPDATE-001"
    ].status is AuditStatus.FAIL


def test_m5_autoupdate_missing_or_mutated_is_unknown() -> None:
    assert audit("config system global\nend\n")[
        "UTM-AUTOUPDATE-001"
    ].status is AuditStatus.UNKNOWN
    assert audit(
        autoupdate("set status enable", "set frequency automatic", "unset frequency")
    )["UTM-AUTOUPDATE-001"].status is AuditStatus.UNKNOWN


def test_m5_autoupdate_unknown_key_prevents_pass() -> None:
    finding = audit(
        autoupdate(
            "set status enable",
            "set frequency automatic",
            "set mystery opaque",
        )
    )["UTM-AUTOUPDATE-001"]

    assert finding.status is AuditStatus.UNKNOWN


def test_m5_autoupdate_explicit_disable_dominates_unknown_key() -> None:
    finding = audit(
        autoupdate(
            "set status disable",
            "set frequency automatic",
            "set mystery opaque",
        )
    )["UTM-AUTOUPDATE-001"]

    assert finding.status is AuditStatus.FAIL


def dnsfilter_profile(*blocklists: str, category_212: str = "block") -> str:
    lists = " ".join(f'"{item}"' for item in blocklists)
    return f'''config dnsfilter profile
    edit "dns-safe"
        set external-ip-blocklist {lists}
        config ftgd-dns
            set options error-allow
            config filters
                edit 1
                    set category 211
                    set action block
                next
                edit 2
                    set category 212
                    set action {category_212}
                next
            end
        end
    next
end
''' + policy_with('set dnsfilter-profile "dns-safe"')


def test_m5_parser_extracts_model_and_version_from_config_header() -> None:
    configuration = FortiGateParser().parse(
        "#config-version=FGT60E-7.4.1-FW-build2577-240514:opmode=0:vdom=0\n"
        "config system global\nend\n"
    )

    assert configuration.device_identity.model == "60E"
    assert configuration.device_identity.firmware_version == "7.4.1"
    assert {"model", "firmware-version"} <= configuration.device_identity.parsed_keys


def test_m5_dnsfilter_model_specific_profile_passes() -> None:
    raw = "#config-version=FG60E-7.4.1:build0000\n" + dnsfilter_profile(
        "IPV4_CTI_SNS", "IPV4_SNS"
    )
    finding = audit(raw)["UTM-DNSFILTER-001"]

    assert finding.status is AuditStatus.PASS
    assert all(item.certainty.value == "certain" for item in finding.evidence_items)


def test_m5_dnsfilter_missing_required_list_or_weak_category_fails() -> None:
    missing = "#config-version=FG60E-7.4.1:build0000\n" + dnsfilter_profile("IPV4_SNS")
    weak = "#config-version=FG60E-7.4.1:build0000\n" + dnsfilter_profile(
        "IPV4_CTI_SNS", "IPV4_SNS", category_212="monitor"
    )

    assert audit(missing)["UTM-DNSFILTER-001"].status is AuditStatus.FAIL
    assert audit(weak)["UTM-DNSFILTER-001"].status is AuditStatus.FAIL


def test_m5_dnsfilter_missing_or_conflicting_model_is_unknown() -> None:
    profile = dnsfilter_profile("IPV4_CTI_SNS", "IPV4_SNS")
    conflicting = (
        "#config-version=FG60E-7.4.1:build0000\n"
        "#config-version=FG40F-7.4.1:build0000\n"
        + profile
    )

    assert audit(profile)["UTM-DNSFILTER-001"].status is AuditStatus.UNKNOWN
    assert audit(conflicting)["UTM-DNSFILTER-001"].status is AuditStatus.UNKNOWN


def test_m5_used_complete_webfilter_profile_passes() -> None:
    raw = """config webfilter profile
    edit "web-safe"
        config web
            set blocklist enable
        end
        config ftgd-wf
            set options error-allow
            config filters
                edit 1
                    set category 207
                next
                edit 2
                    set category 209
                    set action block
                next
                edit 3
                    set category 210
                    set action block
                next
            end
        end
    next
end
""" + policy_with('set webfilter-profile "web-safe"')

    finding = audit(raw)["UTM-WEBFILTER-001"]

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty.value == "certain" for item in finding.evidence_items)


def webfilter_profile_entry(
    name: str = "web-safe",
    *,
    blocklist: str = "enable",
    options: str = "error-allow",
    category_207: str = "",
    category_209: str = "set action block",
    category_210: str = "set action block",
) -> str:
    return f'''    edit "{name}"
        config web
            set blocklist {blocklist}
        end
        config ftgd-wf
            set options {options}
            config filters
                edit 1
                    set category 207
                    {category_207}
                next
                edit 2
                    set category 209
                    {category_209}
                next
                edit 3
                    set category 210
                    {category_210}
                next
            end
        end
    next
'''


def webfilter_profiles(*entries: str) -> str:
    return "config webfilter profile\n" + "".join(entries) + "end\n"


def webfilter_profile(name: str = "web-safe", **kwargs: str) -> str:
    return webfilter_profiles(webfilter_profile_entry(name=name, **kwargs))


def policy_pair(*profile_names: str) -> str:
    entries = []
    for index, name in enumerate(profile_names, start=1):
        entries.append(
            f'''    edit {index}
        set status enable
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set webfilter-profile "{name}"
    next
'''
        )
    return "config firewall policy\n" + "".join(entries) + "end\n"


def test_m5_orphan_profile_group_prevents_false_pass() -> None:
    raw = webfilter_profile() + policy_with(
        'set webfilter-profile "web-safe"',
        'set profile-group "missing-group"',
    )

    assert audit(raw)["UTM-WEBFILTER-001"].status is AuditStatus.UNKNOWN


def test_m5_explicit_profile_failure_dominates_orphan_group() -> None:
    raw = webfilter_profile(blocklist="disable") + policy_with(
        'set webfilter-profile "web-safe"',
        'set profile-group "missing-group"',
    )

    assert audit(raw)["UTM-WEBFILTER-001"].status is AuditStatus.FAIL


def test_m5_resolved_profile_group_can_prove_used_profile() -> None:
    raw = webfilter_profile() + '''config firewall profile-group
    edit "utm-safe"
        set webfilter-profile "web-safe"
    next
end
''' + policy_with('set profile-group "utm-safe"')

    assert audit(raw)["UTM-WEBFILTER-001"].status is AuditStatus.PASS


def test_m5_explicit_webfilter_weakness_is_fail() -> None:
    raw = webfilter_profile(category_209="set action monitor") + policy_with(
        'set webfilter-profile "web-safe"'
    )

    assert audit(raw)["UTM-WEBFILTER-001"].status is AuditStatus.FAIL


def test_m5_webfilter_weakness_dominates_other_ambiguous_profile() -> None:
    raw = (
        webfilter_profiles(
            webfilter_profile_entry(name="weak", blocklist="disable"),
            webfilter_profile_entry(name="ambiguous", category_210="unset action"),
        )
        + policy_pair("weak", "ambiguous")
    )

    assert audit(raw)["UTM-WEBFILTER-001"].status is AuditStatus.FAIL


def test_m5_mutated_webfilter_field_is_unknown() -> None:
    raw = webfilter_profile(category_210="unset action") + policy_with(
        'set webfilter-profile "web-safe"'
    )

    assert audit(raw)["UTM-WEBFILTER-001"].status is AuditStatus.UNKNOWN


def test_m5_orphan_webfilter_reference_is_unknown() -> None:
    finding = audit(policy_with('set webfilter-profile "missing"'))[
        "UTM-WEBFILTER-001"
    ]

    assert finding.status is AuditStatus.UNKNOWN


def test_m5_unknown_utm_license_never_passes() -> None:
    raw = webfilter_profile() + policy_with('set webfilter-profile "web-safe"')

    assert audit(raw, licensed=None)["UTM-WEBFILTER-001"].status is AuditStatus.UNKNOWN
    assert audit(raw, licensed=True, provenance=False)[
        "UTM-WEBFILTER-001"
    ].status is AuditStatus.UNKNOWN


def test_m5_used_complete_antivirus_profile_passes() -> None:
    raw = '''config antivirus profile
    edit "av-safe"
        set external-blocklist-enable-all enable
        set analytics-db enable
    next
end
''' + policy_with('set av-profile "av-safe"')

    assert audit(raw)["UTM-ANTIVIRUS-001"].status is AuditStatus.PASS


def test_m5_used_complete_ips_profile_passes() -> None:
    raw = '''config ips sensor
    edit "ips-safe"
        set block-malicious-url enable
        set scan-botnet-connections block
    next
end
''' + policy_with('set ips-sensor "ips-safe"')

    assert audit(raw)["UTM-IPS-001"].status is AuditStatus.PASS


def test_m5_used_complete_appcontrol_profile_passes() -> None:
    raw = '''config application list
    edit "app-safe"
        config entries
            edit 1
                set category 2
                set action block
            next
            edit 2
                set category 6
                set action block
            next
            edit 3
                set category 7
                set action block
            next
        end
    next
end
''' + policy_with('set application-list "app-safe"')

    assert audit(raw)["UTM-APPCONTROL-001"].status is AuditStatus.PASS


def test_m5_explicit_antivirus_weakness_fails() -> None:
    raw = '''config antivirus profile
    edit "av-weak"
        set external-blocklist-enable-all disable
        set external-blocklist "HASH_SNS_SHA1"
        set analytics-db disable
    next
end
''' + policy_with('set av-profile "av-weak"')

    assert audit(raw)["UTM-ANTIVIRUS-001"].status is AuditStatus.FAIL


def test_m5_missing_antivirus_alternative_is_unknown() -> None:
    raw = '''config antivirus profile
    edit "av-unknown"
        set analytics-db enable
    next
end
''' + policy_with('set av-profile "av-unknown"')

    assert audit(raw)["UTM-ANTIVIRUS-001"].status is AuditStatus.UNKNOWN


def test_m5_explicit_ips_weakness_fails() -> None:
    raw = '''config ips sensor
    edit "ips-weak"
        set block-malicious-url disable
        set scan-botnet-connections block
    next
end
''' + policy_with('set ips-sensor "ips-weak"')

    assert audit(raw)["UTM-IPS-001"].status is AuditStatus.FAIL


def test_m5_mutated_ips_field_is_unknown() -> None:
    raw = '''config ips sensor
    edit "ips-unknown"
        set block-malicious-url enable
        unset block-malicious-url
        set scan-botnet-connections block
    next
end
''' + policy_with('set ips-sensor "ips-unknown"')

    assert audit(raw)["UTM-IPS-001"].status is AuditStatus.UNKNOWN


def test_m5_appcontrol_missing_action_is_unknown_not_implicit_block() -> None:
    raw = '''config application list
    edit "app-unknown"
        config entries
            edit 1
                set category 2 6 7
            next
        end
    next
end
''' + policy_with('set application-list "app-unknown"')

    assert audit(raw)["UTM-APPCONTROL-001"].status is AuditStatus.UNKNOWN


def test_m5_explicit_appcontrol_pass_action_fails() -> None:
    raw = '''config application list
    edit "app-weak"
        config entries
            edit 1
                set category 2 6 7
                set action pass
            next
        end
    next
end
''' + policy_with('set application-list "app-weak"')

    assert audit(raw)["UTM-APPCONTROL-001"].status is AuditStatus.FAIL

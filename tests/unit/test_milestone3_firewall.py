from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest

from vysion.audit.controls.firewall import (
    SENSITIVE_PROTOCOL_RULESET_ID,
    SENSITIVE_PROTOCOL_RULESET_VERSION,
)
from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    Applicability,
    AuditContext,
    AuditPriority,
    AuditStatus,
    EvidenceCertainty,
    ObjectReference,
    ProofState,
    WanSelectionKind,
    Zone,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

M3_IDS = (
    "FW-IMPLICIT-DENY-LOG-001",
    "FW-INTERNET-ALL-SERVICE-001",
    "FW-UTM-PROFILE-BINDING-001",
    "FW-VIP-EXTINTF-ANY-001",
    "FW-VSERVER-EXTINTF-ANY-001",
    "FW-SENSITIVE-PROTOCOL-DENY-001",
)


def audit(raw: str, *, context=None):
    configuration = FortiGateParser().parse(raw)
    return {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(configuration, context=context)
    }


def base_interfaces(*, wan_role: str | None = "wan", include_zone: bool = True) -> str:
    zone = (
        """config system zone
    edit "lan-zone"
        set interface "port1"
    next
    edit "wan-zone"
        set interface "wan1"
    next
end
"""
        if include_zone
        else ""
    )
    wan_role_line = f"        set role {wan_role}\n" if wan_role is not None else ""
    return f"""config system interface
    edit "port1"
        set role lan
        set allowaccess ping
    next
    edit "wan1"
{wan_role_line}        set allowaccess ping
    next
end
{zone}"""


def policy_entry(
    policy_id: int | str,
    *,
    action: str | None = "accept",
    source: str | None = "lan-zone",
    destination: str | None = "wan-zone",
    services: Iterable[str] | None = ("HTTPS",),
    status: str | None = "enable",
    logtraffic: str | None = "all",
    utm_status: str | None = None,
    profiles: str = "",
    extra: str = "",
) -> str:
    lines = [f"    edit {policy_id}"]
    if status is not None:
        lines.append(f"        set status {status}")
    if source is not None:
        lines.append(f'        set srcintf "{source}"')
    if destination is not None:
        lines.append(f'        set dstintf "{destination}"')
    lines.extend(
        [
            '        set srcaddr "all"',
            '        set dstaddr "all"',
        ]
    )
    if action is not None:
        lines.append(f"        set action {action}")
    lines.append('        set schedule "always"')
    if services is not None:
        lines.append("        set service " + " ".join(f'"{service}"' for service in services))
    if logtraffic is not None:
        lines.append(f"        set logtraffic {logtraffic}")
    if utm_status is not None:
        lines.append(f"        set utm-status {utm_status}")
    if profiles:
        lines.extend(profiles.rstrip("\n").splitlines())
    if extra:
        lines.extend(extra.rstrip("\n").splitlines())
    lines.append("    next")
    return "\n".join(lines) + "\n"


def policy_block(*entries: str) -> str:
    return "config firewall policy\n" + "".join(entries) + "end\n"


def service_entry(
    name: str,
    *,
    tcp: str | None = None,
    udp: str | None = None,
    members: Iterable[str] | None = None,
    mutation: str = "",
) -> str:
    lines = [f'    edit "{name}"']
    if tcp is not None:
        lines.append(f'        set tcp-portrange "{tcp}"')
    if udp is not None:
        lines.append(f'        set udp-portrange "{udp}"')
    if members is not None:
        lines.append("        set member " + " ".join(f'"{member}"' for member in members))
    if mutation:
        lines.append(f"        {mutation}")
    lines.append("    next")
    return "\n".join(lines) + "\n"


def complete_firewall_fixture() -> str:
    sensitive_tcp = "88 389 636 445 137-139"
    sensitive_udp = "88 389 1812-1813 137-139"
    return (
        base_interfaces()
        + """config log setting
    set fwpolicy-implicit-log enable
end
"""
        + """config firewall service custom
"""
        + service_entry("HTTPS", tcp="443")
        + service_entry("sensitive-group", tcp=sensitive_tcp, udp=sensitive_udp)
        + "end\n"
        + """config firewall webfilter profile
    edit "web-safe"
        set feature-set proxy
    next
end
"""
        + """config firewall profile-group
    edit "utm-safe"
        set webfilter-profile "web-safe"
    next
end
"""
        + policy_block(
            policy_entry(
                1,
                action="accept",
                services=("HTTPS",),
                logtraffic="utm",
                utm_status="enable",
                profiles='        set webfilter-profile "web-safe"\n',
            ),
            policy_entry(2, action="deny", services=("sensitive-group",), logtraffic="all"),
        )
        + """config firewall vip
    edit "public-web"
        set extintf "wan1"
        set extip 198.51.100.20
        set mappedip "10.0.0.20"
    next
    edit "public-lb"
        set type server-load-balance
        set extintf "wan1"
        config realservers
            edit 1
                set ip 10.0.0.21
                set port 443
            next
        end
    next
end
"""
    )


def test_m3_parser_projects_policy_services_vips_and_nested_realservers() -> None:
    configuration = FortiGateParser().parse(complete_firewall_fixture())

    policy = configuration.policies[0]
    assert policy.status == "enable"
    assert policy.schedule == "always"
    assert policy.services[0].name == "HTTPS"
    assert policy.logtraffic == "utm"
    assert policy.utm_status == "enable"
    assert policy.direct_profile_references[0].name == "web-safe"
    assert policy.destination_interfaces[0].name == "wan-zone"
    sensitive = next(
        service for service in configuration.service_objects if service.name == "sensitive-group"
    )
    assert sensitive.tcp_port_ranges[0].start == 88
    assert sensitive.proof_state is ProofState.PROVEN
    assert configuration.vips[0].extintf == ("wan1",)
    assert configuration.virtual_servers[0].name == "public-lb"
    assert configuration.virtual_servers[0].realservers[0].ip == "10.0.0.21"
    assert configuration.virtual_servers[0].realservers[0].port == 443
    assert configuration.profile_groups[0].name == "utm-safe"


def test_m3_parser_projects_service_groups_and_vip_groups_separately() -> None:
    raw = (
        base_interfaces()
        + """config firewall service custom
    edit "web-service"
        set tcp-portrange 443
    next
end
config firewall service group
    edit "web-group"
        set member "web-service"
    next
end
config firewall vip
    edit "web-vip"
        set extintf "wan1"
        set extip 198.51.100.40
        set mappedip "10.0.0.40"
    next
end
config firewall vipgrp
    edit "published-group"
        set member "web-vip"
    next
end
"""
    )

    configuration = FortiGateParser().parse(raw)

    assert configuration.service_groups[0].name == "web-group"
    assert configuration.service_groups[0].members[0].name == "web-service"
    assert configuration.service_groups[0].proof_state is ProofState.PROVEN
    assert configuration.vip_groups[0].name == "published-group"
    assert configuration.vip_groups[0].members[0].name == "web-vip"
    assert configuration.vip_groups[0].proof_state is ProofState.PROVEN


def test_m3_registry_has_independent_firewall_p0_controls() -> None:
    registered = default_registry()
    by_id = {
        control(FortiGateParser().parse("config system global\nend\n")).control_id: control
        for control in registered
    }

    assert set(M3_IDS) <= set(by_id)
    for control_id in M3_IDS:
        finding = by_id[control_id]
        assert finding.category == "firewall"
        assert finding.priority is AuditPriority.P0


def test_complete_firewall_fixture_passes_all_m3_controls() -> None:
    findings = audit(complete_firewall_fixture())

    assert [findings[control_id].status for control_id in M3_IDS] == [AuditStatus.PASS] * len(
        M3_IDS
    )


def test_m3_passes_have_certain_evidence_and_unknowns_have_unknown_applicability() -> None:
    passing = audit(complete_firewall_fixture())

    for control_id in M3_IDS:
        finding = passing[control_id]
        assert finding.evidence_items
        assert all(
            item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items
        )

    unknown = audit(base_interfaces())
    for control_id in M3_IDS:
        finding = unknown[control_id]
        assert finding.status is AuditStatus.UNKNOWN
        assert finding.applicability is Applicability.UNKNOWN


def test_implicit_deny_log_requires_explicit_enable() -> None:
    raw = base_interfaces() + "config log setting\n    set fwpolicy-implicit-log enable\nend\n"
    finding = audit(raw)["FW-IMPLICIT-DENY-LOG-001"]

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items[0].directive == "fwpolicy-implicit-log"


@pytest.mark.parametrize("value", ["disable", "none"])
def test_implicit_deny_log_explicit_disable_fails(value: str) -> None:
    raw = base_interfaces() + f"config log setting\n    set fwpolicy-implicit-log {value}\nend\n"

    assert audit(raw)["FW-IMPLICIT-DENY-LOG-001"].status is AuditStatus.FAIL


@pytest.mark.parametrize(
    "raw",
    [
        base_interfaces(),
        base_interfaces() + "config log setting\nend\n",
        base_interfaces() + "config log setting\n    unset fwpolicy-implicit-log\nend\n",
    ],
)
def test_implicit_deny_log_missing_or_ambiguous_is_unknown(raw: str) -> None:
    assert audit(raw)["FW-IMPLICIT-DENY-LOG-001"].status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    "mutation",
    [
        "unset fwpolicy-implicit-log",
        "append fwpolicy-implicit-log disable",
        "select fwpolicy-implicit-log disable",
        "unselect fwpolicy-implicit-log enable",
    ],
)
def test_implicit_deny_log_mutation_invalidates_stale_enable(mutation: str) -> None:
    raw = base_interfaces() + (
        f"config log setting\n    set fwpolicy-implicit-log enable\n    {mutation}\nend\n"
    )

    assert audit(raw)["FW-IMPLICIT-DENY-LOG-001"].status is AuditStatus.UNKNOWN


def test_all_service_fails_for_explicit_enabled_accept_to_proven_wan() -> None:
    raw = (
        base_interfaces()
        + "config log setting\n    set fwpolicy-implicit-log enable\nend\n"
        + policy_block(policy_entry(1, services=("ALL",)))
    )

    finding = audit(raw)["FW-INTERNET-ALL-SERVICE-001"]
    assert finding.status is AuditStatus.FAIL
    assert finding.applicability is Applicability.APPLICABLE


def test_all_service_is_not_pass_for_proven_zone_with_missing_interface() -> None:
    configuration = FortiGateParser().parse(
        base_interfaces(include_zone=False)
        + policy_block(policy_entry(1, destination="internet", services=("ALL",)))
    ).model_copy(
        update={
            "zones": (
                Zone(
                    name="internet",
                    interfaces=(
                        ObjectReference(object_type="interface", name="missing"),
                    ),
                    proof_state=ProofState.PROVEN,
                ),
            )
        }
    )
    context = AuditContext.model_validate(
        {
            "wan_selections": [{"name": "internet", "kind": WanSelectionKind.ZONE}],
        }
    )

    findings = {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(configuration, context=context)
    }

    assert findings["FW-INTERNET-ALL-SERVICE-001"].status is AuditStatus.UNKNOWN


def test_all_service_is_not_pass_for_automatic_scope_with_casefold_interface_collision() -> None:
    raw = (
        base_interfaces(include_zone=False)
        + "config log setting\n    set fwpolicy-implicit-log enable\nend\n"
        + "config firewall service custom\n"
        + service_entry("HTTPS", tcp="443")
        + "end\n"
        + policy_block(policy_entry(1, source="port1", destination="wan1", services=("HTTPS",)))
    )
    configuration = FortiGateParser().parse(raw)
    duplicate = next(
        interface for interface in configuration.interfaces if interface.name == "wan1"
    )
    configuration = configuration.model_copy(
        update={
            "interfaces": configuration.interfaces
            + (duplicate.model_copy(update={"name": "WAN1"}),)
        }
    )
    context = AuditContext.model_validate(
        {
            "wan_selections": [{"name": "automatic", "kind": WanSelectionKind.AUTOMATIC}]
        }
    )

    findings = {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(configuration, context=context)
    }

    assert findings["FW-INTERNET-ALL-SERVICE-001"].status is AuditStatus.UNKNOWN


def test_all_service_does_not_fail_for_explicit_non_all_accept() -> None:
    raw = (
        base_interfaces()
        + "config firewall service custom\n"
        + service_entry("HTTPS", tcp="443")
        + "end\n"
        + policy_block(policy_entry(1, services=("HTTPS",)))
    )

    finding = audit(raw)["FW-INTERNET-ALL-SERVICE-001"]
    assert finding.status is AuditStatus.PASS
    assert finding.applicability is Applicability.APPLICABLE


def test_all_service_ignores_explicit_deny_policy_as_not_applicable() -> None:
    raw = base_interfaces() + policy_block(policy_entry(1, action="deny", services=("ALL",)))

    finding = audit(raw)["FW-INTERNET-ALL-SERVICE-001"]
    assert finding.status is AuditStatus.NOT_APPLICABLE
    assert finding.applicability is Applicability.NOT_APPLICABLE


@pytest.mark.parametrize(
    "entry",
    [
        policy_entry(1, action=None),
        policy_entry(1, services=None),
        policy_entry(1, destination=None),
    ],
)
def test_all_service_missing_policy_proof_is_unknown(entry: str) -> None:
    raw = base_interfaces() + policy_block(entry)

    assert audit(raw)["FW-INTERNET-ALL-SERVICE-001"].status is AuditStatus.UNKNOWN


def test_all_service_does_not_skip_isdb_or_legacy_named_service() -> None:
    raw = base_interfaces() + policy_block(policy_entry(1, services=("ISDB",)))

    finding = audit(raw)["FW-INTERNET-ALL-SERVICE-001"]
    assert finding.status is AuditStatus.UNKNOWN
    assert "ISDB" in " ".join(finding.evidence)


def test_utm_missing_binding_fails_but_valid_direct_binding_passes() -> None:
    failing = base_interfaces() + policy_block(
        policy_entry(1, logtraffic="utm", utm_status="enable", profiles="")
    )
    passing = (
        base_interfaces()
        + """config firewall webfilter profile
    edit "web-safe"
        set feature-set proxy
    next
end
"""
        + policy_block(
            policy_entry(
                1,
                logtraffic="utm",
                utm_status="enable",
                profiles='        set webfilter-profile "web-safe"\n',
            )
        )
    )

    assert audit(failing)["FW-UTM-PROFILE-BINDING-001"].status is AuditStatus.FAIL
    assert audit(passing)["FW-UTM-PROFILE-BINDING-001"].status is AuditStatus.PASS


def test_utm_casefold_profile_collision_is_unknown() -> None:
    raw = (
        base_interfaces()
        + """config firewall webfilter profile
    edit "Safe"
    next
    edit "safe"
        set feature-set proxy
    next
    edit "SAFE"
        set feature-set flow
    next
end
"""
        + policy_block(
            policy_entry(
                1,
                logtraffic="utm",
                utm_status="enable",
                profiles='        set webfilter-profile "SAFE"\n',
            )
        )
    )

    assert audit(raw)["FW-UTM-PROFILE-BINDING-001"].status is AuditStatus.UNKNOWN


def test_utm_casefold_profile_group_collision_is_unknown() -> None:
    raw = (
        base_interfaces()
        + """config firewall webfilter profile
    edit "web-safe"
        set feature-set proxy
    next
end
config firewall profile-group
    edit "Utm-Safe"
    next
    edit "utm-safe"
        set webfilter-profile "web-safe"
    next
    edit "UTM-SAFE"
        set webfilter-profile "web-safe"
    next
end
"""
        + policy_block(
            policy_entry(
                1,
                logtraffic="utm",
                utm_status="enable",
                profiles='        set profile-group "UTM-SAFE"\n',
            )
        )
    )

    assert audit(raw)["FW-UTM-PROFILE-BINDING-001"].status is AuditStatus.UNKNOWN


@pytest.mark.parametrize("binding", ["none", "disable"])
def test_utm_explicitly_disabled_binding_fails(binding: str) -> None:
    raw = (
        base_interfaces()
        + """config firewall webfilter profile
    edit "web-safe"
        set feature-set proxy
    next
end
"""
        + policy_block(
            policy_entry(
                1,
                logtraffic="utm",
                utm_status="enable",
                profiles=f'        set webfilter-profile "{binding}"\n',
            )
        )
    )

    assert audit(raw)["FW-UTM-PROFILE-BINDING-001"].status is AuditStatus.FAIL


def test_utm_unresolvable_or_mutated_binding_is_unknown() -> None:
    unknown = base_interfaces() + policy_block(
        policy_entry(
            1,
            logtraffic="utm",
            utm_status="enable",
            profiles='        set webfilter-profile "missing-profile"\n',
        )
    )
    mutated = (
        base_interfaces()
        + """config firewall webfilter profile
    edit "web-safe"
        set feature-set proxy
    next
end
"""
        + policy_block(
            policy_entry(
                1,
                logtraffic="utm",
                utm_status="enable",
                profiles=(
                    '        set webfilter-profile "web-safe"\n'
                    "        unset webfilter-profile\n"
                ),
            )
        )
    )

    assert audit(unknown)["FW-UTM-PROFILE-BINDING-001"].status is AuditStatus.UNKNOWN
    assert audit(mutated)["FW-UTM-PROFILE-BINDING-001"].status is AuditStatus.UNKNOWN


def test_utm_profile_group_resolves_as_a_complete_binding() -> None:
    raw = (
        base_interfaces()
        + """config firewall webfilter profile
    edit "web-safe"
        set feature-set proxy
    next
end
config firewall profile-group
    edit "utm-safe"
        set webfilter-profile "web-safe"
    next
end
"""
        + policy_block(
            policy_entry(
                1,
                logtraffic="utm",
                utm_status="enable",
                profiles='        set profile-group "utm-safe"\n',
            )
        )
    )

    assert audit(raw)["FW-UTM-PROFILE-BINDING-001"].status is AuditStatus.PASS


def test_utm_binding_resolves_typed_m5_profiles() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "anonymized_fortigate_export.conf"

    finding = audit(fixture.read_text(encoding="utf-8"))["FW-UTM-PROFILE-BINDING-001"]

    assert finding.status is AuditStatus.PASS


def test_vip_and_vserver_are_independent_and_any_extintf_fails() -> None:
    raw = (
        base_interfaces()
        + """config firewall vip
    edit "public-vip"
        set extintf "any"
        set extip 198.51.100.30
        set mappedip "10.0.0.30"
    next
    edit "public-vserver"
        set type server-load-balance
        set extintf "any"
        config realservers
            edit 1
                set ip 10.0.0.31
                set port 443
            next
        end
    next
end
"""
    )
    findings = audit(raw)

    assert findings["FW-VIP-EXTINTF-ANY-001"].status is AuditStatus.FAIL
    assert findings["FW-VSERVER-EXTINTF-ANY-001"].status is AuditStatus.FAIL


def test_vip_and_vserver_non_any_extintf_pass_only_when_complete() -> None:
    raw = (
        base_interfaces()
        + """config firewall vip
    edit "public-vip"
        set extintf "wan1"
        set extip 198.51.100.30
        set mappedip "10.0.0.30"
    next
    edit "public-vserver"
        set type server-load-balance
        set extintf "wan1"
        config realservers
            edit 1
                set ip 10.0.0.31
                set port 443
            next
        end
    next
end
"""
    )
    findings = audit(raw)

    assert findings["FW-VIP-EXTINTF-ANY-001"].status is AuditStatus.PASS
    assert findings["FW-VSERVER-EXTINTF-ANY-001"].status is AuditStatus.PASS


@pytest.mark.parametrize(
    "mutation",
    ["unset extintf", 'append extintf "any"', 'select extintf "wan1"', 'unselect extintf "wan1"'],
)
def test_vip_mutation_does_not_preserve_non_any_pass(mutation: str) -> None:
    raw = (
        base_interfaces()
        + """config firewall vip
    edit "public-vip"
        set extintf "wan1"
        set extip 198.51.100.30
        set mappedip "10.0.0.30"
"""
        + f"        {mutation}\n"
        ""
        + """    next
end
"""
    )

    assert audit(raw)["FW-VIP-EXTINTF-ANY-001"].status is AuditStatus.UNKNOWN


def test_sensitive_protocol_control_uses_ruleset_and_resolved_ports_not_names() -> None:
    deceptive = (
        base_interfaces()
        + """config firewall service custom
    edit "KERBEROS"
        set tcp-portrange 1
    next
end
"""
        + policy_block(policy_entry(1, action="accept", services=("KERBEROS",)))
    )
    exposed = (
        base_interfaces()
        + """config firewall service custom
    edit "safe-looking-name"
        set tcp-portrange 88
        set udp-portrange 88
    next
end
"""
        + policy_block(policy_entry(1, action="accept", services=("safe-looking-name",)))
    )

    assert audit(deceptive)["FW-SENSITIVE-PROTOCOL-DENY-001"].status is AuditStatus.UNKNOWN
    finding = audit(exposed)["FW-SENSITIVE-PROTOCOL-DENY-001"]
    assert finding.status is AuditStatus.FAIL
    assert SENSITIVE_PROTOCOL_RULESET_ID in " ".join(finding.evidence)
    assert SENSITIVE_PROTOCOL_RULESET_VERSION in finding.message


def test_sensitive_protocols_pass_only_with_explicit_deny_coverage() -> None:
    raw = (
        base_interfaces()
        + """config firewall service custom
    edit "sensitive"
        set tcp-portrange 88 389 636 445 137-139
        set udp-portrange 88 389 1812-1813 137-139
    next
end
"""
        + policy_block(policy_entry(1, action="deny", services=("sensitive",)))
    )

    finding = audit(raw)["FW-SENSITIVE-PROTOCOL-DENY-001"]
    assert finding.status is AuditStatus.PASS
    assert finding.applicability is Applicability.APPLICABLE


@pytest.mark.parametrize(
    "mutation",
    [
        "unset tcp-portrange",
        "append tcp-portrange 88",
        "select tcp-portrange 88",
        "unselect tcp-portrange 88",
    ],
)
def test_sensitive_service_mutation_is_unknown(mutation: str) -> None:
    raw = (
        base_interfaces()
        + """config firewall service custom
    edit "sensitive"
        set tcp-portrange 88
        set udp-portrange 88
"""
        + f"        {mutation}\n"
        ""
        + """    next
end
"""
        + policy_block(policy_entry(1, action="deny", services=("sensitive",)))
    )

    assert audit(raw)["FW-SENSITIVE-PROTOCOL-DENY-001"].status is AuditStatus.UNKNOWN


def test_sensitive_protocol_explicit_fail_dominates_unknown_flow() -> None:
    raw = (
        base_interfaces()
        + """config firewall service custom
    edit "sensitive"
        set tcp-portrange 88
        set udp-portrange 88
    next
end
"""
        + policy_block(
            policy_entry(1, action="accept", services=("sensitive",)),
            policy_entry(2, action=None, services=("sensitive",)),
        )
    )

    assert audit(raw)["FW-SENSITIVE-PROTOCOL-DENY-001"].status is AuditStatus.FAIL


def test_m3_parser_merges_repeated_disjoint_sections_and_rejects_truncation() -> None:
    duplicate = """config firewall service custom
    edit "sensitive"
        set tcp-portrange 88
    next
end
config firewall service custom
    edit "other"
        set tcp-portrange 89
    next
end
"""
    truncated = """config firewall vip
    edit "public"
        set extintf "wan1"
    next
"""

    configuration = FortiGateParser().parse(duplicate)
    assert {service.name for service in configuration.service_objects} == {"sensitive", "other"}
    assert all(
        service.proof_state is ProofState.PROVEN
        for service in configuration.service_objects
    )
    with pytest.raises(ValueError, match="unsupported or incomplete"):
        FortiGateParser().parse(truncated)

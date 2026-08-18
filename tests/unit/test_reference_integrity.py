from vysion.audit.controls._evidence import (
    entry_for,
    evidence_for_directive,
    evidence_for_sdwan_member,
)
from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    Applicability,
    AuditStatus,
    EvidenceCertainty,
    StructuralDirective,
    StructuralDocument,
    StructuralEntry,
    StructuralSection,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

RESOLVED_REFERENCES_CONFIG = """\
config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
    next
end
config system zone
    edit "outside"
        set interface "wan1"
    next
end
config system sdwan
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
end
config firewall service group
    edit "WEB"
        set member "HTTPS"
    next
end
config firewall policy
    edit 1
        set srcintf "outside"
        set dstintf "outside"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "WEB"
    next
end
"""
EMPTY_REFERENCE_GRAPH_CONFIG = """\
config system interface
end
config system zone
end
config system sdwan
end
config firewall service custom
end
config firewall service group
end
config firewall policy
end
config firewall profile-group
end
config firewall vip
end
config firewall vipgrp
end
config vpn ipsec phase1-interface
end
config vpn ipsec phase2-interface
end
"""


BUILTIN_REFERENCE_CONFIG = """\
config system interface
    edit "wan1"
        set role wan
        set ip 192.0.2.1 255.255.255.0
    next
end
config system zone
end
config system sdwan
end
config firewall service custom
    edit "ALL"
        set protocol IP
    next
end
config firewall service group
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""


WEBPROXY_SERVICE_CONFIG = """\
config firewall service custom
    edit "webproxy"
        set proxy enable
        set protocol ALL
        set tcp-portrange 0-65535:0-65535
    next
end
"""


def test_fortios_builtin_any_and_all_references_are_resolved() -> None:
    finding, _findings = _finding(BUILTIN_REFERENCE_CONFIG)

    assert finding.status is AuditStatus.PASS


def test_fortios_all_protocol_with_port_range_is_a_proven_service() -> None:
    configuration = FortiGateParser().parse(WEBPROXY_SERVICE_CONFIG)

    service = configuration.service_objects[0]
    assert service.proof_state.value == "proven"


def test_default_fortios_service_catalog_is_not_reported_as_orphaned() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "FTP"\n'
        '        set category "File Access"\n'
        '        set tcp-portrange 21\n'
        '    next\n'
        '    edit "AOL"\n'
        '        set tcp-portrange 5190-5194\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    ).replace(
        '    next\nend\nconfig firewall policy',
        '    next\n'
        '    edit "Web Access"\n'
        '        set member "HTTPS"\n'
        '    next\n'
        'end\n'
        'config firewall policy',
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.PASS


def test_typed_reference_resolution_crosses_parser_projection_registry_and_finding() -> None:
    configuration = FortiGateParser().parse(RESOLVED_REFERENCES_CONFIG)

    assert configuration.zones[0].interfaces[0].object_type == "interface"
    assert configuration.service_groups[0].members[0].object_type == "service"
    assert configuration.policies[0].services[0].name == "WEB"

    finding = next(
        finding
        for finding in AuditEngine(default_registry()).run(configuration)
        if finding.control_id == "CFG-REF-INTEGRITY-001"
    )

    assert finding.status is AuditStatus.PASS




def test_casefold_policy_id_collision_is_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        """config firewall policy
    edit 1
        set srcintf "outside"
        set dstintf "outside"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "WEB"
    next
end
""",
        """config firewall policy
    edit "Rule"
        set srcintf "outside"
        set dstintf "outside"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "WEB"
    next
    edit "rule"
        set srcintf "outside"
        set dstintf "outside"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "WEB"
    next
end
""",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_profile_reference_resolves_from_an_alternative_typed_section() -> None:
    raw = (
        RESOLVED_REFERENCES_CONFIG.replace(
            '        set service "WEB"\n',
            '        set service "WEB"\n        set ips-sensor "IPS-FILTER"\n',
        )
        + """config ips sensor
    edit "IPS-FILTER"
        set block-malicious-url enable
        set scan-botnet-connections enable
    next
end
"""
    )

    finding, findings = _finding(raw)

    assert finding.status is AuditStatus.PASS
    assert finding.evidence_items
    assert all(item.certainty.value == "certain" for item in finding.evidence_items)
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def _finding(raw: str):
    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)
    return next(item for item in findings if item.control_id == "CFG-REF-INTEGRITY-001"), findings




def test_nested_entry_ambiguity_cannot_hide_behind_direct_match() -> None:
    section = StructuralSection(
        name="system sdwan",
        line=1,
        directives=(StructuralDirective(name="interface", tokens=("direct",), line=6),),
        entries=(StructuralEntry(name="target", line=2),),
        children=(
            StructuralSection(
                name="zone",
                line=3,
                entries=(
                    StructuralEntry(name="target", line=4),
                    StructuralEntry(name="target", line=5),
                ),
            ),
        ),
    )

    assert entry_for(section, "target") is None
    evidence = evidence_for_directive(
        StructuralDocument(sections=(section,)),
        "system sdwan",
        "interface",
        entry_name="target",
        certainty=EvidenceCertainty.CERTAIN,
    )
    assert evidence.certainty is not EvidenceCertainty.CERTAIN






def test_ambiguous_sdwan_member_source_cannot_be_upgraded_to_certain() -> None:
    member = StructuralEntry(
        name="1",
        line=4,
        directives=(StructuralDirective(name="interface", tokens=("wan1",), line=5),),
        certainty=EvidenceCertainty.AMBIGUOUS,
    )
    document = StructuralDocument(
        sections=(
            StructuralSection(
                name="system sdwan",
                line=1,
                children=(
                    StructuralSection(
                        name="zone",
                        line=2,
                        entries=(StructuralEntry(name="virtual-wan-link", line=3),),
                    ),
                    StructuralSection(
                        name="members",
                        line=4,
                        entries=(member,),
                        certainty=EvidenceCertainty.AMBIGUOUS,
                    ),
                ),
            ),
        ),
    )

    evidence = evidence_for_sdwan_member(
        document,
        "virtual-wan-link",
        "wan1",
        certainty=EvidenceCertainty.CERTAIN,
    )

    assert evidence is None or evidence.certainty is not EvidenceCertainty.CERTAIN


def test_nested_noncanonical_reference_section_is_unknown() -> None:
    raw = (
        """config unknown-wrapper
    config firewall/service/custom
        edit "HIDDEN"
            set tcp-portrange 443
        next
    end
end
"""
        + RESOLVED_REFERENCES_CONFIG
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_unknown_wrapper_with_structured_entries_blocks_not_applicable() -> None:
    raw = (
        """config unknown-wrapper
    edit "HIDDEN"
        set tcp-portrange 443
    next
end
"""
        + EMPTY_REFERENCE_GRAPH_CONFIG
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_nested_noncanonical_reference_section_blocks_not_applicable() -> None:
    raw = (
        """config unknown-wrapper
    config firewall.service.custom
        edit "HIDDEN"
            set tcp-portrange 443
        next
    end
end
"""
        + EMPTY_REFERENCE_GRAPH_CONFIG
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def _with_independent_missing_service_reference(raw: str) -> str:
    return raw.replace(
        '        set service "WEB"\n    next\nend\n',
        '        set service "WEB"\n'
        '    next\n'
        '    edit 2\n'
        '        set srcintf "outside"\n'
        '        set dstintf "outside"\n'
        '        set srcaddr "all"\n'
        '        set dstaddr "all"\n'
        '        set action accept\n'
        '        set service "MISSING"\n'
        '    next\n'
        'end\n',
    )


def test_absent_reference_namespaces_are_unknown_without_engine_finding() -> None:
    finding, findings = _finding("config system global\nend\n")

    assert finding.status is AuditStatus.UNKNOWN
    assert finding.applicability is Applicability.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_explicitly_empty_reference_graph_is_not_applicable() -> None:
    finding, findings = _finding(EMPTY_REFERENCE_GRAPH_CONFIG)

    assert finding.status is AuditStatus.NOT_APPLICABLE
    assert finding.applicability is Applicability.NOT_APPLICABLE
    assert finding.evidence_items
    assert all(item.certainty.value == "certain" for item in finding.evidence_items)
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_missing_reference_is_unknown_without_engine_finding() -> None:
    raw = _with_independent_missing_service_reference(RESOLVED_REFERENCES_CONFIG)

    finding, findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert finding.applicability is Applicability.UNKNOWN
    assert any("not defined" in str(evidence) for evidence in finding.evidence)
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_casefold_collision_is_unknown_without_selecting_a_target() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "https"\n'
        '        set tcp-portrange 8443\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    )

    finding, findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert any(
        "collides after case-folding" in str(evidence) for evidence in finding.evidence
    )
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_mutated_service_group_reference_is_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '        set member "HTTPS"\n',
        '        set member "HTTPS"\n        unset member\n',
    )

    finding, findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_certain_orphan_service_is_a_failure_when_reference_graph_is_complete() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "ORPHAN"\n'
        '        set tcp-portrange 8443\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    )

    finding, findings = _finding(raw)

    assert finding.status is AuditStatus.FAIL
    assert finding.applicability is Applicability.APPLICABLE
    assert any("ORPHAN" in str(evidence) for evidence in finding.evidence)
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_certain_orphan_dominates_an_unrelated_unknown_service_reference() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '        set service "WEB"\n    next\nend\n',
        '        set service "WEB"\n'
        '    next\n'
        '    edit 2\n'
        '        set srcintf "outside"\n'
        '        set dstintf "outside"\n'
        '        set srcaddr "all"\n'
        '        set dstaddr "all"\n'
        '        set action accept\n'
        '        set service "MISSING"\n'
        '    next\n'
        'end\n',
    )
    raw = raw.replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "ORPHAN"\n'
        '        set tcp-portrange 8443\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.FAIL
    assert any("ORPHAN" in str(evidence) for evidence in finding.evidence)
    assert all(item.certainty.value == "certain" for item in finding.evidence_items)


def test_unproven_unreferenced_service_keeps_reference_integrity_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "INCOMPLETE"\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_unreferenced_casefold_collision_keeps_reference_integrity_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "BAD"\n'
        '        set tcp-portrange 8443\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    )
    raw = raw.replace(
        '    next\nend\nconfig firewall policy',
        '    next\n'
        '    edit "bad"\n'
        '        set member "HTTPS"\n'
        '    next\n'
        'end\n'
        'config firewall policy',
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_certain_orphan_failure_exposes_only_certain_structured_evidence() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "ORPHAN"\n'
        '        set tcp-portrange 8443\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    )
    raw += """config vpn ipsec phase2-interface
    edit "phase2-missing"
        set phase1name "MISSING"
        set dhgrp 14
        set proposal aes256-sha256
    next
end
"""

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.FAIL
    assert all(item.certainty.value == "certain" for item in finding.evidence_items)


def test_unproven_unreferenced_profile_group_keeps_reference_integrity_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG + """config firewall profile-group
    edit "INCOMPLETE"
    next
end
"""

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_certain_orphan_dominates_unknown_service_reference_without_certain_root() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace('set service "WEB"', 'set service "MISSING"')
    raw = raw.replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "ORPHAN"\n'
        '        set tcp-portrange 8443\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.FAIL


def test_unproven_service_group_blocks_a_different_certain_orphan() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "ORPHAN"\n'
        '        set tcp-portrange 8443\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    )
    raw = raw.replace(
        '        set member "HTTPS"\n    next\nend\nconfig firewall policy',
        '        set member "HTTPS"\n'
        '    next\n'
        '    edit "INCOMPLETE"\n'
        '    next\n'
        'end\n'
        'config firewall policy',
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_unproven_vip_group_keeps_reference_integrity_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG + """config firewall vipgrp
    edit "INCOMPLETE"
    next
end
"""

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_unreferenced_vip_group_casefold_collision_keeps_reference_integrity_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG + """config firewall vip
    edit "vip1"
        set extintf "wan1"
        set extip 192.0.2.10
        set mappedip "10.0.0.10"
    next
end
config firewall vipgrp
    edit "Group"
        set member "vip1"
    next
    edit "group"
        set member "vip1"
    next
end
"""

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_unproven_typed_profile_blocks_not_applicable_status() -> None:
    raw = EMPTY_REFERENCE_GRAPH_CONFIG + """config ips sensor
    edit "INCOMPLETE"
    next
end
"""

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_vip_group_and_vip_casefold_collision_keeps_reference_integrity_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG + """config firewall vip
    edit "vip1"
        set extintf "wan1"
        set extip 192.0.2.10
        set mappedip "10.0.0.10"
    next
end
config firewall vipgrp
    edit "VIP1"
        set member "vip1"
    next
end
"""

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_noncanonical_top_level_reference_section_is_unknown() -> None:
    raw = (
        "config firewall service custom extra\n"
        "    edit \"HIDDEN\"\n"
        "        set tcp-portrange 1\n"
        "    next\n"
        "end\n"
        + RESOLVED_REFERENCES_CONFIG
    )

    configuration = FortiGateParser().parse(raw)
    finding, findings = _finding(raw)

    assert configuration.document.certainty.value == "certain"
    assert all(service.name != "HIDDEN" for service in configuration.service_objects)
    assert finding.status is AuditStatus.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)

    empty_finding, empty_findings = _finding(
        "config firewall service custom extra\nend\n" + EMPTY_REFERENCE_GRAPH_CONFIG
    )
    assert empty_finding.status is AuditStatus.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in empty_findings)


def test_noncanonical_separator_reference_section_is_unknown() -> None:
    raw = (
        "config firewall/service/custom\n"
        "    edit \"HIDDEN\"\n"
        "        set tcp-portrange 1\n"
        "    next\n"
        "end\n"
        + RESOLVED_REFERENCES_CONFIG
    )

    finding, findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_ambiguous_profile_group_reference_is_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '        set service "WEB"\n',
        '        set service "WEB"\n        set profile-group "A" "B"\n',
    )

    configuration = FortiGateParser().parse(raw)
    finding, findings = _finding(raw)

    assert configuration.policies[0].profile_group is None
    assert finding.status is AuditStatus.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_unproven_secondary_ip_keeps_reference_integrity_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '        set allowaccess ping\n',
        '        set allowaccess ping\n'
        '        config secondaryip\n'
        '            edit 1\n'
        '                set ip 192.0.2.11 255.255.255.0\n'
        '            next\n'
        '        end\n',
    )

    configuration = FortiGateParser().parse(raw)
    finding, findings = _finding(raw)

    assert configuration.interfaces[0].proof_state.value == "proven"
    assert configuration.interfaces[0].secondary_ips[0].proof_state.value == "unknown"
    assert finding.status is AuditStatus.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_mutated_optional_profile_reference_is_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '        set service "WEB"\n',
        '        set service "WEB"\n'
        '        set profile-group "A"\n'
        '        unset profile-group\n',
    )

    configuration = FortiGateParser().parse(raw)
    finding, findings = _finding(raw)

    assert configuration.policies[0].profile_group is None
    assert finding.status is AuditStatus.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)




def test_invalid_or_multitoken_vip_type_is_not_proven() -> None:
    for type_value in ('"not-a-valid-type"', '"not-a-valid-type" "extra"'):
        raw = RESOLVED_REFERENCES_CONFIG + f"""config firewall vip
    edit "BROKEN"
        set type {type_value}
        set extintf "wan1"
        set extip 203.0.113.10
        set mappedip "10.0.0.10"
    next
end
"""

        finding, _findings = _finding(raw)

        assert finding.status is AuditStatus.UNKNOWN


def test_nested_realserver_casefold_collision_keeps_reference_integrity_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG + """config firewall vip
    edit "VS"
        set type server-load-balance
        set extintf "wan1"
        config realservers
            edit "RS"
                set ip 192.0.2.20
                set port 443
            next
            edit "rs"
                set ip 192.0.2.21
                set port 443
            next
        end
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    finding, _findings = _finding(raw)

    assert len(configuration.virtual_servers[0].realservers) == 2
    assert all(
        server.proof_state.value == "proven"
        for server in configuration.virtual_servers[0].realservers
    )
    assert finding.status is AuditStatus.UNKNOWN


def test_nested_realserver_collision_is_unknown_when_vip_type_is_omitted() -> None:
    raw = RESOLVED_REFERENCES_CONFIG + """config firewall vip
    edit "VIP-WITH-CHILDREN"
        set extintf "wan1"
        set extip 192.0.2.30
        set mappedip "10.0.0.30"
        config realservers
            edit "RS"
                set ip 192.0.2.30
                set port 443
            next
            edit "rs"
                set ip 192.0.2.31
                set port 443
            next
        end
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    finding, _findings = _finding(raw)

    assert configuration.vips[0].name == "VIP-WITH-CHILDREN"
    assert finding.status is AuditStatus.UNKNOWN


def test_section_directive_without_entries_is_not_explicitly_empty() -> None:
    raw = EMPTY_REFERENCE_GRAPH_CONFIG.replace(
        "config firewall policy\nend\n",
        "config firewall policy\n    set status enable\nend\n",
    )

    finding, findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert finding.applicability is Applicability.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_section_directive_with_entries_keeps_reference_integrity_unknown() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        "config firewall policy\n",
        "config firewall policy\n    set status enable\n",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_policy_multi_token_profile_reference_is_unknown() -> None:
    raw = (
        RESOLVED_REFERENCES_CONFIG.replace(
            '        set service "WEB"\n',
            '        set service "WEB"\n        set ips-sensor "A" "B"\n',
        )
        + """config ips sensor
    edit "A"
        set block-malicious-url enable
        set scan-botnet-connections enable
    next
    edit "B"
        set block-malicious-url enable
        set scan-botnet-connections enable
    next
end
"""
    )

    finding, findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_mixed_policy_section_cannot_prove_interface_only_reference() -> None:
    raw = EMPTY_REFERENCE_GRAPH_CONFIG.replace(
        "config system interface\nend\n",
        """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
    next
end
""",
    ).replace(
        "config system zone\nend\n",
        """config system zone
    edit "outside"
        set interface "wan1"
    next
end
""",
    ).replace(
        "config firewall policy\nend\n",
        """config firewall policy
    set status enable
    edit 1
        set srcintf "outside"
        set dstintf "outside"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
""",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_nested_sdwan_zone_reference_is_resolved_from_typed_child_entry() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        "config system sdwan\nend\n",
        """config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
        next
    end
end
""",
    )

    configuration = FortiGateParser().parse(raw)
    finding, _findings = _finding(raw)

    assert configuration.sdwan_zones[0].proof_state.value == "proven"
    assert finding.status is AuditStatus.PASS
    sdwan_evidence = next(
        item for item in finding.evidence_items if item.section == "system sdwan -> members"
    )
    assert sdwan_evidence.tokens == ("wan1",)
    assert sdwan_evidence.line == 20
    assert all(item.certainty.value == "certain" for item in finding.evidence_items)






def test_sdwan_direct_and_nested_interfaces_keep_distinct_evidence() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '    next\nend\nconfig system zone',
        '''    next
    edit "wan2"
        set role wan
        set allowaccess ping
    next
end
config system zone''',
        1,
    ).replace(
        "config system sdwan\nend\n",
        """config system sdwan
    config zone
        edit "virtual-wan-link"
            set interface "wan2"
        next
    end
    config members
        edit 1
            set interface "wan1"
        next
    end
end
""",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.PASS
    assert any(
        item.section == "system sdwan"
        and item.tokens == ("wan2",)
        for item in finding.evidence_items
    )
    assert any(
        item.section == "system sdwan -> members"
        and item.tokens == ("wan1",)
        for item in finding.evidence_items
    )


def test_ambiguous_nested_sdwan_members_do_not_emit_certain_evidence() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        "config system sdwan\nend\n",
        """config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
        next
        edit 2
            set interface "wan1"
        next
    end
end
""",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    sdwan_evidence = tuple(
        item
        for item in finding.evidence_items
        if item.section in {"system sdwan", "system sdwan -> members"}
    )
    assert sdwan_evidence
    assert all(item.certainty.value != "certain" for item in sdwan_evidence)


def test_voip_profile_reference_resolves_from_typed_projection() -> None:
    raw = (
        RESOLVED_REFERENCES_CONFIG.replace(
            '        set service "WEB"\n',
            '        set service "WEB"\n        set voip-profile "VOIP"\n',
        )
        + """config firewall voip profile
    edit "VOIP"
        set feature-set proxy
    next
end
"""
    )

    configuration = FortiGateParser().parse(raw)
    finding, _findings = _finding(raw)

    assert any(
        profile.name == "VOIP" and profile.profile_type == "voip profile"
        for profile in configuration.security_profiles
    )
    assert finding.status is AuditStatus.PASS


def test_profile_group_multi_token_reference_is_unknown() -> None:
    raw = (
        RESOLVED_REFERENCES_CONFIG.replace(
            '        set service "WEB"\n',
            '        set service "WEB"\n        set profile-group "GROUP"\n',
        )
        + """config firewall profile-group
    edit "GROUP"
        set ips-sensor "A" "B"
    next
end
config ips sensor
    edit "A"
        set block-malicious-url enable
        set scan-botnet-connections enable
    next
    edit "B"
        set block-malicious-url enable
        set scan-botnet-connections enable
    next
end
"""
    )

    finding, findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert not any(item.control_id.startswith("ENGINE-") for item in findings)


def test_entry_for_rejects_casefold_duplicate_in_entry_child() -> None:
    section = StructuralSection(
        name="firewall policy",
        line=1,
        entries=(
            StructuralEntry(
                name="target",
                line=2,
                children=(
                    StructuralSection(
                        name="nested",
                        line=3,
                        entries=(StructuralEntry(name="TARGET", line=4),),
                    ),
                ),
            ),
        ),
    )

    assert entry_for(section, "target") is None


def test_empty_unknown_wrapper_blocks_not_applicable() -> None:
    raw = """config unknown-wrapper
end
""" + EMPTY_REFERENCE_GRAPH_CONFIG

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_sdwan_member_reference_uses_member_directive_evidence() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        "config system sdwan\nend\n",
        """config system sdwan
    config zone
        edit "virtual-wan-link"
            set member "wan1"
        next
    end
end
""",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.PASS
    assert any(
        item.section == "system sdwan"
        and item.entry == "virtual-wan-link"
        and item.directive == "member"
        and item.tokens == ("wan1",)
        for item in finding.evidence_items
    )


def test_nested_reference_sections_mixing_directives_and_entries_are_unknown() -> None:
    cases = (
        RESOLVED_REFERENCES_CONFIG.replace(
            "config system sdwan\nend\n",
            """config system sdwan
    config zone
        set status enable
        edit "virtual-wan-link"
            set interface "wan1"
        next
    end
end
""",
        ),
        RESOLVED_REFERENCES_CONFIG
        + """config firewall vip
    edit "VS"
        set type server-load-balance
        set extintf "wan1"
        config realservers
            set ip 10.0.0.20
            edit 1
                set ip 10.0.0.21
                set port 443
            next
        end
    next
end
""",
    )

    for raw in cases:
        finding, _findings = _finding(raw)
        assert finding.status is AuditStatus.UNKNOWN


def test_canonical_independent_sections_do_not_block_explicit_empty_graph() -> None:
    raw = """config system global
end
config system admin
end
""" + EMPTY_REFERENCE_GRAPH_CONFIG

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.NOT_APPLICABLE


def test_mixed_direct_entries_and_structural_children_are_unknown() -> None:
    cases = (
        RESOLVED_REFERENCES_CONFIG.replace(
            "config system sdwan\nend\n",
            """config system sdwan
    edit "hidden-entry"
        set member "wan1"
    next
    config zone
        edit "virtual-wan-link"
            set interface "wan1"
        next
    end
end
""",
        ),
        RESOLVED_REFERENCES_CONFIG
        + """config firewall vip
    edit "VS"
        set type static-nat
        set extintf "wan1"
        set extip 203.0.113.10
        set mappedip "10.0.0.10"
    next
    config realservers
        edit 1
            set ip 10.0.0.11
            set port 443
        next
    end
end
""",
    )

    for raw in cases:
        finding, _findings = _finding(raw)
        assert finding.status is AuditStatus.UNKNOWN


def test_sdwan_direct_member_and_nested_member_keep_distinct_provenance() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        '    next\nend\nconfig system zone',
        '''    next
    edit "wan2"
        set role wan
        set allowaccess ping
    next
end
config system zone''',
        1,
    ).replace(
        "config system sdwan\nend\n",
        """config system sdwan
    config zone
        edit "virtual-wan-link"
            set member "wan2"
        next
    end
    config members
        edit 1
            set zone "virtual-wan-link"
            set interface "wan1"
        next
    end
end
""",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.PASS
    assert any(
        item.section == "system sdwan"
        and item.directive == "member"
        and item.tokens == ("wan2",)
        for item in finding.evidence_items
    )
    assert any(
        item.section == "system sdwan -> members"
        and item.directive == "interface"
        and item.tokens == ("wan1",)
        for item in finding.evidence_items
    )


def test_vip_multitoken_extip_is_not_proven() -> None:
    raw = RESOLVED_REFERENCES_CONFIG + """config firewall vip
    edit "VIP"
        set extintf "wan1"
        set extip 203.0.113.10 203.0.113.11
        set mappedip "10.0.0.10"
    next
end
"""

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_unreferenced_service_cycle_is_unknown_not_orphan_failure() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        """config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
end
""",
        """config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
    edit "A"
        set member "B"
    next
    edit "B"
        set member "A"
    next
end
""",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_server_load_balance_multitoken_extip_is_not_proven() -> None:
    raw = RESOLVED_REFERENCES_CONFIG + """config firewall vip
    edit "VSERVER"
        set type server-load-balance
        set extintf "wan1"
        set extip 203.0.113.10 203.0.113.11
        config realservers
            edit 1
                set ip 10.0.0.11
                set port 443
            next
        end
    next
end
"""

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_sdwan_ghost_member_zone_blocks_declared_zone_pass() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        "config system sdwan\nend\n",
        """config system sdwan
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set zone "virtual-wan-link"
            set interface "wan1"
        next
        edit 2
            set zone "ghost-zone"
            set interface "wan1"
        next
    end
end
""",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN


def test_sdwan_direct_interface_evidence_is_not_rewritten_as_nested_member() -> None:
    raw = RESOLVED_REFERENCES_CONFIG.replace(
        "config system sdwan\nend\n",
        """config system sdwan
    config zone
        edit "virtual-wan-link"
            set interface "wan1"
        next
    end
    config members
        edit 1
            set zone "virtual-wan-link"
            set interface "wan1"
        next
    end
end
""",
    )

    finding, _findings = _finding(raw)

    assert finding.status is AuditStatus.UNKNOWN
    assert any(
        item.section == "system sdwan"
        and item.entry == "virtual-wan-link"
        and item.directive == "interface"
        and item.certainty is EvidenceCertainty.AMBIGUOUS
        for item in finding.evidence_items
    )

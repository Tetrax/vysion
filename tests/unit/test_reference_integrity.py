from vysion.audit.engine import AuditEngine
from vysion.audit.models import Applicability, AuditStatus
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

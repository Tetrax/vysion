"""Legacy parity replay for typed sensitive-port deny coverage."""

from vysion.audit.controls.firewall import (
    SENSITIVE_PROTOCOL_RULESET_ID,
    SENSITIVE_PROTOCOL_RULESET_VERSION,
)
from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    AuditContext,
    AuditStatus,
    EvidenceCertainty,
    WanSelection,
    WanSelectionKind,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


def _finding(raw: str):
    context = AuditContext(
        wan_selections=(WanSelection(name="wan1", kind=WanSelectionKind.INTERFACE),)
    )
    return next(
        item
        for item in AuditEngine(default_registry()).run(
            FortiGateParser().parse(raw), context=context
        )
        if item.control_id == "FW-SENSITIVE-PROTOCOL-DENY-001"
    )


def _fixture(*, tcp: str, udp: str) -> str:
    return f"""config system interface
    edit "lan1"
        set role lan
    next
    edit "wan1"
        set role wan
    next
end
config firewall service custom
    edit "Ports-Deny"
        set tcp-portrange {tcp}
        set udp-portrange {udp}
    next
end
config firewall service group
end
config firewall policy
    edit 100
        set status enable
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "Ports-Deny"
    next
end
"""


def test_builtin_all_service_is_known_full_sensitive_coverage() -> None:
    raw = _fixture(
        tcp="88 389 636 445 137-139",
        udp="88 389 1812-1813 137-139",
    ).replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "ALL"\n'
        '        set protocol IP\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    ).replace("set action deny", "set action accept").replace(
        'set service "Ports-Deny"', 'set service "ALL"'
    )

    finding = _finding(raw)

    assert finding.status is AuditStatus.FAIL


def test_builtin_all_service_deny_is_known_full_sensitive_coverage() -> None:
    raw = _fixture(
        tcp="88 389 636 445 137-139",
        udp="88 389 1812-1813 137-139",
    ).replace(
        '    next\nend\nconfig firewall service group',
        '    next\n'
        '    edit "ALL"\n'
        '        set protocol IP\n'
        '    next\n'
        'end\n'
        'config firewall service group',
    ).replace('set service "Ports-Deny"', 'set service "ALL"')

    finding = _finding(raw)

    assert finding.status is AuditStatus.PASS


def test_builtin_all_without_custom_catalog_entry_is_known_full_coverage() -> None:
    raw = _fixture(
        tcp="88 389 636 445 137-139",
        udp="88 389 1812-1813 137-139",
    ).replace('set service "Ports-Deny"', 'set service "ALL"')

    finding = _finding(raw)

    assert finding.status is AuditStatus.PASS


def test_global_any_deny_with_complete_typed_ports_covers_lan_to_wan() -> None:
    finding = _finding(
        _fixture(
            tcp="88 389 636 445 137-139",
            udp="88 389 1812-1813 137-139",
        )
    )

    assert finding.status is AuditStatus.PASS
    assert finding.affected_objects[0].name == "100"
    evidence_text = " ".join(str(item) for item in finding.evidence)
    assert SENSITIVE_PROTOCOL_RULESET_ID in finding.message
    assert SENSITIVE_PROTOCOL_RULESET_VERSION in evidence_text
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)



def test_proven_zone_member_without_explicit_role_is_lan() -> None:
    raw = _fixture(
        tcp="88 389 636 445 137-139",
        udp="88 389 1812-1813 137-139",
    ).replace(
        'config firewall policy\n',
        'config system zone\n'
        '    edit "LAN"\n'
        '        set interface "lan1"\n'
        '    next\n'
        'end\n'
        'config firewall policy\n',
    ).replace(
        '    edit "lan1"\n        set role lan\n',
        '    edit "lan1"\n'
        '        set ip 192.0.2.1/24\n'
        '        set allowaccess ping\n',
    ).replace(
        'set srcintf "any"', 'set srcintf "LAN"'
    ).replace(
        'set dstintf "any"', 'set dstintf "wan1"'
    )

    finding = _finding(raw)

    assert finding.status is AuditStatus.PASS


def test_global_any_deny_with_partial_ports_is_not_a_false_pass() -> None:
    finding = _finding(_fixture(tcp="88 389", udp="88 389"))

    assert finding.status is AuditStatus.UNKNOWN


def test_global_any_accept_with_sensitive_ports_is_a_certain_failure() -> None:
    raw = _fixture(
        tcp="88 389 636 445 137-139",
        udp="88 389 1812-1813 137-139",
    ).replace("set action deny", "set action accept")

    finding = _finding(raw)

    assert finding.status is AuditStatus.FAIL

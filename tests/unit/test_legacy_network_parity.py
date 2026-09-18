import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext, AuditStatus, ProofState
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

GEO_ID = "NET-GEO-IP-USAGE-001"
BLACKHOLE_ID = "NET-RFC6890-BLACKHOLE-001"


def _audit(raw: str, context: AuditContext | None = None):
    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration, context=context)
    return configuration, {finding.control_id: finding for finding in findings}


GEO_PASS = """\
config firewall address
    edit "geo-country"
        set type geography
    next
end
config firewall addrgrp
    edit "geo-inner"
        set member "geo-country"
    next
    edit "geo-outer"
        set member "geo-inner"
    next
end
config firewall policy
    edit 10
        set srcintf "wan-a"
        set dstintf "lan-a"
        set srcaddr "geo-outer"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""


def test_geo_ip_passes_through_real_parser_projection_engine_and_registry() -> None:
    configuration, findings = _audit(GEO_PASS, AuditContext(selected_wans=("wan-a",)))

    assert configuration.address_objects[0].address_type == "geography"
    assert configuration.address_groups[1].members[0].name == "geo-inner"
    assert findings[GEO_ID].status is AuditStatus.PASS
    assert findings[GEO_ID].rule_provenance == "legacy_v1"


def test_geo_ip_certain_absence_fails() -> None:
    raw = GEO_PASS.replace('set srcaddr "geo-outer"', 'set srcaddr "ordinary"')
    assert _audit(raw, AuditContext(selected_wans=("wan-a",)))[1][GEO_ID].status is AuditStatus.FAIL


@pytest.mark.parametrize(
    "raw,context",
    [
        (GEO_PASS, None),
        (
            GEO_PASS.replace('set member "geo-inner"', 'append member "geo-inner"'),
            AuditContext(selected_wans=("wan-a",)),
        ),
        (
            GEO_PASS.replace('set member "geo-inner"', 'set member "geo-inner" "geo-outer"'),
            AuditContext(selected_wans=("wan-a",)),
        ),
        (
            GEO_PASS.replace('edit "geo-country"', 'edit "Geo-Country"', 1).replace(
                "end\nconfig firewall addrgrp",
                '    edit "geo-country"\n'
                "        set type geography\n"
                "    next\nend\nconfig firewall addrgrp",
            ),
            AuditContext(selected_wans=("wan-a",)),
        ),
    ],
)
def test_geo_ip_ambiguous_graph_or_context_is_unknown(
    raw: str, context: AuditContext | None
) -> None:
    assert _audit(raw, context)[1][GEO_ID].status is AuditStatus.UNKNOWN


ROUTE = """\
config router static
    edit 100
        set dstaddr "rfc6890-set"
        set blackhole enable
        set distance 254
    next
end
"""


@pytest.mark.parametrize(
    "raw,mpls,expected",
    [
        (ROUTE, False, AuditStatus.PASS),
        (ROUTE, True, AuditStatus.FAIL),
        (ROUTE.replace("set distance 254", "set distance 253"), True, AuditStatus.PASS),
        (ROUTE.replace("set distance 254", "set distance 253"), False, AuditStatus.FAIL),
        (ROUTE, None, AuditStatus.UNKNOWN),
    ],
)
def test_blackhole_v1_truth_table_through_real_pipeline(
    raw: str, mpls: bool | None, expected: AuditStatus
) -> None:
    context = AuditContext(
        mpls=mpls,
        legacy_v1_rfc6890_policy={"destination_objects": ("rfc6890-set",)},
    )
    configuration, findings = _audit(raw, context)

    assert configuration.static_routes[0].destination.name == "rfc6890-set"
    assert configuration.static_routes[0].proof_state is ProofState.PROVEN
    assert findings[BLACKHOLE_ID].status is expected
    assert findings[BLACKHOLE_ID].rule_provenance == "legacy_v1"


def test_blackhole_is_unknown_for_mutation_or_collision_and_uses_v1_default_target() -> None:
    mutated = ROUTE.replace("set distance 254", "append distance 254")
    collision = ROUTE + ROUTE.replace("edit 100", "edit 101")
    policy = {"destination_objects": ("rfc6890-set",)}

    assert (
        _audit(mutated, AuditContext(mpls=False, legacy_v1_rfc6890_policy=policy))[1][
            BLACKHOLE_ID
        ].status
        is AuditStatus.UNKNOWN
    )
    assert (
        _audit(collision, AuditContext(mpls=False, legacy_v1_rfc6890_policy=policy))[1][
            BLACKHOLE_ID
        ].status
        is AuditStatus.UNKNOWN
    )
    assert _audit(ROUTE, AuditContext(mpls=False))[1][BLACKHOLE_ID].status is AuditStatus.FAIL


def test_registry_appends_network_legacy_controls_in_stable_order() -> None:
    ids = [getattr(control, "control_id", "") for control in default_registry()]
    assert ids[48:50] == [GEO_ID, BLACKHOLE_ID]
    assert len(ids) == 60


# Real 7.2/7.4 backups carry these value keys on firewall address/addrgrp
# entries (geography country codes, MAC hosts, interface scope, routing flag,
# colour).  They are object values, not references, and no control consumes
# them: the probative keys (type/fqdn, member) carry the audit semantics and
# V1's legacy check only reads ``set type geography``.  They must therefore
# not make the entry - and through it the whole section - ambiguous.
GEO_REAL_VALUE_KEYS = """\
config firewall address
    edit "geo-country"
        set type geography
        set country "FR"
    next
    edit "mac-host"
        set type mac
        set macaddr 00:00:5e:00:53:01
    next
    edit "scoped-host"
        set type ipmask
        set subnet 192.0.2.0 255.255.255.0
        set associated-interface "any"
    next
end
config firewall addrgrp
    edit "geo-inner"
        set member "geo-country"
        set allow-routing disable
        set color 3
    next
end
config firewall policy
    edit 10
        set srcintf "wan-a"
        set dstintf "lan-a"
        set srcaddr "geo-inner"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""


def test_geo_ip_concludes_with_real_backup_value_keys() -> None:
    configuration, findings = _audit(
        GEO_REAL_VALUE_KEYS, AuditContext(selected_wans=("wan-a",))
    )

    assert findings[GEO_ID].status is AuditStatus.PASS
    assert {item.name for item in configuration.address_objects} >= {
        "geo-country",
        "mac-host",
        "scoped-host",
    }


def test_geo_ip_stays_unknown_when_a_real_entry_carries_an_unknown_key() -> None:
    raw = GEO_REAL_VALUE_KEYS.replace(
        'set country "FR"', 'set country "FR"\n        set probe-unknown-key 1'
    )

    finding = _audit(raw, AuditContext(selected_wans=("wan-a",)))[1][GEO_ID]
    assert finding.status is AuditStatus.UNKNOWN


COMPLETE_BACKUP_HEADER = (
    "#config-version=FGT60E-7.4.8-FW-build0000-000000:opmode=0:vdom=0:user=admin\n"
    "#buildno=0000\n"
    "#global_vdom=1\n"
    "#conf_file_ver=1\n"
)

GEO_COMPLETE_WITHOUT_ADDRGRP = (
    COMPLETE_BACKUP_HEADER
    + """\
config firewall address
    edit "geo-country"
        set type geography
        set country "FR"
    next
end
config firewall policy
    edit 10
        set srcintf "wan-a"
        set dstintf "lan-a"
        set srcaddr "geo-country"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
)


def test_geo_ip_concludes_when_complete_backup_has_no_address_group_section() -> None:
    raw_used = GEO_COMPLETE_WITHOUT_ADDRGRP
    raw_unused = GEO_COMPLETE_WITHOUT_ADDRGRP.replace(
        'set srcaddr "geo-country"', 'set srcaddr "all"'
    )
    context = AuditContext(selected_wans=("wan-a",))

    assert _audit(raw_used, context)[1][GEO_ID].status is AuditStatus.PASS
    assert _audit(raw_unused, context)[1][GEO_ID].status is AuditStatus.FAIL


def test_geo_ip_keeps_unknown_when_incomplete_backup_lacks_a_section() -> None:
    raw = GEO_COMPLETE_WITHOUT_ADDRGRP.replace(COMPLETE_BACKUP_HEADER, "")

    finding = _audit(raw, AuditContext(selected_wans=("wan-a",)))[1][GEO_ID]
    assert finding.status is AuditStatus.UNKNOWN


def test_geo_ip_concludes_with_policy_defaults_omitted_like_real_backups() -> None:
    """Real 7.2/7.4 backups omit ``action`` and, on internet-service rules,
    ``srcaddr``/``dstaddr``: those fields cannot carry a geography reference."""

    raw = """\
config firewall address
    edit "geo-country"
        set type geography
        set country "FR"
    next
end
config firewall addrgrp
    edit "geo-inner"
        set member "geo-country"
    next
end
config firewall policy
    edit 10
        set srcintf "wan-a"
        set dstintf "lan-a"
        set srcaddr "geo-inner"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
    edit 11
        set srcintf "lan-a"
        set dstintf "wan-a"
        set internet-service enable
        set internet-service-name "Example-SAAS"
        set schedule "always"
    next
end
"""

    _, findings = _audit(raw, AuditContext(selected_wans=("wan-a",)))

    assert findings[GEO_ID].status is AuditStatus.PASS


def test_geo_ip_stays_unknown_when_a_policy_address_reference_is_mutated() -> None:
    raw = GEO_REAL_VALUE_KEYS.replace(
        'set srcaddr "geo-inner"', 'append srcaddr "geo-inner"'
    )

    finding = _audit(raw, AuditContext(selected_wans=("wan-a",)))[1][GEO_ID]
    assert finding.status is AuditStatus.UNKNOWN


def test_geo_ip_concludes_for_objects_without_declared_type_like_real_backups() -> None:
    """FortiOS writes non-default types only: a subnet-only object (implicit
    ``type ipmask``) is not a geography object and must not block the check."""

    raw = GEO_REAL_VALUE_KEYS.replace(
        '    edit "mac-host"\n        set type mac\n',
        '    edit "mac-host"\n',
    ).replace('    edit "scoped-host"\n        set type ipmask\n', '    edit "scoped-host"\n')

    finding = _audit(raw, AuditContext(selected_wans=("wan-a",)))[1][GEO_ID]
    assert finding.status is AuditStatus.PASS

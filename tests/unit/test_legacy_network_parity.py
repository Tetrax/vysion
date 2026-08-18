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


def test_blackhole_is_unknown_for_mutation_collision_or_missing_policy() -> None:
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
    assert _audit(ROUTE, AuditContext(mpls=False))[1][BLACKHOLE_ID].status is AuditStatus.UNKNOWN


def test_registry_appends_network_legacy_controls_in_stable_order() -> None:
    ids = [getattr(control, "control_id", "") for control in default_registry()]
    assert ids[-3:-1] == [GEO_ID, BLACKHOLE_ID]
    assert len(ids) == 51

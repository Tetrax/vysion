from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext, AuditStatus, ContextProvenance, ProofState
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

HA_STRONG = """config system ha
    set group-name "cluster-lab"
    set session-pickup enable
    set session-pickup-connectionless enable
    set session-pickup-expectation enable
    set hbdev "port3" 50 "port4" 50
    set override disable
end
"""


def _findings(raw: str):
    configuration = FortiGateParser().parse(raw)
    return configuration, {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(configuration)
    }


def test_ha_session_pickup_traces_parser_projection_registry() -> None:
    configuration, findings = _findings(HA_STRONG)

    assert configuration.ha_settings is not None
    assert configuration.ha_settings.proof_state is ProofState.PROVEN
    assert findings["HA-SESSION-PICKUP-001"].status is AuditStatus.PASS


def test_ha_session_pickup_explicit_disable_is_fail() -> None:
    raw = HA_STRONG.replace("set session-pickup enable", "set session-pickup disable")

    _, findings = _findings(raw)

    assert findings["HA-SESSION-PICKUP-001"].status is AuditStatus.FAIL


def test_ha_heartbeat_requires_two_certain_interfaces() -> None:
    _, strong = _findings(HA_STRONG)
    _, weak = _findings(
        HA_STRONG.replace(
            'set hbdev "port3" 50 "port4" 50',
            'set hbdev "port3" 50',
        )
    )

    assert strong["HA-HEARTBEAT-REDUNDANCY-001"].status is AuditStatus.PASS
    assert weak["HA-HEARTBEAT-REDUNDANCY-001"].status is AuditStatus.FAIL


def test_ha_override_legacy_rule_is_typed() -> None:
    _, disabled = _findings(HA_STRONG)
    _, wait_30 = _findings(
        HA_STRONG.replace(
            "set override disable",
            "set override enable\n    set override-wait-time 30",
        )
    )
    _, wrong_wait = _findings(
        HA_STRONG.replace(
            "set override disable",
            "set override enable\n    set override-wait-time 10",
        )
    )

    assert disabled["HA-OVERRIDE-001"].status is AuditStatus.PASS
    assert wait_30["HA-OVERRIDE-001"].status is AuditStatus.PASS
    assert wrong_wait["HA-OVERRIDE-001"].status is AuditStatus.FAIL


def test_ha_cabling_stays_unknown_without_operator_observation() -> None:
    configuration = FortiGateParser().parse(HA_STRONG)
    engine = AuditEngine(default_registry())

    unknown = {item.control_id: item for item in engine.run(configuration)}
    proven = {
        item.control_id: item
        for item in engine.run(
            configuration,
            AuditContext(
                ha_cabling_redundancy=True,
                operator_provenance=ContextProvenance(
                    source="operator", method="physical-inspection"
                ),
            ),
        )
    }

    assert unknown["HA-CABLING-REDUNDANCY-001"].status is AuditStatus.UNKNOWN
    assert proven["HA-CABLING-REDUNDANCY-001"].status is AuditStatus.PASS


def test_ha_unknown_structure_never_passes() -> None:
    raw = HA_STRONG.replace("set session-pickup enable", "append session-pickup enable")

    _, findings = _findings(raw)

    for control_id in (
        "HA-SESSION-PICKUP-001",
        "HA-HEARTBEAT-REDUNDANCY-001",
        "HA-OVERRIDE-001",
    ):
        assert findings[control_id].status is AuditStatus.UNKNOWN

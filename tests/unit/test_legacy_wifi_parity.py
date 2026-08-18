import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditStatus
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

WIFI_IDS = (
    "WIFI-FORTIAP-OBSOLETE-001",
    "WIFI-SSID-LIMIT-001",
    "WIFI-RADIO2-40MHZ-001",
    "WIFI-DARRP-001",
    "WIFI-FREQUENCY-HANDOFF-001",
    "WIFI-TIM-001",
    "WIFI-BAND-001",
    "WIFI-CHANNELS-001",
    "WIFI-SHORT-GUARD-INTERVAL-001",
)


PASS_CONFIG = """
config wireless-controller wtp
    edit "FAP231F00000000"
        set wtp-profile "office-profile"
    next
end
config wireless-controller wtp-profile
    edit "office-profile"
        set frequency-handoff enable
        config radio-1
            set mode ap
            set vaps "ssid-a" "ssid-b"
            set darrp enable
            set band 802.11ax-only
            set channel "1" "6" "11"
            set short-guard-interval enable
        end
        config radio-2
            set mode ap
            set vaps "ssid-a" "ssid-b"
            set channel-bonding 40MHz
            set darrp enable
            set band 802.11ac-only
            set short-guard-interval enable
        end
        set powersave-optimize tim
    next
end
"""


def _audit(raw: str):
    configuration = FortiGateParser().parse(raw)
    findings = {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(configuration)
    }
    return configuration, findings


def test_wifi_tracer_through_real_parser_typed_projection_engine_registry() -> None:
    configuration, findings = _audit(PASS_CONFIG)

    assert configuration.wireless_access_points[0].profile.name == "office-profile"
    assert configuration.wireless_profiles[0].radios[0].channels == ("1", "6", "11")
    assert tuple(findings)[-9:] == WIFI_IDS
    assert all(findings[control_id].status is AuditStatus.PASS for control_id in WIFI_IDS)
    assert all(findings[control_id].rule_provenance == "legacy_v1" for control_id in WIFI_IDS)


FAIL_CONFIGS = {
    WIFI_IDS[0]: PASS_CONFIG.replace("FAP231F00000000", "FAP14C00000000"),
    WIFI_IDS[1]: PASS_CONFIG.replace(
        'set vaps "ssid-a" "ssid-b"', 'set vaps "a" "b" "c" "d" "e"', 1
    ),
    WIFI_IDS[2]: PASS_CONFIG.replace("set channel-bonding 40MHz", "set channel-bonding 20MHz"),
    WIFI_IDS[3]: PASS_CONFIG.replace("set darrp enable", "set darrp disable", 1),
    WIFI_IDS[4]: PASS_CONFIG.replace(
        "set frequency-handoff enable", "set frequency-handoff disable"
    ),
    WIFI_IDS[5]: PASS_CONFIG.replace(
        "set powersave-optimize tim", "set powersave-optimize disable"
    ),
    WIFI_IDS[6]: PASS_CONFIG.replace("set band 802.11ax-only", "set band 802.11ax"),
    WIFI_IDS[7]: PASS_CONFIG.replace('set channel "1" "6" "11"', 'set channel "1" "6"'),
    WIFI_IDS[8]: PASS_CONFIG.replace(
        "set short-guard-interval enable", "set short-guard-interval disable", 1
    ),
}


@pytest.mark.parametrize("control_id", WIFI_IDS)
def test_each_wifi_control_has_a_real_pipeline_fail(control_id: str) -> None:
    _, findings = _audit(FAIL_CONFIGS[control_id])
    assert findings[control_id].status is AuditStatus.FAIL


@pytest.mark.parametrize("control_id", WIFI_IDS)
def test_each_wifi_control_is_unknown_for_mutated_wtp_reference(control_id: str) -> None:
    raw = PASS_CONFIG.replace(
        'set wtp-profile "office-profile"', 'append wtp-profile "office-profile"'
    )
    _, findings = _audit(raw)
    assert findings[control_id].status is AuditStatus.UNKNOWN


@pytest.mark.parametrize("control_id", WIFI_IDS)
def test_each_wifi_control_is_not_applicable_for_certain_empty_wtp(control_id: str) -> None:
    _, findings = _audit("config wireless-controller wtp\nend\n")
    assert findings[control_id].status is AuditStatus.NOT_APPLICABLE


def test_missing_profile_and_casefold_collisions_are_unknown() -> None:
    missing = PASS_CONFIG.replace('set wtp-profile "office-profile"', 'set wtp-profile "missing"')
    collision = PASS_CONFIG + PASS_CONFIG.replace(
        'edit "office-profile"', 'edit "OFFICE-PROFILE"'
    ).split("config wireless-controller wtp-profile", 1)[1].join(
        ("config wireless-controller wtp-profile", "")
    )
    assert all(
        _audit(missing)[1][control_id].status is AuditStatus.UNKNOWN for control_id in WIFI_IDS
    )
    assert all(
        _audit(collision)[1][control_id].status is AuditStatus.UNKNOWN for control_id in WIFI_IDS
    )


def test_registry_appends_exactly_nine_wifi_controls() -> None:
    ids = [getattr(control, "control_id", "") for control in default_registry()]
    assert tuple(ids[-9:]) == WIFI_IDS
    assert len(ids) == 60


def test_certain_fail_has_priority_over_an_unrelated_unknown_profile() -> None:
    mixed = FAIL_CONFIGS[WIFI_IDS[7]].replace(
        "config wireless-controller wtp-profile",
        'config wireless-controller wtp\n    edit "FAP231F11111111"\n'
        '        set wtp-profile "missing"\n    next\nend\n'
        "config wireless-controller wtp-profile",
    )
    assert _audit(mixed)[1][WIFI_IDS[7]].status is AuditStatus.FAIL

from vysion.audit.controls.legacy_network import check_legacy_rfc6890_blackhole
from vysion.audit.controls.system_parity import check_admin_https_port
from vysion.audit.controls.vpn import check_dh_groups
from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext, AuditStatus, FortiGateConfiguration
from vysion.audit.parser import FortiGateParser
from vysion.reports.presentation import build_presentation


def parse(raw: str):
    return FortiGateParser().parse(raw)


def test_admin_sport_out_of_range_is_unknown() -> None:
    cfg = parse('config system global\n    set admin-sport 999999\nend\n')
    assert check_admin_https_port(cfg).status is AuditStatus.UNKNOWN


def test_unknown_fortios_dh_group_is_unknown() -> None:
    cfg = parse(
        'config vpn ipsec phase1-interface\n'
        '    edit "p1"\n'
        '        set interface "wan1"\n'
        '        set dhgrp 999\n'
        '    next\nend\n'
        'config vpn ipsec phase2-interface\n'
        '    edit "p2"\n'
        '        set phase1name "p1"\n'
        '        set dhgrp 14\n'
        '    next\nend\n'
    )
    assert check_dh_groups(cfg).status is AuditStatus.UNKNOWN


def test_disabled_blackhole_route_is_not_counted_as_active() -> None:
    cfg = parse(
        'config router static\n'
        '    edit 100\n'
        '        set status disable\n'
        '        set dstaddr "rfc6890-set"\n'
        '        set blackhole enable\n'
        '        set distance 254\n'
        '    next\nend\n'
    )
    finding = check_legacy_rfc6890_blackhole(cfg, AuditContext(mpls=False))
    assert finding.status is AuditStatus.FAIL


def test_engine_error_has_stable_id_and_presentation_row() -> None:
    def broken(configuration: FortiGateConfiguration):
        raise RuntimeError("fixture")

    finding = AuditEngine((broken,)).run(FortiGateConfiguration(), AuditContext())[0]
    assert finding.control_id == "ENGINE-broken"
    presentation = build_presentation((finding,))
    assert presentation.engine_error_rows[0].status is AuditStatus.ERROR

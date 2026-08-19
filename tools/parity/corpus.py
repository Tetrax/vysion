from tools.parity.differential import DifferentialCase

BACKUP_HEADER = """\
#config-version=FGT60F-7.2.9-FW-build1-1:opmode=0
#buildno=1
#global_vdom=1
#conf_file_ver=1
"""
WAN1_INTERFACE = """\
config system interface
    edit "wan1"
        set role wan
        set status up
        set allowaccess ping
    next
end
"""


def _case(
    case_id: str,
    legacy_callable: str,
    v2_control_id: str,
    body: str,
    *,
    accepted_transitions: tuple[str, ...] = (),
) -> DifferentialCase:
    return DifferentialCase(
        case_id=case_id,
        legacy_callable=legacy_callable,
        v2_control_id=v2_control_id,
        config=BACKUP_HEADER + body,
        accepted_transitions=accepted_transitions,
    )


def synthetic_cases() -> tuple[DifferentialCase, ...]:
    return (
        _case(
            "guest-present",
            "verifier_compte_guest",
            "IAM-GUEST-ACCOUNT-001",
            'config user local\n    edit "guest"\n        set type password\n    next\nend\n',
        ),
        _case(
            "guest-absent",
            "verifier_compte_guest",
            "IAM-GUEST-ACCOUNT-001",
            'config user local\n    edit "analyst"\n        set type password\n    next\nend\n',
        ),
        _case(
            "default-admin-present",
            "verifier_compte_admin",
            "IAM-DEFAULT-ADMIN-001",
            "config system admin\n"
            '    edit "admin"\n'
            "        set accprofile super_admin\n"
            "    next\nend\n",
        ),
        _case(
            "default-admin-absent",
            "verifier_compte_admin",
            "IAM-DEFAULT-ADMIN-001",
            "config system admin\n"
            '    edit "secops"\n'
            "        set accprofile super_admin\n"
            "    next\nend\n",
        ),
        _case(
            "vip-any",
            "verifier_vips_extintf_any",
            "FW-VIP-EXTINTF-ANY-001",
            'config firewall vip\n    edit "published"\n        set extintf "any"\n'
            "        set extip 192.0.2.10\n"
            '        set mappedip "10.0.0.10"\n'
            "    next\nend\n",
        ),
        _case(
            "vip-specific",
            "verifier_vips_extintf_any",
            "FW-VIP-EXTINTF-ANY-001",
            "config firewall vip\n"
            '    edit "published"\n'
            '        set extintf "wan1"\n'
            "        set extip 192.0.2.10\n"
            '        set mappedip "10.0.0.10"\n'
            "    next\nend\n"
            + WAN1_INTERFACE,
        ),
        _case(
            "vserver-any",
            "verifier_vs_extintf_any",
            "FW-VSERVER-EXTINTF-ANY-001",
            "config firewall vip\n"
            '    edit "frontend"\n'
            "        set type server-load-balance\n"
            '        set extintf "any"\n'
            "        config realservers\n"
            "            edit 1\n"
            "                set ip 10.0.0.20\n"
            "                set port 443\n"
            "            next\n"
            "        end\n"
            "    next\nend\n",
        ),
        _case(
            "vserver-specific",
            "verifier_vs_extintf_any",
            "FW-VSERVER-EXTINTF-ANY-001",
            "config firewall vip\n"
            '    edit "frontend"\n'
            "        set type server-load-balance\n"
            '        set extintf "wan1"\n'
            "        config realservers\n"
            "            edit 1\n"
            "                set ip 10.0.0.20\n"
            "                set port 443\n"
            "            next\n"
            "        end\n"
            "    next\nend\n"
            + WAN1_INTERFACE,
        ),
        _case(
            "ssl-vpn-disabled",
            "verifier_vpn_ssl_utilisation",
            "VPN-SSL-001",
            "config vpn ssl settings\n    set status disable\nend\n",
            accepted_transitions=("PASS->NOT_APPLICABLE",),
        ),
        _case(
            "ssl-vpn-configured",
            "verifier_vpn_ssl_utilisation",
            "VPN-SSL-001",
            "config vpn ssl settings\n"
            "    set status enable\n"
            '    set source-interface "wan1"\n'
            "end\n",
        ),
    )


def real_reference_cases(config: str) -> tuple[DifferentialCase, ...]:
    pairs = (
        ("real-guest", "verifier_compte_guest", "IAM-GUEST-ACCOUNT-001", ()),
        ("real-default-admin", "verifier_compte_admin", "IAM-DEFAULT-ADMIN-001", ()),
        (
            "real-vip-any",
            "verifier_vips_extintf_any",
            "FW-VIP-EXTINTF-ANY-001",
            ("PASS->NOT_APPLICABLE",),
        ),
        ("real-vserver-any", "verifier_vs_extintf_any", "FW-VSERVER-EXTINTF-ANY-001", ()),
        (
            "real-ssl-vpn",
            "verifier_vpn_ssl_utilisation",
            "VPN-SSL-001",
            ("PASS->NOT_APPLICABLE",),
        ),
        ("real-implicit-deny", "verifier_logs_deny_implicit", "FW-IMPLICIT-DENY-LOG-001", ()),
        ("real-auto-usb", "verifier_auto_install_usb", "SYS-AUTO-INSTALL-USB-001", ()),
    )
    return tuple(
        DifferentialCase(
            case_id=case_id,
            legacy_callable=legacy_callable,
            v2_control_id=v2_control_id,
            config=config,
            accepted_transitions=accepted_transitions,
        )
        for case_id, legacy_callable, v2_control_id, accepted_transitions in pairs
    )

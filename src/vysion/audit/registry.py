from vysion.audit.controls.administration import (
    check_admin_mfa,
    check_default_admin,
    check_guest_account,
    check_local_user_mfa,
)
from vysion.audit.controls.external_services import (
    check_fortiguard_psirt,
    check_ldaps_connectors,
)
from vysion.audit.controls.firewall import (
    check_implicit_deny_log,
    check_internet_all_service,
    check_sensitive_protocol_deny,
    check_utm_profile_binding,
    check_vip_extintf_any,
    check_vserver_extintf_any,
)
from vysion.audit.controls.ha import (
    check_ha_cabling_redundancy,
    check_ha_heartbeat_redundancy,
    check_ha_override,
    check_ha_session_pickup,
)
from vysion.audit.controls.legacy_admin import (
    check_legacy_admin_loopback,
    check_legacy_dns_database,
    check_legacy_local_admin,
    check_legacy_pki_presence,
    check_legacy_pki_removal,
)
from vysion.audit.controls.legacy_network import (
    check_legacy_geo_ip_usage,
    check_legacy_rfc6890_blackhole,
)
from vysion.audit.controls.network import check_wan_management_access
from vysion.audit.controls.network_parity import (
    check_by_sequence_usage,
    check_sdwan_usage,
    check_sip_alg,
    check_ssl_ssh_profiles,
)
from vysion.audit.controls.object_usage import check_unused_service_objects
from vysion.audit.controls.references import check_reference_integrity
from vysion.audit.controls.schedules import check_legacy_schedule_inventory
from vysion.audit.controls.system import check_automatic_revision_backups, check_hostname
from vysion.audit.controls.system_parity import (
    check_admin_https_port,
    check_auto_install_usb,
    check_fortianalyzer_sync,
    check_fortimanager_sync,
)
from vysion.audit.controls.utm import (
    check_antivirus_profiles,
    check_appcontrol_profiles,
    check_dnsfilter_profiles,
    check_ips_profiles,
    check_utm_autoupdate,
    check_utm_license,
    check_webfilter_profiles,
)
from vysion.audit.controls.utm_parity import (
    check_fortiguard_anycast,
    check_fortisandbox_cloud,
    check_mail_filter_usage,
)
from vysion.audit.controls.vpn import (
    check_dh_groups,
    check_ikev2,
    check_ssl_vpn,
    check_vpn_crypto,
)
from vysion.audit.controls.wifi import (
    check_band,
    check_channels,
    check_darrp,
    check_frequency_handoff,
    check_obsolete_fortiap,
    check_radio2_40mhz,
    check_short_guard_interval,
    check_ssid_limit,
    check_tim,
)
from vysion.audit.engine import Control


def default_registry() -> tuple[Control, ...]:
    return (
        check_hostname,
        check_wan_management_access,
        check_admin_mfa,
        check_local_user_mfa,
        check_default_admin,
        check_guest_account,
        check_implicit_deny_log,
        check_internet_all_service,
        check_utm_profile_binding,
        check_vip_extintf_any,
        check_vserver_extintf_any,
        check_sensitive_protocol_deny,
        check_ssl_vpn,
        check_ikev2,
        check_dh_groups,
        check_vpn_crypto,
        check_utm_license,
        check_utm_autoupdate,
        check_dnsfilter_profiles,
        check_webfilter_profiles,
        check_antivirus_profiles,
        check_ips_profiles,
        check_appcontrol_profiles,
        check_ldaps_connectors,
        check_fortiguard_psirt,
        check_automatic_revision_backups,
        check_reference_integrity,
        check_auto_install_usb,
        check_fortimanager_sync,
        check_fortianalyzer_sync,
        check_admin_https_port,
        check_sip_alg,
        check_ha_session_pickup,
        check_ha_heartbeat_redundancy,
        check_ha_override,
        check_ha_cabling_redundancy,
        check_fortisandbox_cloud,
        check_fortiguard_anycast,
        check_sdwan_usage,
        check_by_sequence_usage,
        check_mail_filter_usage,
        check_ssl_ssh_profiles,
        check_unused_service_objects,
        check_legacy_local_admin,
        check_legacy_pki_removal,
        check_legacy_pki_presence,
        check_legacy_admin_loopback,
        check_legacy_dns_database,
        check_legacy_geo_ip_usage,
        check_legacy_rfc6890_blackhole,
        check_legacy_schedule_inventory,
        check_obsolete_fortiap,
        check_ssid_limit,
        check_radio2_40mhz,
        check_darrp,
        check_frequency_handoff,
        check_tim,
        check_band,
        check_channels,
        check_short_guard_interval,
    )

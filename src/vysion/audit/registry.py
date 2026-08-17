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
from vysion.audit.controls.network import check_wan_management_access
from vysion.audit.controls.references import check_reference_integrity
from vysion.audit.controls.system import check_automatic_revision_backups, check_hostname
from vysion.audit.controls.utm import (
    check_antivirus_profiles,
    check_appcontrol_profiles,
    check_dnsfilter_profiles,
    check_ips_profiles,
    check_utm_autoupdate,
    check_utm_license,
    check_webfilter_profiles,
)
from vysion.audit.controls.vpn import (
    check_dh_groups,
    check_ikev2,
    check_ssl_vpn,
    check_vpn_crypto,
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
    )

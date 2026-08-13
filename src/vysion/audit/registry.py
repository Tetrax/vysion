from vysion.audit.controls.administration import check_admin_mfa
from vysion.audit.controls.network import check_wan_management_access
from vysion.audit.controls.system import check_hostname
from vysion.audit.engine import Control


def default_registry() -> tuple[Control, ...]:
    return (check_hostname, check_wan_management_access, check_admin_mfa)

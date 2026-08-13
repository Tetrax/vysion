from vysion.audit.models import AuditFinding, AuditStatus, FortiGateConfiguration

_DISABLED = {None, "", "disable", "none"}
_SUPPORTED = {"fortitoken", "email", "sms"}


def check_admin_mfa(configuration: FortiGateConfiguration) -> AuditFinding:
    if "system admin" not in configuration.parsed_entry_sections:
        return AuditFinding(
            control_id="IAM-ADMIN-MFA-001",
            title="MFA des administrateurs",
            status=AuditStatus.UNKNOWN,
            message="Section system admin absente ou vide dans la configuration fournie.",
            risk="État MFA des administrateurs impossible à déterminer.",
            recommendation="Fournir une configuration FortiGate complète.",
        )
    unsupported = [
        admin.name
        for admin in configuration.administrators
        if admin.two_factor not in _DISABLED | _SUPPORTED
    ]
    if unsupported:
        return AuditFinding(
            control_id="IAM-ADMIN-MFA-001",
            title="MFA des administrateurs",
            status=AuditStatus.UNKNOWN,
            evidence=tuple(f"méthode MFA non reconnue: {name}" for name in unsupported),
            message="Méthode MFA non reconnue pour au moins un administrateur.",
            risk="État MFA impossible à conclure avec le tracer actuel.",
            recommendation="Vérifier la méthode MFA et étendre le parser avant conclusion.",
        )
    missing = [
        admin.name
        for admin in configuration.administrators
        if admin.two_factor in _DISABLED
    ]
    valid = not missing
    message = (
        "Tous les administrateurs déclarés utilisent le MFA."
        if valid
        else "MFA absent pour au moins un administrateur."
    )
    return AuditFinding(
        control_id="IAM-ADMIN-MFA-001",
        title="MFA des administrateurs",
        status=AuditStatus.PASS if valid else AuditStatus.FAIL,
        evidence=tuple(f"administrateur sans MFA: {name}" for name in missing),
        message=message,
        risk=None if valid else "Compromission facilitée d'un compte administrateur.",
        recommendation=None if valid else "Activer une méthode MFA pour chaque administrateur.",
    )

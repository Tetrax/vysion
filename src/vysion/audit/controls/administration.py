from vysion.audit.models import AuditFinding, AuditStatus, FortiGateConfiguration

_DISABLED = {"", "disable", "none"}
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

    disabled = [
        admin.name
        for admin in configuration.administrators
        if "two-factor" in admin.parsed_keys and admin.two_factor in _DISABLED
    ]
    if disabled:
        return AuditFinding(
            control_id="IAM-ADMIN-MFA-001",
            title="MFA des administrateurs",
            status=AuditStatus.FAIL,
            evidence=tuple(f"administrateur sans MFA: {name}" for name in disabled),
            message="MFA absent pour au moins un administrateur.",
            risk="Compromission facilitée d'un compte administrateur.",
            recommendation="Activer une méthode MFA pour chaque administrateur.",
        )

    unknown = [
        admin.name
        for admin in configuration.administrators
        if "two-factor" not in admin.parsed_keys
    ]
    if unknown:
        return AuditFinding(
            control_id="IAM-ADMIN-MFA-001",
            title="MFA des administrateurs",
            status=AuditStatus.UNKNOWN,
            evidence=tuple(f"directive MFA absente: {name}" for name in unknown),
            message="État MFA impossible à déterminer pour au moins un administrateur.",
            risk="État MFA impossible à conclure avec la configuration fournie.",
            recommendation="Fournir la directive two-factor de chaque administrateur.",
        )

    unsupported = [
        admin.name for admin in configuration.administrators if admin.two_factor not in _SUPPORTED
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

    return AuditFinding(
        control_id="IAM-ADMIN-MFA-001",
        title="MFA des administrateurs",
        status=AuditStatus.PASS,
        message="Tous les administrateurs déclarés utilisent le MFA.",
    )

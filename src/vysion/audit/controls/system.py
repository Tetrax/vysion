from vysion.audit.models import AuditFinding, AuditStatus, FortiGateConfiguration


def check_hostname(configuration: FortiGateConfiguration) -> AuditFinding:
    if "system global" not in configuration.parsed_value_sections:
        return AuditFinding(
            control_id="SYS-HOSTNAME-001",
            title="Hostname explicite",
            status=AuditStatus.UNKNOWN,
            message="Section system global absente ou vide dans la configuration fournie.",
            risk="Hostname impossible à déterminer.",
            recommendation="Fournir une configuration FortiGate complète.",
        )
    normalized = configuration.hostname.strip() if configuration.hostname else ""
    valid = bool(normalized and normalized.lower() != "fortigate")
    return AuditFinding(
        control_id="SYS-HOSTNAME-001",
        title="Hostname explicite",
        status=AuditStatus.PASS if valid else AuditStatus.FAIL,
        evidence=(f"hostname: {configuration.hostname}",) if configuration.hostname else (),
        message="Le hostname est explicite." if valid else "Le hostname est absent ou générique.",
        risk=None if valid else "Identification ambiguë de l'équipement.",
        recommendation=None if valid else "Définir un hostname unique et documenté.",
    )

from vysion.audit.models import AuditFinding, AuditStatus, FortiGateConfiguration


def check_wan_management_access(configuration: FortiGateConfiguration) -> AuditFinding:
    if "system interface" not in configuration.parsed_entry_sections:
        return AuditFinding(
            control_id="NET-WAN-MGMT-001",
            title="Administration SSH sur interface WAN",
            status=AuditStatus.UNKNOWN,
            message="Section system interface absente ou vide dans la configuration fournie.",
            risk="Exposition WAN impossible à déterminer.",
            recommendation="Fournir une configuration FortiGate complète.",
        )
    wan_interfaces = [
        interface
        for interface in configuration.interfaces
        if interface.name.lower().startswith("wan") or interface.role == "wan"
    ]
    if not wan_interfaces:
        return AuditFinding(
            control_id="NET-WAN-MGMT-001",
            title="Administration SSH sur interface WAN",
            status=AuditStatus.UNKNOWN,
            message="Aucune interface WAN identifiable dans la configuration fournie.",
            risk="Exposition WAN impossible à déterminer.",
            recommendation="Fournir une configuration permettant d'identifier les interfaces WAN.",
        )
    exposed = [
        f"{interface.name}: allowaccess includes ssh"
        for interface in wan_interfaces
        if "ssh" in interface.allowaccess
    ]
    missing_evidence = [
        interface.name for interface in wan_interfaces if "allowaccess" not in interface.parsed_keys
    ]
    if not exposed and missing_evidence:
        return AuditFinding(
            control_id="NET-WAN-MGMT-001",
            title="Administration SSH sur interface WAN",
            status=AuditStatus.UNKNOWN,
            evidence=tuple(
                f"allowaccess absent pour l'interface WAN: {name}" for name in missing_evidence
            ),
            message="Accès d'administration WAN impossible à déterminer.",
            risk="Exposition WAN impossible à exclure.",
            recommendation="Fournir la directive allowaccess de chaque interface WAN.",
        )
    message = "SSH est exposé sur une interface WAN." if exposed else "Aucun accès SSH WAN détecté."
    return AuditFinding(
        control_id="NET-WAN-MGMT-001",
        title="Administration SSH sur interface WAN",
        status=AuditStatus.FAIL if exposed else AuditStatus.PASS,
        evidence=tuple(exposed),
        message=message,
        risk="Exposition de l'administration sur un réseau non fiable." if exposed else None,
        recommendation="Retirer SSH de allowaccess sur les interfaces WAN." if exposed else None,
    )

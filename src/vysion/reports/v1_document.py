from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class V1DocumentSlot:
    number: str
    title: str
    control_ids: tuple[str, ...] = ()
    kind: str = "finding"
    image: str | None = None
    note: str | None = None


@dataclass(frozen=True, slots=True)
class V1DocumentSection:
    number: str
    title: str
    slots: tuple[V1DocumentSlot, ...]


# Keep the Word export identical to the historical mandatory report.  The
# engine may expose additional V2 findings, but they must not silently change
# the client-facing comparison perimeter.
V1_DOCUMENT_SECTIONS = (
    V1DocumentSection(
        "3.1",
        "Audit - Système",
        (
            V1DocumentSlot("3.1.1", "Version Fortigate", ("EXT-PSIRT-001",), "version"),
            V1DocumentSlot("3.1.2", "Modèle Fortigate", (), "model"),
            V1DocumentSlot("3.1.3", "Sauvegardes automatiques", ("SYS-BACKUP-AUTO-001",)),
            V1DocumentSlot("3.1.4", "Objets sans référence", ("CFG-UNUSED-SERVICE-001",)),
            V1DocumentSlot(
                "3.1.5", "Auto-installation d'image par USB", ("SYS-AUTO-INSTALL-USB-001",)
            ),
        ),
    ),
    V1DocumentSection(
        "3.2",
        "Audit - Administration et comptes",
        (
            V1DocumentSlot("3.2.1", "Port HTTPS personnalisé", ("SYS-ADMIN-HTTPS-PORT-001",)),
            V1DocumentSlot(
                "3.2.2", "Synchronisation avec un FortiManager", ("SYS-FORTIMANAGER-SYNC-001",)
            ),
            V1DocumentSlot(
                "3.2.3", "Synchronisation avec un FortiAnalyzer", ("SYS-FORTIANALYZER-SYNC-001",)
            ),
            V1DocumentSlot(
                "3.2.4",
                "Durcissement accès administration à votre Fortigate",
                ("NET-WAN-MGMT-001",),
            ),
            V1DocumentSlot("3.2.5", "Compte 'Admin' par défaut", ("IAM-DEFAULT-ADMIN-001",)),
            V1DocumentSlot(
                "3.2.6",
                "MFA pour les comptes admins et utilisateurs",
                ("IAM-ADMIN-MFA-001", "IAM-LOCAL-USER-MFA-001"),
            ),
        ),
    ),
    V1DocumentSection(
        "3.3",
        "Audit - Réseaux et flux",
        (
            V1DocumentSlot("3.3.1", "Règles en 'By Sequence'", ("FW-BY-SEQUENCE-USAGE-001",)),
            V1DocumentSlot(
                "3.3.2", "Logs sur la règle implicit deny", ("FW-IMPLICIT-DENY-LOG-001",)
            ),
            V1DocumentSlot("3.3.3", "Utilisation du SD-WAN", ("NET-SDWAN-USAGE-001",)),
            V1DocumentSlot(
                "3.3.4", "Blocage des ISDB malveillants", ("NET-ISDB-WAN-001",), "typed", "isdb.png"
            ),
            V1DocumentSlot(
                "3.3.5", "Filtrage des ports vers Internet", ("FW-INTERNET-ALL-SERVICE-001",)
            ),
            V1DocumentSlot("3.3.6", "Absence de VIP en ANY", ("FW-VIP-EXTINTF-ANY-001",)),
            V1DocumentSlot(
                "3.3.7", "Absence de Virtual Server en ANY", ("FW-VSERVER-EXTINTF-ANY-001",)
            ),
            V1DocumentSlot("3.3.8", "Utilisation de la GEO-IP", ("NET-GEO-IP-USAGE-001",)),
            V1DocumentSlot(
                "3.3.9", "Utilisation de nos CTI", ("NET-CTI-WAN-001",), "typed", "cti.png"
            ),
            V1DocumentSlot(
                "3.3.10", "Logs en UTM sans profil de sécurité", ("FW-UTM-PROFILE-BINDING-001",)
            ),
            V1DocumentSlot(
                "3.3.11", "Route Blackhole pour les réseaux privés", ("NET-RFC6890-BLACKHOLE-001",)
            ),
            V1DocumentSlot(
                "3.3.12", "Ports-Deny vers Internet", ("FW-SENSITIVE-PROTOCOL-DENY-001",)
            ),
            V1DocumentSlot("3.3.13", "Utilisation du LDAPS", ("IAM-LDAPS-001",)),
        ),
    ),
    V1DocumentSection(
        "3.4",
        "Audit - Connexions distantes : VPN",
        (
            V1DocumentSlot("3.4.1", "Utilisation du VPN SSL", ("VPN-SSL-001",)),
            V1DocumentSlot(
                "3.4.2", "Durcissement des VPN IPSEC : contrôle IKE", ("VPN-IKEV2-001",)
            ),
            V1DocumentSlot(
                "3.4.3", "Durcissement des VPN IPSEC : contrôle DH Group", ("VPN-DH-001",)
            ),
            V1DocumentSlot(
                "3.4.4", "Durcissement des VPN IPSEC : ESP et algorithmes", ("VPN-CRYPTO-001",)
            ),
        ),
    ),
    V1DocumentSection(
        "3.5",
        "Audit - Profils de sécurité UTM",
        (
            V1DocumentSlot("3.5.1", "Vérification de la licence UTM", ("UTM-LICENSE-001",)),
            V1DocumentSlot("3.5.2", "Mises à jour FortiGuard", ("UTM-AUTOUPDATE-001",)),
            V1DocumentSlot("3.5.3", "FortiSandbox Cloud", ("UTM-FORTISANDBOX-CLOUD-001",)),
            V1DocumentSlot(
                "3.5.4",
                "Utilisation du DNS-Filter",
                ("UTM-DNSFILTER-001",),
                "finding",
                "security_profiles.png",
            ),
            V1DocumentSlot("3.5.5", "Utilisation du Web-Filter", ("UTM-WEBFILTER-001",)),
            V1DocumentSlot("3.5.6", "Utilisation de l'Antivirus", ("UTM-ANTIVIRUS-001",)),
            V1DocumentSlot("3.5.7", "Utilisation de l'IPS", ("UTM-IPS-001",)),
            V1DocumentSlot(
                "3.5.8", "Utilisation de l'Application Control", ("UTM-APPCONTROL-001",)
            ),
        ),
    ),
)

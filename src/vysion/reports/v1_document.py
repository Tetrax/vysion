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


V1_DOCUMENT_SECTIONS = (
    V1DocumentSection(
        "3.1",
        "Audit - Système",
        (
            V1DocumentSlot("3.1.1", "Version Fortigate", ("EXT-PSIRT-001",), "version"),
            V1DocumentSlot("3.1.2", "Modèle Fortigate", (), "model"),
            V1DocumentSlot(
                "3.1.3",
                "Sauvegardes automatiques des révisions FortiGate",
                ("SYS-BACKUP-AUTO-001",),
            ),
            V1DocumentSlot("3.1.4", "Objets sans référence", ("CFG-UNUSED-SERVICE-001",)),
            V1DocumentSlot(
                "3.1.5", "Auto-installation USB FortiGate", ("SYS-AUTO-INSTALL-USB-001",)
            ),
            V1DocumentSlot("3.1.6", "Synchronisation FortiManager", ("SYS-FORTIMANAGER-SYNC-001",)),
            V1DocumentSlot(
                "3.1.7", "Synchronisation FortiAnalyzer", ("SYS-FORTIANALYZER-SYNC-001",)
            ),
            V1DocumentSlot(
                "3.1.8", "Port HTTPS d'administration personnalisé", ("SYS-ADMIN-HTTPS-PORT-001",)
            ),
            V1DocumentSlot(
                "3.1.9",
                "Inventaire des schedules de policies",
                ("FW-LEGACY-SCHEDULE-INVENTORY-001",),
            ),
        ),
    ),
    V1DocumentSection(
        "3.2",
        "Audit - Administration et comptes",
        (
            V1DocumentSlot(
                "3.2.1", "Protocoles d'administration sur interfaces WAN", ("NET-WAN-MGMT-001",)
            ),
            V1DocumentSlot(
                "3.2.2", "MFA des administrateurs", ("IAM-ADMIN-MFA-001", "IAM-LOCAL-USER-MFA-001")
            ),
            V1DocumentSlot(
                "3.2.3", "Absence du compte administrateur par défaut", ("IAM-DEFAULT-ADMIN-001",)
            ),
            V1DocumentSlot("3.2.4", "Absence du compte guest", ("IAM-GUEST-ACCOUNT-001",)),
            V1DocumentSlot("3.2.5", "Comptes historiques SNS/PKI", (), "group"),
            V1DocumentSlot(
                "3.2.6", "Suppression compte PKI historique", ("IAM-LEGACY-PKI-REMOVAL-001",)
            ),
            V1DocumentSlot("3.2.7", "Présence compte PKI géré", ("IAM-LEGACY-PKI-PRESENCE-001",)),
            V1DocumentSlot(
                "3.2.8",
                "Accès administration historique via loopback",
                ("NET-LEGACY-ADMIN-LOOPBACK-001",),
            ),
            V1DocumentSlot("3.2.9", "Entrée DNS database historique", ("DNS-LEGACY-DATABASE-001",)),
            V1DocumentSlot(
                "3.2.10",
                "Présence d'un compte administrateur local pour SNS",
                ("IAM-LEGACY-ADMIN-001",),
            ),
        ),
    ),
    V1DocumentSection(
        "3.3",
        "Audit - Réseaux et flux",
        (
            V1DocumentSlot(
                "3.3.1", "Journalisation du deny implicite", ("FW-IMPLICIT-DENY-LOG-001",)
            ),
            V1DocumentSlot("3.3.2", "Services ALL vers Internet", ("FW-INTERNET-ALL-SERVICE-001",)),
            V1DocumentSlot("3.3.2.1", "Absence de VIP en ANY", ("FW-VIP-EXTINTF-ANY-001",)),
            V1DocumentSlot(
                "3.3.2.2", "Absence de Virtual Server en ANY", ("FW-VSERVER-EXTINTF-ANY-001",)
            ),
            V1DocumentSlot(
                "3.3.3",
                "Refus explicite des protocoles sensibles",
                (),
                "cross_reference",
                note="Voir Ports-Deny vers Internet.",
            ),
            V1DocumentSlot("3.3.4", "Désactivation SIP ALG", ("NET-SIP-ALG-001",)),
            V1DocumentSlot(
                "3.3.5",
                "Utilisation du SD-WAN pour les WAN sélectionnées",
                ("NET-SDWAN-USAGE-001",),
            ),
            V1DocumentSlot(
                "3.3.6", "Usage des politiques par séquence", ("FW-BY-SEQUENCE-USAGE-001",)
            ),
            V1DocumentSlot("3.3.7", "Utilisation du filtrage Geo-IP", ("NET-GEO-IP-USAGE-001",)),
            V1DocumentSlot("3.3.8", "Route blackhole RFC6890", ("NET-RFC6890-BLACKHOLE-001",)),
            V1DocumentSlot(
                "3.3.9", "Utilisation des CTI", ("NET-CTI-WAN-001",), "typed", "cti.png"
            ),
            V1DocumentSlot("3.3.10", "Logs en UTM présents", ("FW-UTM-PROFILE-BINDING-001",)),
            V1DocumentSlot(
                "3.3.11", "Blocage ISDB malveillant", ("NET-ISDB-WAN-001",), "typed", "isdb.png"
            ),
            V1DocumentSlot(
                "3.3.12", "Ports-Deny vers Internet", ("FW-SENSITIVE-PROTOCOL-DENY-001",)
            ),
            V1DocumentSlot("3.3.13", "Utilisation du LDAPS", ("IAM-LDAPS-001",)),
        ),
    ),
    V1DocumentSection(
        "3.4",
        "Audit - Cluster",
        (
            V1DocumentSlot(
                "3.4.1",
                "Conservation des sessions lors du basculement HA",
                ("HA-SESSION-PICKUP-001",),
            ),
            V1DocumentSlot(
                "3.4.2", "Redondance des interfaces heartbeat HA", ("HA-HEARTBEAT-REDUNDANCY-001",)
            ),
            V1DocumentSlot("3.4.3", "Politique override du cluster HA", ("HA-OVERRIDE-001",)),
            V1DocumentSlot(
                "3.4.4",
                "Redondance physique du câblage HA",
                ("HA-CABLING-REDUNDANCY-001",),
                "finding",
                "cluster.png",
            ),
        ),
    ),
    V1DocumentSection(
        "3.5",
        "Audit - Connexions distantes VPN",
        (
            V1DocumentSlot("3.5.1", "Utilisation du VPN SSL", ("VPN-SSL-001",)),
            V1DocumentSlot(
                "3.5.2", "Durcissement des VPN IPSEC : contrôle IKE", ("VPN-IKEV2-001",)
            ),
            V1DocumentSlot(
                "3.5.3", "Durcissement des VPN IPSEC : contrôle DH Group", ("VPN-DH-001",)
            ),
            V1DocumentSlot(
                "3.5.4", "Durcissement des VPN IPSEC : ESP et algorithmes", ("VPN-CRYPTO-001",)
            ),
        ),
    ),
    V1DocumentSection(
        "3.6",
        "Audit - Profils de sécurité UTM",
        (
            V1DocumentSlot("3.6.1", "Licence UTM", ("UTM-LICENSE-001",)),
            V1DocumentSlot("3.6.2", "Mises à jour AV/IPS", ("UTM-AUTOUPDATE-001",)),
            V1DocumentSlot(
                "3.6.3", "DNS Filter", ("UTM-DNSFILTER-001",), "finding", "security_profiles.png"
            ),
            V1DocumentSlot("3.6.4", "WebFilter", ("UTM-WEBFILTER-001",)),
            V1DocumentSlot("3.6.5", "Antivirus", ("UTM-ANTIVIRUS-001",)),
            V1DocumentSlot("3.6.6", "IPS", ("UTM-IPS-001",)),
            V1DocumentSlot("3.6.7", "Application Control", ("UTM-APPCONTROL-001",)),
            V1DocumentSlot("3.6.8", "FortiSandbox Cloud", ("UTM-FORTISANDBOX-CLOUD-001",)),
            V1DocumentSlot("3.6.9", "FortiGuard Anycast", ("UTM-FORTIGUARD-ANYCAST-001",)),
            V1DocumentSlot("3.6.10", "Mail Filter", ("UTM-MAIL-FILTER-USAGE-001",)),
            V1DocumentSlot(
                "3.6.11", "Inspection SSL/SSH - Probe Failure", ("FW-SSL-SSH-PROFILE-001",)
            ),
        ),
    ),
    V1DocumentSection(
        "3.7",
        "Audit - WIFI",
        (
            V1DocumentSlot("3.7.1", "Modèle de FAP", ("WIFI-FORTIAP-OBSOLETE-001",)),
            V1DocumentSlot("3.7.2", "Nombre de SSID par profil WIFI", ("WIFI-SSID-LIMIT-001",)),
            V1DocumentSlot("3.7.3", "Utilisation de la bande 5GHz", ("WIFI-RADIO2-40MHZ-001",)),
            V1DocumentSlot("3.7.4", "Option 'Radio Resource Provision'", ("WIFI-DARRP-001",)),
            V1DocumentSlot("3.7.5", "Option 'Frequency Handoff'", ("WIFI-FREQUENCY-HANDOFF-001",)),
            V1DocumentSlot("3.7.6", "Option 'TIM'", ("WIFI-TIM-001",)),
            V1DocumentSlot("3.7.7", "Conformité des canaux radio utilisés", ("WIFI-CHANNELS-001",)),
            V1DocumentSlot(
                "3.7.8", "Conformité des bandes radio utilisées (802.11)", ("WIFI-BAND-001",)
            ),
            V1DocumentSlot(
                "3.7.9", "Option Short Guard Interval", ("WIFI-SHORT-GUARD-INTERVAL-001",)
            ),
        ),
    ),
)

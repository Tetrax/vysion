# Matrice de restitution V1/V2

Cette matrice est la référence de comparaison client. Le moteur conserve ses contrôles internes et leurs `control_id`; la couche de restitution expose les titres V1, l'ordre documentaire V1 et explique les écarts de cardinalité.

## Périmètre

- Points métier V1 comparables : **57**.
- Findings internes V2 exécutés : **60**.
- Capacités V1 enregistrées : **53**, produisant **56** findings V2.
- Sous-vérifications supplémentaires issues des splits V1 : **3**.
- Contrôles complémentaires V2-only : **4**.
- Capacités V1 typed hors registre : **2** ; projections de données : **2**.
- EOL et hit counts restent hors périmètre de la gate (`BLOCKED_EXTERNAL_SOURCE` / `BLOCKED_RUNTIME_DATA`).

## Matrice métier

| # | Contrôle V1 / libellé métier | Contrôle(s) V2 correspondant(s) | Relation | Classification | Résultat de présentation |
|---:|---|---|---|---|---|
| 1 | Absence de VIP en ANY | `FW-VIP-EXTINTF-ANY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 2 | Absence de Virtual Server en ANY | `FW-VSERVER-EXTINTF-ANY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 3 | Règles en 'By Sequence' | `FW-BY-SEQUENCE-USAGE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 4 | Objets sans référence | `CFG-UNUSED-SERVICE-001` | `narrowed` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 5 | Absence du compte guest | `IAM-GUEST-ACCOUNT-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 6 | Absence du compte administrateur par défaut | `IAM-DEFAULT-ADMIN-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 7 | Utilisation du VPN SSL | `VPN-SSL-001` | `equivalent` | `SEMANTIC_EQUIVALENT` | agrégé depuis les findings V2 |
| 8 | Services ALL vers Internet | `FW-INTERNET-ALL-SERVICE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 9 | Utilisation de la GEO-IP | `NET-GEO-IP-USAGE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 10 | Logs sur la règle implicit deny | `FW-IMPLICIT-DENY-LOG-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 12 | Auto-installation USB FortiGate | `SYS-AUTO-INSTALL-USB-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 13 | Blocage des ISDB malveillants | `NET-ISDB-WAN-001` | `implementation_not_registered` | `EXACT_MATCH` | implémentation typée hors registre |
| 14 | Protocoles d'administration sur interfaces WAN | `NET-WAN-MGMT-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 15 | Présence d'un compte administrateur local pour SNS | `IAM-LEGACY-ADMIN-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 16 | Suppression compte PKI historique | `IAM-LEGACY-PKI-REMOVAL-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 17 | Présence compte PKI géré | `IAM-LEGACY-PKI-PRESENCE-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 18 | Synchronisation FortiAnalyzer | `SYS-FORTIANALYZER-SYNC-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 19 | Synchronisation FortiManager | `SYS-FORTIMANAGER-SYNC-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 20 | MFA des administrateurs | `IAM-ADMIN-MFA-001, IAM-LOCAL-USER-MFA-001` | `split` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 21 | Durcissement des VPN IPSEC | `VPN-IKEV2-001, VPN-DH-001, VPN-CRYPTO-001` | `split` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 22 | Utilisation de nos CTI | `NET-CTI-WAN-001` | `implementation_not_registered` | `EXACT_MATCH` | implémentation typée hors registre |
| 23 | Utilisation du LDAPS | `IAM-LDAPS-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 24 | Sauvegardes automatiques des révisions FortiGate | `SYS-BACKUP-AUTO-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 25 | Accès administration historique via loopback | `NET-LEGACY-ADMIN-LOOPBACK-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 26 | Entrée DNS database historique | `DNS-LEGACY-DATABASE-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 27 | Désactivation SIP ALG | `NET-SIP-ALG-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 28 | FortiSandbox Cloud | `UTM-FORTISANDBOX-CLOUD-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 29 | FortiGuard Anycast | `UTM-FORTIGUARD-ANYCAST-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 30 | Mises à jour AV/IPS | `UTM-AUTOUPDATE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 31 | Route blackhole RFC6890 | `NET-RFC6890-BLACKHOLE-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 32 | Redondance physique du câblage HA | `HA-CABLING-REDUNDANCY-001` | `operator_context` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 33 | Conservation des sessions lors du basculement HA | `HA-SESSION-PICKUP-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 34 | Redondance des interfaces heartbeat HA | `HA-HEARTBEAT-REDUNDANCY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 35 | Politique override du cluster HA | `HA-OVERRIDE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 36 | Ports-Deny vers Internet | `FW-SENSITIVE-PROTOCOL-DENY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 37 | Utilisation du SD-WAN pour les WAN sélectionnées | `NET-SDWAN-USAGE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 38 | Logs en UTM sans profil de sécurité | `FW-UTM-PROFILE-BINDING-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 39 | Mail Filter | `UTM-MAIL-FILTER-USAGE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 40 | WebFilter | `UTM-WEBFILTER-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 41 | Antivirus | `UTM-ANTIVIRUS-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 42 | DNS Filter | `UTM-DNSFILTER-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 43 | IPS | `UTM-IPS-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 44 | Application Control | `UTM-APPCONTROL-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 45 | Port HTTPS d'administration personnalisé | `SYS-ADMIN-HTTPS-PORT-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 46 | Modèle de FAP | `WIFI-FORTIAP-OBSOLETE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 47 | Nombre de SSID par profil WIFI | `WIFI-SSID-LIMIT-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 48 | Utilisation de la bande 5GHz | `WIFI-RADIO2-40MHZ-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 49 | Option 'Radio Resource Provision' | `WIFI-DARRP-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 50 | Option 'Frequency Handoff' | `WIFI-FREQUENCY-HANDOFF-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 51 | Option 'TIM' | `WIFI-TIM-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 53 | Utilisateurs et administrateurs | `FortiGateConfiguration.administrators -> JSON/XLSX` | `projection` | `EXACT_MATCH` | projection de données |
| 54 | Répartition des règles actives et désactivées | `policy statistics in canonical report` | `projection` | `EXACT_MATCH` | projection de données |
| 55 | Inventaire des schedules de policies | `FW-LEGACY-SCHEDULE-INVENTORY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 56 | Inspection SSL/SSH - Probe Failure | `FW-SSL-SSH-PROFILE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 57 | Conformité des bandes radio utilisées (802.11) | `WIFI-BAND-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 58 | Conformité des canaux radio utilisés | `WIFI-CHANNELS-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 59 | Option Short Guard Interval | `WIFI-SHORT-GUARD-INTERVAL-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |

## Contrôles complémentaires V2-only

| Contrôle interne | Libellé présenté | Motif |
|---|---|---|
| `SYS-HOSTNAME-001` | Hostname FortiGate | V1 extracted hostname for reports but did not count it as one of the 59 business checks. |
| `UTM-LICENSE-001` | Licence UTM | V2 makes operator-provided UTM licence proof explicit rather than hiding it in a GUI boolean. |
| `EXT-PSIRT-001` | Version Fortigate | V2 separates FortiOS PSIRT correlation from EOL; it is not an EOL substitute. |
| `CFG-REF-INTEGRITY-001` | Intégrité des références de configuration | V2 structural fail-closed integrity control added for typed reference recovery. |

## Lecture comparative

Un audit historique reste lisible comme **57 points métier V1**. Vysion 2.7 conserve **60 contrôles moteur** : les sous-vérifications détaillent les points V1 concernés et les contrôles V2-only restent séparés. Aucun contrôle interne n’est supprimé.

## Ordre DOCX V1

Le DOCX applique l’ordre client V1 numéroté `3.1` à `3.7`, conserve le VPN SSL même lorsqu’il est non applicable, et reprend les schémas V1 HA, CTI, ISDB et profils UTM.

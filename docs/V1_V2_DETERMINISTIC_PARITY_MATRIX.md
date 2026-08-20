# Matrice de restitution V1/V2

Cette matrice est la référence de comparaison client. Le moteur conserve ses contrôles internes et leurs `control_id`; la couche de restitution expose le libellé métier V1 et explique les écarts de cardinalité.

## Périmètre

- Points métier V1 comparables : **57**.
- Findings internes V2 exécutés : **60**.
- Capacités V1 enregistrées : **53**, produisant **56** findings V2.
- Sous-vérifications supplémentaires issues des splits V1 : **3**.
- Contrôles complémentaires V2-only : **4**.
- Capacités V1 typed hors registre : **2** ; projections de données : **2**.
- Les capacités EOL et hit counts restent hors périmètre de cette matrice comparable (`BLOCKED_EXTERNAL_SOURCE` / `BLOCKED_RUNTIME_DATA`).

## Matrice métier

| # | Contrôle V1 / libellé métier | Contrôle(s) V2 correspondant(s) | Relation | Classification | Résultat de présentation |
|---:|---|---|---|---|---|
| 1 | Contrôle absence de VIP avec any en interface | `FW-VIP-EXTINTF-ANY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 2 | Contrôle absence de Virtual Server avec any en interface | `FW-VSERVER-EXTINTF-ANY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 3 | Utilisation des règles en 'By Sequence' | `FW-BY-SEQUENCE-USAGE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 4 | Absence d'objet sans référence | `CFG-UNUSED-SERVICE-001` | `narrowed` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 5 | Contrôle de la suppression du compte local 'Guest' | `IAM-GUEST-ACCOUNT-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 6 | Contrôle de la suppression du compte 'Admin' | `IAM-DEFAULT-ADMIN-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 7 | Contrôle de la non-utilisation du VPN-SSL | `VPN-SSL-001` | `equivalent` | `SEMANTIC_EQUIVALENT` | agrégé depuis les findings V2 |
| 8 | Filtrage des ports au strict minimum pour les flux vers Internet | `FW-INTERNET-ALL-SERVICE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 9 | Filtrage des IP en fonction de leur pays d'origine | `NET-GEO-IP-USAGE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 10 | Activation des logs sur la règle 'deny implicit' | `FW-IMPLICIT-DENY-LOG-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 12 | Contrôle désactivation USB | `SYS-AUTO-INSTALL-USB-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 13 | Utilisation des listes d'ISDB malveillantes | `NET-ISDB-WAN-001` | `implementation_not_registered` | `EXACT_MATCH` | implémentation typée hors registre |
| 14 | Désactivation du SSH, HTTP et HTTPS sur les interfaces WAN | `NET-WAN-MGMT-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 15 | Contrôle de la présence d'un compte administrateur local pour SNS | `IAM-LEGACY-ADMIN-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 16 | Contrôle de la suppression du compte PKI 'sns' | `IAM-LEGACY-PKI-REMOVAL-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 17 | Contrôle de la présence du compte PKI 'pki-sns' | `IAM-LEGACY-PKI-PRESENCE-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 18 | Synchronisation des logs avec un FortiAnalyzer | `SYS-FORTIANALYZER-SYNC-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 19 | Synchronisation avec un FortiManager | `SYS-FORTIMANAGER-SYNC-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 20 | Vérification de la présence de MFA sur les comptes locaux administrateurs et utilisateurs | `IAM-ADMIN-MFA-001, IAM-LOCAL-USER-MFA-001` | `split` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 21 | Durcissement des VPN IPSEC | `VPN-IKEV2-001, VPN-DH-001, VPN-CRYPTO-001` | `split` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 22 | Utilisation de nos CTI | `NET-CTI-WAN-001` | `implementation_not_registered` | `EXACT_MATCH` | implémentation typée hors registre |
| 23 | Connecteur LDAPS | `IAM-LDAPS-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 24 | Sauvegardes automatiques de la configuration | `SYS-BACKUP-AUTO-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 25 | Durcissement accès administration à votre FGT | `NET-LEGACY-ADMIN-LOOPBACK-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 26 | DNS Database SNS | `DNS-LEGACY-DATABASE-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 27 | Désactivation du SIP ALG | `NET-SIP-ALG-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 28 | Configuration FortiSandbox Cloud | `UTM-FORTISANDBOX-CLOUD-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 29 | Désactivation des requêtes anycast vers FortiGuard | `UTM-FORTIGUARD-ANYCAST-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 30 | FortiGuard - Mises à jour automatiques des bases AV + IPS | `UTM-AUTOUPDATE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 31 | Route Blackhole pour les réseaux privés | `NET-RFC6890-BLACKHOLE-001` | `parameterized` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 32 | Redondance du câblage entre les FortiGate (HA) | `HA-CABLING-REDUNDANCY-001` | `operator_context` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 33 | Activer le session pickup | `HA-SESSION-PICKUP-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 34 | Redondance des interfaces de HA (Heartbeat) | `HA-HEARTBEAT-REDUNDANCY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 35 | Override à 30 secondes ou désactivé | `HA-OVERRIDE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 36 | Blocage de certains ports pour les flux vers Internet : KERBEROS, LDAP, LDAPS, RADIUS, SAMBA, SMB | `FW-SENSITIVE-PROTOCOL-DENY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 37 | Utilisation du SD-WAN | `NET-SDWAN-USAGE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 38 | Absence de règles avec logs en UTM sans profils de sécurité activés | `FW-UTM-PROFILE-BINDING-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 39 | Eviter le Mail Filter | `UTM-MAIL-FILTER-USAGE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 40 | Utilisation du Web-Filter | `UTM-WEBFILTER-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 41 | Utilisation de l'Antivirus | `UTM-ANTIVIRUS-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 42 | Utilisation du DNS-Filter | `UTM-DNSFILTER-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 43 | Utilisation de l'IPS | `UTM-IPS-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 44 | Blocage Proxy, P2P et Remote access via l'Application Control | `UTM-APPCONTROL-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 45 | Personnalisation du port HTTPS pour l'accès admin | `SYS-ADMIN-HTTPS-PORT-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 46 | Modèle de FortiAP - Prévention de l'obsolescence | `WIFI-FORTIAP-OBSOLETE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 47 | Nombre de SSID par profil WIFI | `WIFI-SSID-LIMIT-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 48 | Utilisation de la bande 5GHz sur le canal 40MHz | `WIFI-RADIO2-40MHZ-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 49 | Activation de l'option 'Radio Resource Provision' | `WIFI-DARRP-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 50 | Activation de l'option 'Frequency Handoff' | `WIFI-FREQUENCY-HANDOFF-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 51 | Activation de l'option 'TIM' | `WIFI-TIM-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 53 | Utilisateurs et administrateurs | `FortiGateConfiguration.administrators -> JSON/XLSX` | `projection` | `EXACT_MATCH` | projection de données |
| 54 | Répartition des règles actives et désactivées | `policy statistics in canonical report` | `projection` | `EXACT_MATCH` | projection de données |
| 55 | Inventaire des schedules de policies | `FW-LEGACY-SCHEDULE-INVENTORY-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 56 | Inspection SSL/SSH - Probe Failure | `FW-SSL-SSH-PROFILE-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 57 | Conformité des bandes radio utilisées (802.11) | `WIFI-BAND-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 58 | Conformité des canaux radio utilisés | `WIFI-CHANNELS-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |
| 59 | Activation de l'option Short Guard Interval | `WIFI-SHORT-GUARD-INTERVAL-001` | `equivalent` | `EXACT_MATCH` | agrégé depuis les findings V2 |

## Contrôles complémentaires V2-only

| Contrôle interne | Libellé présenté | Motif |
|---|---|---|
| `SYS-HOSTNAME-001` | Identification du FortiGate | V1 extracted hostname for reports but did not count it as one of the 59 business checks. |
| `UTM-LICENSE-001` | Vérification de la licence UTM | V2 makes operator-provided UTM licence proof explicit rather than hiding it in a GUI boolean. |
| `EXT-PSIRT-001` | Vérification FortiGuard PSIRT | V2 separates FortiOS PSIRT correlation from EOL; it is not an EOL substitute. |
| `CFG-REF-INTEGRITY-001` | Intégrité des références de configuration | V2 structural fail-closed integrity control added for typed reference recovery. |

## Lecture comparative

Un audit historique peut donc être présenté comme **57 points métier V1**. Un audit V2 conserve **60 contrôles moteur** : les 3 lignes supplémentaires sont des sous-vérifications nécessaires à deux points V1, et les 4 contrôles V2-only sont présentés séparément. Aucun contrôle interne n’est supprimé pour obtenir ce rapprochement.

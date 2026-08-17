# Vysion v2.3 — Functional Parity V1

> Matrice de pilotage de la récupération de valeur métier V1 dans l’architecture typée V2.
> V1 est l’oracle fonctionnel ; V2 reste la frontière technique et de preuve.

## État de référence figé

- Checkout : `/home/tetrax/workspace/vysion/vysion-v2`
- Branche : `feat/v2.2-business-ux`
- HEAD de base : `d3a83c3b2cd0a74014adf3f6d187624c4e54ba8d`
- V1 oracle read-only : `/home/tetrax/workspace/vysion/audit-fgt-vysion`
- Fonction oracle : `backend/app/audit/legacy_functions.py::auditer`
- Extraction déterministe : **59 appels métier distincts**, vérifiés par AST Python 3.12
- Registre V2 observé : **31 contrôles**, préfixe historique stable, aucun `ENGINE-*`
- V1 `legacy_functions.py` n’est pas parsable par Python 3.11 à cause d’une f-string PEP 701 ; Python 3.12.3 l’analyse correctement. Aucun code V1 n’est exécuté dans cette comparaison.
- V2 possède au démarrage cinq fichiers P1 non committés, conservés hors de cette migration :
  - `src/vysion/audit/controls/_evidence.py`
  - `src/vysion/audit/controls/references.py`
  - `src/vysion/audit/firewall_projection.py`
  - `src/vysion/audit/parser.py`
  - `tests/unit/test_reference_integrity.py`
- Le service déjà présent sur `127.0.0.1:8000` est hors périmètre et n’a pas été démarré ni modifié.

## Légende de l’inventaire A/B/C

- **A — équivalent** : une capacité V2 enregistrée couvre déjà le comportement métier principal V1 ; le replay de parité reste à confirmer pour le statut et les détails de preuve.
- **B — partiel** : une projection ou un contrôle V2 couvre une partie du comportement, mais il manque une règle, une donnée opérateur, une restitution ou une branche V1.
- **C — absent** : aucun chemin V2 exécutable équivalent n’a été identifié.

Ces catégories sont l’inventaire initial. Elles deviennent ensuite : `MIGRATED`, `BLOCKED_EXTERNAL_SOURCE` ou `LEGACY_REVIEW_REQUIRED` uniquement après replay et preuve d’exécution.

## Matrice exhaustive des 59 capacités V1

| # | Domaine | Fonction V1 appelée par `auditer()` | V2 actuel | Couverture V2 / cible | Note de parité |
|---:|---|---|:---:|---|---|
| 1 | Réseau / firewall | `verifier_vips_extintf_any` | A | `FW-VIP-EXTINTF-ANY-001` | Même détection d’exposition `extintf any`, à rejouer sur fixture V1. |
| 2 | Réseau / firewall | `verifier_vs_extintf_any` | A | `FW-VSERVER-EXTINTF-ANY-001` | Même détection pour virtual servers. |
| 3 | Réseau / firewall | `verifier_usage_by_sequence` | C | Nouveau contrôle de séquence/règle | Comptage/ordre historique absent du registre V2. |
| 4 | Réseau / objets | `detecter_objets_non_utilises` | C | Projection objets + contrôle orphelins | V2 possède des résolutions de références, pas la restitution legacy complète des objets inutilisés. |
| 5 | Système / administration | `verifier_compte_guest` | A | `IAM-GUEST-ACCOUNT-001` | Absence du compte guest. |
| 6 | Système / administration | `verifier_compte_admin` | A | `IAM-DEFAULT-ADMIN-001` | Absence du compte administrateur par défaut. |
| 7 | VPN | `verifier_vpn_ssl_utilisation` | A | `VPN-SSL-001` | État/usage SSL-VPN typé. |
| 8 | Réseau / firewall | `verifier_presence_all_port_dans_regles` | C | Nouveau contrôle de couverture des ports ALL | La couverture de services V2 ne reproduit pas encore cette règle legacy. |
| 9 | Réseau / firewall | `verifier_utilisation_geo_ip` | C | Nouveau contrôle Geo-IP | Aucun équivalent V2 identifié. |
| 10 | Réseau / firewall | `verifier_logs_deny_implicit` | A | `FW-IMPLICIT-DENY-LOG-001` | Journalisation du deny implicite. |
| 11 | Système / lifecycle | `verifier_modele_fortigate_eol` | C | Source/version EOL à définir | Ne pas confondre avec PSIRT ; dépendance externe éventuelle. |
| 12 | Système | `verifier_auto_install_usb` | A | `SYS-AUTO-INSTALL-USB-001` | Migré dans le premier tracer ; PASS exige les deux directives disable certaines. |
| 13 | Réseau / external services | `verifier_presence_isdb` | A | `NET-ISDB-WAN-001` | Blocage ISDB entrant/sortant sur flux WAN. |
| 14 | Réseau | `verifier_http_https_desactive_sur_interfaces_wan` | A | `NET-WAN-MGMT-001` | Accès d’administration sur interfaces WAN ; replay nécessaire pour confirmer SSH/HTTP/HTTPS. |
| 15 | Administration / identité | `verifier_compte_admin_[REDACTED]` | C | Contrôle compte admin historique + MFA métier | Règle historique spécifique, absente du registre V2. |
| 16 | Administration / identité | `verifier_suppression_compte_pki_[REDACTED]` | C | Contrôle compte admin PKI historique | Règle historique spécifique, absente du registre V2. |
| 17 | Administration / identité | `verifier_presence_compte_pki_[REDACTED]` | C | Contrôle compte admin PKI historique | Règle historique spécifique, absente du registre V2. |
| 18 | Administration | `verifier_sync_fortianalyzer` | A | `SYS-FORTIANALYZER-SYNC-001` | Migré ; enable + serveur certain, disable explicite FAIL, absence UNKNOWN. |
| 19 | Administration | `verifier_sync_fortimanager` | A | `SYS-FORTIMANAGER-SYNC-001` | Migré ; type FortiManager + fmg certain, ou FortiGuard explicite. |
| 20 | Administration / identité | `verifier_mfa_utilisateurs_admins` | A | `IAM-ADMIN-MFA-001` + `IAM-LOCAL-USER-MFA-001` | Le chemin V2 sépare administrateurs et utilisateurs locaux. |
| 21 | VPN | `verifier_durcissement_vpn_ipsec_split` | B | `VPN-IKEV2-001`, `VPN-DH-001`, `VPN-CRYPTO-001` | Les trois contrôles V2 couvrent les branches principales ; comparer exactement les listes/messages legacy. |
| 22 | Réseau / external services | `verifier_presence_cti` | A | `NET-CTI-WAN-001` | Présence CTI sur les flux WAN. |
| 23 | Administration / identité | `verifier_ldaps` | A | `IAM-LDAPS-001` | LDAPS + certificat CA, avec statut absent/ambigu à aligner. |
| 24 | Système | `verifier_sauvegardes_automatiques` | A | `SYS-BACKUP-AUTO-001` | `revision-backup-on-logout` + `revision-image-auto-backup`. |
| 25 | Administration / réseau | `verifier_acces_admin_[REDACTED]_via_loopback` | C | Projection loopback/FQDN/VIP + contrôle historique | Règle métier historique absente. |
| 26 | Système / réseau | `verifier_dns_database` | C | Projection `system dns-database` | Entrée FQDN historique absente de V2. |
| 27 | Réseau / firewall | `verifier_sip_alg` | C | Projection session-helper/VoIP | Règle SIP ALG historique absente ; projection VoIP V2 à compléter. |
| 28 | UTM / external services | `verifier_fortisandbox_cloud` | C | Contrôle FortiSandbox Cloud | Dépend licence et région ; besoin d’AuditContext si non présent dans backup. |
| 29 | UTM / external services | `verifier_anycast_fortiguard` | C | Contrôle Anycast FortiGuard | Aucun équivalent V2 identifié. |
| 30 | UTM / external services | `verifier_mises_a_jour_fortiguard` | B | `UTM-AUTOUPDATE-001` | Proche des mises à jour AV/IPS, mais la portée FortiGuard legacy doit être comparée. |
| 31 | Réseau / firewall | `verifier_route_blackhole` | C | Projection routes + contexte MPLS/L2L | Dépend de `mpls_l2l`, aucun contrôle V2. |
| 32 | HA | `verifier_ha_redundance_cablage` | C | Projection HA + AuditContext | Nécessite l’observation opérateur `ha_cabling_redundancy`. |
| 33 | HA | `verifier_ha_session_pickup` | C | Projection HA/session-pickup | Aucun contrôle V2. |
| 34 | HA | `verifier_ha_redundance_interfaces` | C | Projection HA/heartbeat | Aucun contrôle V2. |
| 35 | HA | `verifier_ha_override` | C | Projection HA/override | Aucun contrôle V2. |
| 36 | Réseau / firewall | `verifier_ports_deny` | B | `FW-SENSITIVE-PROTOCOL-DENY-001` | Proximité sur les protocoles sensibles, mais couverture et portée des ports legacy à comparer. |
| 37 | Réseau | `verifier_utilisation_sdwan` | C | Projection SD-WAN + contrôle d’utilisation | Le parser/projection existe, aucun contrôle V2 enregistré. |
| 38 | Réseau / UTM | `verifier_profils_securite_sur_regles` | A | `FW-UTM-PROFILE-BINDING-001` | Liaison des profils utilisés sur les règles. |
| 39 | UTM | `verifier_mail_filter` | C | Projection mailfilter + contrôle | Aucun équivalent V2. |
| 40 | UTM | `verifier_webfilter_profiles` | A | `UTM-WEBFILTER-001` | Conformité des WebFilter utilisés. |
| 41 | UTM | `verifier_antivirus_profiles` | A | `UTM-ANTIVIRUS-001` | Conformité des profils Antivirus utilisés. |
| 42 | UTM | `verifier_dnsfilter_profiles` | A | `UTM-DNSFILTER-001` | Conformité des profils DNS Filter utilisés. |
| 43 | UTM | `verifier_ips_profiles` | A | `UTM-IPS-001` | Conformité des profils IPS utilisés. |
| 44 | UTM | `verifier_app_control_profiles` | A | `UTM-APPCONTROL-001` | Conformité des profils Application Control utilisés. |
| 45 | Système / administration | `verifier_port_https_admin` | A | `SYS-ADMIN-HTTPS-PORT-001` | Migré ; 443 explicite FAIL, port personnalisé certain PASS, absence/ambiguïté UNKNOWN. |
| 46 | Wi-Fi | `check_obsolete_fortiap_devices` | C | Projection wireless-controller WTP | Aucun support Wi-Fi V2. |
| 47 | Wi-Fi | `verifier_nombre_ssid_par_profil_wifi` | C | Projection Wi-Fi/SSID | Aucun support Wi-Fi V2. |
| 48 | Wi-Fi | `verifier_utilisation_bande_5ghz` | C | Projection Wi-Fi/radio | Aucun support Wi-Fi V2. |
| 49 | Wi-Fi | `verifier_darrp_enable` | C | Projection Wi-Fi/DARRP | Aucun support Wi-Fi V2. |
| 50 | Wi-Fi | `verifier_frequency_handoff` | C | Projection Wi-Fi/handoff | Aucun support Wi-Fi V2. |
| 51 | Wi-Fi | `verifier_tim_enable` | C | Projection Wi-Fi/TIM | Aucun support Wi-Fi V2. |
| 52 | Reporting / statistiques | `verifier_logs_par_regle` | C | Statistiques de logs par règle | Nécessite données de configuration/runtime séparées. |
| 53 | Reporting / inventaire | `exporter_utilisateurs_admins` | C | Inventaire administrateurs typé | V2 expose les findings mais pas encore cet inventaire dédié. |
| 54 | Reporting / statistiques | `compter_regles_activ_ou_desactiv` | C | Statistiques policies | Aucun équivalent V2. |
| 55 | Reporting / statistiques | `collect_schedule_data` | C | Statistiques schedules | Aucun équivalent V2. |
| 56 | Réseau / firewall | `verifier_ssl_ssh_profiles` | C | Projection SSL/SSH profiles | Aucun contrôle V2 dédié. |
| 57 | Wi-Fi | `verifier_band_conformite` | C | Projection Wi-Fi/bande | Aucun support Wi-Fi V2. |
| 58 | Wi-Fi | `verifier_channels_conformite` | C | Projection Wi-Fi/canaux | Aucun support Wi-Fi V2. |
| 59 | Wi-Fi | `verifier_short_guard_interval` | C | Projection Wi-Fi/SGI | Aucun support Wi-Fi V2. |

## Synthèse courante

- **A — équivalents identifiés : 22**
- **B — partiels identifiés : 3**
- **C — absents identifiés : 34**
- Total : **59 / 59**

Les comptes sont calculés sur la colonne `V2 actuel` et doivent rester reproductibles à partir de cette table. Une capacité A n’est pas encore déclarée `MIGRATED` tant qu’elle n’a pas été rejouée sur une configuration synthétique réaliste et comparée à la sortie V1 observable.

## Dispositions explicites du Lot A

| # | Capacité | Disposition | Justification |
|---:|---|---|---|
| 11 | Modèle FortiGate EOL | `BLOCKED_EXTERNAL_SOURCE` | La source Fortinet publique, versionnée et vérifiable n’est pas disponible dans ce checkout ; aucun EOL n’est spéculé. |
| 12 | Auto-install USB | `MIGRATED` | `SYS-AUTO-INSTALL-USB-001`, tests PASS/FAIL/UNKNOWN et replay moteur. |
| 15 | Compte admin historique | `LEGACY_REVIEW_REQUIRED` | La liste de comptes et l’adresse MFA historiques sont spécifiques ; la cible doit être fournie par l’opérateur, jamais codée en clair. |
| 16 | Suppression compte PKI historique | `LEGACY_REVIEW_REQUIRED` | Le nom de compte/groupe historique est spécifique ; politique opérateur requise. |
| 17 | Présence compte PKI historique | `LEGACY_REVIEW_REQUIRED` | Le nom de compte/groupe historique est spécifique ; politique opérateur requise. |
| 18 | Synchronisation FortiAnalyzer | `MIGRATED` | `SYS-FORTIANALYZER-SYNC-001`, sections classiques/cloud typées. |
| 19 | Synchronisation FortiManager | `MIGRATED` | `SYS-FORTIMANAGER-SYNC-001`, mode et serveur typés. |
| 25 | Accès admin historique via loopback | `LEGACY_REVIEW_REQUIRED` | Domaine/FQDN/VIP historique spécifique ; cible opérateur requise. |
| 26 | DNS database historique | `LEGACY_REVIEW_REQUIRED` | FQDN historique spécifique ; cible opérateur requise. |
| 45 | Port HTTPS admin | `MIGRATED` | `SYS-ADMIN-HTTPS-PORT-001`, 443 FAIL, port personnalisé PASS, preuve absente UNKNOWN. |

## Ordre de migration accélérée

1. **Lot A — Système / administration** : auto-install USB, central-management FortiManager/FortiAnalyzer, comptes historiques/PKI, admin-sport, loopback/DNS à cible opérateur, puis inventaire administrateurs.
2. **Lot B — Réseau / firewall / objets** : objets inutilisés, séquence, ALL/ports, Geo-IP, SIP ALG/VoIP, routes blackhole, SD-WAN utilisé, SSL/SSH profiles.
3. **Lot C — HA / VPN** : HA complet, puis parité fine des branches VPN déjà partiellement couvertes.
4. **Lot D — UTM** : FortiSandbox, Anycast, mail filter et parité FortiGuard/autoupdate.
5. **Lot E — Wi-Fi** : FortiAP, SSID, radio, DARRP, handoff, TIM, bandes, canaux, SGI.
6. **Lot F — Reporting / statistiques / inventaires** : logs, policies, schedules, administrateurs et restitution.

Chaque capacité migrée devra finalement porter un statut `MIGRATED`, `BLOCKED_EXTERNAL_SOURCE` ou `LEGACY_REVIEW_REQUIRED`, avec source V1, projection V2, test représentatif et replay de fixture.

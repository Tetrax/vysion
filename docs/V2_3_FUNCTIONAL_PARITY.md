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
- Registre V2 observé : **43 contrôles**, préfixe historique stable, aucun `ENGINE-*`
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
| 4 | Réseau / objets | `detecter_objets_non_utilises` | A | `CFG-UNUSED-SERVICE-001` | Restitution typed des services réellement orphelins ; la portée est volontairement bornée à la famille service custom/groupe/policy complète. |
| 5 | Système / administration | `verifier_compte_guest` | A | `IAM-GUEST-ACCOUNT-001` | Absence du compte guest. |
| 6 | Système / administration | `verifier_compte_admin` | A | `IAM-DEFAULT-ADMIN-001` | Absence du compte administrateur par défaut. |
| 7 | VPN | `verifier_vpn_ssl_utilisation` | A | `VPN-SSL-001` | État/usage SSL-VPN typé. |
| 8 | Réseau / firewall | `verifier_presence_all_port_dans_regles` | A | `FW-INTERNET-ALL-SERVICE-001` | ALL canonique sur policy accept/enable vers une WAN certaine ; deny/disable hors portée, service non résolu UNKNOWN. |
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
| 21 | VPN | `verifier_durcissement_vpn_ipsec_split` | A | `VPN-IKEV2-001`, `VPN-DH-001`, `VPN-CRYPTO-001` | Les trois branches legacy sont couvertes par des projections IPsec typées et un ruleset versionné. |
| 22 | Réseau / external services | `verifier_presence_cti` | A | `NET-CTI-WAN-001` | Présence CTI sur les flux WAN. |
| 23 | Administration / identité | `verifier_ldaps` | A | `IAM-LDAPS-001` | LDAPS + certificat CA, avec statut absent/ambigu à aligner. |
| 24 | Système | `verifier_sauvegardes_automatiques` | A | `SYS-BACKUP-AUTO-001` | `revision-backup-on-logout` + `revision-image-auto-backup`. |
| 25 | Administration / réseau | `verifier_acces_admin_[REDACTED]_via_loopback` | C | Projection loopback/FQDN/VIP + contrôle historique | Règle métier historique absente. |
| 26 | Système / réseau | `verifier_dns_database` | C | Projection `system dns-database` | Entrée FQDN historique absente de V2. |
| 27 | Réseau / firewall | `verifier_sip_alg` | A | `NET-SIP-ALG-001` | Migré ; helper SIP certain ou mode ALG explicite FAIL, preuve incomplète UNKNOWN. |
| 28 | UTM / external services | `verifier_fortisandbox_cloud` | A | `UTM-FORTISANDBOX-CLOUD-001` | Région Europe explicite + licence UTM opérateur sourcée ; absence UNKNOWN. |
| 29 | UTM / external services | `verifier_anycast_fortiguard` | A | `UTM-FORTIGUARD-ANYCAST-001` | `fortiguard-anycast disable` explicite, sans supposer le défaut. |
| 30 | UTM / external services | `verifier_mises_a_jour_fortiguard` | A | `UTM-AUTOUPDATE-001` | Statut/fréquence typés ; aucune conformité n’est déduite d’une section absente. |
| 31 | Réseau / firewall | `verifier_route_blackhole` | C | Projection routes + contexte MPLS/L2L | Dépend de `mpls_l2l`, aucun contrôle V2. |
| 32 | HA | `verifier_ha_redundance_cablage` | A | `HA-CABLING-REDUNDANCY-001` + AuditContext | Observation opérateur sourcée ; reste UNKNOWN quand le backup seul ne peut pas prouver le physique. |
| 33 | HA | `verifier_ha_session_pickup` | A | `HA-SESSION-PICKUP-001` | Les trois options legacy sont projetées et contrôlées sans raw-text. |
| 34 | HA | `verifier_ha_redundance_interfaces` | A | `HA-HEARTBEAT-REDUNDANCY-001` | `hbdev` est projeté avec validation des paires interface/priorité. |
| 35 | HA | `verifier_ha_override` | A | `HA-OVERRIDE-001` | `disable` ou `enable` avec attente exacte de 30 secondes reproduisent la règle legacy. |
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
| 53 | Reporting / inventaire | `exporter_utilisateurs_admins` | A | Inventaire administrateurs typé | Feuille Comptes XLSX et JSON canonique, sans secret d'authentification. |
| 54 | Reporting / statistiques | `compter_regles_activ_ou_desactiv` | A | Statistiques policies | Comptages total/enable/disable/inconnu depuis les policies typées. |
| 55 | Reporting / statistiques | `collect_schedule_data` | C | Statistiques schedules | Aucun équivalent V2. |
| 56 | Réseau / firewall | `verifier_ssl_ssh_profiles` | C | Projection SSL/SSH profiles | Aucun contrôle V2 dédié. |
| 57 | Wi-Fi | `verifier_band_conformite` | C | Projection Wi-Fi/bande | Aucun support Wi-Fi V2. |
| 58 | Wi-Fi | `verifier_channels_conformite` | C | Projection Wi-Fi/canaux | Aucun support Wi-Fi V2. |
| 59 | Wi-Fi | `verifier_short_guard_interval` | C | Projection Wi-Fi/SGI | Aucun support Wi-Fi V2. |

## Synthèse courante

- **A — équivalents identifiés : 35**
- **B — partiels identifiés : 1**
- **C — absents identifiés : 23**
- Total : **59 / 59**
- Disposition réellement `MIGRATED` : **39 / 59** (66,1 %)

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
| 27 | SIP ALG | `MIGRATED` | `NET-SIP-ALG-001`, absence du helper SIP et mode kernel-helper-based prouvés séparément. |
| 45 | Port HTTPS admin | `MIGRATED` | `SYS-ADMIN-HTTPS-PORT-001`, 443 FAIL, port personnalisé PASS, preuve absente UNKNOWN. |

### Capacités A héritées rejouées par la suite d'intégration

| # | Capacité | Disposition | Preuve V2 |
|---:|---|---|---|
| 1 | VIP exposée sur any | `MIGRATED` | `FW-VIP-EXTINTF-ANY-001`, projection VIP et tests PASS/FAIL/UNKNOWN. |
| 2 | Virtual server exposé sur any | `MIGRATED` | `FW-VSERVER-EXTINTF-ANY-001`, projection virtual server et replay moteur. |
| 5 | Compte guest | `MIGRATED` | `IAM-GUEST-ACCOUNT-001`, comptes locaux typés. |
| 6 | Compte admin par défaut | `MIGRATED` | `IAM-DEFAULT-ADMIN-001`, administrateurs typés. |
| 10 | Logs du deny implicite | `MIGRATED` | `FW-IMPLICIT-DENY-LOG-001`, directive structurée. |
| 13 | ISDB sur flux WAN | `MIGRATED` | `NET-ISDB-WAN-001`, relations policy/WAN typées. |
| 14 | Administration sur WAN | `MIGRATED` | `NET-WAN-MGMT-001`, sélection WAN et allowaccess structurés. |
| 20 | MFA administrateurs/utilisateurs | `MIGRATED` | `IAM-ADMIN-MFA-001` et `IAM-LOCAL-USER-MFA-001`. |
| 22 | CTI sur flux WAN | `MIGRATED` | `NET-CTI-WAN-001`, relations external-resource/WAN typées. |
| 23 | LDAPS | `MIGRATED` | `IAM-LDAPS-001`, statut et certificat CA structurés. |
| 24 | Sauvegardes automatiques | `MIGRATED` | `SYS-BACKUP-AUTO-001`, deux directives requises et fail-closed. |

## Dispositions explicites du Lot HA / VPN

| # | Capacité | Disposition | Justification |
|---:|---|---|---|
| 7 | Usage SSL-VPN | `MIGRATED` | `VPN-SSL-001` sépare désactivation certaine, usage explicite et preuve incomplète. |
| 21 | Durcissement IPsec | `MIGRATED` | IKEv2, DH et propositions sont projetés par phase et restitués dans trois findings stables. |
| 32 | Redondance du câblage HA | `MIGRATED` | `HA-CABLING-REDUNDANCY-001` consomme uniquement une observation opérateur sourcée ; sinon UNKNOWN. |
| 33 | Session pickup HA | `MIGRATED` | Les trois directives requises sont certaines pour PASS ; disable explicite produit FAIL. |
| 34 | Redondance heartbeat HA | `MIGRATED` | Deux interfaces certaines sont requises ; une interface certaine produit FAIL. |
| 35 | Override HA | `MIGRATED` | Règle legacy reproduite avec override désactivé ou attente exacte de 30 secondes. |

## Dispositions explicites du Lot UTM / Wi-Fi

| # | Capacité | Disposition | Justification |
|---:|---|---|---|
| 28 | FortiSandbox Cloud | `MIGRATED` | Région structurée, licence UTM et provenance opérateur sont requises pour PASS. |
| 29 | FortiGuard Anycast | `MIGRATED` | Valeur structurée explicite ; absence et valeur non canonique restent UNKNOWN. |
| 30 | Mises à jour FortiGuard | `MIGRATED` | Le contrôle autoupdate existant couvre statut et fréquence sans scanner le raw-text. |
| 38 | Profils UTM sur règles | `MIGRATED` | Relations policy → profil direct/groupe typées et contrôle enregistré. |
| 39 | Mail Filter | `MIGRATED` | `UTM-MAIL-FILTER-USAGE-001` reproduit la règle legacy : toute directive certaine `emailfilter-profile` dans une policy produit FAIL ; absence certaine PASS, namespace absent ou mutation UNKNOWN. |
| 40 | WebFilter | `MIGRATED` | Profils utilisés, catégories et relations de groupe sont projetés et contrôlés. |
| 41 | Antivirus | `MIGRATED` | Profils utilisés et réglages nécessaires sont projetés et contrôlés. |
| 42 | DNS Filter | `MIGRATED` | Profils utilisés, catégories et options sont projetés et contrôlés. |
| 43 | IPS | `MIGRATED` | Profils utilisés et statut sont projetés et contrôlés. |
| 44 | Application Control | `MIGRATED` | Profils utilisés, entrées et options sont projetés et contrôlés. |
| 46 | FortiAP obsolète | `LEGACY_REVIEW_REQUIRED` | Aucun corpus de backup V2 ne contient le namespace wireless-controller WTP. |
| 47 | Nombre de SSID par profil | `LEGACY_REVIEW_REQUIRED` | Aucun corpus de backup V2 ne permet un replay sans contrôle spéculatif. |
| 48 | Utilisation 5 GHz | `LEGACY_REVIEW_REQUIRED` | Aucun profil radio observable dans le corpus V2. |
| 49 | DARRP | `LEGACY_REVIEW_REQUIRED` | Aucun profil radio observable dans le corpus V2. |
| 50 | Frequency handoff | `LEGACY_REVIEW_REQUIRED` | Aucun profil radio observable dans le corpus V2. |
| 51 | TIM | `LEGACY_REVIEW_REQUIRED` | Aucun profil radio observable dans le corpus V2. |
| 57 | Bandes Wi-Fi | `LEGACY_REVIEW_REQUIRED` | Aucun profil radio observable dans le corpus V2. |
| 58 | Canaux Wi-Fi | `LEGACY_REVIEW_REQUIRED` | Aucun profil radio observable dans le corpus V2. |
| 59 | Short guard interval | `LEGACY_REVIEW_REQUIRED` | Aucun profil radio observable dans le corpus V2. |

## Dispositions explicites du Lot reporting / inventaires / exports

| # | Capacité | Disposition | Justification |
|---:|---|---|---|
| 52 | Logs par règle | `BLOCKED_EXTERNAL_SOURCE` | Les compteurs de logs sont runtime et absents des backups ; ils restent explicitement non renseignés. |
| 53 | Inventaire administrateurs | `MIGRATED` | Les comptes typés sont exposés dans le JSON canonique et la feuille XLSX Comptes, sans credential. |
| 54 | Statistiques de règles | `MIGRATED` | Total, enable explicite, disable explicite et statut inconnu sont communs au JSON, DOCX et XLSX. |
| 55 | Inventaire schedules | `LEGACY_REVIEW_REQUIRED` | Les références de policy existent mais les objets schedule ne sont pas encore projetés complètement. |
| 56 | Profils SSL/SSH | `MIGRATED` | `FW-SSL-SSH-PROFILE-001` résout les profils utilisés et valide le sous-bloc typed `https` aux seuils FortiOS exacts de V1 ; mutation/collision/résolution incomplète UNKNOWN. |

## Dispositions explicites du lot réseau

| # | Capacité | Disposition | Justification |
|---:|---|---|---|
| 3 | Usage par séquence | `MIGRATED` | `FW-BY-SEQUENCE-USAGE-001` reproduit les trois critères legacy sur le document structurel : `global-label`, plusieurs interfaces, ou `any` dans `srcintf`/`dstintf`. L’absence ou l’ambiguïté reste UNKNOWN. |
| 4 | Objets inutilisés | `MIGRATED` | `CFG-UNUSED-SERVICE-001` restitue uniquement les services custom/groupes certainement orphelins depuis le graphe typed. Namespace absent/incomplet, collision, mutation, cycle ou résolution incomplète restent UNKNOWN ; famille certaine vide NOT_APPLICABLE. |
| 8 | Service ALL dans les règles | `MIGRATED` | `FW-INTERNET-ALL-SERVICE-001` rejoué avec sélection WAN typed : ALL canonique sur accept/enable certain produit FAIL ; deny/disable est hors portée ; destination ou service non résolu reste UNKNOWN. Les exemptions historiques spécifiques ne sont pas recopiées. |
| 9 | Geo-IP | `LEGACY_REVIEW_REQUIRED` | Aucun contrôle V2 n'est enregistré et l'applicabilité métier doit être confirmée. |
| 31 | Route blackhole | `LEGACY_REVIEW_REQUIRED` | La règle dépend du contexte MPLS/L2L et d'une projection de routes dédiée. |
| 36 | Ports sensibles interdits | `LEGACY_REVIEW_REQUIRED` | Le contrôle V2 est partiel ; couverture et portée legacy ne sont pas encore équivalentes. |

## Disposition du tracer réseau SD-WAN

| # | Capacité | Disposition | Justification |
|---:|---|---|---|
| 37 | Utilisation SD-WAN | `MIGRATED` | `NET-SDWAN-USAGE-001` vérifie via le contexte WAN typé que chaque interface sélectionnée est un membre SD-WAN certain ; section/contexte absent ou relation ambiguë restent UNKNOWN. Replay parser → moteur → registre sur fixture FortiOS zone/members. |

## Ordre de migration accélérée

1. **Lot A — Système / administration** : auto-install USB, central-management FortiManager/FortiAnalyzer, comptes historiques/PKI, admin-sport, loopback/DNS à cible opérateur, puis inventaire administrateurs.
2. **Lot B — Réseau / firewall / objets** : objets inutilisés, séquence, ALL/ports, Geo-IP, SIP ALG/VoIP, routes blackhole, SD-WAN utilisé, SSL/SSH profiles.
3. **Lot C — HA / VPN** : HA complet, puis parité fine des branches VPN déjà partiellement couvertes.
4. **Lot D — UTM** : FortiSandbox, Anycast, mail filter et parité FortiGuard/autoupdate.
5. **Lot E — Wi-Fi** : FortiAP, SSID, radio, DARRP, handoff, TIM, bandes, canaux, SGI.
6. **Lot F — Reporting / statistiques / inventaires** : logs, policies, schedules, administrateurs et restitution.

Chaque capacité migrée devra finalement porter un statut `MIGRATED`, `BLOCKED_EXTERNAL_SOURCE` ou `LEGACY_REVIEW_REQUIRED`, avec source V1, projection V2, test représentatif et replay de fixture.

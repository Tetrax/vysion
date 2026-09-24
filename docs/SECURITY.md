# Sécurité du socle Vysion v2

## Frontière d'exposition

- en mode proxy hôte (VPS et VM), seul Nginx écoute sur le port conteneur `8080`, en HTTP clair, et le Nginx de l'hôte termine TLS pour `vysion.valdev.me` : aucun certificat ni clé dans le conteneur ;
- en mode standalone, le Nginx du conteneur termine TLS sur `443` : le seul certificat possible dans le conteneur est alors celui importé depuis l'admin, rangé dans le volume `vysion-certs` ;
- FastAPI écoute sur `127.0.0.1:8000` ;
- l'ingress est le bind de la pile active : `${BIND_ADDRESS}:${HOST_PORT}` (`127.0.0.1` et `8080` par défaut) en mode proxy hôte, `${BIND_ADDRESS}:${HTTPS_PORT:-443}` en standalone ;
- aucune IP Docker statique et aucun réseau externe (`Subnet-Docker` supprimé) ;
- l'image est référencée par digest OCI immuable `ghcr.io/tetrax/vysion@sha256:<64 hex>`, jamais par tag, dans `compose.yml`, `compose.proxy.yml` et `compose.helper.yml` : `IMAGE_DIGEST` (`sha256:<64 hex>`) est obligatoire, Compose ne rend que `ghcr.io/tetrax/vysion@${IMAGE_DIGEST}` (aucun tag n'est exprimable), Docker refuse toute référence malformée (`latest`, `sha-latest`, SHA court, hex majuscule ou non hexadécimale) à l'acquisition de l'image avant tout conteneur, le contrat CI exige `ghcr.io/tetrax/vysion@sha256:[0-9a-f]{64}` et la publication vérifie le lien avec le label `org.opencontainers.image.revision` ;
- seule exception assumée (décision 0011) : `compose.standalone.yml` en ligne suit le tag **mutable** `ghcr.io/tetrax/vysion:stable` avec `pull_policy: always`, pour qu'une mise à jour tienne en un *Update the stack* sans variable à saisir. Ce tag n'est promu qu'après les gates de `main`, jamais depuis une pull request, par copie du manifeste du tag `sha-<commit>` déjà vérifié (aucun rebuild), et la révision OCI réellement exécutée reste vérifiable par son label — rollback par pin `sha-<commit>`/digest ;
- les volumes aux noms stables sont déclarés externes dans `compose.yml`, `compose.proxy.yml` et `compose.helper.yml` (créés une fois, jamais ni créés ni supprimés par ces piles) et **gérés par Compose** dans `compose.standalone.yml` / `compose.standalone.offline.yml` (créés au premier déploiement Portainer zéro-commande, jamais supprimés par la pile) : la pile ne renomme ni ne supprime jamais `vysion-reports`, `vysion-state` ni `vysion-certs` ;
- l'accès reste limité par le firewall externe du fournisseur VPS et la source réseau configurée.

## Défense en profondeur du conteneur

- utilisateur non-root UID/GID `10001` ;
- filesystem en lecture seule ;
- `cap_drop: ALL` ;
- `no-new-privileges` ;
- tmpfs bornés ;
- trois volumes nommés stables séparés (externes en VPS/proxy/helper, gérés par Compose en standalone) : `vysion-reports` (rapports UUID/TTL), `vysion-state` (état d'administration fail-closed) et `vysion-certs` (certificats, mode standalone uniquement) ;
- limites CPU, mémoire et PID ;
- configuration HTTP versionnée dans l'image, sans montage de configuration ; le seul certificat pouvant entrer dans le conteneur est celui du mode standalone, écrit dans le volume `vysion-certs` ;
- aucun Node/Vite dans le runtime.

## HTTP

Le TLS (1.2/1.3, Let's Encrypt) est terminé par le Nginx de l'hôte. Dans le conteneur,
Nginx applique :

- `client_max_body_size 5m` ;
- `client_body_timeout 15s` ;
- timeouts proxy bornés ;
- CSP restrictive ;
- `X-Content-Type-Options` ;
- `X-Frame-Options` ;
- `Referrer-Policy` ;
- `Permissions-Policy` ;
- cache immutable uniquement sur les assets Vite hashés.
- `Cache-Control: no-store, private` sur toute réponse API contenant un rapport.

FastAPI applique en plus sa propre limite en octets avant parsing métier.

## Limites connues du socle

- parser FortiGate structurel alimentant les contrôles enregistrés du socle et la corrélation PSIRT ;
- parser fail-closed sur les preuves auditées : section/preuve absente, interface WAN non identifiable, `allowaccess`/MFA indéterminable ou mutation non interprétée d'une clé auditée → `UNKNOWN`, jamais `PASS` ; une preuve antérieure est invalidée par toute directive ultérieure incomplète ou mutation non interprétée de la même clé ; une non-conformité explicitement prouvée reste `FAIL` ;
- sections réellement non auditées, clés supplémentaires et sous-sections inconnues traversées puis ignorées sans devenir des preuves ; section auditée imbriquée ou nom de section ressemblant à une section auditée → rejet ;
- UTF-8 et BOM UTF-8 initial acceptés ; NUL, contrôles C0/C1 non autorisés, DEL, caractères de format invisibles et séparateurs Unicode dangereux rejetés ; lexer probant sans transformation implicite des backslashes ou guillemets ;
- structure tronquée, section auditée top-level dupliquée, directive placée hors `edit` dans une section à entrées, directive probante dupliquée ou valeur probante lexicalement ambiguë → rejet ;
- le hostname doit respecter une syntaxe DNS/hostname ; vide ou générique → `FAIL`, lexicalement malformé → rejet ;
- les contrôles externes restent dépendants d'une observation complète et fraîche ; une réponse PSIRT absente, incomplète, non corrélée ou périmée produit `UNKNOWN` ;
- le contrôle WAN identifie les interfaces nommées `wan*` ou portant explicitement `set role wan` ; les zones et SD-WAN sont résolus par projection typée et les collisions restent ambiguës ;
- le contrôle MFA ne reconnaît encore que `fortitoken`, `email` et `sms` ; une autre valeur reste `UNKNOWN` ;
- le rapport JSON canonique est persisté ; les exports DOCX et XLSX sont générés à la demande depuis le même modèle Pydantic typé, sans copie persistante supplémentaire ;
- FortiGuard vérifie la disponibilité de l'endpoint et corrèle les advisories critiques/élevés à la version FortiOS lorsque la réponse est complète ; le contenu externe reste `UNKNOWN` si la source ne peut pas être vérifiée ;
- le périmètre VDOM est limité à un VDOM explicitement sélectionné ; une configuration multi-VDOM sans sélection produit `UNKNOWN` ;
- stockage mono-instance local, cohérent avec un unique conteneur ;
- purge TTL au démarrage, avant écriture et à la lecture ; une sauvegarde externe du volume conserve sa propre politique de rétention ;
- aucune homologation de production n'est revendiquée.

## Surface d'administration, état durable et certificats (V2)

- **Périmètre** : seule `/admin` et ses API `/api/admin/*` exigent une session ; aucune authentification globale n'est installée, le parcours principal reste anonyme derrière la frontière réseau existante, et aucun token, API key ni signature d'URL n'existe dans ce périmètre (sessions/cookies uniquement). Non-régression prouvée par `tests/integration/test_admin_api.py` et `tests/integration/test_admin_certificates.py` ;
- **mutations** : session + jeton `X-CSRF-Token` + `Origin` exact ; verrous par portée (compte, setup, récupération, client) avec TTL ; anti-énumération (réponses identiques puis 429) ; corps limités (1 Mo admin, 512 Ko certificat) ;
- **état durable** : SQLite privé dans `vysion-state` (fichier 0600, répertoire 0700, échec fail-closed si corrompu ou schéma plus récent) ; mots de passe scrypt ; secrets SMTP write-only dans l'état, jamais dans l'environnement ni dans une réponse ; tickets de récupération et d'activation hachés (`token_digest`), usage unique, liés à la session (et, pour l'activation, au digest exact du candidat) ; `vysion-admin` n'accepte les secrets que sur stdin, jamais en argument, et ne les ré-échoue jamais ;
- **certificats** : validation stricte (format PEM/PKCS#12, dates sur horloge injectée, SAN/hostname avec wildcard RFC 6125, vérification de chaîne OpenSSL, chargement TLS réel), staging privé 0700/0600, générations immutables, pointeur `active` basculé atomiquement, relecture de l'empreinte SHA-256 servie après activation avec rollback automatique ; la passphrase PKCS#12 transite par stdin (`fd:0`), jamais dans `argv` ; le bootstrap standalone auto-signé (2 jours) est remplacé dès le premier import admin ;
- **helper root (mode VPS)** : l'application non-root ne détient aucun droit sur `/etc/letsencrypt` ni sur le rechargement de Nginx. Elle ne parle qu'à la socket Unix `0660 root:<VYSION_PGID>` dans un répertoire `0750`, montée **lecture seule** dans le conteneur sous `/vysion-helper` (`compose.helper.yml`, `VYSION_HELPER_SOCKET_PATH` explicite — un chemin sous `/run` serait masqué par le tmpfs `/var/run`, symlink de `/run`), et le pair est vérifié par `SO_PEERCRED` sur le uid **et** le gid avant toute réponse. Le protocole est JSON préfixé longueur, versionné et borné (tailles de requête/réponse, rejet des clés dupliquées) ; **quatre actions seulement** y circulent — `ping`, `status`, `validate`, `activate` — avec des ensembles de clés stricts, si bien qu'aucun chemin, aucune lignée et aucune commande ne peuvent jamais arriver par ce canal ; `install` et `renew` n'existent qu'en CLI root. Aucune clé privée ne transite par la socket (seules des métadonnées et des digests), aucun détail interne n'est renvoyé en cas d'erreur (`kind` + message fixe, jamais l'echo du contenu reçu) et le staging expire par TTL. Le service tourne sous systemd avec `ProtectSystem=strict`, `NoNewPrivileges`, `CapabilityBoundingSet` réduite (`CAP_CHOWN`, `CAP_FOWNER`, `CAP_DAC_*`, `CAP_NET_BIND_SERVICE`) et `ReadWritePaths` limité à `/var/lib/vysion`, `/var/log/nginx` et `/run/vysion-cert-helper`. `nginx -t` précède **toujours** le rechargement, l'empreinte SHA-256 servie est relue et une échec restaure la génération précédente. Non-régression prouvée par `tests/unit/test_certprotocol.py`, `tests/integration/test_helper_backend.py` et `tests/unit/test_certhelper.py` ;
- **email** : une seule configuration durable dans l'état privé SQLite (`vysion-state`), transport unique sélectionné (`smtp` ou `microsoft365`) — jamais les deux à la fois. Les secrets (mot de passe SMTP, client secret OAuth) sont **write-only** : ils ne sont ni renvoyés, ni journalisés, ni relus par l'UI (la projection publique ne porte que `configured`, `transport`, `provenance` et `secret_configured`), un champ vide conserve la valeur enregistrée, et une ligne inutilisable est refusée avant toute écriture. Les endpoints Microsoft 365 sont **fixes** (`login.microsoftonline.com/<tenant>/oauth2/v2.0/token`, `graph.microsoft.com/v1.0/users/<mailbox>/sendMail`) en flux `client_credentials` : aucun callback ni login utilisateur, aucun jeton de bureau. Le test d'envoi exige session + `X-CSRF-Token` + `Origin` exact, est limité par portée client (5 / 600 s), a un délai borné et ne renvoie qu'un diagnostic nettoyé ; il utilise toujours la dernière configuration enregistrée. La récupération reste **fail-closed** tant que la configuration et `PUBLIC_ORIGIN` sont incomplètes. Aucun appel réseau réel en CI (`_urlopen` injecté). Non-régression prouvée par `tests/integration/test_admin_email.py`, `tests/unit/test_graphmail.py` et `tests/unit/test_email_transport.py` ;
- **volumes** : nommés et stables `vysion-state`, `vysion-certs`, `vysion-reports`, séparés, jamais supprimés ni renommés par la pile (externes sur les piles VPS/proxy/helper, créés par Compose au déploiement en standalone) ; `VYSION_VOLUME_PREFIX` (défaut vide) isole validations et smokes sur des volumes dédiés ; sauvegarde manuelle sous une frontière cohérente (les conteneurs porteurs sont d'abord arrêtés — quiescence — puis redémarrés) et restauration testée uniquement sur volumes jetables, avec vérification des empreintes (`scripts/backup.sh`, `scripts/restore.sh`, rejoué par `tests/contract/test_backup_restore_roundtrip.py`) ; en complément sans CLI, l'export/import de migration chiffré (« Bundle de migration » ci-dessous).

## Bundle de migration chiffré (V2)

- **objets** : export depuis une session admin authentifiée (`X-CSRF-Token` + `Origin` exact) après ré-authentification du mot de passe courant (échecs bornés, même verrou que le changement de mot de passe) ; import uniquement sur une instance **réellement non initialisée** (aucun compte, `Origin` exact, 5 échecs → 429 pendant 15 min) : dès qu'un administrateur existe la route anonyme répond 409 — aucun endpoint de restauration anonyme n'existe après enrôlement ;
- **format** : conteneur `VYSIONMIG` versionné (magique, version, sel 16 o, nonce 12 o, en-tête en AAD) + **AES-256-GCM** ; KDF `scrypt` borné (`n=2**15, r=8, p=1, dklen=32, maxmem=64 MiB`) via `hashlib`/OpenSSL ; dépendance épinglée `cryptography==46.0.5` (empreintes verrouillées dans `requirements.lock`) — aucune primitive maison, tout format, version ou algorithme inconnu est refusé avant toute écriture utile ;
- **bornes** : bundle ≤ 4 Mo (borné côté ASGI, sous le `client_max_body_size 5m`), état ≤ 16 Mo, certificat ≤ 512 Ko par pièce, manifeste ≤ 64 Ko, ZIP ≤ 4 entrées ; secret erroné et archive altérée partagent un refus constant (AEAD, aucun oracle) ;
- **validation stricte** : manifeste à clés exactes (format, version, empreintes SHA-256, tailles, `excluded: ["reports"]`), noms d'entrées limités à la liste blanche — traversée, symlink, entrée inattendue, doublon, répertoire et méthode de compression hors bornes refusés — lecture de chaque entrée bornée à sa taille déclarée (anti zip bomb), base SQLite : `integrity_check`, version de schéma, schéma canonique vérifié objet par objet (statement CREATE stocké de chaque table/index — colonnes, contraintes, défauts ; vue, trigger, table ou index inattendu refusé), compte administrateur présent, puis réouverture et lectures réelles via `StateStore` avant tout échange — base étrangère, vide, corrompue ou impropre refusée, état initial conservé ;
- **restauration atomique** : staging privé `0700` dans le volume d'état, copie de sauvegarde de l'état d'origine, `os.replace` sous un verrou « premier rendu » partagé avec l'enrôlement, vérification après remplacement ; **toute panne pendant l'application roule en arrière sur l'état d'origine** — ni état partiel, ni enrôlement ouvert au-delà de l'état exact d'avant la tentative — et un état illisible reste « indéterminé » (503), jamais « aucun administrateur » ;
- **hygiène après restauration** : sessions, codes de récupération, verrous et tickets de certificat de l'export sont révoqués avant que l'état ne devienne courant : aucun jeton ancien ne survit à la migration ;
- **certificat** : seul le mode standalone l'importe, avec la validation TLS existante (SAN/`VYSION_TLS_HOSTNAME`, dates, cohérence de chaîne, chargement réel) puis l'activation courante (`nginx -t`, rechargement, empreinte servie) ; sinon le certificat bootstrap reste servi, l'état restauré reste utilisable et l'UI présente l'action d'import manuel ;
- **secrets** : passphrase et mot de passe courant uniquement en corps de POST — jamais en URL ni en journal (access-log Uvicorn désactivé, format Nginx sans `$uri`/`$request_uri`) — messages de refus constants sans écho de contenu, export servi en `Content-Disposition: attachment` + `Cache-Control: no-store, private` ; la réponse d'import ne porte que des projections publiques (`status`, `certificate`, `email`, `reports_included: false`) ;
- **exclusion** : les rapports TTL ne quittent jamais l'instance par ce canal (le manifeste porte `excluded: ["reports"]`, la rétention reste celle des archives de volumes) ; non-régression prouvée par `tests/unit/test_migration_bundle.py` et `tests/integration/test_admin_migration.py`.

## En-têtes transférés et origine publique (V2)

- **Confiance forwarded (règle unique)** : l'application ne croit `X-Forwarded-For`,
  `X-Forwarded-Proto`, `X-Forwarded-Client-Proto` et `X-Real-IP` que selon la
  résolution `vysion.security.TrustedProxy.resolve`, bornée par
  `VYSION_TRUSTED_PROXY_CIDRS` (défaut `127.0.0.1/32` — client local
  uniquement, **aucun défaut silencieux** dans `compose.proxy.yml`). En mode
  VPS, une requête qui arrive sur le port publié est observée depuis la
  passerelle du bridge Docker (jamais depuis `127.0.0.1`) : ce hop doit être
  ajouté explicitement au déploiement (aucun subnet n'est imposé), sinon le
  schéma `https` de l'arête hôte est ignoré et le cookie de session n'est
  pas `Secure`. La couche interne est épinglée par
  contrat : le Nginx du conteneur rejette les en-têtes transférés des clients
  au niveau `server`, réécrit `X-Real-IP` sur l'observation locale
  (`$remote_addr`), complète `X-Forwarded-For` (`$proxy_add_x_forwarded_for`),
  pose `X-Forwarded-Proto` sur son propre `$scheme` et transmet la vérité du
  proxy externe via `X-Forwarded-Client-Proto` ; uvicorn tourne **sans**
  confiance forwarded (aucune réécriture de pair ou de schéma en aval).
  Conséquences vérifiées par tests : une tentative de contournement des
  verrous par `X-Forwarded-For` forgé est comptée sur le client réellement
  observé, un client non digne de confiance ne peut pas déclarer `https`, et
  un proxy externe explicite transmet correctement chaîne et schéma.
- **Origine publique** : `VYSION_PUBLIC_ORIGIN` est l'**unique** autorité de
  l'origine (en standalone elle est dérivée de `VYSION_TLS_HOSTNAME`, port
  443 implicite : changez le port public, définissez `PUBLIC_ORIGIN` avec son
  port). Toute mutation `/api/admin/*` doit présenter `Origin` et `Host`
  exacts — l'origine n'est jamais dérivée du `Host` attaquant — sinon 403
  `origin_mismatch`. Sans origine configurée (défaut VPS/proxy), **aucune
  mutation admin n'a lieu** : setup, connexion, récupération et certificats
  renvoient 503 « origine publique non configurée », la première exécution
  reste fermée, et le lien de récupération n'est jamais fabriqué depuis un
  en-tête contrôlable.

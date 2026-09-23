# Sécurité du socle Vysion v2

## Frontière d'exposition

- seul Nginx écoute sur le port conteneur `8080`, en HTTP clair ;
- le Nginx de l'hôte termine TLS pour `vysion.valdev.me` : aucun certificat ni clé dans le conteneur ;
- FastAPI écoute sur `127.0.0.1:8000` ;
- le port hôte est lié à `${BIND_ADDRESS}:${HOST_PORT}` (`127.0.0.1` et `8080` par défaut), seul ingress de la pile ;
- aucune IP Docker statique et aucun réseau externe (`Subnet-Docker` supprimé) ;
- l'image est référencée par digest OCI immuable `ghcr.io/tetrax/vysion@sha256:<64 hex>`, jamais par tag : `IMAGE_DIGEST` (`sha256:<64 hex>`) est obligatoire, Compose ne rend que `ghcr.io/tetrax/vysion@${IMAGE_DIGEST}` (aucun tag n'est exprimable), Docker refuse toute référence malformée (`latest`, `sha-latest`, SHA court, hex majuscule ou non hexadécimale) à l'acquisition de l'image avant tout conteneur, le contrat CI exige `ghcr.io/tetrax/vysion@sha256:[0-9a-f]{64}` et la publication vérifie le lien avec le label `org.opencontainers.image.revision` ;
- le volume `vysion-reports` est déclaré externe : la pile ne le crée ni ne le supprime ;
- l'accès reste limité par le firewall externe du fournisseur VPS et la source réseau configurée.

## Défense en profondeur du conteneur

- utilisateur non-root UID/GID `10001` ;
- filesystem en lecture seule ;
- `cap_drop: ALL` ;
- `no-new-privileges` ;
- tmpfs bornés ;
- volume unique pour les rapports ;
- limites CPU, mémoire et PID ;
- configuration HTTP versionnée dans l'image, sans montage de configuration ni de certificat ;
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
- **volumes** : externes et stables `vysion-state`, `vysion-certs`, `vysion-reports`, séparés, jamais supprimés par la pile ; `VYSION_VOLUME_PREFIX` (défaut vide) isole validations et smokes sur des volumes dédiés ; sauvegarde manuelle sous une frontière cohérente (les conteneurs porteurs sont d'abord arrêtés — quiescence — puis redémarrés) et restauration testée uniquement sur volumes jetables, avec vérification des empreintes (`scripts/backup.sh`, `scripts/restore.sh`, rejoué par `tests/contract/test_backup_restore_roundtrip.py`).

## En-têtes transférés et origine publique (V2)

- **Confiance forwarded (règle unique)** : l'application ne croit `X-Forwarded-For`,
  `X-Forwarded-Proto`, `X-Forwarded-Client-Proto` et `X-Real-IP` que selon la
  résolution `vysion.security.TrustedProxy.resolve`, bornée par
  `VYSION_TRUSTED_PROXY_CIDRS` (défaut `127.0.0.1/32`, **aucun défaut
  silencieux** dans `compose.proxy.yml`). La couche interne est épinglée par
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
- **Origine publique** : `VYSION_PUBLIC_ORIGIN` est l'autorité de l'origine
  (sinon, en standalone, elle est dérivée de `VYSION_TLS_HOSTNAME` et du port
  d'écoute). Toute mutation `/api/admin/*` doit présenter `Origin` et `Host`
  exacts — l'origine n'est jamais dérivée du `Host` attaquant — sinon 403
  `origin_mismatch`. Sans origine configurée, la demande de récupération
  SMTP renvoie 503 « récupération indisponible » et le lien n'est jamais
  fabriqué depuis un en-tête contrôlable.

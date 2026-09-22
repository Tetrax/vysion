# Sécurité du socle Vysion v2

## Frontière d'exposition

- seul Nginx écoute sur le port conteneur `8080`, en HTTP clair ;
- le Nginx de l'hôte termine TLS pour `vysion.valdev.me` : aucun certificat ni clé dans le conteneur ;
- FastAPI écoute sur `127.0.0.1:8000` ;
- le port hôte est lié à `${BIND_ADDRESS}:${HOST_PORT}` (`127.0.0.1` et `8080` par défaut), seul ingress de la pile ;
- aucune IP Docker statique et aucun réseau externe (`Subnet-Docker` supprimé) ;
- l'image est référencée par un tag GHCR immuable `sha-<commit complet>`, jamais `latest` ;
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

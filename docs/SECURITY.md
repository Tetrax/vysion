# Sécurité du socle Vysion v2

## Frontière d'exposition

- seul Nginx écoute sur le port conteneur `8443` ;
- FastAPI écoute sur `127.0.0.1:8000` ;
- le port hôte est lié à `${BIND_ADDRESS}:443` ;
- l'accès reste limité par le firewall externe du fournisseur VPS et la source réseau configurée.

## Défense en profondeur du conteneur

- utilisateur non-root UID/GID `10001` ;
- filesystem en lecture seule ;
- `cap_drop: ALL` ;
- `no-new-privileges` ;
- tmpfs bornés ;
- volume unique pour les rapports ;
- limites CPU, mémoire et PID ;
- certificats montés en lecture seule ;
- aucun Node/Vite dans le runtime.

## HTTP

Nginx applique :

- `client_max_body_size 5m` ;
- `client_body_timeout 15s` ;
- timeouts proxy bornés ;
- TLS 1.2/1.3 ;
- CSP restrictive ;
- `X-Content-Type-Options` ;
- `X-Frame-Options` ;
- `Referrer-Policy` ;
- `Permissions-Policy` ;
- cache immutable uniquement sur les assets Vite hashés.
- `Cache-Control: no-store, private` sur toute réponse API contenant un rapport.

FastAPI applique en plus sa propre limite en octets avant parsing métier.

## Limites connues du socle

- authentification applicative volontairement absente ; le contrôle d'accès repose sur l'allowlist IP externe acceptée pour Vysion ;
- parser volontairement minimal ;
- parser fail-closed dans les sections auditées : section absente/vide ou interface WAN sans `allowaccess` → `UNKNOWN`; structure tronquée/imbriquée, bloc audité top-level dupliqué, mutation non interprétée, directive hors entrée, directive dupliquée/malformée ou clé/valeur `allowaccess` non supportée → rejet ;
- le tracer rejette toute sous-section `config`, même sous une section inconnue ;
- un lexer commun ferme la grammaire de `config`, `edit` et `set` sans transformation : ASCII imprimable, guillemets doubles autour d'un token entier, séparateurs whitespace explicites, aucun backslash ni whitespace terminal de ligne et noms de section alphanumériques/tirets ; les sections auditées doivent être top-level, sont canonicalisées avant classification et tout lookalike d'un nom audité est rejeté comme ambigu ;
- le hostname doit respecter une syntaxe DNS/hostname ; vide ou générique → `FAIL`, lexicalement malformé → rejet ;
- seulement trois contrôles représentatifs ;
- le contrôle WAN du tracer identifie uniquement les interfaces dont le nom commence par `wan` ; rôles, zones et SD-WAN restent à porter depuis l'oracle legacy avant équivalence fonctionnelle ;
- le contrôle MFA ne reconnaît encore que `fortitoken`, `email` et `sms` ; une autre valeur reste `UNKNOWN` ;
- le rapport JSON canonique est persisté ; les exports DOCX et XLSX sont générés à la demande depuis le même modèle Pydantic typé, sans copie persistante supplémentaire ;
- FortiGuard vérifie actuellement la disponibilité du endpoint, pas encore les advisories corrélés au firmware ;
- stockage mono-instance local, cohérent avec un unique conteneur ;
- purge TTL au démarrage, avant écriture et à la lecture ; une sauvegarde externe du volume conserve sa propre politique de rétention ;
- aucune homologation de production n'est revendiquée.

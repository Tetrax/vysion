# Vysion v2 — socle

Vysion v2 est le nouveau socle interne SNS Security d'audit de configurations FortiGate. Il part d'un historique Git neuf et n'importe aucun code, template Office, rapport ou asset sensible de l'ancien Vysion.

## Périmètre livré

- parser FortiGate minimal et neuf, fail-closed dans les sections auditées ;
- modèles Pydantic immuables et statuts `PASS`, `FAIL`, `UNKNOWN`, `ERROR` ;
- registre modulaire couvrant le système, le réseau, l'administration, le firewall, le VPN, l'UTM, les connecteurs LDAP et la corrélation PSIRT FortiOS ;
- API FastAPI d'upload et de téléchargement JSON / DOCX / XLSX ;
- stockage par UUID v4 avec timestamps UTC, TTL, purge au démarrage, avant écriture et à la lecture ;
- adaptateur FortiGuard fail-closed pour la disponibilité et la corrélation PSIRT (`UNKNOWN` ou `ERROR`, jamais `PASS` implicite) ;
- interface React minimale compilée au build, avec téléchargement des trois formats ;
- un Dockerfile multi-stage, un conteneur, des piles Compose et trois volumes externes : `vysion-reports` (rapports UUID/TTL), `vysion-state` (état d'administration durable, fail-closed) et `vysion-certs` (certificats du mode standalone) ;
- Nginx interne en HTTP sur `8080` pour les limites HTTP, les headers, les statiques et le proxy `/api` ;
- TLS terminé chez l'opérateur (modes proxy : Nginx de l'hôte ou reverse proxy externe) ou dans le conteneur (mode standalone, certificats importés depuis `/admin`) : aucun montage de certificat ni de clé dans le mode proxy ;
- FastAPI accessible uniquement sur `127.0.0.1` dans le conteneur.

Ce socle ne porte volontairement pas toutes les règles legacy. Le rapport JSON typé est la source
canonique persistée sous UUID/TTL et téléchargeable via `/api/reports/{uuid}.json` ; les fichiers DOCX et XLSX sont générés à la demande depuis ce
même modèle, sans template ni asset legacy et sans copie persistante supplémentaire.

Une section nécessaire absente ou vide produit `UNKNOWN`, jamais un `PASS`. Une interface WAN sans preuve `allowaccess`, un administrateur sans directive `two-factor` ou une mutation non interprétée portant sur une preuve auditée produit également `UNKNOWN`. Toute preuve antérieure est invalidée par une directive ultérieure incomplète ou une mutation non interprétée de la même clé. Une non-conformité explicitement prouvée reste `FAIL`, même si d'autres entrées sont indéterminées. Une configuration structurellement tronquée, un bloc audité top-level dupliqué, un nom de section ressemblant à une section auditée, une section auditée imbriquée, une directive placée hors `edit` dans une section à entrées, une directive probante dupliquée ou une valeur probante lexicalement ambiguë est rejetée.

Les sections auditées `system global`, `system interface` et `system admin` sont interprétées uniquement lorsqu'elles sont top-level. Le parser suit la structure FortiGate `config` / `edit` / `next` / `end` ; les sections réellement non auditées, clés supplémentaires et sous-sections inconnues sont traversées puis ignorées et ne peuvent pas devenir des preuves. Les lookalikes d'une section auditée et les sections auditées exactes sous un wrapper sont rejetés afin qu'aucune preuve dangereuse ne puisse être masquée. UTF-8 et un BOM UTF-8 initial sont acceptés, notamment dans les commentaires et valeurs non utilisées. NUL, contrôles C0/C1 non autorisés, DEL, caractères de format invisibles et séparateurs Unicode dangereux sont rejetés.

La valeur `hostname` doit respecter une syntaxe DNS/hostname (labels de 1 à 63 caractères, lettres/chiffres/tirets, longueur totale maximale de 253 caractères). Une valeur vide ou générique `fortigate` reste un constat `FAIL`; une valeur lexicalement malformée est rejetée.

Le contrôle WAN identifie les interfaces dont le nom commence par `wan` ou dont `set role wan` est explicitement présent. Les zones et l'appartenance SD-WAN sont projetées depuis la structure FortiOS et restent fail-closed lorsqu'une référence est absente ou ambiguë.

Le vocabulaire `allowaccess` reconnu par ce tracer est borné aux valeurs FortiOS connues suivantes : `fabric`, `fgfm`, `ftm`, `http`, `https`, `ping`, `probe-response`, `radius-acct`, `snmp`, `speed-test`, `ssh` et `telnet`. Une valeur inconnue invalide la preuve et produit `UNKNOWN` afin d'éviter un faux `PASS`.

Le contrôle MFA ne conclut `PASS` que pour les méthodes actuellement reconnues (`fortitoken`, `email`, `sms`) ; toute autre valeur produit `UNKNOWN` jusqu'à validation métier.

## Architecture

```text
HTTPS :443                     Nginx de l'hôte (Let's Encrypt)
   │                                   │
   └────────────► 127.0.0.1:${HOST_PORT:-8080}
                              │
                              ▼
┌──────────────────────────────────────┐
│ Conteneur unique Vysion             │
│                                      │
│ Nginx non-root :8080 (HTTP clair)    │
│ ├─ limites HTTP et headers           │
│ ├─ fichiers React compilés          │
│ └─ /api → 127.0.0.1:8000            │
│                    │                 │
│                    ▼                 │
│              FastAPI/Uvicorn         │
│              ├─ parser              │
│              ├─ contrôles typés     │
│              ├─ FortiGuard          │
│              ├─ JSON UUID/TTL       │
│              └─ exports DOCX/XLSX   │
└───────────────────┬──────────────────┘
                    ▼
     volumes externes vysion-reports / vysion-state
     (+ vysion-certs en mode standalone)
```

Le conteneur n'écoute qu'à travers le bind `${BIND_ADDRESS:-127.0.0.1}:${HOST_PORT:-8080}` :
pas d'IP Docker statique, pas de réseau externe. `BIND_ADDRESS` sélectionne l'IP,
`HOST_PORT` sélectionne le port (`8080` en production, `18080` pendant une validation
temporaire).

Décision d'edge : `docs/decisions/0001-single-container-http-edge.json` et
`docs/decisions/0006-host-terminated-tls-loopback-http.json`.

## Modes de déploiement

Trois piles coexistent, toutes immuables (`IMAGE_DIGEST` requis) et toutes sans IP Docker statique :

| Mode | Pile | TLS | `VYSION_TLS_HOSTNAME` | `TRUSTED_PROXY_CIDRS` | `PUBLIC_ORIGIN` |
| --- | --- | --- | --- | --- | --- |
| VPS / Portainer (production) | `compose.yml` | terminé par le Nginx de l'hôte | — | défaut `127.0.0.1/32` : **à expliciter sur le hop Docker observé** (cf. `docs/OPERATIONS.md`) | **requis pour l'admin** (503 sinon) |
| Standalone (VM propre) | `compose.standalone.yml` | terminé dans le conteneur | **requis** | défaut `127.0.0.1/32` | dérivée de `VYSION_TLS_HOSTNAME` |
| VM derrière un reverse proxy externe | `compose.proxy.yml` | terminé chez l'opérateur | — | **requis, aucun défaut silencieux** | **requis pour l'admin** (503 sinon) |

- `TRUSTED_PROXY_CIDRS` décrit les seules sources dont l'application accepte
  les en-têtes transférés (`X-Forwarded-*`, `X-Real-IP`) : résolution unique
  dans `vysion.security.TrustedProxy.resolve`, avec le Nginx interne qui
  rejette et complète ces en-têtes avant l'application et uvicorn qui tourne
  sans confiance forwarded. Sans cette variable, `compose.proxy.yml` refuse
  de se résoudre. En mode VPS, une requête qui arrive par le port publié est
  observée depuis la **passerelle du bridge Docker** (jamais depuis
  `127.0.0.1`) : renseignez-la avec ce hop réellement observé — la pile
  n'impose aucun subnet — sinon le `https` déclaré par le Nginx hôte est
  ignoré et le cookie de session n'est pas `Secure`.
- `PUBLIC_ORIGIN` est l'autorité de toute mutation `/api/admin/*` : `Origin`
  et `Host` exacts sont exigés (sinon 403, l'origine n'étant jamais dérivée
  d'un `Host` attaquant) et, sans origine configurée, **aucune mutation
  n'a lieu** — setup, connexion, récupération et certificats renvoient 503,
  aucun lien n'étant fabriqué depuis un en-tête contrôlable. En standalone,
  l'origine est dérivée de `VYSION_TLS_HOSTNAME` (port 443 implicite) ;
  changez le port public, définissez `PUBLIC_ORIGIN` avec son port.
- `VYSION_VOLUME_PREFIX` (défaut vide) préfixe les noms des volumes externes
  pour que validations et smokes n'utilisent jamais les volumes de
  production ; avec le défaut vide les noms restent `vysion-reports`,
  `vysion-state`, `vysion-certs`.

Les trois piles déclarent les mêmes volumes externes (créés une fois par
`docker volume create`, voir `docs/OPERATIONS.md`) et la sauvegarde manuelle
coupe de façon cohérente les conteneurs qui les montent
(`scripts/backup.sh`), avec restauration testée sur volumes jetables :
`scripts/restore.sh` lit ses archives avec `VYSION_BACKUP_PREFIX` (le préfixe
de la sauvegarde, vide pour la production) et écrit ses volumes avec
`VYSION_VOLUME_PREFIX`, et échoue si aucune archive attendue n'est trouvée.

## Développement local

```bash
uv sync --group dev
uv run pytest -q
uv run ruff check src tests

cd frontend
npm ci --ignore-scripts
npm test
npm run lint
npm run build
npm audit --audit-level=high
```

## Validation de livraison

`IMAGE_DIGEST` est obligatoire et vaut le digest OCI `sha256:<64 hex>` de
l'image : Compose en déduit la référence immuable `ghcr.io/tetrax/vysion@<digest>`.
Sans lui — ou avec une valeur vide — la commande échoue ; `latest`, `sha-latest`,
un SHA court ou une valeur non hexadécimale sont refusés par Docker lui-même
à l'acquisition de l'image, avant tout conteneur. Le digest se lit dans le
journal de la CI de publication ou avec
`docker buildx imagetools inspect ghcr.io/tetrax/vysion:sha-<commit>`.

```bash
IMAGE_DIGEST="sha256:<64 hex>" docker compose config --quiet
HOST_PORT=8080  IMAGE_DIGEST="sha256:<64 hex>" docker compose config --quiet
HOST_PORT=18080 IMAGE_DIGEST="sha256:<64 hex>" docker compose config --quiet
TRUSTED_PROXY_CIDRS="127.0.0.1/32,10.0.0.0/8" IMAGE_DIGEST="sha256:<64 hex>" \
  docker compose -f compose.proxy.yml config --quiet
docker build --pull -t vysion:local .   # un build local ne peut jamais porter la
                                        # référence de déploiement (digest non taguable)
```

En mode VPS aucun certificat n'est nécessaire pour démarrer le conteneur : le
TLS est terminé par le Nginx de l'hôte. Le mode standalone génère au premier
démarrage un certificat bootstrap de court terme puis importe le certificat
réel via `/admin` (volume `vysion-certs`). La configuration HTTP du conteneur
est versionnée dans `deploy/nginx.conf` puis copiée dans l'image.

Aucun déploiement automatique n'est autorisé par la création de ce socle. Le chemin
unique est la Git Stack Portainer, avec la checklist de bascule et de rollback de
`docs/OPERATIONS.md`.

## Données et confidentialité

Ne jamais versionner :

- configurations FortiGate importées ;
- rapports générés ;
- certificats ou clés ;
- variables d'instance ;
- templates ou assets hérités ;
- données client réelles.

Les réponses API contenant un rapport imposent `Cache-Control: no-store, private`. L'accès est réservé au réseau interne via le reverse proxy et le filtrage réseau.

Les exports sont disponibles tant que le rapport stocké n'a pas expiré :

```text
/api/reports/{uuid}.json
/api/reports/{uuid}.docx
/api/reports/{uuid}.xlsx
```

L'export XLSX neutralise les préfixes de formule dans toutes les valeurs textuelles contrôlables par
un fichier importé. Les exports ne contiennent aucune macro.

Les fixtures des tests sont synthétiques et intégrées aux tests Python.

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
- un Dockerfile multi-stage, un conteneur, un service Compose et un volume externe `vysion-reports` ;
- Nginx interne en HTTP sur `8080` pour les limites HTTP, les headers, les statiques et le proxy `/api` ;
- TLS terminé par le Nginx de l'hôte : aucun certificat, aucune clé et aucun montage TLS dans le conteneur ;
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
     volume externe vysion-reports
```

Le conteneur n'écoute qu'à travers le bind `${BIND_ADDRESS:-127.0.0.1}:${HOST_PORT:-8080}` :
pas d'IP Docker statique, pas de réseau externe. `BIND_ADDRESS` sélectionne l'IP,
`HOST_PORT` sélectionne le port (`8080` en production, `18080` pendant une validation
temporaire).

Décision d'edge : `docs/decisions/0001-single-container-http-edge.json` et
`docs/decisions/0006-host-terminated-tls-loopback-http.json`.

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

`IMAGE_TAG` est obligatoire et doit être un tag immuable `sha-<commit complet>` :
la commande échoue sans lui.

```bash
IMAGE_TAG="sha-$(git rev-parse HEAD)" docker compose config --quiet
HOST_PORT=18080 IMAGE_TAG="sha-$(git rev-parse HEAD)" docker compose config --quiet
IMAGE_TAG="sha-$(git rev-parse HEAD)" docker compose build --pull
```

Aucun certificat n'est nécessaire pour démarrer le conteneur : le TLS est terminé
par le Nginx de l'hôte, et la configuration HTTP du conteneur est versionnée dans
`deploy/nginx.conf` puis copiée dans l'image.

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

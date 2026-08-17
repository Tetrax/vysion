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
- un Dockerfile multi-stage, un conteneur, un service Compose et un volume ;
- Nginx interne pour TLS, limites HTTP, headers, statiques et proxy `/api` ;
- FastAPI accessible uniquement sur `127.0.0.1` dans le conteneur.

Ce socle ne porte volontairement pas toutes les règles legacy. Le rapport JSON typé est la source
canonique persistée sous UUID/TTL ; les fichiers DOCX et XLSX sont générés à la demande depuis ce
même modèle, sans template ni asset legacy et sans copie persistante supplémentaire.

Une section nécessaire absente ou vide produit `UNKNOWN`, jamais un `PASS`. Une interface WAN sans preuve `allowaccess`, un administrateur sans directive `two-factor` ou une mutation non interprétée portant sur une preuve auditée produit également `UNKNOWN`. Toute preuve antérieure est invalidée par une directive ultérieure incomplète ou une mutation non interprétée de la même clé. Une non-conformité explicitement prouvée reste `FAIL`, même si d'autres entrées sont indéterminées. Une configuration structurellement tronquée, un bloc audité top-level dupliqué, un nom de section ressemblant à une section auditée, une section auditée imbriquée, une directive placée hors `edit` dans une section à entrées, une directive probante dupliquée ou une valeur probante lexicalement ambiguë est rejetée.

Les sections auditées `system global`, `system interface` et `system admin` sont interprétées uniquement lorsqu'elles sont top-level. Le parser suit la structure FortiGate `config` / `edit` / `next` / `end` ; les sections réellement non auditées, clés supplémentaires et sous-sections inconnues sont traversées puis ignorées et ne peuvent pas devenir des preuves. Les lookalikes d'une section auditée et les sections auditées exactes sous un wrapper sont rejetés afin qu'aucune preuve dangereuse ne puisse être masquée. UTF-8 et un BOM UTF-8 initial sont acceptés, notamment dans les commentaires et valeurs non utilisées. NUL, contrôles C0/C1 non autorisés, DEL, caractères de format invisibles et séparateurs Unicode dangereux sont rejetés.

La valeur `hostname` doit respecter une syntaxe DNS/hostname (labels de 1 à 63 caractères, lettres/chiffres/tirets, longueur totale maximale de 253 caractères). Une valeur vide ou générique `fortigate` reste un constat `FAIL`; une valeur lexicalement malformée est rejetée.

Le contrôle WAN identifie les interfaces dont le nom commence par `wan` ou dont `set role wan` est explicitement présent. Les zones et l'appartenance SD-WAN sont projetées depuis la structure FortiOS et restent fail-closed lorsqu'une référence est absente ou ambiguë.

Le vocabulaire `allowaccess` reconnu par ce tracer est borné aux valeurs FortiOS connues suivantes : `fabric`, `fgfm`, `ftm`, `http`, `https`, `ping`, `probe-response`, `radius-acct`, `snmp`, `speed-test`, `ssh` et `telnet`. Une valeur inconnue invalide la preuve et produit `UNKNOWN` afin d'éviter un faux `PASS`.

Le contrôle MFA ne conclut `PASS` que pour les méthodes actuellement reconnues (`fortitoken`, `email`, `sms`) ; toute autre valeur produit `UNKNOWN` jusqu'à validation métier.

## Architecture

```text
HTTPS :443
   │
   ▼
┌──────────────────────────────────────┐
│ Conteneur unique Vysion             │
│                                      │
│ Nginx non-root :8443                │
│ ├─ TLS et headers                   │
│ ├─ limite upload et timeouts        │
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
           volume vysion-reports
```

Décision HTTPS : `docs/decisions/0001-single-container-http-edge.json`.

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

```bash
docker compose config --quiet
docker compose build --pull
```

Le démarrage nécessite un certificat et une clé hors Git :

```text
/opt/vysion/tls/tls.crt
/opt/vysion/tls/tls.key
```

Aucun déploiement Portainer n'est autorisé par la création de ce socle. La méthode future unique sera Portainer Git Stack après validation explicite.

## Données et confidentialité

Ne jamais versionner :

- configurations FortiGate importées ;
- rapports générés ;
- certificats ou clés ;
- variables d'instance ;
- templates ou assets hérités ;
- données client réelles.

Les réponses API contenant un rapport imposent `Cache-Control: no-store, private`.

Les exports sont disponibles tant que le rapport JSON canonique n'a pas expiré :

```text
/api/reports/{uuid}.json
/api/reports/{uuid}.docx
/api/reports/{uuid}.xlsx
```

L'export XLSX neutralise les préfixes de formule dans toutes les valeurs textuelles contrôlables par
un fichier importé. Les exports ne contiennent aucune macro.

Les fixtures des tests sont synthétiques et intégrées aux tests Python.

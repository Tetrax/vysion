# Vysion v2 — socle

Vysion v2 est le nouveau socle interne SNS Security d'audit de configurations FortiGate. Il part d'un historique Git neuf et n'importe aucun code, template Office, rapport ou asset sensible de l'ancien Vysion.

## Périmètre livré

- parser FortiGate minimal et neuf, fail-closed dans les sections auditées ;
- modèles Pydantic immuables et statuts `PASS`, `FAIL`, `UNKNOWN`, `ERROR` ;
- registre modulaire de trois contrôles représentatifs : hostname, SSH WAN, MFA administrateur ;
- API FastAPI d'upload et de téléchargement JSON / DOCX / XLSX ;
- stockage par UUID v4 avec timestamps UTC, TTL, purge au démarrage, avant écriture et à la lecture ;
- adaptateur FortiGuard fail-closed (`UNKNOWN` ou `ERROR`, jamais `PASS` implicite) ;
- interface React minimale compilée au build, avec téléchargement des trois formats ;
- un Dockerfile multi-stage, un conteneur, un service Compose et un volume ;
- Nginx interne pour TLS, limites HTTP, headers, statiques et proxy `/api` ;
- FastAPI accessible uniquement sur `127.0.0.1` dans le conteneur.

Ce socle ne porte volontairement pas toutes les règles legacy. Le rapport JSON typé est la source
canonique persistée sous UUID/TTL ; les fichiers DOCX et XLSX sont générés à la demande depuis ce
même modèle, sans template ni asset legacy et sans copie persistante supplémentaire.

Une section nécessaire absente ou vide produit `UNKNOWN`, jamais un `PASS`. Une interface WAN sans preuve `allowaccess` produit également `UNKNOWN`. Une configuration tronquée, un bloc audité top-level dupliqué, une structure imbriquée dans une section auditée, une mutation non interprétée, une directive dupliquée ou malformée, une directive placée hors entrée, ou une clé/valeur `allowaccess` non supportée est rejetée plutôt qu'auditée partiellement.

Les sections auditées `system global`, `system interface` et `system admin` doivent être top-level. Le tracer V2 rejette toute sous-section `config`, y compris sous une section inconnue : aucun wrapper ne peut donc masquer une preuve. Un lexer commun valide `config`, `edit` et `set` sans décodage d'échappement : ASCII imprimable uniquement, guillemets doubles autour d'un token entier, séparateurs whitespace explicites, aucun backslash ni whitespace terminal de ligne, noms de section composés de mots alphanumériques/tirets. Leur nom est canonicalisé avant classification ; toute forme ressemblant à une section auditée sans être exactement égale est rejetée comme ambiguë.

La valeur `hostname` doit respecter une syntaxe DNS/hostname (labels de 1 à 63 caractères, lettres/chiffres/tirets, longueur totale maximale de 253 caractères). Une valeur vide ou générique `fortigate` reste un constat `FAIL`; une valeur lexicalement malformée est rejetée.

Le contrôle WAN du tracer reconnaît uniquement les interfaces dont le nom commence par `wan`. La détection par rôle, zone ou SD-WAN fait partie de la migration métier future et ce socle ne revendique donc pas l'équivalence fonctionnelle avec Vysion v1.

Le vocabulaire `allowaccess` accepté par ce tracer est volontairement borné aux valeurs FortiOS connues suivantes : `fabric`, `fgfm`, `ftm`, `http`, `https`, `ping`, `probe-response`, `radius-acct`, `snmp`, `speed-test`, `ssh` et `telnet`. Une valeur inconnue est rejetée afin d'éviter un faux `PASS`.

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

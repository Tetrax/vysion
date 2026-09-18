# Résumé du projet Vysion – FortiGate Audit

## Finalité

Vysion est un outil interne de SNS Security qui analyse une sauvegarde de configuration FortiGate au format `.conf`. Il extrait les informations utiles du pare-feu, exécute un ensemble de contrôles de conformité et produit deux livrables en français :

- un rapport Excel détaillé ;
- un rapport Word présentant les constats et les risques.

L'application actuellement utilisée est une application web. L'ancienne application de bureau Tkinter est conservée dans `legacy/` uniquement comme archive et n'est ni importée ni déployée.

## Parcours utilisateur

L'interface guide l'utilisateur en six états successifs :

1. import d'un fichier FortiGate `.conf` ;
2. lecture des métadonnées et saisie des renseignements client (client, site, numéro de série, fin de licence et uptime) ;
3. sélection des interfaces, zones et zones SD-WAN considérées comme WAN, avec présélection selon le rôle détecté ;
4. choix des options d'audit : licence UTM, présence d'un lien MPLS/L2L, redondance du câblage HA et nombre de règles sans correspondance ;
5. exécution de l'audit ;
6. affichage d'un résumé, des avertissements, d'une courte liste de contrôles de base non conformes, puis téléchargement des rapports Excel et Word.

Le pourcentage affiché par l'interface pendant l'audit est simulé côté navigateur ; il ne représente pas une remontée de progression réelle du serveur.

## Architecture

```text
Navigateur React/Vite
        |
        | HTTP multipart (/api/upload et /api/audit)
        v
API FastAPI
        |
        +-- lecture et orchestration des contrôles
        |   `backend/app/audit/services.py`
        |
        +-- moteur historique d'audit (environ 12 000 lignes)
        |   `backend/app/audit/legacy_functions.py`
        |
        +-- adaptateurs de génération Excel et Word
            `backend/app/audit/reports.py`
                    |
                    v
             répertoire de rapports persistant
```

### Frontend

- React 18, TypeScript et Vite.
- L'essentiel de l'interface et de son état se trouve dans `modern_audit_app/frontend/src/App.tsx`.
- En développement, Vite tourne sur le port `5173` et relaie `/api` vers FastAPI sur le port `8000`.
- En production, le frontend compilé est servi directement par FastAPI : l'interface et l'API ont donc la même origine.

### Backend

- FastAPI reçoit les fichiers et les options sous forme de formulaire multipart.
- Le fichier de configuration est écrit temporairement, lu par le moteur d'audit, puis supprimé en fin de traitement.
- `services.py` appelle les fonctions historiques dans l'ordre prévu par l'ancienne application et rassemble leurs résultats dans un dictionnaire commun.
- Chaque contrôle est protégé par un appel tolérant aux erreurs : une défaillance isolée ajoute un avertissement et renvoie une valeur non conforme par défaut, sans nécessairement interrompre tout l'audit.
- `reports.py` traduit ce dictionnaire en longues listes d'arguments attendues par les générateurs historiques Excel et Word.
- Les ressources nécessaires aux rapports (modèles, logos, images et tableur de fin de vie des modèles) sont dans `modern_audit_app/backend/Références/`.

## Contrôles réalisés

Le service expose actuellement 57 indicateurs dont le nom se termine par `_conform`. Les contrôles couvrent notamment :

- version FortiOS, vulnérabilités CVE et fin de vie du modèle ;
- comptes administrateurs, MFA, PKI, LDAPS et accès d'administration ;
- ports d'administration et protocoles HTTP/HTTPS/SSH exposés sur les WAN ;
- synchronisation FortiManager/FortiAnalyzer, sauvegardes et journaux ;
- règles de pare-feu, objets inutilisés, VIP/virtual servers, Geo-IP, ISDB et CTI ;
- SD-WAN, routes blackhole, SIP ALG, FortiGuard et FortiSandbox ;
- haute disponibilité, reprise de session, redondance et override ;
- VPN SSL et IPsec (IKE, Diffie-Hellman, algorithmes, split tunneling) ;
- profils UTM : antivirus, IPS, filtrage web/DNS/mail, App Control et inspection SSL/SSH ;
- FortiAP et Wi-Fi : modèles obsolètes, SSID, bande 5 GHz, DARRP, handoff, TIM, canaux et short guard interval.

La documentation historique parle parfois de « 67+ contrôles ». Le code d'orchestration courant contient 57 clés de conformité ; ce nombre est celui renvoyé comme total par l'API. L'écran de résultat ne détaille qu'une sélection de 9 contrôles de base, tandis que les rapports contiennent le résultat complet.

## API

| Méthode et route | Rôle |
|---|---|
| `GET /health` | Sonde de disponibilité du service |
| `POST /api/upload` | Valide et analyse le `.conf`, puis retourne hostname, version, modèle, interfaces et zones |
| `POST /api/audit` | Exécute les contrôles, génère les deux rapports et retourne le résumé ainsi que les liens de téléchargement |
| `GET /api/download/{filename}` | Télécharge un rapport généré ; le nom est contrôlé pour empêcher une traversée de répertoires |

## Exécution et déploiement

### Déploiement recommandé

À la racine du dépôt :

```bash
cp .env.example .env
docker compose up -d --build
```

L'image Docker est construite en deux étapes : Node 20 compile le frontend, puis Python 3.12 exécute l'ensemble avec un utilisateur non privilégié. Un seul conteneur publie normalement l'application sur `http://localhost:8000`.

Les rapports sont stockés dans le volume Docker nommé `vysion-reports`, afin de survivre aux redémarrages et aux reconstructions. Les variables principales sont :

- `VYSION_PORT` : port publié sur l'hôte, `8000` par défaut ;
- `CORS_ORIGINS` : origines autorisées si l'interface est hébergée séparément ;
- `REPORTS_DIR` : dossier d'écriture des rapports côté backend ;
- `FRONTEND_DIR` : dossier du frontend compilé servi par FastAPI.

### Développement local

Le backend peut être lancé avec Uvicorn sur le port `8000`, et le frontend avec `npm run dev` sur le port `5173`. `modern_audit_app/start.bat` automatise ce démarrage sous Windows. `docker-compose.dev.yml` fournit aussi un environnement à rechargement automatique avec montage du code source.

## Dépendances principales

- Backend : Python, FastAPI, Uvicorn, Pydantic, `python-multipart`.
- Analyse et rapports : `openpyxl`, `python-docx`, pandas, Pillow.
- Accès réseau et parsing HTML : Requests et Beautiful Soup.
- Frontend : React, React DOM, TypeScript et Vite.
- Des dépendances MSAL sont encore présentes, mais semblent appartenir à du code hérité ou inutilisé.

## Points d'attention

### Sécurité et données

- L'application ne possède aucune authentification. Elle ne doit pas être exposée directement sur Internet ou sur un réseau non maîtrisé.
- Les fichiers `.conf` et les rapports contiennent des données client sensibles. Ils ne doivent pas être versionnés.
- Tous les utilisateurs pouvant joindre le service peuvent lancer un audit et télécharger un rapport s'ils en connaissent le nom.
- Le volume `vysion-reports` contient des livrables client et doit être sauvegardé et protégé.

### Fiabilité

- Le contrôle des CVE repose actuellement sur une page FortiGuard protégée contre les robots. Le code détecte le cas où la vérification est impossible et demande une revue manuelle, mais la solution durable est d'utiliser l'API PSIRT de Fortinet.
- Il n'existe pas de tests automatisés dans le dépôt malgré la présence de `pytest` dans les dépendances. Les changements sont validés manuellement avec une configuration connue et par lecture des rapports.
- Le moteur principal est un fichier historique monolithique d'environ 12 000 lignes et 98 fonctions. Les signatures très longues des générateurs de rapports rendent les évolutions fragiles.
- Certaines documentations secondaires ne sont plus totalement synchronisées avec le code réel, notamment le nombre de contrôles et l'état du frontend.

## Repères dans le dépôt

| Chemin | Rôle |
|---|---|
| `README.md` | Documentation opérationnelle principale |
| `docker-compose.yml` | Déploiement dans un conteneur unique avec volume persistant |
| `docker-compose.dev.yml` | Développement conteneurisé avec rechargement automatique |
| `modern_audit_app/Dockerfile` | Construction du frontend et de l'image Python de production |
| `modern_audit_app/backend/app/main.py` | Routes FastAPI, CORS, téléchargement et service du frontend |
| `modern_audit_app/backend/app/audit/services.py` | Orchestration des contrôles et agrégation des résultats |
| `modern_audit_app/backend/app/audit/legacy_functions.py` | Moteur d'analyse et générateurs historiques réellement utilisés |
| `modern_audit_app/backend/app/audit/reports.py` | Passage des résultats aux générateurs Excel et Word |
| `modern_audit_app/frontend/src/App.tsx` | Assistant web complet |
| `modern_audit_app/backend/Références/` | Modèles, logos et données de référence indispensables |
| `modern_audit_app/docs/TODO.md` | Priorités techniques connues |
| `legacy/` | Ancienne application Tkinter archivée, non déployée |

## Priorités techniques déjà identifiées

1. remplacer le scraping FortiGuard par l'API Fortinet PSIRT ;
2. ajouter une configuration FortiGate anonymisée de test et des tests sur le parsing et les contrôles critiques ;
3. décider et mettre en œuvre le besoin d'authentification pour le déploiement ;
4. retirer le code et les dépendances devenus inutiles (`legacy_adapter.py`, anciens réglages, `fix_imports.py`, MSAL si confirmé) ;
5. découpler progressivement le moteur monolithique et remplacer les appels de rapport à très nombreux arguments par des structures typées.

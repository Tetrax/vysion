# Scope du projet Vysion

Vysion est un outil interne SNS Security qui audite des sauvegardes de
configuration FortiGate (`.conf`), exécute 57 contrôles de conformité et génère
des rapports Excel et Word en français destinés aux clients.

Les échanges et les contenus produits pour ce projet doivent être en français.

## Ce qui tourne réellement

Le code de l'application est uniquement sous `modern_audit_app/` :

| Chemin | Rôle |
|---|---|
| `backend/app/main.py` | Application FastAPI, quatre endpoints et service de l'interface compilée |
| `backend/app/audit/legacy_functions.py` | Moteur d'audit d'environ 12 000 lignes et 57 fonctions `verifier_*` |
| `backend/app/audit/services.py` | `run_complete_audit()`, qui appelle tous les contrôles |
| `backend/app/audit/reports.py` | Passage des résultats aux générateurs Excel et Word |
| `backend/app/audit/models.py` | Modèles des options d'audit |
| `backend/Références/` | Logos, modèles de documents et classeur EOL |
| `frontend/src/App.tsx` | Interface complète sous forme d'assistant en six étapes |

## Le dossier `legacy/` n'est pas utilisé

`legacy/` contient l'application Tkinter d'origine (`main_audit.py`) et un ancien
instantané. Rien dans ce dossier ne tourne, rien n'est importé par l'application
et ce dossier n'est pas copié dans l'image Docker. Il s'agit uniquement d'une
archive de référence.

`legacy_functions.py` est une copie du moteur d'audit extrait de
`main_audit.py`. Les deux versions ont divergé depuis. En conséquence :

- ne jamais modifier un fichier de `legacy/` ;
- ne pas se baser sur `legacy/main_audit.py` pour déterminer le comportement
  actuel : `modern_audit_app/backend/app/audit/legacy_functions.py` fait foi ;
- utiliser éventuellement l'ancienne version pour comprendre une intention
  d'origine, et uniquement dans ce but.

## La version Docker doit rester cohérente

L'application est déployée en interne sous forme d'image Docker. Une seule
image sert l'API et l'interface sur le port `8000`.

| Chemin | Rôle |
|---|---|
| `modern_audit_app/Dockerfile` | Construction en deux étapes : Node compile le frontend, puis `python:3.12-slim` exécute le backend |
| `docker-compose.yml` | Déploiement |
| `docker-compose.dev.yml` | Développement par bind mount avec rechargement automatique |
| `.env.example` | Variables d'environnement documentées |

Après chaque modification, vérifier son impact sur l'image Docker et le signaler
explicitement :

- **Nouvelle dépendance Python** : l'ajouter à
  `backend/requirements.txt` avec une version figée. L'image installe uniquement
  depuis des wheels, sans compilateur. Utiliser Python 3.12 et non Python 3.13,
  car pandas 2.2.3 ne possède pas de wheel pour Python 3.13.
- **Nouvelle dépendance frontend** : maintenir `package.json` et
  `package-lock.json` cohérents. L'image exécute `npm ci`, qui échoue si le
  fichier de verrouillage est décalé.
- **Nouvelle variable d'environnement** : la déclarer à quatre endroits : sa
  lecture dans le code, `docker-compose.yml`, `.env.example` et le tableau
  Configuration du `README.md`.
- **Nouveau fichier dans `Références/`** : il est automatiquement copié dans
  l'image, mais doit être suivi par Git pour ne pas rester uniquement sur la
  machine locale.
- **Nouvelle route API** : la déclarer avant le montage des fichiers statiques à
  la fin de `main.py`. Ce montage capture toutes les URL et masquerait une route
  déclarée après lui.
- **Nouveau fichier écrit par l'application** : l'écrire dans `REPORTS_DIR` ou
  sous `/var/lib/vysion`. Dans le conteneur, `/opt/vysion` appartient à `root`
  tandis que l'application tourne avec l'UID `10001`; une écriture à côté des
  sources échoue donc avec `permission denied`.
- **Déplacement d'un rapport** : utiliser `shutil.move`, jamais `Path.rename`,
  car le déplacement peut traverser deux systèmes de fichiers lorsque le volume
  Docker est monté.

## Ajouter ou modifier un contrôle : chaîne complète

Un contrôle traverse quatre fichiers. Si seuls trois d'entre eux sont mis à
jour, le contrôle peut ne pas apparaître ou afficher le résultat d'un autre
contrôle.

1. `legacy_functions.py` : fonction `verifier_*` renvoyant un tuple
   `(message, conforme)`. Respecter exactement la forme des fonctions voisines.
2. `services.py` : appel via `safe_call()`, avec un `default=` de la même forme
   que le tuple, puis ajout du résultat au dictionnaire retourné.
3. `main.py` : entrée dans la liste `checks`, avec le bon intitulé et les bonnes
   clés de résultat.
4. `reports.py` : les générateurs Excel et Word reçoivent respectivement environ
   160 et 110 arguments positionnels. Une valeur insérée au mauvais rang décale
   tout ce qui suit sans nécessairement provoquer d'erreur.

Si le contrôle nécessite une saisie de l'utilisateur, mettre également à jour :

- `models.py` ;
- `frontend/src/App.tsx` ;
- `frontend/src/types.ts`.

## Règles de contribution

- Ne pas réécrire ou restructurer `legacy_functions.py`. Lire la fonction
  concernée, la modifier sur place et laisser le reste inchangé.
- Une demande correspond à un seul sujet. Ne pas corriger au passage des
  éléments qui n'ont pas été demandés.
- Ne modifier aucun fichier non mentionné dans la demande. Si un autre fichier
  semble devoir changer, prévenir avant de le modifier.
- Lorsqu'une demande porte sur la logique d'audit, expliquer d'abord les
  changements envisagés et leur raison, sans modifier le code. Attendre la
  validation avant l'implémentation.
- Tous les textes destinés aux rapports doivent être en français, notamment les
  messages de contrôle, intitulés et recommandations.
- Le projet ne possède aucun test automatique. Ne pas annoncer une vérification
  qui n'a pas réellement été exécutée et indiquer explicitement les contrôles
  manuels que l'utilisateur doit effectuer.

## Données clients

Ne jamais demander une configuration FortiGate réelle ou un rapport d'audit
client, et ne jamais en inclure dans les réponses. Ces fichiers peuvent contenir
des noms d'établissements, des adresses IP, des règles de pare-feu et des numéros
de série. Lorsqu'un exemple est nécessaire, générer une configuration fictive.

Ne jamais proposer de commiter :

- `modern_audit_app/backend/reports/` ;
- un fichier `.conf` ;
- `token_cache.bin` ;
- `.env` ;
- un environnement `.venv` ;
- un exécutable `.exe`.

## Problèmes connus

- Le contrôle CVE analyse une page de `fortiguard.com`, désormais placée derrière
  une protection anti-robots qui répond avec un statut HTTP 200 et une page de
  vérification. Le code détecte ce cas et renvoie « vérification impossible » au
  lieu de conclure à tort que le firmware est sain. La correction durable
  consiste à utiliser l'API PSIRT de Fortinet, ce qui nécessite des identifiants.
- L'application déployée ne possède aucune authentification.
- `fix_imports.py`, `legacy_adapter.py` et l'import `msal` sont du code mort.

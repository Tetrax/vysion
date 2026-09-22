# Exploitation du socle Vysion v2

## Source de vérité

- repository GitHub privé unique ;
- `compose.yml` versionné unique, servi par la Git Stack Portainer unique ;
- image GHCR immuable référencée par digest OCI `ghcr.io/tetrax/vysion@sha256:<64 hex>`, jamais par tag : la CI publie en plus un tag humain `sha-<commit complet>` et lie l'image à son commit par le label OCI `org.opencontainers.image.revision`, vérifié à la publication ;
- aucun `docker compose up/down` dans le parcours normal : la bascule et le rollback utilisent Portainer, l'arrêt de l'ancienne instance est la seule opération hôte documentée ;
- aucun secret dans Git : identifiants Git et GHCR saisis dans Portainer uniquement.

## Frontière réseau et TLS

- le Nginx de l'hôte termine déjà TLS pour `vysion.valdev.me` (Let's Encrypt) et fait `proxy_pass http://127.0.0.1:8080` ;
- dans le conteneur, Nginx non-root écoute en **HTTP clair sur le port 8080**, accessible uniquement via le bind hôte ;
- aucun certificat, aucune clé et aucun montage TLS dans le conteneur : la configuration HTTP est versionnée (`deploy/nginx.conf`) et copiée dans l'image, jamais montée depuis un fichier non versionné ;
- FastAPI reste sur `127.0.0.1:8000` dans le conteneur ;
- le seul ingress est le bind `${BIND_ADDRESS}:${HOST_PORT}` ; pas d'IP Docker statique, pas de réseau externe `Subnet-Docker`.

## Variables de déploiement

| Variable | Rôle | Valeur |
| --- | --- | --- |
| `IMAGE_DIGEST` | digest OCI `sha256:<64 hex>` de l'image déployée (voir « Obtenir et saisir la référence immuable ») | **requis**, aucune valeur par défaut |
| `BIND_ADDRESS` | IP publiée sur l'hôte (IP uniquement) | `127.0.0.1` |
| `HOST_PORT` | port publié sur l'hôte (port uniquement) | `8080` en production, `18080` pendant la validation |
| `VYSION_REVISION` | révision compilée dans l'image | renseignée par CI |

`BIND_ADDRESS` et `HOST_PORT` sont indépendants : on ne change jamais l'IP pour changer le port.

`IMAGE_DIGEST` est le digest complet `sha256:<64 hex>` de l'image : Compose ne peut rendre que `ghcr.io/tetrax/vysion@${IMAGE_DIGEST}`, une référence adressée par le contenu. Un tag n'est tout simplement pas exprimable à cet endroit. Sans `IMAGE_DIGEST` ou avec une valeur vide, la pile refuse de se résoudre (interpolation Compose). Pour toute autre valeur non conforme — `latest`, `sha-latest`, un SHA court, une valeur majuscule ou non hexadécimale — Compose rend la référence mais Docker lui-même la refuse à l'acquisition de l'image (`invalid reference format` / `invalid checksum digest format`), avant tout contact au registre et avant toute création de conteneur : aucun service ne peut devenir `healthy`. Une image construite localement ne peut pas non plus usurper la référence déployée, Docker refusant de taguer un digest (`build tag cannot contain a digest`). Le contrat CI rejette en plus tout rendu différent de `ghcr.io/tetrax/vysion@sha256:[0-9a-f]{64}` et toute référence que `docker pull` accepterait.

```bash
# la pile refuse de se résoudre sans le digest d'image
docker compose config --quiet                       # échec attendu
IMAGE_DIGEST= docker compose config --quiet         # échec attendu (valeur vide)
# l'ancien nom mutable ne résout plus rien
IMAGE_TAG=latest docker compose config --quiet      # échec attendu
# cible finale (IMAGE_DIGEST = sha256:<64 hex> publié par la CI)
HOST_PORT=8080  IMAGE_DIGEST=sha256:<64 hex> docker compose config --quiet
# validation temporaire à côté de l'instance en service
HOST_PORT=18080 IMAGE_DIGEST=sha256:<64 hex> docker compose config --quiet
```

## Obtenir et saisir la référence immuable

1. relever le commit à déployer (`git rev-parse HEAD`, 40 hex) et vérifier que la CI **exact-head** de ce commit est entièrement verte ;
2. obtenir le digest `sha256:<64 hex>` publié par la CI pour ce commit, au choix :
   - journal de l'étape « Verify the commit link and print the immutable digest » du job **Publish container image** : la ligne affichée est `ghcr.io/tetrax/vysion@sha256:<64 hex>` — copier la partie après `@` ;
   - `docker buildx imagetools inspect ghcr.io/tetrax/vysion:sha-<commit complet>` → ligne `Digest: sha256:<64 hex>` ;
3. le lien digest ↔ commit est prouvé à la publication : la même étape CI compare `org.opencontainers.image.revision` du push réel à `github.sha` et refuse sinon ;
4. saisir dans Portainer, variables de la stack : `IMAGE_DIGEST=sha256:<64 hex>`, `HOST_PORT`, `BIND_ADDRESS` (plus les variables métier) ;
5. contrôler le rendu avant déploiement : `HOST_PORT=<port> IMAGE_DIGEST=sha256:<64 hex> docker compose config --quiet`.

## Vérifier l'image réellement exécutée

```bash
# la référence configurée du conteneur : doit être ghcr.io/tetrax/vysion@sha256:<64 hex>
docker inspect --format '{{.Config.Image}}' vysion-vysion-1
# le digest réellement présent dans le daemon, attaché au nom de l'image
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
  "$(docker inspect --format '{{.Image}}' vysion-vysion-1)"
# le commit attendu : preuve digest <-> commit via le label OCI
docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' vysion-vysion-1
```

Le premier doit être la saisie `IMAGE_DIGEST`, le troisième doit être le commit 40 hex déployé. Un digest local reconstruit (RepoDigests vide) ou un label absent signe une image qui n'a pas été publiée par la CI : rollback.

## Volume des rapports

- le volume est **externe** et porte exactement le nom `vysion-reports` (`external: true`) : Compose ne le crée, ne le renomme et ne le supprime jamais ;
- c'est le même volume que celui de l'instance en service, ce qui assure la continuité des rapports ;
- une pile de validation `HOST_PORT=18080` attache donc aussi `vysion-reports` : les écritures sont limitées aux UUID de rapport et la purge ne touche que les rapports expirés (TTL), jamais un rapport en cours de validité ;
- aucune sauvegarde n'est stockée dans ce volume (voir ci-dessous).

## Healthcheck

Le healthcheck de l'image et de la pile appelle :

```text
http://127.0.0.1:8080/healthz
```

La requête traverse Nginx puis est proxifiée vers `127.0.0.1:8000/api/health` : un healthcheck `healthy` prouve que Nginx répond **et** que FastAPI répond derrière lui.

## Logs

- accès HTTP Nginx : stdout ;
- erreurs Nginx : stderr ;
- événements FastAPI/Uvicorn : stdout/stderr ;
- access-log Uvicorn désactivé pour éviter le double journal d'accès ;
- le format d'accès Nginx ne journalise ni `$uri`, ni `$request_uri`, afin de ne pas exposer les UUID de rapport ; il conserve méthode, statut, volume, durée et user-agent.

## Cycle de vie des rapports

- les rapports utilisent un UUID v4 et des timestamps UTC timezone-aware ;
- les réponses de création et de téléchargement imposent `Cache-Control: no-store, private` ;
- un rapport expiré est refusé et supprimé lors de sa lecture ;
- le stockage purge aussi les rapports expirés au démarrage de l'application et avant chaque nouvelle écriture ;
- la purge ne remplace pas une politique séparée de rétention des sauvegardes du volume.

## Checklist de bascule vers la Git Stack Portainer

Les étapes sont séquencées. Un gate non vert interdit de passer à l'étape suivante.

### G0 — conditions d'arrêt (gate d'entrée)

- PR vérifiée fusionnée sur `main`, CI verte au HEAD exact ;
- image `ghcr.io/tetrax/vysion:sha-<commit complet>` publiée par CI et visible dans GHCR, digest `sha256:<64 hex>` relevé (journal CI ou `docker buildx imagetools inspect`) ;
- sauvegarde du volume réalisée **et** restaurée avec succès sur un volume jetable (G1) ;
- credential Git et credential GHCR opérationnels dans Portainer (G2) ;
- pile de validation saine sur `HOST_PORT=18080` (G3) ;
- commandes de rollback (G7) écrites à portée de main.

### G1 — sauvegarde du volume et test de restauration

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="$HOME/vysion-backups"
mkdir -p "$BACKUP_DIR"

docker run --rm -v vysion-reports:/data:ro -v "$BACKUP_DIR":/backup alpine:3.20 \
  tar czf "/backup/vysion-reports-${STAMP}.tar.gz" -C /data .
sha256sum "$BACKUP_DIR/vysion-reports-${STAMP}.tar.gz"

# test de restauration sur un volume jetable, jamais sur vysion-reports
CHECK=vysion-reports-restore-check
docker volume create "$CHECK"
docker run --rm -v "$CHECK":/data -v "$BACKUP_DIR":/backup alpine:3.20 \
  tar xzf "/backup/vysion-reports-${STAMP}.tar.gz" -C /data
docker run --rm -v "$CHECK":/data alpine:3.20 sh -c 'ls -la /data | head -20'
docker volume rm "$CHECK"
```

**Gate G1** : l'archive existe, son sha256 est noté, et le contenu restauré correspond (au moins un fichier de rapport). Sans ce test, la sauvegarde n'est pas considérée comme valide.

### G2 — credentials Git et GHCR (dans Portainer, jamais dans Git)

1. créer dans Portainer un credential Git avec un PAT GitHub de portée `repo` (lecture du repository privé) ;
2. créer dans Portainer un registre `ghcr.io` avec un PAT de portée `read:packages` ;
3. vérifier dans Portainer que l'image `ghcr.io/tetrax/vysion:sha-<commit complet>` est listable/pullable.

**Gate G2** : les deux credentials sont en place et aucune valeur n'a été commitée ni envoyée dans le repository.

### G3 — validation temporaire sur `HOST_PORT=18080`

1. `HOST_PORT=18080 IMAGE_DIGEST=sha256:<64 hex> docker compose config --quiet` (contrat de la pile) ;
2. déployer dans Portainer une pile temporaire `vysion-smoke` depuis le même `compose.yml`, avec `HOST_PORT=18080`, `BIND_ADDRESS=127.0.0.1`, `IMAGE_DIGEST=sha256:<64 hex>` ;
3. contrôles :
   - `docker inspect --format '{{.State.Health.Status}}' <conteneur>` → `healthy` ;
   - `docker inspect --format '{{.Config.Image}}' <conteneur>` → `ghcr.io/tetrax/vysion@sha256:<64 hex>` saisi ;
   - `docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' <conteneur>` → commit 40 hex attendu ;
   - `curl -s http://127.0.0.1:18080/healthz` → JSON `status: ok` ;
   - UI chargée sur `http://127.0.0.1:18080/` ;
   - création d'audit avec un export JSON, DOCX et XLSX ;
   - aucun montage TLS, volume monté sur `vysion-reports` ;
4. retirer la pile `vysion-smoke` (le volume externe `vysion-reports` n'est pas touché) et vérifier qu'aucun conteneur ni port `18080` ne subsiste.

**Gate G3** : les contrôles sont verts. L'instance en service sur `8080` n'a pas été modifiée pendant toute cette étape.

### G4 — arrêt de l'ancienne instance

> Étape hôte exceptionnelle, hors parcours normal. L'instance en service est conservée comme **conteneur de repli**, pas supprimée.

```bash
docker stop vysion-vysion-1
docker rename vysion-vysion-1 vysion-legacy-fallback
```

- le Nginx de l'hôte n'est pas modifié : il pointe déjà sur `127.0.0.1:8080`, port libéré à l'arrêt ;
- le volume `vysion-reports` et l'image `vysion:7101b32dbde41c2ff4510dcd7f2030ba06b675bf` restent intacts ;
- **ne pas** exécuter `docker compose up/down` depuis l'ancien répertoire de travail : ses labels visent aussi le projet `vysion` et tueraient la nouvelle pile.

**Gate G4** : le port `8080` est libre (`ss -ltnp | grep 8080` vide) et le conteneur de repli est stopped, jamais supprimé.

### G5 — déploiement final sur `HOST_PORT=8080`

1. `HOST_PORT=8080 IMAGE_DIGEST=sha256:<64 hex> docker compose config --quiet` ;
2. dans Portainer, déployer la Git Stack `vysion` depuis le repository, chemin `compose.yml`, variables : `IMAGE_DIGEST=sha256:<64 hex>`, `HOST_PORT=8080`, `BIND_ADDRESS=127.0.0.1` (plus les variables métier si nécessaires) ;
3. ne jamais utiliser `latest` : toute référence non immuable est refusée par Docker avant le démarrage du conteneur.

### G6 — contrôles post-bascule

- `docker inspect --format '{{.State.Health.Status}}' vysion-vysion-1` → `healthy` ;
- `docker inspect --format '{{.Config.Image}}' vysion-vysion-1` → `ghcr.io/tetrax/vysion@sha256:<64 hex>` déployé ;
- `docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' vysion-vysion-1` → commit 40 hex attendu (voir « Vérifier l'image réellement exécutée ») ;
- `curl -s http://127.0.0.1:8080/healthz` → JSON `status: ok` avec la bonne révision ;
- `curl -sI https://vysion.valdev.me/` depuis l'extérieur → réponse TLS du Nginx hôte puis 200 ;
- UI chargée, création d'audit, exports JSON / DOCX / XLSX ;
- `docker inspect` : volume monté `vysion-reports`, `ReadonlyRootfs`, `CapDrop: ALL`, `no-new-privileges`, limites CPU/RAM/PID, bind `127.0.0.1:8080` ;
- aucun conteneur `vysion-smoke-*`, aucun service en écoute sur `18080` ;
- logs Nginx/conteneur sans erreur d'amorçage ni 5xx en chaîne ;
- l'ancien déploiement n'a pas été supprimé (repli disponible).

**Gate de stabilité** : conserver le conteneur de repli au moins 7 jours après validation complète.

### G7 — rollback

**Déclencheurs** (une seule suffit) :

- `healthy` absent plus de 2 minutes après le déploiement, ou status `unhealthy` ;
- `/healthz` ne renvoie pas 200 ;
- UI inaccessible ou erreur 5xx depuis le Nginx hôte ;
- création d'audit ou export JSON/DOCX/XLSX en échec ;
- volume `vysion-reports` non monté dans le conteneur ;
- corruption ou disparition de données dans le volume.

**Actions, dans cet ordre** :

1. **Régression applicative, pile saine** : dans Portainer, remettre `IMAGE_DIGEST=<sha256:<64 hex> du dernier état sain>` (variable `IMAGE_DIGEST` actuellement déployée, visible dans Portainer, ou digest affiché par la CI du commit sain) puis **Update the stack** (jamais de tag mutable). La configuration et le volume ne changent pas.
2. **Pile inutilisable** : dans Portainer, arrêter puis supprimer la stack `vysion` — un volume déclaré `external` n'est jamais supprimé avec la stack — puis restaurer l'ancienne instance :

   ```bash
   docker rename vysion-legacy-fallback vysion-vysion-1
   docker start vysion-vysion-1
   ```

3. vérifier `/healthz`, l'UI et un audit complet ; le Nginx de l'hôte n'a jamais changé de cible ;
4. investiguer la cause avant toute nouvelle tentative, et ne jamais supprimer `vysion-reports` ni l'image `vysion:7101b32dbde41c2ff4510dcd7f2030ba06b675bf` tant que le repli n'est pas caduc ;
5. après stabilisation (7 jours), supprimer définitivement le conteneur de repli.

**Pièges connus**

- le conteneur de repli référence en lecture le fichier hôte `deploy/nginx-container-http.conf` (non versionné) : ne pas le supprimer tant que le repli existe. Sa version versionnée, octet pour octet identique, est `deploy/nginx.conf` dans ce repository ;
- l'ancien répertoire de travail contient un `compose.yml` qui ne correspond plus à l'instance en service : ne pas l'exécuter après la bascule ;
- un rollback applicatif ne supprime, ne renomme ni ne recrée jamais `vysion-reports`.

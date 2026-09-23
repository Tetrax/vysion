# Exploitation du socle Vysion v2

## Source de vérité

- repository GitHub privé unique ;
- `compose.yml` versionné unique, servi par la Git Stack Portainer unique ;
- image GHCR immuable référencée par digest OCI `ghcr.io/tetrax/vysion@sha256:<64 hex>`, jamais par tag : la CI publie en plus un tag humain `sha-<commit complet>` et lie l'image à son commit par le label OCI `org.opencontainers.image.revision`, vérifié à la publication ; la stack de production ne contient volontairement aucune section `build`, car Portainer doit consommer cette image publiée et Docker ne peut pas taguer un build local avec un digest ;
- aucun `docker compose up/down` dans le parcours normal : la bascule et le rollback utilisent Portainer, l'arrêt de l'ancienne instance est la seule opération hôte documentée ;
- aucun secret dans Git : identifiants Git et GHCR saisis dans Portainer uniquement.

## Frontière réseau et TLS

- le Nginx de l'hôte termine déjà TLS pour `vysion.valdev.me` (Let's Encrypt) et fait `proxy_pass http://127.0.0.1:8080` ;
- dans le conteneur, Nginx non-root écoute en **HTTP clair sur le port 8080**, accessible uniquement via le bind hôte ;
- en mode proxy hôte, aucun certificat, aucune clé et aucun montage TLS dans le conteneur : la configuration HTTP est versionnée (`deploy/nginx.conf`) et copiée dans l'image, jamais montée depuis un fichier non versionné (le mode standalone, lui, range ses certificats dans `vysion-certs`) ;
- FastAPI reste sur `127.0.0.1:8000` dans le conteneur ;
- le seul ingress est le bind `${BIND_ADDRESS}:${HOST_PORT}` ; pas d'IP Docker statique, pas de réseau externe `Subnet-Docker`.

## Variables de déploiement

| Variable | Rôle | Valeur |
| --- | --- | --- |
| `IMAGE_DIGEST` | digest OCI `sha256:<64 hex>` de l'image déployée (voir « Obtenir et saisir la référence immuable ») | **requis**, aucune valeur par défaut |
| `BIND_ADDRESS` | IP publiée sur l'hôte (IP uniquement) | `127.0.0.1` |
| `HOST_PORT` | port publié sur l'hôte (port uniquement) | `8080` en production, `18080` pendant la validation |
| `VYSION_REVISION` | révision compilée dans l'image | renseignée par CI |
| `TRUSTED_PROXY_CIDRS` | CIDRs des seules proxies dont l'application accepte les en-têtes transférés (`X-Forwarded-*`, `X-Real-IP`) | défaut `127.0.0.1/32` (**client local uniquement**, ce n'est pas « l'hôte ») : en VPS, à renseigner explicitement avec le hop Docker observé — la requête publiée arrive depuis la passerelle du bridge, jamais depuis `127.0.0.1` — sans subnet imposé (voir « Modes TLS ») ; **obligatoire, sans défaut** dans `compose.proxy.yml` |
| `PUBLIC_ORIGIN` | origine publique de référence : toute mutation `/api/admin/*` (setup, connexion, récupération, certificats) et liens de récupération | vide : dérivée de `VYSION_TLS_HOSTNAME` (port 443) en standalone ; sans valeur, **toute mutation admin est refusée en 503** — jamais dérivée du `Host` |
| `VYSION_VOLUME_PREFIX` | préfixe des noms de volumes externes (isolation des validations et des smokes) | vide : noms stables `vysion-reports`, `vysion-state`, `vysion-certs` |

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

## Volumes (rapports, état, certificats) et isolation des validations

Trois volumes externes, créés **une fois** sur l'hôte — Portainer ne crée jamais un volume déclaré `external` :

```bash
docker volume create vysion-reports
docker volume create vysion-state
docker volume create vysion-certs
```

- `vysion-reports` : rapports UUID/TTL, même volume pour toutes les piles attachées ;
- `vysion-state` : SQLite privé de l'administration (fail-closed) ;
- `vysion-certs` : générations de certificats du mode standalone ;
- la pile ne les crée, ne les renomme et ne les supprime jamais (`external: true`) ;
- `VYSION_VOLUME_PREFIX` (défaut vide) préfixe les noms rendus par Compose : avec le défaut vide les noms restent stables et aucun changement de production n'a lieu. Pour une validation ou un smoke on crée d'abord des volumes dédiés, de sorte qu'aucune écriture n'atteigne jamais les volumes de production :

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
docker volume create vysion-smoke-$STAMP-vysion-state
docker volume create vysion-smoke-$STAMP-vysion-reports
# déployer la pile de validation avec VYSION_VOLUME_PREFIX=vysion-smoke-$STAMP-,
# puis supprimer la pile et ces volumes à la fin de la validation :
docker volume rm vysion-smoke-$STAMP-vysion-state vysion-smoke-$STAMP-vysion-reports
```

- aucune sauvegarde n'est stockée dans ces volumes (voir « Sauvegarde et restauration »).

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

### G1 — sauvegarde cohérente et test de restauration

```bash
BACKUP_DIR="$HOME/vysion-backups"
# quiescence : backup.sh arrête les conteneurs qui montent les volumes visés,
# archive les trois volumes sans écriture possible, puis les redémarre
scripts/backup.sh "$BACKUP_DIR"
ARCHIVE_DIR=$(ls -dt "$BACKUP_DIR"/vysion-* | head -1)
sha256sum "$ARCHIVE_DIR"/*.tar.gz | tee "$ARCHIVE_DIR/SHA256SUMS"

# restauration de contrôle sur des volumes jetables, jamais sur
# vysion-reports / vysion-state / vysion-certs : les archives portent le
# nom de la production (VYSION_BACKUP_PREFIX vide) et la cible est préfixée
CHECK_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
VYSION_BACKUP_PREFIX= VYSION_VOLUME_PREFIX="vysion-smoke-$CHECK_STAMP-" scripts/restore.sh "$ARCHIVE_DIR"
for base in vysion-reports vysion-state vysion-certs; do
  docker run --rm -v "vysion-smoke-$CHECK_STAMP-$base":/data alpine:3.20 \
    sh -c 'ls -la /data | head -20' || true
done
# comparer les empreintes SHA-256 des fichiers restaurés à celles notées
# avant la sauvegarde, puis supprimer ces volumes jetables :
docker volume rm "vysion-smoke-$CHECK_STAMP-vysion-reports" \
  "vysion-smoke-$CHECK_STAMP-vysion-state" "vysion-smoke-$CHECK_STAMP-vysion-certs"
```

**Gate G1** : l'archive existe, ses empreintes sha256 sont notées, et le contenu restauré sur les volumes jetables correspond aux empreintes d'origine. Sans ce test, la sauvegarde n'est pas considérée comme valide. Le nom des archives (`VYSION_BACKUP_PREFIX`, vide pour la production) et le nom des volumes cibles (`VYSION_VOLUME_PREFIX`) sont indépendants ; `scripts/restore.sh` **échoue (exit 1)** lorsqu'aucune archive attendue n'est trouvée, au lieu de signaler une restauration qui n'a rien restauré.

### G2 — credentials Git et GHCR (dans Portainer, jamais dans Git)

1. créer dans Portainer un credential Git avec un PAT GitHub de portée `repo` (lecture du repository privé) ;
2. créer dans Portainer un registre `ghcr.io` avec un PAT de portée `read:packages` ;
3. vérifier dans Portainer que l'image `ghcr.io/tetrax/vysion:sha-<commit complet>` est listable/pullable.

**Gate G2** : les deux credentials sont en place et aucune valeur n'a été commitée ni envoyée dans le repository.

### G3 — validation temporaire sur `HOST_PORT=18080`

1. `HOST_PORT=18080 IMAGE_DIGEST=sha256:<64 hex> docker compose config --quiet` (contrat de la pile) et `VYSION_VOLUME_PREFIX=vysion-smoke-<stamp>- HOST_PORT=18080 IMAGE_DIGEST=sha256:<64 hex> docker compose config --quiet` avec les volumes de validation créés au préalable (`docker volume create vysion-smoke-<stamp>-vysion-state` et `docker volume create vysion-smoke-<stamp>-vysion-reports`) ;
2. déployer dans Portainer une pile temporaire `vysion-smoke` depuis le même `compose.yml`, avec `HOST_PORT=18080`, `BIND_ADDRESS=127.0.0.1`, `IMAGE_DIGEST=sha256:<64 hex>` et `VYSION_VOLUME_PREFIX=vysion-smoke-<stamp>-` : la validation n'écrit **jamais** dans les volumes de production ;
3. contrôles :
   - `docker inspect --format '{{.State.Health.Status}}' <conteneur>` → `healthy` ;
   - `docker inspect --format '{{.Config.Image}}' <conteneur>` → `ghcr.io/tetrax/vysion@sha256:<64 hex>` saisi ;
   - `docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' <conteneur>` → commit 40 hex attendu ;
   - `curl -s http://127.0.0.1:18080/healthz` → JSON `status: ok` ;
   - UI chargée sur `http://127.0.0.1:18080/` ;
   - création d'audit avec un export JSON, DOCX et XLSX ;
   - aucun montage TLS, volumes montés `vysion-smoke-<stamp>-vysion-state` et `vysion-smoke-<stamp>-vysion-reports` (pas les volumes de production) ;
4. retirer la pile `vysion-smoke` puis ses volumes de validation (`docker volume rm vysion-smoke-<stamp>-vysion-state vysion-smoke-<stamp>-vysion-reports`) et vérifier qu'aucun conteneur ni port `18080` ne subsiste.

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
2. relever le hop Docker observé (`docker inspect --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' <conteneur de validation>`) et préparer `TRUSTED_PROXY_CIDRS=<passerelle>/32` ainsi que `PUBLIC_ORIGIN=<origine publique exacte>` (voir « Modes TLS ») ;
3. dans Portainer, déployer la Git Stack `vysion` depuis le repository, chemin `compose.yml`, variables : `IMAGE_DIGEST=sha256:<64 hex>`, `HOST_PORT=8080`, `BIND_ADDRESS=127.0.0.1`, `TRUSTED_PROXY_CIDRS=<passerelle>/32`, `PUBLIC_ORIGIN=<origine publique>` (plus les variables métier si nécessaires) ;
4. ne jamais utiliser `latest` : toute référence non immuable est refusée par Docker avant le démarrage du conteneur.

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
- session administrateur : le cookie `vysion_session` porte le drapeau `Secure` derrière le Nginx hôte (preuve que `TRUSTED_PROXY_CIDRS` porte le hop observé) ;
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

## Surface d'administration (V2)

- URL : `/admin` (SPA servie par nginx via `try_files`), API sous `/api/admin/*` ; première exécution : le formulaire « Configuration initiale » crée l'unique compte administrateur (12 à 1024 octets UTF-8), puis connexion normale ;
- protections : session `vysion_session` (HttpOnly, SameSite=Strict, Secure en HTTPS), jeton `X-CSRF-Token`, `Origin` exact sur toute mutation, verrouillage après échecs et anti-énumération (réponses uniformes puis 429) ;
- **le parcours d'audit reste anonyme** (upload, preview, création d'audit, téléchargements UUID+TTL) : aucune authentification globale n'est installée, non-régression prouvée par `tests/integration/test_admin_api.py` et `tests/integration/test_admin_certificates.py` ;
- SMTP et adresse de récupération : `vysion-admin configure-smtp` (secrets saisis sur stdin, jamais en argument). Sans SMTP, la récupération par courriel reste proprement indisponible ; le recours break-glass est `vysion-admin reset-password` ;
- sessions : liste et révocation depuis le tableau de bord ; changement de mot de passe depuis le tableau de bord (révoque les sessions).

## Modes TLS

- **Proxy hôte (défaut, `VYSION_TLS_BACKEND=none`, VPS Portainer)** : TLS terminé par le Nginx hôte (décision 0006), HTTP loopback 8080 dans le conteneur, allowlist et 403 loopback conservés, aucun volume de certificats — la topologie de l'instance en service ne change pas. **Deux variables explicites à la bascule** :
  - `TRUSTED_PROXY_CIDRS` doit porter le hop Docker **réellement observé** par le conteneur : une requête qui arrive sur le port publié vient de la passerelle du bridge, pas de `127.0.0.1`. Relevez-la sans imposer aucun subnet :

    ```bash
    docker inspect --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' vysion-vysion-1
    # → TRUSTED_PROXY_CIDRS=<passerelle>/32 dans les variables de la stack
    ```

    Sans ce hop de confiance, le `https` déclaré par le Nginx hôte (`X-Forwarded-Proto` transmis en `X-Forwarded-Client-Proto`) est ignoré : le cookie de session administrateur revient **sans** le drapeau `Secure` (preuve par le smoke VPS de la carte, négatif sur le défaut).
  - `PUBLIC_ORIGIN` doit porter l'origine publique exacte du navigateur (par ex. `https://vysion.valdev.me`) : sans elle, **toute mutation `/api/admin/*` est refusée en 503** (setup, connexion, récupération, certificats), la première exécution restant fermée plutôt que d'être réalisée sous une autorité arbitraire.
- **Standalone (`compose.standalone.yml`, `VYSION_TLS_BACKEND=local`, `VYSION_TLS_HOSTNAME` obligatoire)** : TLS terminé dans le conteneur sur 443. Au premier démarrage, l'entrypoint génère un certificat auto-signé de 2 jours (bootstrap) pour rendre l'UI accessible en HTTPS ; importer ensuite le vrai certificat depuis `/admin` : PEM complet + clé, ou PKCS#12 + passphrase. La validation refuse tout certificat expiré/à venir, SAN incompatible, chaîne incohérente ou clé non correspondante (test de chargement TLS réel). L'activation passe par un ticket à usage unique lié à la session et au digest du candidat (300 s), puis `nginx -t` + rechargement + vérification de l'empreinte servie, avec rollback automatique vers la génération précédente en cas d'échec. Une chaîne de type production (feuille + intermédiaires, sans racine — la racine vit chez les clients) est acceptée ; une feuille sans son émetteur ou une chaîne incohérente reste refusée.
- **Proxy externe (`compose.proxy.yml`, `VYSION_TLS_BACKEND=none`)** : TLS terminé par le reverse proxy de l'opérateur, conteneur en HTTP clair sur 8080. `TRUSTED_PROXY_CIDRS` est **obligatoire — aucun défaut silencieux** — et décrit les seules sources dont l'application accepte `X-Forwarded-*` / `X-Real-IP` (couche interne : le Nginx du conteneur rejette les en-têtes clients, réécrit `X-Real-IP` sur l'observation locale et complète `X-Forwarded-For`, uvicorn tourne sans confiance forwarded). `PUBLIC_ORIGIN` fixe l'autorité de toute mutation `/api/admin/*` et des liens de récupération : sans elle, ces mutations sont refusées en 503 — jamais fabriquées depuis un `Host` contrôlable.
- **Helper VPS (`compose.helper.yml`, `VYSION_TLS_BACKEND=helper`, `VYSION_TLS_HOSTNAME` obligatoire)** : TLS terminé par le Nginx hôte comme en mode `none`, mais `/admin` gère réellement le certificat. Le conteneur reste non-root et read-only : il ne parle qu'à la socket Unix privée du service root `vysion-cert-helper`, montée **lecture seule**. Voir « Certificats en mode helper » ci-dessous.

## Certificats en mode helper (VPS administrable)

Certbot reste l'**autorité ACME** (il signe et renouvelle) ; le service root devient l'**autorité servie** (générations, `nginx -t`, rechargement, empreinte relue). Une seule mécanique, donc aucun conflit entre renouvellement automatique et import manuel.

### Installation (une fois)

```bash
# 1. Séquence d'installation idempotente : sources, scripts déployés,
#    unité systemd et TOUS les répertoires que l'unité exige avant démarrage
#    (/var/lib/vysion compris — un ReadWritePaths sans cible existante fait
#    échouer le démarrage du service ; /run/vysion-cert-helper est recréé
#    par systemd après un reboot). Réexécuter ce script est sans effet :
#    /etc/vysion/cert-helper.env n'est jamais écrasé.
sudo deploy/vysion-cert-install.sh
sudo $EDITOR /etc/vysion/cert-helper.env     # VYSION_TLS_HOSTNAME, PUID/PGID, chemins

# 2. Répertoire de socket déjà en place, puis service
sudo systemctl daemon-reload
sudo systemctl enable --now vysion-cert-helper
sudo -u root PYTHONPATH=/opt/vysion/src python3 -m vysion.certhelper ping \
  --socket /run/vysion-cert-helper/helper.sock

# 3. Import idempotent du certificat déjà servi (génération 1)
sudo /opt/vysion/deploy/vysion-cert-bootstrap.sh

# 4. Bascule du Nginx hôte vers l'autorité helper (idempotente, avec rollback)
sudo /opt/vysion/deploy/vysion-cert-migrate-nginx.sh

# 5. Renouvellement automatique : Certbot délègue au même mécanisme
sudo ln -s /opt/vysion/deploy/certbot-vysion-deploy.sh \
           /etc/letsencrypt/renewal-hooks/deploy/vysion-helper.sh
```

`deploy/vysion-cert-install.sh` est la seule voie décrite : il installe `src`
(la `PYTHONPATH` de l'unité), les **quatre** scripts que les étapes 3 à 5
invoquent sous `/opt/vysion/deploy` (exécutables `0755`), l'unité dans
`/etc/systemd/system` (`0644`), l'exemple de configuration dans
`/etc/vysion` (`0644`, créé **une seule fois** puis propriété de
l'opérateur), et les répertoires `0750` de l'état et de la socket ainsi que
`/var/log/nginx` s'il manque. Il échoue explicitement si une source ou un
script manque, ne démarre aucun service (l'édition du fichier
d'environnement reste l'étape suivante) et refuse de tourner sans root
au-dessus des chemins par défaut. L'unité crée de son côté
`StateDirectory=vysion` et `RuntimeDirectory=vysion-cert-helper` avant
`ExecStart`, donc un redémarrage de l'hôte ne laisse jamais un
`ReadWritePaths` pointer vers un répertoire absent. Toute la séquence
documentée ci-dessus — installation, `ping`, bootstrap, migration, hook —
est rejouée dans une sandbox (racine alternative, nginx en stub, serveur TLS
local, jamais `/etc`) par `tests/contract/test_helper_install.py`.

### Bascule du Nginx hôte (migration vers l'autorité servie)

Tant que le Nginx hôte lit `/etc/letsencrypt/live/<host>/{fullchain,privkey}.pem`, un import manuel depuis `/admin` ne peut **pas** devenir le certificat servi : l'empreinte relue sur `:443` ne correspond pas, l'activation est donc rétrogradée par rollback. La migration repointe `ssl_certificate` / `ssl_certificate_key` sur `$HELPER_CERTS_DIR/active/{fullchain,key}.pem` — la génération immuable promue par le helper — pour que renouvellement Certbot et import manuel convergent vers **une seule autorité servie**.

- **Ordre obligatoire** : helper démarré → `vysion-cert-bootstrap.sh` (génération 1 = certificat déjà servi, donc l'empreinte ne change pas au moment de la bascule) → migration → hook Certbot. Sans génération active, la migration refuse (exit 1) sans rien toucher à `/etc/nginx`.
- **Séquence, à chaque étape** : sauvegarde de chaque fichier touché → `nginx -t` **avant** tout rechargement → rechargement → contrôle de l'empreinte SHA-256 réellement servie (`127.0.0.1:443`, SNI = `VYSION_TLS_HOSTNAME`, via `openssl s_client`, comparée à la génération active). Échec de `nginx -t`, du rechargement ou de l'empreinte → restauration de la configuration d'origine, `nginx -t` puis rechargement de retour — exit 1.
- **Idempotent** : déjà repointé → « rien à faire », aucun rechargement.
- **Rollback manuel** : le chemin de sauvegarde est imprimé en fin de migration (`backup=...`, sous `/var/backups/vysion-nginx-helper/`) ; `sudo /opt/vysion/deploy/vysion-cert-migrate-nginx.sh restore <sauvegarde>` restaure les fichiers d'origine, valide et recharge. Rollback complet : restaurez, puis désactivez le hook (`rm /etc/letsencrypt/renewal-hooks/deploy/vysion-helper.sh`) si l'on revient au mode `none`.
- **Permissions** : le master nginx (root) lit la clé au `-t`/rechargement ; `generations` est `0700` root et les fichiers `0600`. Un master non-root ou un accès refusé fait échouer le contrôle d'empreinte → la configuration est restaurée automatiquement.
- **Preuves** : `tests/contract/test_nginx_migration.py` rejoue la migration entière (succès, `nginx -t` en échec, empreinte divergente, idempotence, bootstrap absent, hostname absent, `restore`) dans une arborescence sandbox avec nginx en stub et un serveur TLS local — jamais contre `/etc`, conformément à la carte.

### Fonctionnement

- **Socket** : `/run/vysion-cert-helper/helper.sock`, `0660 root:<VYSION_PGID>` dans un répertoire `0750` ; le pair est vérifié par `SO_PEERCRED` sur le uid **et** le gid — tout autre processus est refusé. Le conteneur la monte en `:ro` (`compose.helper.yml`).
- **Protocole** : JSON préfixé longueur, versionné, avec bornes de taille, rejet des clés dupliquées et des clés inattendues. Quatre actions seulement : `ping`, `status`, `validate`, `activate`. `install` et `renew` **n'existent qu'en CLI root**, jamais sur la socket.
- **Activation** : ticket d'administration (usage unique, lié à la session et au digest) → digest du staging re-vérifié par le helper → génération immuable promue → `nginx -t` **puis** rechargement → empreinte SHA-256 réellement servie relue sur `127.0.0.1:443` → rollback automatique en cas d'écart.
- **Staging** : privé (`0700`) et purgé par TTL (10 min) : un candidat jamais activé disparaît tout seul.
- **Idempotence** : `install`/`renew` comparent l'empreinte de la lignée à celle déjà servie ; si elle coïncide, aucune génération n'est créée et aucun rechargement n'a lieu. Un hook Certbot rejoué est donc toujours sans effet.

### Opérations

```bash
# État lu par l'application elle-même (même chemin que /admin)
sudo PYTHONPATH=/opt/vysion/src python3 -m vysion.certhelper status \
  --socket /run/vysion-cert-helper/helper.sock
journalctl -u vysion-cert-helper -f
systemctl status vysion-cert-helper
```

Le service ne journalise jamais de clé ni de secret : seuls les messages OpenSSL/nginx normalisés et le résultat des actions sortent.

## Sauvegarde et restauration (manuelles, frontière cohérente)

1. **Sauvegarde** : `scripts/backup.sh /chemin/destination` crée un répertoire horodaté contenant `vysion-state.tar.gz`, `vysion-certs.tar.gz`, `vysion-reports.tar.gz` (volumes absents ignorés, `VYSION_VOLUME_PREFIX` respecté — le préfixe s'applique alors aussi aux **noms d'archives** et se transmet à la restauration par `VYSION_BACKUP_PREFIX`) sous **une seule frontière cohérente** : le script découvre d'abord les conteneurs qui montent ces volumes, les arrête (quiescence — aucun écriture SQLite, certificat ou rapport pendant la prise), archive, puis redémarre ces conteneurs (y compris en cas d'interruption, via un `trap`). Aucun timer hôte ; noter `sha256sum` des archives produites.
2. **Restauration (même hôte ou VM vierge)** : créer les volumes s'ils sont absents —

   ```bash
   docker volume create vysion-state
   docker volume create vysion-certs
   docker volume create vysion-reports
   ```

   — arrêter la pile, `scripts/restore.sh /chemin/destination/vysion-HORODATAGE` (`VYSION_BACKUP_PREFIX` vide pour une sauvegarde de production, sinon le préfixe sous lequel elle a été prise), puis `docker compose up -d` (ou Git Stack Portainer) — la restauration de `vysion-certs` réactive HTTPS standalone sans re-import.
3. **Test de restauration (obligatoire avant toute bascule)** : uniquement sur des volumes jetables, jamais sur les volumes en service : `VYSION_BACKUP_PREFIX=<préfixe de la sauvegarde, vide pour la production> VYSION_VOLUME_PREFIX=restore-<stamp>- scripts/restore.sh <répertoire d'archives>`, comparer les empreintes SHA-256 des fichiers restaurés à celles notées à la sauvegarde, puis supprimer ces volumes. Le script **échoue (exit 1)** si aucune archive attendue n'est trouvée : un contrôle qui ne restaure rien n'est jamais vert. Le round-trip complet (quiescence, archives, mutation, restauration, empreintes) est rejoué automatiquement par `tests/contract/test_backup_restore_roundtrip.py`, y compris une sauvegarde prise sous un nom puis restaurée sous un autre préfixe.
4. **Vérification** : `GET /healthz`, `GET /api/admin/status`, connexion sur `/admin`, téléchargement d'un rapport existant par UUID, `GET /api/admin/certificates` en standalone.
5. **Rollback applicatif** : `git revert` / repointage de la stack sur le digest d'image précédent ; aucun rollback ne supprime ni ne recrée `vysion-state`, `vysion-certs` ni `vysion-reports`.

## Déploiement et rollback VPS (inchangé)

Le chemin de production reste la Git Stack Portainer sur `compose.yml` avec `IMAGE_DIGEST` immuable (0006) : ce chantier ne modifie ni le runtime VPS, ni Portainer, ni le Nginx hôte, ni le certificat actif. Rollback : digest précédent côté Portainer, le conteneur de repli du runbook historique demeurant disponible.

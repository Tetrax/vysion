# Exploitation du socle Vysion v2

## Source de vérité

- repository GitHub privé unique ;
- `compose.yml` unique ;
- service Portainer Git Stack unique ;
- image et référence Git immuables après validation ;
- aucun `docker compose up/down` par SSH dans le parcours normal.

## Certificats TLS

Les fichiers restent hors Git et hors image :

```text
/opt/vysion/tls/tls.crt
/opt/vysion/tls/tls.key
```

Ils sont montés en lecture seule dans `/run/vysion/tls`.

Le processus tourne avec UID/GID `10001`. Sur l'hôte, le certificat et la clé doivent donc rester restrictifs tout en étant lisibles par le GID `10001` (par exemple propriétaire `root:10001`, répertoire `0750`, certificat `0640`, clé `0640`). Ne pas rendre la clé lisible par tous.

### Renouvellement

1. obtenir le certificat et la clé auprès de la source interne autorisée ;
2. valider localement que certificat et clé correspondent ;
3. écrire les nouveaux fichiers sous des noms temporaires sur le même filesystem ;
4. appliquer propriétaire `root:10001` et permissions restrictives permettant la lecture au GID `10001` ;
5. remplacer atomiquement `tls.crt` et `tls.key` ;
6. lancer **Pull and redeploy** dans Portainer, sans changer la référence Git ni l'image ;
7. vérifier l'état healthy, la chaîne TLS, la date d'expiration et `/api/health` ;
8. restaurer les deux anciens fichiers et redéployer si le healthcheck échoue.

Le socle privilégie un redéploiement contrôlé plutôt qu'un mécanisme de reload automatique. Un reload Nginx sans restart ne sera ajouté que si le besoin opérationnel est démontré.

## Healthcheck

Le healthcheck appelle :

```text
https://${VYSION_TLS_SERVER_NAME}:8443/healthz
```

Dans le conteneur, `curl --resolve ${VYSION_TLS_SERVER_NAME}:8443:127.0.0.1` résout explicitement ce nom TLS vers la boucle locale sans remplacer le nom validé par le certificat. Nginx termine TLS puis interroge FastAPI sur `127.0.0.1:8000/api/health`. Le healthcheck vérifie donc les deux processus et leur liaison locale.

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

## Rollback applicatif futur

1. conserver la référence Git et l'`IMAGE_TAG` précédents ;
2. sélectionner ces deux valeurs dans Portainer ;
3. utiliser **Pull and redeploy** ;
4. vérifier healthcheck, HTTPS et un audit synthétique ;
5. ne pas supprimer le volume `vysion-reports` pendant un rollback applicatif.

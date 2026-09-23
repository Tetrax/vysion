#!/bin/sh
# Manual backup of every durable Vysion volume (state, certificates,
# reports) under ONE coherent boundary: every container that mounts one of
# those volumes is stopped first, so nothing can write — no SQLite
# transaction, no certificate activation, no report write — while the
# archives are taken, and the containers are started again afterwards. No
# host timer: the operator runs this on the chosen cadence.
#
# VYSION_VOLUME_PREFIX carries the same meaning as in the compose files: it
# lets validation/smoke stacks back up their own disjoint volumes without
# ever touching the live ones. It prefixes BOTH the volumes that are read
# and the archive names that are produced, which is why restore.sh takes it
# back as VYSION_BACKUP_PREFIX (where the archives come from) separately
# from VYSION_VOLUME_PREFIX (where they go).
#
# Usage: VYSION_VOLUME_PREFIX= scripts/backup.sh [destination-directory]
set -eu

alpine='alpine:3.20.1@sha256:dabf91b69c191a1a0a1628fd6bdd029c0c4018041c7f052870bb13c5a222ae76'
destination="${1:-./vysion-backups}"
prefix="${VYSION_VOLUME_PREFIX:-}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="$destination/vysion-$stamp"

volumes=""
for base in vysion-state vysion-certs vysion-reports; do
  volume="$prefix$base"
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    volumes="$volumes $volume"
  else
    echo "skip $volume (absent on this host)" >&2
  fi
done
if [ -z "$volumes" ]; then
  echo "no Vysion volume found (prefix '$prefix'): nothing to back up" >&2
  exit 1
fi

# Quiesce: collect every running container that mounts a target volume, so
# the archives share one single point in time instead of three live reads.
targets=""
for volume in $volumes; do
  for identifier in $(docker ps -q --filter "volume=$volume"); do
    case " $targets " in
      *" $identifier "*) ;;
      *) targets="$targets $identifier" ;;
    esac
  done
done

restart_containers() {
  if [ -n "$targets" ]; then
    # shellcheck disable=SC2086
    docker start $targets >/dev/null 2>&1 || {
      echo "WARNING: restart these containers manually: $targets" >&2
    }
    targets=""
  fi
}
trap 'restart_containers' EXIT INT TERM

if [ -n "$targets" ]; then
  echo "quiescing containers:$targets" >&2
  # shellcheck disable=SC2086
  if ! docker stop $targets >/dev/null; then
    echo "cannot stop the containers holding the volumes: aborting" >&2
    exit 1
  fi
fi

mkdir -p "$output"
for volume in $volumes; do
  docker run --rm --read-only \
    -v "$volume:/source:ro" \
    -v "$output:/backup" \
    "$alpine" tar -C /source -czf "/backup/$volume.tar.gz" .
  echo "saved $volume"
done

restart_containers
trap - EXIT INT TERM

echo "Backup complete: $output"
echo "Restore onto the same volumes:   VYSION_BACKUP_PREFIX=$prefix VYSION_VOLUME_PREFIX=$prefix scripts/restore.sh $output"
echo "Control restore on disposable volumes: VYSION_BACKUP_PREFIX=$prefix VYSION_VOLUME_PREFIX=vysion-smoke-<stamp>- scripts/restore.sh $output"

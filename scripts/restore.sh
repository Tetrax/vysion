#!/bin/sh
# Restore the Vysion volumes from a directory produced by scripts/backup.sh.
# Run it with the stack stopped, then start the stack again. The restore
# target must be disposable volumes when this is a test: never point it at
# the live volumes outside of a documented recovery.
#
# VYSION_VOLUME_PREFIX carries the same meaning as in scripts/backup.sh and
# the compose files.
#
# Usage: VYSION_VOLUME_PREFIX= scripts/restore.sh <backup-directory>
set -eu

alpine='alpine:3.20.1@sha256:dabf91b69c191a1a0a1628fd6bdd029c0c4018041c7f052870bb13c5a222ae76'
source_dir="${1:?usage: scripts/restore.sh <backup-directory>}"
prefix="${VYSION_VOLUME_PREFIX:-}"

for base in vysion-state vysion-certs vysion-reports; do
  volume="$prefix$base"
  archive="$source_dir/$volume.tar.gz"
  if [ ! -f "$archive" ]; then
    echo "skip $volume (no archive in $source_dir)" >&2
    continue
  fi
  docker volume create "$volume" >/dev/null
  docker run --rm --read-only \
    -v "$volume:/target" \
    -v "$source_dir:/backup:ro" \
    "$alpine" sh -c "find /target -mindepth 1 -delete && tar -C /target -xzf /backup/$volume.tar.gz"
  echo "restored $volume"
done

echo "Restore complete: start the stack (docker compose up -d) then verify /healthz and /api/admin/status"

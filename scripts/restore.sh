#!/bin/sh
# Restore the Vysion volumes from a directory produced by scripts/backup.sh.
# Run it with the stack stopped, then start the stack again. The restore
# target must be disposable volumes when this is a test: never point it at
# the live volumes outside of a documented recovery.
#
# The name of the SOURCE archives and the name of the TARGET volumes are
# two independent decisions:
#
#   VYSION_BACKUP_PREFIX  prefix the archives carry, i.e. the prefix the
#                         backup was taken with (empty for a backup of the
#                         live volumes: vysion-state.tar.gz, ...).
#   VYSION_VOLUME_PREFIX  prefix of the volumes written (empty restores the
#                         live names, a stamp restores disposable copies).
#
# A backup taken under one name therefore restores under any other prefix —
# the documented control path is a production backup restored onto stamped,
# disposable volumes — and the script FAILS when no expected archive exists
# instead of reporting success over three skipped files.
#
# Usage: VYSION_VOLUME_PREFIX=vysion-smoke-<stamp>- scripts/restore.sh <backup-directory>
set -eu

alpine='alpine:3.20.1@sha256:dabf91b69c191a1a0a1628fd6bdd029c0c4018041c7f052870bb13c5a222ae76'
source_dir="${1:?usage: scripts/restore.sh <backup-directory>}"
target_prefix="${VYSION_VOLUME_PREFIX:-}"
source_prefix="${VYSION_BACKUP_PREFIX:-}"

restored=""
for base in vysion-state vysion-certs vysion-reports; do
  archive_name="${source_prefix}${base}.tar.gz"
  archive="$source_dir/$archive_name"
  if [ ! -f "$archive" ]; then
    echo "skip $archive_name (no archive in $source_dir)" >&2
    continue
  fi
  volume="$target_prefix$base"
  docker volume create "$volume" >/dev/null
  docker run --rm --read-only \
    -v "$volume:/target" \
    -v "$source_dir:/backup:ro" \
    "$alpine" sh -c "find /target -mindepth 1 -delete && tar -C /target -xzf /backup/$archive_name"
  echo "restored $volume (from $archive_name)"
  restored="$restored $volume"
done

if [ -z "$restored" ]; then
  echo "restore failed: no expected archive in $source_dir (source prefix '$source_prefix'; set VYSION_BACKUP_PREFIX to the prefix the backup was taken with)" >&2
  exit 1
fi

echo "Restore complete:$restored"
echo "Start the stack (docker compose up -d) then verify /healthz and /api/admin/status"

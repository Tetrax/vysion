#!/bin/sh
# Manual backup of every durable Vysion volume (state, certificates,
# reports). No host timer: the operator runs this on the chosen cadence.
#
# Usage: scripts/backup.sh [destination-directory]
set -eu

alpine='alpine:3.20.1@sha256:dabf91b69c191a1a0a1628fd6bdd029c0c4018041c7f052870bb13c5a222ae76'
destination="${1:-./vysion-backups}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="$destination/vysion-$stamp"

mkdir -p "$output"
for volume in vysion-state vysion-certs vysion-reports; do
  if ! docker volume inspect "$volume" >/dev/null 2>&1; then
    echo "skip $volume (absent on this host)" >&2
    continue
  fi
  docker run --rm --read-only \
    -v "$volume:/source:ro" \
    -v "$output:/backup" \
    "$alpine" tar -C /source -czf "/backup/$volume.tar.gz" .
  echo "saved $volume"
done

echo "Backup complete: $output"
echo "Restore with: scripts/restore.sh $output"

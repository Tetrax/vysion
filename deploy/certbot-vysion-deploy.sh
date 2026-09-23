#!/bin/sh
# Certbot renew-deploy hook for Vysion (helper mode).
#
# Certbot stays the ACME authority: it renews the lineage, then asks the
# helper — through the very same authoritative mechanism the admin UI uses —
# to promote it. Nothing is copied by hand and no second authority appears.
#
# Install:
#   ln -s /opt/vysion/deploy/certbot-vysion-deploy.sh \
#         /etc/letsencrypt/renewal-hooks/deploy/vysion-helper.sh
#
# Test/deployment override: VYSION_LETSENCRYPT_LIVE_DIR (default
# /etc/letsencrypt/live) — used to replay the sequence in a sandbox.
set -eu

env_file=${VYSION_CERT_HELPER_ENV:-/etc/vysion/cert-helper.env}
if [ -r "$env_file" ]; then
    # shellcheck disable=SC1090
    . "$env_file"
fi

: "${VYSION_TLS_HOSTNAME:?VYSION_TLS_HOSTNAME is required in $env_file}"
: "${VYSION_CERT_HELPER:=python3 -m vysion.certhelper}"
export PYTHONPATH=${VYSION_PYTHONPATH:-/opt/vysion/src}

expected="${VYSION_LETSENCRYPT_LIVE_DIR:-/etc/letsencrypt/live}/${VYSION_TLS_HOSTNAME}"
if [ "${RENEWED_LINEAGE:-}" != "$expected" ]; then
    # Another certificate on this host: not ours, so nothing to promote.
    exit 0
fi

# Idempotent: an already-served lineage creates no generation and reloads
# nothing, so a re-run is always safe.
exec ${VYSION_CERT_HELPER} renew \
    --lineage "$RENEWED_LINEAGE" \
    --hostname "$VYSION_TLS_HOSTNAME" \
    --certs-dir "${HELPER_CERTS_DIR:-/var/lib/vysion/certificates}"

#!/bin/sh
# One-shot, idempotent bootstrap of the certificate currently served by the
# host nginx into the helper's first generation.
#
# Run it once when moving a VPS to helper mode, before enabling the renew
# hook: Certbot keeps renewing, and the helper becomes the single authority
# for what is actually served. Running it twice is a no-op — if the lineage
# already is the served certificate, no generation is created.
#
#   sudo /opt/vysion/deploy/vysion-cert-bootstrap.sh
set -eu

env_file=${VYSION_CERT_HELPER_ENV:-/etc/vysion/cert-helper.env}
if [ -r "$env_file" ]; then
    # shellcheck disable=SC1090
    . "$env_file"
fi

: "${VYSION_TLS_HOSTNAME:?VYSION_TLS_HOSTNAME is required in $env_file}"
: "${VYSION_CERT_HELPER:=python3 -m vysion.certhelper}"
export PYTHONPATH=${VYSION_PYTHONPATH:-/opt/vysion/src}

lineage="/etc/letsencrypt/live/${VYSION_TLS_HOSTNAME}"
if [ ! -r "$lineage/fullchain.pem" ] || [ ! -r "$lineage/privkey.pem" ]; then
    echo "bootstrap impossible : lineage absent ou illisible dans $lineage" >&2
    exit 1
fi

exec ${VYSION_CERT_HELPER} install \
    --lineage "$lineage" \
    --hostname "$VYSION_TLS_HOSTNAME" \
    --certs-dir "${HELPER_CERTS_DIR:-/var/lib/vysion/certificates}"

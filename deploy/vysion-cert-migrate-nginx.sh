#!/bin/sh
# Repoint the host nginx from the Certbot lineage to the helper's served
# certificate authority — the missing step that makes a manual admin import
# (or a renewal re-import) actually become the served certificate.
#
# Ordering on a VPS (see docs/OPERATIONS.md):
#   1. install + start vysion-cert-helper
#   2. vysion-cert-bootstrap.sh      (generation 1 = the cert already served)
#   3. this script                   (repoint + nginx -t + reload + verify)
#   4. install the Certbot deploy hook
#
# Guarantees:
#   * `nginx -t` runs strictly before any reload;
#   * the fingerprint actually served is read back on SMOKE_HOST:SMOKE_PORT
#     with SNI = VYSION_TLS_HOSTNAME and must equal the active generation;
#   * any failure restores the original configuration and reloads it back;
#   * a copy of every touched file is kept for a manual rollback:
#       vysion-cert-migrate-nginx.sh restore <backup-dir>
#   * running it twice is a no-op.
#
# Test/deployment overrides: NGINX_CONF_DIR, NGINX_BIN, HELPER_CERTS_DIR,
# VYSION_MIGRATE_BACKUP_ROOT, VYSION_NO_SYSTEMCTL=1, SMOKE_HOST, SMOKE_PORT.
set -eu

env_file=${VYSION_CERT_HELPER_ENV:-/etc/vysion/cert-helper.env}
if [ -r "$env_file" ]; then
    # shellcheck disable=SC1090
    . "$env_file"
fi

# Missing hostname: refuse before touching anything.
: "${VYSION_TLS_HOSTNAME:?VYSION_TLS_HOSTNAME is required in $env_file}"

certs_dir=${HELPER_CERTS_DIR:-/var/lib/vysion/certificates}
conf_dir=${NGINX_CONF_DIR:-/etc/nginx}
nginx_bin=${NGINX_BIN:-nginx}
backup_root=${VYSION_MIGRATE_BACKUP_ROOT:-/var/backups/vysion-nginx-helper}
smoke_host=${SMOKE_HOST:-127.0.0.1}
smoke_port=${SMOKE_PORT:-443}
lineage_dir="/etc/letsencrypt/live/$VYSION_TLS_HOSTNAME"
active_fullchain="$certs_dir/active/fullchain.pem"
active_key="$certs_dir/active/key.pem"

test_config() {
    if ! "$nginx_bin" -t; then
        echo "nginx -t a echoue" >&2
        return 1
    fi
    return 0
}

reload_nginx() {
    if [ "${VYSION_NO_SYSTEMCTL:-0}" != "1" ] && command -v systemctl >/dev/null 2>&1; then
        if systemctl reload nginx 2>/dev/null; then
            return 0
        fi
    fi
    "$nginx_bin" -s reload
}

# Fingerprint of the certificate really served, vs the active generation.
# Both sides are DER + SHA-256, exactly like the application's own probe.
fingerprints_match() {
    expected_file=$(mktemp)
    served_file=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '$expected_file' '$served_file'" EXIT
    openssl x509 -in "$active_fullchain" -outform DER -out "$expected_file" 2>/dev/null || return 1
    timeout 10 openssl s_client \
        -connect "$smoke_host:$smoke_port" \
        -servername "$VYSION_TLS_HOSTNAME" </dev/null 2>/dev/null \
        | openssl x509 -outform DER -out "$served_file" 2>/dev/null || return 1
    [ -s "$expected_file" ] && [ -s "$served_file" ] || return 1
    expected=$(sha256sum <"$expected_file" | cut -d' ' -f1)
    served=$(sha256sum <"$served_file" | cut -d' ' -f1)
    [ "$expected" = "$served" ]
}

# ---------------------------------------------------------------------------
# restore <backup-dir>
# ---------------------------------------------------------------------------
if [ "${1:-}" = "restore" ]; then
    backup=${2:?usage: $0 restore <backup-dir>}
    manifest="$backup/files.txt"
    if [ ! -r "$manifest" ]; then
        echo "sauvegarde introuvable ou illisible : $manifest" >&2
        exit 1
    fi
    while IFS= read -r relative; do
        [ -n "$relative" ] || continue
        if [ ! -r "$backup/$relative" ]; then
            echo "fichier de sauvegarde manquant : $backup/$relative" >&2
            exit 1
        fi
        mkdir -p "$conf_dir/$(dirname "$relative")"
        cp -p "$backup/$relative" "$conf_dir/$relative"
    done <"$manifest"
    if ! test_config; then
        echo "rollback : nginx -t refuse la configuration restauree" >&2
        exit 1
    fi
    if ! reload_nginx; then
        echo "rollback : rechargement de nginx impossible" >&2
        exit 1
    fi
    echo "rollback effectue : $backup"
    exit 0
fi

# ---------------------------------------------------------------------------
# migrate (default)
# ---------------------------------------------------------------------------
if [ ! -r "$active_fullchain" ] || [ ! -r "$active_key" ]; then
    echo "generation active absente dans $certs_dir : lancez d'abord vysion-cert-bootstrap.sh" >&2
    exit 1
fi

files=$(grep -rlIF -- "$lineage_dir/" "$conf_dir" 2>/dev/null || true)
if [ -z "$files" ]; then
    if grep -rlIF -- "$certs_dir/active/" "$conf_dir" >/dev/null 2>&1; then
        echo "nginx sert deja l'autorite helper : rien a faire"
        exit 0
    fi
    echo "aucune configuration nginx sous $conf_dir ne reference $lineage_dir" >&2
    exit 1
fi

backup="$backup_root/$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$backup"
: >"$backup/files.txt"
for file in $files; do
    relative=${file#"$conf_dir"/}
    mkdir -p "$backup/$(dirname "$relative")"
    cp -p "$file" "$backup/$relative"
    printf '%s\n' "$relative" >>"$backup/files.txt"
done

restore_backup() {
    while IFS= read -r relative; do
        [ -n "$relative" ] || continue
        if [ -r "$backup/$relative" ]; then
            mkdir -p "$conf_dir/$(dirname "$relative")"
            cp -p "$backup/$relative" "$conf_dir/$relative"
        fi
    done <"$backup/files.txt"
}

# Escape the dots of the hostname so the sed pattern stays literal.
hostname_pattern=$(printf '%s' "$VYSION_TLS_HOSTNAME" | sed 's/\./\\./g')
for file in $files; do
    sed -i \
        -e "s|/etc/letsencrypt/live/$hostname_pattern/fullchain.pem|$active_fullchain|g" \
        -e "s|/etc/letsencrypt/live/$hostname_pattern/privkey.pem|$active_key|g" \
        "$file"
done

if ! test_config; then
    restore_backup
    echo "migration annulee : configuration restauree depuis $backup" >&2
    exit 1
fi
if ! reload_nginx; then
    restore_backup
    test_config || true
    reload_nginx || true
    echo "migration annulee : rechargement impossible, configuration restauree depuis $backup" >&2
    exit 1
fi
if ! fingerprints_match; then
    restore_backup
    test_config || true
    reload_nginx || true
    echo "migration annulee : le certificat servi ne correspond pas a la generation active ; configuration restauree depuis $backup" >&2
    exit 1
fi

echo "migration effectuee : nginx sert $active_fullchain"
echo "backup=$backup"
echo "rollback manuel : $0 restore $backup"
exit 0

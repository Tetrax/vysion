#!/bin/sh
# One idempotent install sequence for helper mode on a fresh host.
#
# Everything docs/OPERATIONS.md invokes afterwards lives here: the helper
# sources (the unit's PYTHONPATH), the deploy scripts (bootstrap, nginx
# migration, Certbot hook), the systemd unit — and every directory the
# hardened unit whitelists, created BEFORE the service may start, because a
# ReadWritePaths target must already exist when systemd sets up the
# namespace (and /run does not survive a reboot).
#
# Guarantees:
#   * safe to run twice: the operator's cert-helper.env is never overwritten
#     and no file is re-typed;
#   * scripts land executable (0755), unit and env example 0644, state and
#     socket directories 0750, sources readable (0644 files / 0755 dirs)
#     whatever the umask;
#   * nothing is started here: edit the env file first, then
#     `systemctl daemon-reload && systemctl enable --now` (see the runbook).
#
# Test/sandbox overrides: VYSION_OPT_DIR, VYSION_ETC_DIR, VYSION_STATE_DIR,
# VYSION_RUNTIME_DIR, VYSION_NGINX_LOG_DIR, VYSION_SYSTEMD_DIR,
# VYSION_SRC_DIR, VYSION_DEPLOY_DIR.
set -eu

opt_dir=${VYSION_OPT_DIR:-/opt/vysion}
etc_dir=${VYSION_ETC_DIR:-/etc/vysion}
state_dir=${VYSION_STATE_DIR:-/var/lib/vysion}
runtime_dir=${VYSION_RUNTIME_DIR:-/run/vysion-cert-helper}
nginx_log_dir=${VYSION_NGINX_LOG_DIR:-/var/log/nginx}
systemd_dir=${VYSION_SYSTEMD_DIR:-/etc/systemd/system}

# Source of truth: this script's own tree — the repository checkout, or the
# already installed copy when re-run from $opt_dir/deploy.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root_dir=$(dirname -- "$here")
src_dir=${VYSION_SRC_DIR:-$root_dir/src}
deploy_dir=${VYSION_DEPLOY_DIR:-$here}

if [ "$(id -u)" -ne 0 ] && [ -z "${VYSION_OPT_DIR:-}${VYSION_ETC_DIR:-}${VYSION_STATE_DIR:-}" ]; then
    echo "installation impossible : ce script doit tourner en root (sudo $0)" >&2
    echo "(surchargez VYSION_OPT_DIR/VYSION_ETC_DIR/VYSION_STATE_DIR/... pour un bac a sable)" >&2
    exit 1
fi

if [ ! -d "$src_dir/vysion" ]; then
    echo "sources introuvables : $src_dir" >&2
    exit 1
fi
for required in vysion-cert-install.sh vysion-cert-bootstrap.sh \
    vysion-cert-migrate-nginx.sh certbot-vysion-deploy.sh \
    vysion-cert-helper.service vysion-cert-helper.env.example; do
    if [ ! -r "$deploy_dir/$required" ]; then
        echo "fichier manquant : $deploy_dir/$required" >&2
        exit 1
    fi
done

# Directories: application tree, operator config, systemd unit, plus every
# path the unit whitelists (state, nginx log, socket).
install -d -m 0755 "$opt_dir" "$etc_dir" "$systemd_dir" "$nginx_log_dir"
install -d -m 0750 "$state_dir" "$runtime_dir"

# Sources (the unit's Environment=PYTHONPATH=/opt/vysion/src).
if [ "$src_dir" != "$opt_dir/src" ]; then
    install -d -m 0755 "$opt_dir/src"
    cp -R "$src_dir/." "$opt_dir/src/"
    chmod -R u=rwX,go=rX "$opt_dir/src"
else
    echo "sources deja en place : $opt_dir/src"
fi

# The scripts the runbook invokes, installed executable — this is the step
# the previous procedure skipped, leaving /opt/vysion/deploy/* absent.
install -d -m 0755 "$opt_dir/deploy"
if [ "$deploy_dir" != "$opt_dir/deploy" ]; then
    for script in vysion-cert-install.sh vysion-cert-bootstrap.sh \
        vysion-cert-migrate-nginx.sh certbot-vysion-deploy.sh; do
        install -m 0755 "$deploy_dir/$script" "$opt_dir/deploy/$script"
    done
    install -m 0644 "$deploy_dir/vysion-cert-helper.service" "$opt_dir/deploy/vysion-cert-helper.service"
    install -m 0644 "$deploy_dir/vysion-cert-helper.env.example" \
        "$opt_dir/deploy/vysion-cert-helper.env.example"
else
    echo "scripts deja en place : $opt_dir/deploy"
    chmod 0755 "$opt_dir/deploy/vysion-cert-install.sh" \
        "$opt_dir/deploy/vysion-cert-bootstrap.sh" \
        "$opt_dir/deploy/vysion-cert-migrate-nginx.sh" \
        "$opt_dir/deploy/certbot-vysion-deploy.sh"
fi

# Operator environment file: created once from the example, then owned by
# the operator — a re-install never overwrites what has been edited.
env_file="$etc_dir/cert-helper.env"
if [ -e "$env_file" ]; then
    echo "env conserve : $env_file"
else
    install -m 0644 "$deploy_dir/vysion-cert-helper.env.example" "$env_file"
    echo "env cree : $env_file"
fi

# systemd unit. The daemon-reload stays an explicit runbook step so the
# operator controls when the service becomes startable.
install -m 0644 "$deploy_dir/vysion-cert-helper.service" "$systemd_dir/vysion-cert-helper.service"

echo "sources  : $opt_dir/src"
echo "scripts  : $opt_dir/deploy"
echo "etat     : $state_dir (0750)"
echo "socket   : $runtime_dir (0750)"
echo "nginx log: $nginx_log_dir"
echo "unit     : $systemd_dir/vysion-cert-helper.service"
echo "env      : $env_file"

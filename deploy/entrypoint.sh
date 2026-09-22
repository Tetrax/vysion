#!/bin/sh
set -eu

mkdir -p \
  /tmp/nginx/client_temp \
  /tmp/nginx/proxy_temp \
  /tmp/nginx/fastcgi_temp \
  /tmp/nginx/uwsgi_temp \
  /tmp/nginx/scgi_temp

nginx_config=/etc/nginx/nginx.conf
if [ "${VYSION_TLS_BACKEND:-none}" = "local" ]; then
  # Standalone: the container terminates TLS itself. Bootstrap with a short
  # lived self-signed certificate when the volume is empty so the admin UI
  # can be reached over HTTPS to import the real certificate.
  certs=/app/certs
  tls_hostname="${VYSION_TLS_HOSTNAME:?VYSION_TLS_HOSTNAME is required when VYSION_TLS_BACKEND=local}"
  if [ ! -e "$certs/active" ]; then
    umask 077
    bootstrap="$certs/.bootstrap-$$"
    mkdir -p "$bootstrap"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
      -keyout "$bootstrap/key.pem" \
      -out "$bootstrap/fullchain.pem" \
      -subj "/CN=${tls_hostname}" \
      -addext "subjectAltName=DNS:${tls_hostname}"
    # Bootstrap through the real staging pipeline so the generation carries
    # its metadata: active()/rollback treat a metadata-less directory as no
    # certificate at all, which would make an activation roll back to nothing.
    BOOTSTRAP_DIR="$bootstrap" python3 - <<'PY'
import os
import pathlib
import sys

from vysion.certificates import CertificateError, CertificateStore

here = pathlib.Path("/app/certs")
boot = pathlib.Path(os.environ["BOOTSTRAP_DIR"])
try:
    store = CertificateStore(here)
    store.validate(
        certificate=(boot / "fullchain.pem").read_bytes(),
        private_key=(boot / "key.pem").read_bytes(),
        hostname=os.environ["VYSION_TLS_HOSTNAME"],
    )
    generation = store.promote()
except CertificateError as exc:
    print(f"vysion-entrypoint: bootstrap impossible : {exc}", file=sys.stderr)
    raise SystemExit(1)
print(
    "vysion-entrypoint: bootstrap TLS certificate generated for "
    f"{os.environ['VYSION_TLS_HOSTNAME']} (valid 2 days, generation {generation.number})",
    file=sys.stderr,
)
PY
    rm -rf "$bootstrap"
  fi
  nginx_config=/etc/nginx/nginx-standalone.conf
fi

uvicorn vysion.api.app:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8000 \
  --proxy-headers \
  --forwarded-allow-ips 127.0.0.1 \
  --no-access-log &
api_pid=$!

nginx -c "$nginx_config" -g 'daemon off;' &
nginx_pid=$!

shutdown() {
  code=$1
  kill -TERM "$api_pid" "$nginx_pid" 2>/dev/null || true
  wait "$api_pid" "$nginx_pid" 2>/dev/null || true
  exit "$code"
}
trap 'shutdown 0' INT TERM

while kill -0 "$api_pid" 2>/dev/null && kill -0 "$nginx_pid" 2>/dev/null; do
  sleep 1
done

shutdown 1

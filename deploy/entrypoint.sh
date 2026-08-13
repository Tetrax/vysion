#!/bin/sh
set -eu

mkdir -p \
  /tmp/nginx/client_temp \
  /tmp/nginx/proxy_temp \
  /tmp/nginx/fastcgi_temp \
  /tmp/nginx/uwsgi_temp \
  /tmp/nginx/scgi_temp

uvicorn vysion.api.app:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8000 \
  --proxy-headers \
  --forwarded-allow-ips 127.0.0.1 \
  --no-access-log &
api_pid=$!

nginx -g 'daemon off;' &
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

FROM node:22.23.2-bookworm@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a AS frontend-build
WORKDIR /build/frontend
ARG VYSION_REVISION=unknown
ENV VITE_VYSION_REVISION=${VYSION_REVISION}
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY VERSION /build/VERSION
COPY frontend/ ./
RUN npm run build

FROM python:3.12.10-slim-bookworm@sha256:fd95fa221297a88e1cf49c55ec1828edd7c5a428187e67b5d1805692d11588db AS runtime
ARG VYSION_UID=10001
ARG VYSION_GID=10001
ARG VYSION_REVISION=unknown
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    VYSION_TLS_SERVER_NAME=vysion.internal.example \
    VYSION_REVISION=${VYSION_REVISION} \
    PATH=/opt/vysion-venv/bin:$PATH

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl nginx \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid ${VYSION_GID} vysion \
    && useradd --uid ${VYSION_UID} --gid ${VYSION_GID} --no-create-home --shell /usr/sbin/nologin vysion

WORKDIR /app
COPY requirements.lock ./
RUN python -m venv /opt/vysion-venv \
    && pip install --no-cache-dir --require-hashes -r requirements.lock
COPY VERSION ./VERSION
COPY docs/V1_V2_CAPABILITY_MAP.json ./docs/V1_V2_CAPABILITY_MAP.json
COPY src/ ./src/
RUN mkdir -p /app/data/reports /tmp/nginx/client_temp /tmp/nginx/proxy_temp \
    && chown -R vysion:vysion /app/data /tmp/nginx

COPY --from=frontend-build /build/frontend/dist/ /app/static/
COPY deploy/nginx.conf /etc/nginx/nginx.conf
COPY deploy/entrypoint.sh /usr/local/bin/vysion-entrypoint
RUN chmod 0555 /usr/local/bin/vysion-entrypoint \
    && chmod 0755 /etc/nginx \
    && chmod 0644 /etc/nginx/nginx.conf \
    && chmod 0644 /app/VERSION \
    && chmod -R a=rX /app/static /app/src \
    && rm -rf /var/log/nginx /var/cache/nginx

USER vysion:vysion
EXPOSE 8443
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl --fail --silent --show-error --cacert /run/vysion/tls/tls.crt --resolve ${VYSION_TLS_SERVER_NAME}:8443:127.0.0.1 https://${VYSION_TLS_SERVER_NAME}:8443/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/vysion-entrypoint"]

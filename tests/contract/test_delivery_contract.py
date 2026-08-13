from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def test_runtime_reports_ignore_is_anchored_without_hiding_source_modules() -> None:
    gitignore = (ROOT / ".gitignore").read_text().splitlines()
    dockerignore = (ROOT / ".dockerignore").read_text().splitlines()

    assert "/reports/" in gitignore
    assert "reports/" not in gitignore
    assert "/reports" in dockerignore
    assert "reports" not in dockerignore
    assert (ROOT / "src/vysion/reports/json_report.py").is_file()


def test_compose_defines_one_service_one_volume_and_one_https_port() -> None:
    compose = yaml.safe_load((ROOT / "compose.yml").read_text())

    assert list(compose["services"]) == ["vysion"]
    service = compose["services"]["vysion"]
    assert service["ports"] == ["${BIND_ADDRESS:-127.0.0.1}:443:8443"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert "VYSION_TLS_SERVER_NAME" in service["environment"]
    assert "--resolve" in service["healthcheck"]["test"][-1]
    assert "https://$${VYSION_TLS_SERVER_NAME}:8443/healthz" in service["healthcheck"]["test"][-1]
    assert list(compose["volumes"]) == ["vysion-reports"]
    assert "node" not in str(service).lower()


def test_nginx_owns_tls_http_limits_headers_static_files_and_api_proxy() -> None:
    nginx = (ROOT / "deploy/nginx.conf").read_text()

    for directive in (
        "listen 8443 ssl",
        "ssl_certificate /run/vysion/tls/tls.crt",
        "ssl_certificate_key /run/vysion/tls/tls.key",
        "client_max_body_size 5m",
        "client_body_timeout 15s",
        "proxy_connect_timeout 5s",
        "proxy_read_timeout 120s",
        "fastcgi_temp_path /tmp/nginx/fastcgi_temp",
        "uwsgi_temp_path /tmp/nginx/uwsgi_temp",
        "scgi_temp_path /tmp/nginx/scgi_temp",
        "add_header X-Content-Type-Options nosniff always",
        "add_header X-Frame-Options DENY always",
        "location /api/",
        "proxy_pass http://127.0.0.1:8000",
        "try_files $uri $uri/ /index.html",
    ):
        assert directive in nginx
    log_format = nginx.split("log_format main", maxsplit=1)[1].split(";", maxsplit=1)[0]
    assert "$uri" not in log_format
    assert "$request_uri" not in log_format


def test_runtime_stage_has_no_node_and_fastapi_binds_only_loopback() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    runtime = dockerfile.split("FROM python:", maxsplit=1)[1]
    entrypoint = (ROOT / "deploy/entrypoint.sh").read_text()

    assert "node" not in runtime.lower()
    assert "npm" not in runtime.lower()
    assert "--host 127.0.0.1" in entrypoint
    assert "--factory" in entrypoint
    assert "nginx -g 'daemon off;'" in entrypoint
    assert "trap 'shutdown 0' INT TERM" in entrypoint
    assert "shutdown 1" in entrypoint
    for path in (
        "/tmp/nginx/client_temp",
        "/tmp/nginx/proxy_temp",
        "/tmp/nginx/fastcgi_temp",
        "/tmp/nginx/uwsgi_temp",
        "/tmp/nginx/scgi_temp",
    ):
        assert path in entrypoint

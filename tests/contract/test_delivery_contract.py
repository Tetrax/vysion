import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]

# The only deployable image reference: compose hard-codes the registry and
# repository and interpolates only into the digest position of `name@digest`,
# so a tag — mutable by definition — can never be expressed in the rendered
# reference.
IMMUTABLE_IMAGE_PATTERN = re.compile(r"^ghcr\.io/tetrax/vysion@sha256:[0-9a-f]{64}$")

# Every non-immutable value must be refused before a container can exist:
# compose refuses the empty value at interpolation time, and Docker itself
# refuses the malformed references while acquiring the image ("invalid
# reference format" / "invalid checksum digest format", before any registry
# contact and before any container is created).
NON_IMMUTABLE_IMAGE_VALUES = (
    "latest",  # mutable tag
    "sha-latest",  # legacy pseudo-tag from the previous contract
    "deadbeef",  # short SHA, bare
    "sha256:deadbeef",  # short SHA with algorithm
    "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",  # uppercase hex
    "sha256:zzzz0123456789zzzz0123456789zzzz0123456789zzzz0123456789zzzz0123",  # non-hex
)

# Format-valid digest used to render the stack: rendering never needs the
# image to exist — only the reference must be immutable and well-formed.
VALID_DIGEST = "sha256:" + "0123456789abcdef" * 4


def test_runtime_reports_ignore_is_anchored_without_hiding_source_modules() -> None:
    gitignore = (ROOT / ".gitignore").read_text().splitlines()
    dockerignore = (ROOT / ".dockerignore").read_text().splitlines()

    assert "/reports/" in gitignore
    assert "reports/" not in gitignore
    assert "/reports" in dockerignore
    assert "reports" not in dockerignore
    assert (ROOT / "src/vysion/reports/json_report.py").is_file()


def test_compose_targets_one_loopback_http_service_with_one_external_volume() -> None:
    raw = (ROOT / "compose.yml").read_text()
    compose = yaml.safe_load(raw)

    assert list(compose["services"]) == ["vysion"]
    service = compose["services"]["vysion"]
    # BIND_ADDRESS selects the published IP only; HOST_PORT selects the published
    # port so a temporary 18080 stack can coexist with the running instance
    # before the final 8080 cutover.
    assert service["ports"] == ["${BIND_ADDRESS:-127.0.0.1}:${HOST_PORT:-8080}:8080"]
    # The stack refuses to resolve without the image digest, and compose
    # interpolates only into the digest position of `name@digest`: a tag is
    # structurally impossible in the rendered image reference.
    assert service["image"].startswith("ghcr.io/tetrax/vysion@${IMAGE_DIGEST:")
    assert ":?" in service["image"]
    assert "IMAGE_TAG" not in service["image"]
    assert "IMAGE_COMMIT" not in service["image"]
    assert "pull_policy" not in service
    # The Portainer Git Stack consumes the CI-published digest. Keeping a
    # Compose `build` section makes Portainer invoke `docker compose build`,
    # which cannot tag a locally built image with a digest reference.
    assert "build" not in service
    # Hardening of the running instance is preserved.
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["pids_limit"] == 128
    assert service["mem_limit"] == "${MEM_LIMIT:-512m}"
    assert service["cpus"] == "${CPU_LIMIT:-1.0}"
    assert service["tmpfs"]
    assert service["restart"] == "unless-stopped"
    # Exactly one named volume, declared external so the reports data keeps its
    # identity across stacks; no bind mount, no static IP, no external network.
    assert list(compose["volumes"]) == ["vysion-reports"]
    assert compose["volumes"]["vysion-reports"] == {"external": True, "name": "vysion-reports"}
    assert service["volumes"] == ["vysion-reports:/app/data/reports"]
    assert "networks" not in service
    assert "networks" not in compose
    # No internal TLS: the host Nginx already terminates TLS for the vhost.
    assert "VYSION_TLS_SERVER_NAME" not in service["environment"]
    for forbidden in ("Subnet-Docker", "ipv4_address", "/run/vysion/tls", "ssl", "TLS"):
        assert forbidden not in raw, forbidden
    # The healthcheck crosses Nginx and FastAPI over plain loopback HTTP.
    assert service["healthcheck"]["test"][-1] == (
        "curl --fail --silent --show-error http://127.0.0.1:8080/healthz"
    )
    assert "node" not in str(service).lower()


def _require_docker_compose() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is required to render compose.yml")
    probe = subprocess.run(["docker", "compose", "version"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("the docker compose plugin is required to render compose.yml")


def _require_docker_daemon() -> None:
    probe = subprocess.run(["docker", "info"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("a running docker daemon is required to prove the refusal gate")


def _clean_env(**env: str) -> dict[str, str]:
    """IMAGE_* never leaks from the caller's environment; --env-file replaces
    any local .env file."""
    clean = {key: value for key, value in os.environ.items() if not key.startswith("IMAGE_")}
    clean.update(env)
    return clean


def _compose_config(empty_env: Path, *args: str, **env: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "--env-file", str(empty_env), "config", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=_clean_env(**env),
        check=False,
    )


def _compose_pull(empty_env: Path, value: str) -> subprocess.CompletedProcess:
    """The deployment step that runs before any container exists: acquiring
    the image, exactly as `docker compose up` does on the host."""
    return subprocess.run(
        ["docker", "compose", "--env-file", str(empty_env), "pull", "vysion"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=_clean_env(IMAGE_DIGEST=value),
        check=False,
    )


def _compose_ps(empty_env: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "--env-file", str(empty_env), "ps", "-a"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=_clean_env(IMAGE_DIGEST=VALID_DIGEST),
        check=False,
    )


def test_compose_refuses_every_non_immutable_image_reference(tmp_path: Path) -> None:
    """Negative contract: `latest`, `sha-latest`, short SHAs, uppercase or
    non-hex values and the empty value are all refused — the empty value by
    compose at interpolation time, the others by Docker itself while acquiring
    the image — and no container of the stack is ever created, so Vysion can
    never become healthy with them."""
    _require_docker_compose()
    _require_docker_daemon()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    missing = _compose_config(empty_env, "--quiet")
    assert missing.returncode != 0, missing.stdout + missing.stderr

    empty = _compose_config(empty_env, "--quiet", IMAGE_DIGEST="")
    assert empty.returncode != 0, empty.stdout + empty.stderr

    # The legacy mutable variables must not resolve either.
    legacy = _compose_config(empty_env, "--quiet", IMAGE_TAG="latest")
    assert legacy.returncode != 0, legacy.stdout + legacy.stderr
    legacy_commit = _compose_config(empty_env, "--quiet", IMAGE_COMMIT="latest")
    assert legacy_commit.returncode != 0, legacy_commit.stdout + legacy_commit.stderr

    for value in NON_IMMUTABLE_IMAGE_VALUES:
        rendered = _compose_config(empty_env, IMAGE_DIGEST=value)
        if rendered.returncode != 0:
            continue  # already refused by compose itself
        image = yaml.safe_load(rendered.stdout)["services"]["vysion"]["image"]
        # Every rendered non-immutable reference must be rejected while the
        # image is acquired: through compose, and directly at the daemon with
        # the exact reference compose would pull.
        pull = _compose_pull(empty_env, value)
        assert pull.returncode != 0, pull.stdout + pull.stderr
        direct = subprocess.run(
            ["docker", "pull", image],
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=False,
        )
        assert direct.returncode != 0, direct.stdout + direct.stderr

    # Nothing was ever created for the stack: no container can become healthy.
    ps = _compose_ps(empty_env)
    assert ps.returncode == 0, ps.stdout + ps.stderr
    rows = [line for line in ps.stdout.splitlines() if line.strip() and not line.startswith("NAME")]
    assert rows == [], rows


def test_compose_renders_the_exact_immutable_reference_for_a_valid_digest(
    tmp_path: Path,
) -> None:
    """Positive contract: a format-valid OCI digest renders exactly the
    immutable GHCR reference used for the deployment, on both cutover ports."""
    _require_docker_compose()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    for host_port in ("8080", "18080"):
        rendered = _compose_config(empty_env, HOST_PORT=host_port, IMAGE_DIGEST=VALID_DIGEST)
        assert rendered.returncode == 0, rendered.stdout + rendered.stderr
        service = yaml.safe_load(rendered.stdout)["services"]["vysion"]
        image = service["image"]
        assert image == f"ghcr.io/tetrax/vysion@{VALID_DIGEST}"
        assert IMMUTABLE_IMAGE_PATTERN.fullmatch(image)
        # The port scenarios stay valid: loopback bind, target 8080 inside,
        # the requested port published outside.
        port = service["ports"][0]
        assert port["host_ip"] == "127.0.0.1"
        assert port["target"] == 8080
        assert str(port["published"]) == host_port


def test_env_example_pins_an_immutable_image_digest_and_a_separate_host_port() -> None:
    entries = dict(
        line.split("=", maxsplit=1)
        for line in (ROOT / ".env.example").read_text().splitlines()
        if line and not line.startswith("#")
    )

    # The example itself satisfies the immutable contract: a full sha256
    # digest, never a mutable tag and never a legacy variable name.
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", entries["IMAGE_DIGEST"])
    assert "IMAGE_TAG" not in entries
    assert "IMAGE_COMMIT" not in entries
    assert entries["BIND_ADDRESS"] == "127.0.0.1"
    assert entries["HOST_PORT"] == "8080"
    assert "TLS_CERTS_DIR" not in entries
    assert "TLS_SERVER_NAME" not in entries
    assert "VYSION_IPV4_ADDRESS" not in entries


def test_operations_doc_publishes_the_sequenced_cutover_and_rollback_checklist() -> None:
    operations = (ROOT / "docs/OPERATIONS.md").read_text().casefold()

    for marker in (
        "host_port=18080",
        "host_port=8080",
        "vysion-reports",
        "sauvegarde",
        "restauration",
        "rollback",
        "ghcr",
        # The runbook must say how to obtain and enter the immutable
        # reference, and how to verify the image actually running.
        "image_digest",
        "imagetools",
        "org.opencontainers.image.revision",
    ):
        assert marker in operations, marker


def test_ci_publishes_the_commit_tag_and_verifies_the_revision_label_link() -> None:
    """Traceability contract: CI still publishes the human tag sha-<commit>
    and ties the image back to its commit through the OCI label
    org.opencontainers.image.revision — verified at publish time against
    github.sha — while the publish job prints the digest operators paste into
    IMAGE_DIGEST."""
    workflow = (ROOT / ".github/workflows/publish-container.yml").read_text()

    assert "tags: ghcr.io/tetrax/vysion:sha-${{ github.sha }}" in workflow
    assert "org.opencontainers.image.revision=${{ github.sha }}" in workflow
    # The publish job proves the link on the pushed image, not only in source.
    assert 'index .Config.Labels "org.opencontainers.image.revision"' in workflow
    assert "RepoDigests" in workflow


def test_field_backup_module_collects_without_permission_errors() -> None:
    """A field backup that exists but is unreadable (other user's home) must
    skip its tests instead of breaking the standard suite for every user."""
    module = ROOT / "tests" / "unit" / "test_docx_v1_restoration.py"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", str(module)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 0, output
    assert "PermissionError" not in output, output


def test_nginx_serves_plain_http_on_8080_and_forwards_the_host_proxy_headers() -> None:
    nginx = (ROOT / "deploy/nginx.conf").read_text()

    for directive in (
        "listen 8080;",
        "listen [::]:8080;",
        "root /app/static;",
        "client_max_body_size 5m",
        "client_body_timeout 15s",
        "proxy_connect_timeout 5s",
        "proxy_read_timeout 120s",
        "fastcgi_temp_path /tmp/nginx/fastcgi_temp",
        "uwsgi_temp_path /tmp/nginx/uwsgi_temp",
        "scgi_temp_path /tmp/nginx/scgi_temp",
        "add_header X-Content-Type-Options nosniff always",
        "add_header X-Frame-Options DENY always",
        "location = /healthz",
        "location /api/",
        "proxy_pass http://127.0.0.1:8000",
        "proxy_set_header X-Real-IP $http_x_real_ip;",
        "proxy_set_header X-Forwarded-For $http_x_forwarded_for;",
        "proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;",
        "try_files $uri $uri/ /index.html",
    ):
        assert directive in nginx, directive
    # TLS lives on the host Nginx; nothing inside the container speaks it.
    assert "ssl" not in nginx
    assert "8443" not in nginx
    log_format = nginx.split("log_format main", maxsplit=1)[1].split(";", maxsplit=1)[0]
    assert "$uri" not in log_format
    assert "$request_uri" not in log_format


def test_image_contains_the_http_runtime_config_and_drops_every_tls_reference() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    runtime = dockerfile.split("FROM python:", maxsplit=1)[1]
    entrypoint = (ROOT / "deploy/entrypoint.sh").read_text()

    assert "node" not in runtime.lower()
    assert "npm" not in runtime.lower()
    assert "EXPOSE 8080" in runtime
    assert "8443" not in dockerfile
    assert "--cacert" not in dockerfile
    assert "VYSION_TLS_SERVER_NAME" not in dockerfile
    assert "http://127.0.0.1:8080/healthz" in runtime
    assert "COPY deploy/nginx.conf /etc/nginx/nginx.conf" in dockerfile
    assert "nginx-container-http.conf" not in dockerfile
    assert "USER vysion:vysion" in runtime
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


def test_runtime_presentation_map_is_readable_by_non_root_runtime_user() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()

    assert "COPY docs/V1_V2_CAPABILITY_MAP.json ./docs/V1_V2_CAPABILITY_MAP.json" in dockerfile
    assert "/app/docs" in dockerfile.split("FROM python:", maxsplit=1)[1]

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


def test_compose_targets_one_loopback_http_service_with_stable_external_volumes() -> None:
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
    # Two named volumes, declared external so the reports data and the durable
    # administration state keep their identity across stacks; no bind mount,
    # no static IP, no external network. The certificate volume only exists in
    # the standalone stack (compose.standalone.yml). The optional
    # VYSION_VOLUME_PREFIX (default empty) exists so validation stacks and
    # smokes can run on disjoint volumes without touching the live ones.
    assert list(compose["volumes"]) == ["vysion-reports", "vysion-state"]
    assert compose["volumes"]["vysion-reports"] == {
        "external": True,
        "name": "${VYSION_VOLUME_PREFIX:-}vysion-reports",
    }
    assert compose["volumes"]["vysion-state"] == {
        "external": True,
        "name": "${VYSION_VOLUME_PREFIX:-}vysion-state",
    }
    assert service["volumes"] == [
        "vysion-reports:/app/data/reports",
        "vysion-state:/app/data/state",
    ]
    assert "networks" not in service
    assert "networks" not in compose
    # No internal TLS: the host Nginx already terminates TLS for the vhost.
    assert "VYSION_TLS_SERVER_NAME" not in service["environment"]
    # Forwarded-trust and public-origin wiring: the host hop is trusted by
    # default, an external proxy CIDR list and the authoritative origin are
    # operator-settable, and the origin defaults to unset (never invented).
    assert service["environment"]["VYSION_TRUSTED_PROXY_CIDRS"] == (
        "${TRUSTED_PROXY_CIDRS:-127.0.0.1/32}"
    )
    assert service["environment"]["VYSION_PUBLIC_ORIGIN"] == "${PUBLIC_ORIGIN:-}"
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


def _render(
    compose_file: str, empty_env: Path, *args: str, **env: str
) -> subprocess.CompletedProcess:
    """Render one compose file with a caller-chosen synthetic environment."""
    return subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            compose_file,
            "--env-file",
            str(empty_env),
            "config",
            *args,
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=_clean_env(**env),
        check=False,
    )


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


def test_nginx_serves_plain_http_on_8080_and_forwards_the_observed_hop() -> None:
    nginx = (ROOT / "deploy/nginx.conf").read_text()
    standalone = (ROOT / "deploy/nginx-standalone.conf").read_text()

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
        # $http_host keeps the client port: the origin check compares against
        # the exact Host the browser used (18080/18443 staging included).
        "proxy_set_header Host $http_host;",
        # Forwarded-trust contract (review finding): the app may only ever see
        # hops THIS nginx observed. Client input is never forwarded as a hop
        # or as a scheme; an upstream proxy's scheme claim passes through a
        # separate header the app gates on the trusted CIDRs.
        "proxy_set_header X-Real-IP $remote_addr;",
        "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "proxy_set_header X-Forwarded-Proto $scheme;",
        "proxy_set_header X-Forwarded-Client-Proto $http_x_forwarded_proto;",
        "try_files $uri $uri/ /index.html",
    ):
        assert directive in nginx, directive
    # The client-controlled variants must be gone from both configs.
    for config in (nginx, standalone):
        assert "$http_x_real_ip" not in config
        assert "X-Forwarded-For $http_x_forwarded_for" not in config
        assert "$vysion_forwarded_proto" not in config
        for directive in (
            "proxy_set_header X-Real-IP $remote_addr;",
            "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "proxy_set_header X-Forwarded-Proto $scheme;",
            "proxy_set_header X-Forwarded-Client-Proto $http_x_forwarded_proto;",
        ):
            assert directive in config, directive
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
    # uvicorn must not trust forwarded headers on its own: the peer and the
    # scheme come from the application's own TrustedProxy.resolve, so no
    # client-controlled X-Forwarded-* value can rewrite either. uvicorn's
    # proxy_headers default is ON (the round-2 smoke caught the scope client
    # being rewritten from X-Forwarded-For, which defeated the loopback-gated
    # trust), so the disable flag is mandatory, not implied by absence.
    assert "--no-proxy-headers" in entrypoint
    assert "--proxy-headers" not in entrypoint.replace("--no-proxy-headers", "")
    assert "--forwarded-allow-ips" not in entrypoint
    # The default runtime stays plain HTTP: the standalone TLS terminator is
    # an explicit opt-in (VYSION_TLS_BACKEND=local selects the separate
    # nginx-standalone.conf), never the default config.
    assert "nginx -c \"$nginx_config\" -g 'daemon off;'" in entrypoint
    assert "nginx_config=/etc/nginx/nginx.conf" in entrypoint
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


def test_standalone_stack_requires_tls_settings_and_the_three_stable_volumes() -> None:
    """Decision 0007 + zero-CLI Portainer install: the standalone stack
    terminates TLS itself and must resolve with an explicit hostname only —
    no `IMAGE_DIGEST` (the online install tracks the promoted `stable`
    channel, decision 0011) — while mounting the three stable volumes —
    Compose-managed (not external), so a fresh Git Stack creates them
    itself with the stable names, without any host command, and the data
    survives recreate. Certificates live apart from state and reports."""
    raw = (ROOT / "compose.standalone.yml").read_text()
    compose = yaml.safe_load(raw)

    service = compose["services"]["vysion"]
    # The one stack that is updatable in one click: a literal channel tag
    # plus a pull policy that re-acquires it, never an interpolation.
    assert service["image"] == "ghcr.io/tetrax/vysion:stable"
    assert service["pull_policy"] == "always"
    assert "${" not in service["image"]
    assert "${IMAGE_DIGEST" not in raw
    environment = service["environment"]
    assert environment["VYSION_TLS_BACKEND"] == "local"
    assert environment["VYSION_TLS_HOSTNAME"].startswith("${VYSION_TLS_HOSTNAME:?")
    # The authoritative origin can be pinned (non-443 ports); otherwise it is
    # derived from VYSION_TLS_HOSTNAME inside the application.
    assert environment["VYSION_PUBLIC_ORIGIN"] == "${PUBLIC_ORIGIN:-}"
    assert environment["VYSION_TRUSTED_PROXY_CIDRS"] == (
        "${TRUSTED_PROXY_CIDRS:-127.0.0.1/32}"
    )
    assert service["ports"] == ["${BIND_ADDRESS:-127.0.0.1}:${HTTPS_PORT:-443}:443"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["tmpfs"]
    assert list(compose["volumes"]) == ["vysion-reports", "vysion-state", "vysion-certs"]
    for volume, mount in (
        ("vysion-reports", "vysion-reports:/app/data/reports"),
        ("vysion-state", "vysion-state:/app/data/state"),
        ("vysion-certs", "vysion-certs:/app/certs"),
    ):
        # Managed by Compose with the stable name: `external: true` would
        # force a `docker volume create` on the host before the stack could
        # even start, which a Portainer-only install cannot perform.
        assert compose["volumes"][volume] == {
            "name": "${VYSION_VOLUME_PREFIX:-}" + volume,
        }
        assert "external" not in compose["volumes"][volume]
        assert mount in service["volumes"]
    assert service["healthcheck"]["test"][-1] == (
        "curl --fail --silent --show-error http://127.0.0.1:8080/healthz"
    )
    # Certificates are only referenced by the dedicated standalone config and
    # entrypoint bootstrap, never by the proxy runtime config.
    assert "ssl" not in (ROOT / "deploy/nginx.conf").read_text()
    standalone = (ROOT / "deploy/nginx-standalone.conf").read_text()
    assert "listen 443 ssl;" in standalone
    assert "ssl_certificate /app/certs/active/fullchain.pem;" in standalone
    assert "ssl_certificate_key /app/certs/active/key.pem;" in standalone


def test_runtime_presentation_map_is_readable_by_non_root_runtime_user() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()

    assert "COPY docs/V1_V2_CAPABILITY_MAP.json ./docs/V1_V2_CAPABILITY_MAP.json" in dockerfile
    assert "/app/docs" in dockerfile.split("FROM python:", maxsplit=1)[1]


def test_proxy_stack_requires_an_explicit_trusted_proxy_and_stays_plain_http() -> None:
    """Deployment mode 2 (VM behind an external reverse proxy): generic, no
    host path/IP/subnet imposed, no bundled certificate, and the trusted
    proxy CIDR list is a required operator decision — never a silent
    default."""
    raw = (ROOT / "compose.proxy.yml").read_text()
    compose = yaml.safe_load(raw)

    assert list(compose["services"]) == ["vysion"]
    service = compose["services"]["vysion"]
    assert service["image"].startswith("ghcr.io/tetrax/vysion@${IMAGE_DIGEST:")
    assert ":?" in service["image"]
    environment = service["environment"]
    assert environment["VYSION_TRUSTED_PROXY_CIDRS"].startswith(
        "${TRUSTED_PROXY_CIDRS:?"
    )
    assert environment["VYSION_PUBLIC_ORIGIN"] == "${PUBLIC_ORIGIN:-}"
    # The container never terminates the connection itself in this mode.
    assert "VYSION_TLS_BACKEND" not in environment
    assert "VYSION_TLS_HOSTNAME" not in environment
    assert service["ports"] == ["${BIND_ADDRESS:-127.0.0.1}:${HOST_PORT:-8080}:8080"]
    # Same durable state contract as the VPS mode, no certificate volume.
    assert list(compose["volumes"]) == ["vysion-reports", "vysion-state"]
    for volume in ("vysion-reports", "vysion-state"):
        assert compose["volumes"][volume] == {
            "external": True,
            "name": "${VYSION_VOLUME_PREFIX:-}" + volume,
        }
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["pids_limit"] == 128
    assert service["tmpfs"]
    assert "networks" not in service
    assert "networks" not in compose
    for forbidden in ("Subnet-Docker", "ipv4_address", "ssl", "TLS"):
        assert forbidden not in raw, forbidden


def test_proxy_stack_renders_with_synthetic_variables_and_refuses_without_them(
    tmp_path: Path,
) -> None:
    _require_docker_compose()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    missing_cidr = _render("compose.proxy.yml", empty_env, IMAGE_DIGEST=VALID_DIGEST)
    assert missing_cidr.returncode != 0, missing_cidr.stdout + missing_cidr.stderr
    assert "TRUSTED_PROXY_CIDRS" in missing_cidr.stderr

    rendered = _render(
        "compose.proxy.yml",
        empty_env,
        IMAGE_DIGEST=VALID_DIGEST,
        TRUSTED_PROXY_CIDRS="127.0.0.1/32,10.0.0.0/8",
        PUBLIC_ORIGIN="https://vysion.example.com",
        HOST_PORT="18080",
    )
    assert rendered.returncode == 0, rendered.stderr
    service = yaml.safe_load(rendered.stdout)["services"]["vysion"]
    assert service["image"] == f"ghcr.io/tetrax/vysion@{VALID_DIGEST}"
    assert service["environment"]["VYSION_TRUSTED_PROXY_CIDRS"] == (
        "127.0.0.1/32,10.0.0.0/8"
    )
    assert service["environment"]["VYSION_PUBLIC_ORIGIN"] == (
        "https://vysion.example.com"
    )
    volumes = yaml.safe_load(rendered.stdout)["volumes"]
    # Defaults are unchanged: without a prefix the stable production names win.
    assert volumes["vysion-reports"]["name"] == "vysion-reports"
    assert volumes["vysion-state"]["name"] == "vysion-state"


def test_volume_prefix_isolates_validation_stacks_from_the_live_volumes(
    tmp_path: Path,
) -> None:
    """VYSION_VOLUME_PREFIX (empty by default) lets a smoke or a validation
    stack bind disjoint external volumes while the production names stay
    byte-for-byte the default."""
    _require_docker_compose()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    default = _render("compose.yml", empty_env, IMAGE_DIGEST=VALID_DIGEST)
    assert default.returncode == 0, default.stderr
    default_volumes = yaml.safe_load(default.stdout)["volumes"]
    assert default_volumes["vysion-reports"]["name"] == "vysion-reports"
    assert default_volumes["vysion-state"]["name"] == "vysion-state"

    prefixed = _render(
        "compose.standalone.yml",
        empty_env,
        VYSION_TLS_HOSTNAME="vysion.example.com",
        VYSION_VOLUME_PREFIX="smoke-20260922-",
    )
    assert prefixed.returncode == 0, prefixed.stderr
    volumes = yaml.safe_load(prefixed.stdout)["volumes"]
    assert volumes["vysion-reports"]["name"] == "smoke-20260922-vysion-reports"
    assert volumes["vysion-state"]["name"] == "smoke-20260922-vysion-state"
    assert volumes["vysion-certs"]["name"] == "smoke-20260922-vysion-certs"


def test_readme_documents_the_three_modes_and_the_durable_volumes() -> None:
    """Review finding: the README still claimed a single reports volume and
    no certificate in the container. It must describe every deployment mode,
    every durable volume and the knobs the modes need."""
    readme = (ROOT / "README.md").read_text()
    for marker in (
        "compose.standalone.yml",
        "compose.proxy.yml",
        "vysion-state",
        "vysion-certs",
        "vysion-reports",
        "TRUSTED_PROXY_CIDRS",
        "PUBLIC_ORIGIN",
        "VYSION_VOLUME_PREFIX",
    ):
        assert marker in readme, marker
    # The old single-volume / no-certificate claims must be gone as such.
    assert "aucun certificat, aucune clé et aucun montage TLS dans le conteneur" not in (
        readme
    )
    # Review round-2 finding 2: 127.0.0.1/32 is not "the host hop" in the
    # VPS path — the rollout must name the Docker hop it actually observes.
    assert "défaut `127.0.0.1/32` (hôte)" not in readme
    # Review round-2 finding 1: PUBLIC_ORIGIN gates every admin mutation.
    assert "503" in readme


def test_restore_script_separates_source_archives_from_target_volumes() -> None:
    """Review round-2 finding 3: restore.sh must read its archives with
    VYSION_BACKUP_PREFIX (the prefix the backup was taken with) and write
    its volumes with VYSION_VOLUME_PREFIX, so a production backup restores
    onto prefixed disposable volumes — and an empty restore must fail."""
    restore = (ROOT / "scripts/restore.sh").read_text()
    assert "VYSION_BACKUP_PREFIX" in restore
    assert "VYSION_VOLUME_PREFIX" in restore
    assert "no expected archive" in restore
    assert "exit 1" in restore
    backup = (ROOT / "scripts/backup.sh").read_text()
    assert "VYSION_BACKUP_PREFIX" in backup


def test_operations_doc_covers_volume_prerequisites_modes_and_coherent_backup() -> None:
    operations = (ROOT / "docs/OPERATIONS.md").read_text().casefold()
    for marker in (
        # Fresh/current instance must create the external volumes before the
        # Portainer stack references them.
        "docker volume create vysion-state",
        "docker volume create vysion-certs",
        # Explicit third mode + its required trust decision.
        "compose.proxy.yml",
        "trusted_proxy_cidrs",
        "public_origin",
        # The backup boundary must be coherent (quiesced stack), and restore
        # proven on disposable volumes.
        "quies",
        "volume jetable",
        "empreinte",
        "docker volume create vysion-smoke-",
        # Review round-2 finding 3: the source archive names
        # (VYSION_BACKUP_PREFIX) are independent from the target volume
        # prefix (VYSION_VOLUME_PREFIX), and an empty restore must fail.
        "vysion_backup_prefix",
        "exit 1",
    ):
        assert marker in operations, marker


def test_compose_helper_mounts_a_read_only_socket_and_never_a_certificate() -> None:
    """The fourth stack: host nginx terminates TLS, a root helper owns the
    material, and the container receives a socket it may only read. Nothing
    writable and nothing secret is ever mounted into the application."""
    raw = (ROOT / "compose.helper.yml").read_text()
    compose = yaml.safe_load(raw)

    assert list(compose["services"]) == ["vysion"]
    service = compose["services"]["vysion"]
    assert service["image"].startswith("ghcr.io/tetrax/vysion@${IMAGE_DIGEST")
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]

    environment = service["environment"]
    assert environment["VYSION_TLS_BACKEND"] == "helper"
    # No silent fallback: the SAN the certificate must match is imposed.
    assert "${VYSION_TLS_HOSTNAME:?" in environment["VYSION_TLS_HOSTNAME"]
    # Still behind an external proxy: forwarded trust stays explicit.
    assert "${TRUSTED_PROXY_CIDRS:?" in environment["VYSION_TRUSTED_PROXY_CIDRS"]

    mounts = service["volumes"]
    helper_mounts = [entry for entry in mounts if entry.startswith("/run/vysion-cert-helper:")]
    # The host directory does not move — the systemd unit owns it — while the
    # container side is exactly the path compose hands to the application.
    # That path must also survive the declared tmpfs: see
    # test_the_helper_socket_path_cannot_be_masked_by_a_mount_or_tmpfs.
    assert helper_mounts == [
        f"/run/vysion-cert-helper:{os.path.dirname(environment['VYSION_HELPER_SOCKET_PATH'])}:ro"
    ]
    # The application must never receive a writable certificate path, and the
    # helper's generations are not a Docker volume: they live on the host.
    assert not any("certs" in entry for entry in mounts)
    assert "vysion-certs" not in compose.get("volumes", {})
    assert list(compose["volumes"]) == ["vysion-reports", "vysion-state"]


# ``/var/run`` is a symlink to ``/run`` inside the image: a tmpfs declared on
# ``/var/run`` (Nginx needs one) therefore hides whatever is mounted *under*
# ``/run``. This is not theoretical — it is how the helper socket vanished
# when the certificate administration of PR #16 reached a real host: the
# container stayed healthy, ``docker inspect`` kept announcing the bind, and
# ``stat /run/vysion-cert-helper`` returned ENOENT.
IMAGE_SYMLINKS = {"/var/run": "/run"}


def _inside_image(path: str) -> str:
    """A mount target as the container resolves it, known symlinks included."""
    normalized = os.path.normpath(path)
    for link, target in IMAGE_SYMLINKS.items():
        if normalized == link or normalized.startswith(f"{link}/"):
            normalized = f"{target}{normalized[len(link) :]}"
    return os.path.normpath(normalized)


def _covers(parent: str, child: str) -> bool:
    """``parent`` sits on ``child`` — equal, or above it: mounting there hides it."""
    return child == parent or child.startswith(f"{parent}/")


def _declared_mount_targets(service: dict) -> dict[str, str]:
    """Every destination a volume, a bind or a tmpfs occupies, with its entry."""
    targets: dict[str, str] = {}
    for entry in service.get("volumes", []):
        parts = entry.split(":")
        if len(parts) >= 2:
            targets[parts[1]] = entry
    for entry in service.get("tmpfs", []):
        targets[entry.split(":", 1)[0]] = entry
    return targets


def test_the_helper_socket_path_cannot_be_masked_by_a_mount_or_tmpfs() -> None:
    """The socket helper mode consumes must survive every declared mount.

    The defect this pins down: a bind on ``/run/vysion-cert-helper`` was
    announced by ``docker inspect`` yet absent in the container, because the
    tmpfs mounted on ``/var/run`` — a symlink to ``/run`` — mounted over it.
    Declaration is not reachability, so the contract is structural rather
    than anecdotal:

    * the path the application consumes is stated in compose, never left to
      the in-image default and never interpolated;
    * it is fed by the host directory the systemd unit owns, still ``:ro``;
    * no other declared mount sits on that path, above it or below it,
      ``/var/run`` symlink included.
    """
    compose = yaml.safe_load((ROOT / "compose.helper.yml").read_text())
    service = compose["services"]["vysion"]
    environment = service["environment"]

    declared = environment.get("VYSION_HELPER_SOCKET_PATH")
    assert declared, "helper mode must set VYSION_HELPER_SOCKET_PATH explicitly"
    assert "${" not in declared, f"the socket path must be a literal, got {declared}"
    socket_path = _inside_image(declared)
    socket_directory = _inside_image(os.path.dirname(declared))

    # Host side: the helper's own directory, unchanged, still read-only.
    host_source = "/run/vysion-cert-helper"
    helper_binds = [
        entry for entry in service["volumes"] if entry.split(":", 1)[0] == host_source
    ]
    assert helper_binds == [f"{host_source}:{os.path.dirname(declared)}:ro"]

    # The helper's own bind is what supplies the socket: every *other*
    # declared mount must leave both the socket and its directory alone.
    mounts = _declared_mount_targets(service)
    mounts.pop(os.path.dirname(declared), None)
    for target, entry in mounts.items():
        resolved = _inside_image(target)
        for reference, label in ((socket_path, "socket"), (socket_directory, "directory")):
            assert not _covers(resolved, reference), (
                f"{entry} is mounted at {resolved} and hides the helper {label} {declared} "
                f"(the /var/run tmpfs resolves to /run)"
            )
            assert not _covers(reference, resolved), (
                f"{entry} is mounted at {resolved}, inside the helper {label} {declared}"
            )


def test_helper_scripts_and_unit_are_shipped_and_idempotent_by_construction() -> None:
    """The deployment surface the helper mode ships with."""
    unit = (ROOT / "deploy/vysion-cert-helper.service").read_text()
    assert "vysion.certhelper serve" in unit
    assert "ProtectSystem=strict" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet" in unit
    # The unit must not be able to write anywhere the material lives except
    # the generations directory itself.
    readwrite = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths"))
    assert "/etc" not in readwrite

    renew_hook = (ROOT / "deploy/certbot-vysion-deploy.sh").read_text()
    assert "RENEWED_LINEAGE" in renew_hook
    # The hook still matches Certbot's own live tree by default; the
    # VYSION_LETSENCRYPT_LIVE_DIR override exists only so the documented
    # sequence can be replayed against a sandbox (never /etc).
    assert "/etc/letsencrypt/live" in renew_hook
    assert "VYSION_LETSENCRYPT_LIVE_DIR" in renew_hook
    assert "renew" in renew_hook

    bootstrap = (ROOT / "deploy/vysion-cert-bootstrap.sh").read_text()
    assert "install" in bootstrap
    assert "/etc/letsencrypt/live" in bootstrap
    assert "VYSION_LETSENCRYPT_LIVE_DIR" in bootstrap

    # Review round-1 finding 3: the host nginx must actually be repointed to
    # the helper's active generation, with `nginx -t` before any reload, a
    # read-back of the served fingerprint, automatic restore on failure and
    # an explicit `restore` subcommand for manual rollback.
    migrate = ROOT / "deploy/vysion-cert-migrate-nginx.sh"
    migration = migrate.read_text()
    assert os.access(migrate, os.X_OK), "the migration script must ship executable"
    assert "#!/bin/sh" in migration
    assert '"$nginx_bin" -t' in migration
    assert "openssl s_client" in migration
    assert "sha256sum" in migration
    assert "restore_backup" in migration
    assert '"restore"' in migration
    assert "vysion-cert-bootstrap.sh" in migration  # ordering gate before touching /etc
    # The runbook documents the order, the read-back and the manual rollback.
    operations = (ROOT / "docs/OPERATIONS.md").read_text().casefold()
    for marker in (
        "vysion-cert-migrate-nginx.sh",
        "nginx -t",
        "empreinte sha-256 réellement servie",
        "restore <sauvegarde>",
    ):
        assert marker in operations, marker

    env_example = (ROOT / "deploy/vysion-cert-helper.env.example").read_text()
    # Ids and paths only: the example must not carry anything credential-like.
    assert "PASSWORD" not in env_example.upper()
    assert "SECRET=" not in env_example.upper()


def test_the_runbook_installs_every_helper_path_the_unit_requires() -> None:
    """Review round-2: on a fresh host, the documented commands alone must
    reach helper start, bootstrap, nginx migration and hook installation.

    The previous runbook copied only ``src`` into ``/opt/vysion`` while steps
    3-5 invoked ``/opt/vysion/deploy/*`` scripts that were never installed
    there, and nothing created ``/var/lib/vysion`` although the hardened unit
    whitelists it in ``ReadWritePaths`` (a non-``-`` entry systemd requires to
    exist before ExecStart).
    """
    operations = (ROOT / "docs/OPERATIONS.md").read_text().casefold()
    # One idempotent install sequence replaces the partial copy step.
    assert "vysion-cert-install.sh" in operations
    assert "cp -r src /opt/vysion/" not in operations
    install = ROOT / "deploy/vysion-cert-install.sh"
    assert install.is_file(), "the install sequence must ship"
    assert os.access(install, os.X_OK), "the install sequence must ship executable"
    install_text = install.read_text()
    assert "#!/bin/sh" in install_text
    # Every path the unit and the runbook depend on is managed there.
    for path in (
        "/opt/vysion",
        "/etc/vysion",
        "/var/lib/vysion",
        "/run/vysion-cert-helper",
        "/var/log/nginx",
        "/etc/systemd/system",
    ):
        assert path in install_text, path
    # The documented order stays: install, then service, then bootstrap,
    # then migration, then the Certbot hook.
    order = [
        operations.index(marker)
        for marker in (
            "vysion-cert-install.sh",
            "vysion-cert-bootstrap.sh",
            "vysion-cert-migrate-nginx.sh",
            "certbot-vysion-deploy.sh",
        )
    ]
    assert order == sorted(order), order

    unit = (ROOT / "deploy/vysion-cert-helper.service").read_text()
    # systemd creates the state and runtime directories itself before
    # ExecStart, so a reboot cannot leave ReadWritePaths dangling.
    assert "StateDirectory=vysion" in unit
    assert "RuntimeDirectory=vysion-cert-helper" in unit
    readwrite = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths"))
    for path in readwrite.partition("=")[2].split():
        assert path.lstrip("-") in install_text, path


def test_offline_stack_requires_the_imported_tag_and_the_same_hardening() -> None:
    """Decision 0010: offline distribution through Portainer's
    Images → Import alone. A `docker load`ed tar carries its tag but never
    its OCI digest, so this stack demands the imported tag (`VYSION_IMAGE`)
    while keeping every standalone hardening guarantee — including the
    three stable Compose-managed volumes that make the install zero-CLI."""
    raw = (ROOT / "compose.standalone.offline.yml").read_text()
    compose = yaml.safe_load(raw)

    assert list(compose["services"]) == ["vysion"]
    service = compose["services"]["vysion"]
    assert service["image"].startswith("${VYSION_IMAGE:?")
    assert "IMAGE_DIGEST" not in service["image"]
    environment = service["environment"]
    assert environment["VYSION_TLS_BACKEND"] == "local"
    assert "${VYSION_TLS_HOSTNAME:?" in environment["VYSION_TLS_HOSTNAME"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["healthcheck"]["test"][-1] == (
        "curl --fail --silent --show-error http://127.0.0.1:8080/healthz"
    )
    assert compose["volumes"] == {
        "vysion-reports": {"name": "${VYSION_VOLUME_PREFIX:-}vysion-reports"},
        "vysion-state": {"name": "${VYSION_VOLUME_PREFIX:-}vysion-state"},
        "vysion-certs": {"name": "${VYSION_VOLUME_PREFIX:-}vysion-certs"},
    }
    # Neither standalone stack may reintroduce `external`: a Portainer-only
    # install has no host command to pre-create a volume.
    for stack in ("compose.standalone.yml", "compose.standalone.offline.yml"):
        assert "external: true" not in (ROOT / stack).read_text()


def test_offline_stack_renders_only_with_the_imported_reference(
    tmp_path: Path,
) -> None:
    _require_docker_compose()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    missing = _render("compose.standalone.offline.yml", empty_env)
    assert missing.returncode != 0, missing.stdout + missing.stderr

    # Exactly one required variable is missing here, so every compose
    # reporting policy (first error only, or all of them) must name
    # VYSION_IMAGE: the assertion must not depend on which missing
    # variable the renderer happens to walk first.
    missing_image = _render(
        "compose.standalone.offline.yml",
        empty_env,
        VYSION_TLS_HOSTNAME="vysion.example.com",
    )
    assert missing_image.returncode != 0, missing_image.stdout + missing_image.stderr
    assert "VYSION_IMAGE" in missing_image.stderr

    rendered = _render(
        "compose.standalone.offline.yml",
        empty_env,
        VYSION_IMAGE="ghcr.io/tetrax/vysion:sha-deadbeef",
        VYSION_TLS_HOSTNAME="vysion.example.com",
    )
    assert rendered.returncode == 0, rendered.stderr
    assert "image: ghcr.io/tetrax/vysion:sha-deadbeef" in rendered.stdout
    assert "name: vysion-certs" in rendered.stdout


def test_runbook_documents_the_zero_cli_fresh_install_and_the_bundle() -> None:
    """Valentin's requirement: a company-fresh install must be documented
    end to end from the Portainer UI only — both distributions, the exact
    prerequisites, onboarding, digest updates, encrypted backup, rollback
    and the supplier/client split — plus the migration bundle itself."""
    operations = (ROOT / "docs/OPERATIONS.md").read_text().casefold()
    for marker in (
        "installation neuve chez une entreprise",
        "compose.standalone.offline.yml",
        # online: public repo + public package (2026-09-24) -> anonymous
        # clone/pull, NO registry credential; read:packages kept only as the
        # documented private-registry variant
        "aucun registre ni pat",
        "lecture anonyme",
        "variante (registry privée)",
        "read:packages",
        "ghcr",
        "git repository",
        "image_digest",
        # offline: image tar via Images → Import, compose via Stacks → Upload
        "*images* → *upload*",
        "*stacks*",
        "vysion_image",
        # prerequisites spelled out
        "vysion_tls_hostname",
        "tcp 443",
        "linux/amd64",
        "dns",
        "dépôt public",
        # anonymous audit => internal/filtered network, never open Internet
        "réseau interne ou filtré",
        "sans login applicatif",
        # the operator's checklist
        "onboarding",
        "sauvegarde chiffrée",
        "migration chiffrée entre instances",
        "vysmig",
        "aes-256-gcm",
        "scrypt",
        "rollback",
        "responsabilités fournisseur / client",
        "healthz",
    ):
        assert marker in operations, marker

    security = (ROOT / "docs/SECURITY.md").read_text().casefold()
    for marker in (
        "bundle de migration chiffré",
        "aes-256-gcm",
        "cryptography==46.0.5",
        "aucun endpoint de restauration anonyme",
        'excluded: ["reports"]',
    ):
        assert marker in security, marker

    readme = (ROOT / "README.md").read_text()
    assert ".vysmig" in readme
    assert "compose.standalone.offline.yml" in readme


def test_the_migration_dependency_is_pinned_with_verified_hashes() -> None:
    """The authenticated cipher is the one added dependency: pinned to an
    exact version in pyproject, and every hash locked in requirements.lock
    so the image's `pip install --require-hashes` verifies each artifact."""
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert '"cryptography==' in pyproject
    lock = (ROOT / "requirements.lock").read_text()
    index = lock.index("cryptography==")
    window = lock[index : index + 4096]
    assert "--hash=sha256:" in window
    version = window.partition("==")[2].partition("\\")[0].partition("\n")[0].strip(" \t\\")
    assert version
    pyproject_version = pyproject.partition('"cryptography==')[2].partition('"')[0]
    assert version == pyproject_version

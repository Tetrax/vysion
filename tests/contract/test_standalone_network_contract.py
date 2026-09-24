"""Deterministic network attachment and the generic Portainer variables of
the online standalone stack (``compose.standalone.yml``).

Four variables are in play, all of them entered in the Portainer stack UI:

* ``TLS_HOSTNAME``            the ONE required variable — the DNS name this
  instance serves, handed to the application as its internal
  ``VYSION_TLS_HOSTNAME`` (whose runtime contract does not move);
* ``DOCKER_NETWORK``          name of the Docker network to join;
* ``DOCKER_NETWORK_EXTERNAL`` ``true`` requires that network to pre-exist;
* ``IPV4_ADDRESS``            static IPv4 of the container on that network.

The three network variables are optional and empty by default: without them
the stack must render and deploy exactly as before (Compose creates the
project network itself), the published port stays governed by
``BIND_ADDRESS`` / ``HTTPS_PORT``, and no site-specific network name,
subnet, address or port may ever be pinned in Git.

The last three tests are the isolated Docker recette: they need a daemon and
are skipped unless ``VYSION_NETWORK_RECETTE=1`` is set, so the default suite
(and CI) never starts a container::

    VYSION_NETWORK_RECETTE=1 uv run pytest tests/contract/test_standalone_network_contract.py -q
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
STANDALONE = "compose.standalone.yml"
# Fixed project name for every render: the stack network is named
# `<project>_default`, so the default rendering must be reproducible on any
# checkout (the directory name of a worktree is not).
RENDER_PROJECT = "vysion-contract"
RENDER_DEFAULT_NETWORK = f"{RENDER_PROJECT}_default"
STABLE_VOLUMES = ("vysion-reports", "vysion-state", "vysion-certs")
NETWORK_VARIABLES = ("DOCKER_NETWORK", "DOCKER_NETWORK_EXTERNAL", "IPV4_ADDRESS")

# Recette-only: subnets tried in order until one does not overlap any network
# already present on the host. Never a production subnet, never an address of
# a real site — the whole point of the recette is that it is disposable.
CANDIDATE_SUBNETS = ("172.31.240.0/24", "172.31.241.0/24", "10.241.7.0/24", "10.241.8.0/24")

RECETTE = os.environ.get("VYSION_NETWORK_RECETTE") == "1"
requires_recette = pytest.mark.skipif(
    not RECETTE,
    reason="set VYSION_NETWORK_RECETTE=1 to run the isolated Docker recette",
)


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _require_docker_compose() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is required to render compose.standalone.yml")
    probe = subprocess.run(["docker", "compose", "version"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("the docker compose plugin is required to render compose.standalone.yml")


def _require_docker_daemon() -> None:
    probe = subprocess.run(["docker", "info"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("a running docker daemon is required for the recette")


def _clean_env(**env: str) -> dict[str, str]:
    """No deployment value ever leaks from the caller's environment."""
    ignored = (
        "IMAGE_",
        "DOCKER_NETWORK",
        "DOCKER_NETWORK_EXTERNAL",
        "IPV4_ADDRESS",
        "TLS_HOSTNAME",
    )
    clean = {key: value for key, value in os.environ.items() if not key.startswith(ignored[0])}
    for name in ignored[1:]:
        clean.pop(name, None)
    clean.update(env)
    return clean


def _render(empty_env: Path, *args: str, **env: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            RENDER_PROJECT,
            "-f",
            STANDALONE,
            "--env-file",
            str(empty_env),
            *args,
            "config",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=_clean_env(**env),
        check=False,
    )


def _compose(project: str, empty_env: Path, *args: str, **env: str) -> subprocess.CompletedProcess:
    """The same stack, driven the way Portainer drives it: an explicit
    project name, the standalone file, and the stack's environment."""
    return subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            STANDALONE,
            "--env-file",
            str(empty_env),
            *args,
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=_clean_env(**env),
        check=False,
    )


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _existing_subnets() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    listing = subprocess.run(
        ["docker", "network", "ls", "-q"], capture_output=True, text=True, check=False
    )
    subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for network_id in listing.stdout.split():
        inspected = subprocess.run(
            ["docker", "network", "inspect", network_id, "--format", "{{json .IPAM.Config}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        for config in json.loads(inspected.stdout or "[]") or []:
            subnet = (config or {}).get("Subnet")
            if subnet and ":" not in subnet:
                subnets.append(ipaddress.ip_network(subnet))
    return subnets


def _free_subnet() -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    existing = _existing_subnets()
    for candidate in CANDIDATE_SUBNETS:
        network = ipaddress.ip_network(candidate)
        if not any(network.overlaps(other) for other in existing):
            return network
    raise AssertionError(f"no disposable subnet available among {CANDIDATE_SUBNETS}")


def _network_names() -> set[str]:
    listing = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True
    )
    return set(listing.stdout.split())


def _volume_names() -> set[str]:
    listing = subprocess.run(
        ["docker", "volume", "ls", "--format", "{{.Name}}"], capture_output=True, text=True
    )
    return set(listing.stdout.split())


def _project_containers(project: str) -> list[str]:
    listing = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
    )
    return [line for line in listing.stdout.split() if line]


# --- Source contract ----------------------------------------------------------


def test_the_network_variables_are_generic_optional_and_never_site_specific() -> None:
    """Generic names, empty defaults, and nothing of a real site in Git:
    no prefixed alias, no `Subnet-Docker`, no imposed subnet, no literal
    address other than the loopback used by the healthcheck."""
    raw = _read(STANDALONE)

    for expression in (
        "name: ${DOCKER_NETWORK:-${COMPOSE_PROJECT_NAME:-vysion-standalone}_default}",
        "external: ${DOCKER_NETWORK_EXTERNAL:-false}",
        "ipv4_address: ${IPV4_ADDRESS:-}",
    ):
        assert expression in raw, expression
    # The Portainer interface stays generic: no Vysion-prefixed network alias.
    for alias in ("VYSION_DOCKER_NETWORK", "VYSION_IPV4_ADDRESS", "VYSION_DOCKER_NETWORK_EXTERNAL"):
        assert alias not in raw, alias
    assert "Subnet-Docker" not in raw
    assert "ipam" not in raw

    addresses = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", raw))
    assert addresses <= {"127.0.0.1"}, f"site-specific address pinned in Git: {addresses}"

    compose = yaml.safe_load(raw)
    service = compose["services"]["vysion"]
    assert service["networks"]["default"] == {"ipv4_address": "${IPV4_ADDRESS:-}"}
    assert compose["networks"]["default"] == {
        "name": "${DOCKER_NETWORK:-${COMPOSE_PROJECT_NAME:-vysion-standalone}_default}",
        "external": "${DOCKER_NETWORK_EXTERNAL:-false}",
    }
    # The fallback names the stack's own network, never a fixed one: whatever
    # the project is, an empty DOCKER_NETWORK resolves to `<project>_default`.
    fallback = compose["networks"]["default"]["name"]
    assert "${DOCKER_NETWORK:-" in fallback and fallback.endswith("_default}")


def test_the_scope_of_the_change_is_the_online_standalone_only() -> None:
    """Minimal change: no other stack grows a network attachment, and the
    stacks that keep the internal hostname name keep reading it."""
    for untouched in (
        "compose.yml",
        "compose.proxy.yml",
        "compose.helper.yml",
        "compose.standalone.offline.yml",
    ):
        text = _read(untouched)
        for marker in (*NETWORK_VARIABLES, "ipv4_address", "networks:"):
            assert marker not in text, f"{untouched} must not grow {marker}"

    offline = _read("compose.standalone.offline.yml")
    assert "${VYSION_TLS_HOSTNAME:?" in offline
    assert "${TLS_HOSTNAME" not in offline


def test_tls_hostname_is_the_generic_portainer_variable_of_the_standalone() -> None:
    """The operator types TLS_HOSTNAME; the container keeps reading the
    internal VYSION_TLS_HOSTNAME, so the application contract is untouched."""
    raw = _read(STANDALONE)
    assert "VYSION_TLS_HOSTNAME: ${TLS_HOSTNAME:?" in raw
    assert "${VYSION_TLS_HOSTNAME:?" not in raw
    # The other modes are out of scope and unchanged.
    assert "${VYSION_TLS_HOSTNAME:?" in _read("compose.helper.yml")


# --- Render contract ----------------------------------------------------------


def test_without_any_network_variable_the_stack_renders_as_it_always_did(tmp_path: Path) -> None:
    """Criterion 1: no network variable => the stack's own network, created
    by Compose, with every hardening, port and volume invariant intact."""
    _require_docker_compose()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    rendered = _render(empty_env, TLS_HOSTNAME="vysion.example.com")
    assert rendered.returncode == 0, rendered.stderr
    document = yaml.safe_load(rendered.stdout)

    network = document["networks"]["default"]
    # Criterion 1 on the render: the stack's own Compose-managed network,
    # named after the project — and never an empty network name, which
    # `config` hides while `up` rejects it.
    assert network.get("name") == RENDER_DEFAULT_NETWORK, network
    assert network.get("external") in (None, False), network
    assert "ipam" not in network
    attachment = document["services"]["vysion"]["networks"]["default"] or {}
    assert "ipv4_address" not in attachment

    # Criterion 5: image channel, port, healthcheck and hardening preserved.
    service = document["services"]["vysion"]
    assert service["image"] == "ghcr.io/tetrax/vysion:stable"
    assert service["pull_policy"] == "always"
    assert service["ports"] == [
        {
            "mode": "ingress",
            "target": 443,
            "published": "443",
            "protocol": "tcp",
            "host_ip": "127.0.0.1",
        }
    ]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["healthcheck"]["test"][-1] == (
        "curl --fail --silent --show-error http://127.0.0.1:8080/healthz"
    )
    # Criterion 3: the three volumes keep their stable production names.
    assert document["volumes"] == {
        volume: {"name": volume} for volume in STABLE_VOLUMES
    }


def test_the_three_network_variables_reach_the_rendered_stack(tmp_path: Path) -> None:
    """With them the stack joins the named network — external or not — with
    the requested address; left empty they fall back to the stack's own
    `<project>_default` network instead of an unusable blank name."""
    _require_docker_compose()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")
    hostname = {"TLS_HOSTNAME": "vysion.example.com"}

    full = _render(
        empty_env,
        **hostname,
        DOCKER_NETWORK="Subnet-Docker",
        DOCKER_NETWORK_EXTERNAL="true",
        IPV4_ADDRESS="172.30.250.12",
    )
    assert full.returncode == 0, full.stderr
    document = yaml.safe_load(full.stdout)
    assert document["networks"]["default"] == {"name": "Subnet-Docker", "external": True}
    assert document["services"]["vysion"]["networks"]["default"]["ipv4_address"] == (
        "172.30.250.12"
    )

    named_only = _render(empty_env, **hostname, DOCKER_NETWORK="vysion-corp")
    assert named_only.returncode == 0, named_only.stderr
    document = yaml.safe_load(named_only.stdout)
    # external defaults to false and the address is never invented.
    assert document["networks"]["default"] == {"name": "vysion-corp"}
    assert "ipv4_address" not in document["services"]["vysion"]["networks"]["default"]

    # A Portainer field left empty is the same as never touching it.
    blank = _render(
        empty_env,
        **hostname,
        DOCKER_NETWORK="",
        DOCKER_NETWORK_EXTERNAL="",
        IPV4_ADDRESS="",
    )
    assert blank.returncode == 0, blank.stderr
    document = yaml.safe_load(blank.stdout)
    # An empty Portainer field is the same as never touching it: the stack's
    # own network, no external requirement, no imposed address.
    blank_network = document["networks"]["default"]
    assert blank_network.get("name") == RENDER_DEFAULT_NETWORK, blank_network
    assert blank_network.get("external") in (None, False), blank_network
    assert "ipv4_address" not in (document["services"]["vysion"]["networks"]["default"] or {})


def test_the_published_port_stays_independent_of_the_network_settings(tmp_path: Path) -> None:
    """BIND_ADDRESS / HTTPS_PORT keep governing the published endpoint, with
    or without a network attachment — and the legacy hostname entry is dead."""
    _require_docker_compose()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    rendered = _render(
        empty_env,
        TLS_HOSTNAME="vysion.example.com",
        BIND_ADDRESS="0.0.0.0",
        HTTPS_PORT="8443",
        DOCKER_NETWORK="vysion-corp",
        DOCKER_NETWORK_EXTERNAL="true",
        IPV4_ADDRESS="172.30.250.12",
    )
    assert rendered.returncode == 0, rendered.stderr
    document = yaml.safe_load(rendered.stdout)
    port = document["services"]["vysion"]["ports"][0]
    assert port["host_ip"] == "0.0.0.0" and str(port["published"]) == "8443"

    legacy = _render(empty_env, VYSION_TLS_HOSTNAME="vysion.example.com")
    assert legacy.returncode != 0, "the legacy VYSION_TLS_HOSTNAME entry must no longer resolve"
    assert "TLS_HOSTNAME" in legacy.stderr


def test_the_documentation_publishes_the_exact_portainer_table(tmp_path: Path) -> None:
    """Criterion 7: the runbook carries the exact variable table, a secretless
    example with placeholders, and the WAF/determinism reminder; the README
    and the example env file agree with it."""
    _require_docker_compose()
    operations = _read("docs/OPERATIONS.md").casefold()
    for marker in (
        "docker_network",
        "docker_network_external",
        "ipv4_address",
        "tls_hostname",
        "ip_vm:port",
        "déterminisme",
        "<ipv4-appartenant-au-sous-réseau-de-ce-réseau>",
        "declared as external, but could not be found",
        "no configured subnet contains ip address",
        "jamais de subnet, d'adresse ni de port d'entreprise dans git",
    ):
        assert marker in operations, marker

    readme = _read("README.md").casefold()
    for marker in ("docker_network", "docker_network_external", "ipv4_address", "ip_vm:port"):
        assert marker in readme, marker

    example = _read(".env.example")
    for entry in ("TLS_HOSTNAME=", "DOCKER_NETWORK=", "DOCKER_NETWORK_EXTERNAL=", "IPV4_ADDRESS="):
        assert f"\n{entry}" in example, entry
    assert "VYSION_DOCKER_NETWORK" not in example

    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")
    assert _render(empty_env, TLS_HOSTNAME="vysion.example.com").returncode == 0


# --- Isolated Docker recette (opt-in) ----------------------------------------


def _recette_env(
    project: str,
    subnet: ipaddress.IPv4Network | ipaddress.IPv6Network,
    address: str,
    port: int,
) -> dict:
    return {
        "TLS_HOSTNAME": "vysion.recette.test",
        "DOCKER_NETWORK": f"{project}-net",
        "DOCKER_NETWORK_EXTERNAL": "true",
        "IPV4_ADDRESS": address,
        "VYSION_VOLUME_PREFIX": f"{project}-",
        "BIND_ADDRESS": "127.0.0.1",
        "HTTPS_PORT": str(port),
        "_subnet": str(subnet),
    }


def _recette_kwargs(env: dict) -> dict:
    return {key: value for key, value in env.items() if not key.startswith("_")}


def _wait_for_a_healthy_container(
    project: str, empty_env: Path, kwargs: dict
) -> tuple[str, str, list]:
    """A container that merely started is not a stack that works: wait for the
    daemon's own healthcheck, and read its probe log — a bare `healthy` status
    is cheap to misread."""
    container = ""
    for _ in range(60):
        found = _compose(project, empty_env, "ps", "-q", "vysion", **kwargs)
        container = found.stdout.strip()
        if container:
            break
        time.sleep(1)
    assert container, f"no container of the {project} stack"

    healthy = ""
    for _ in range(90):
        inspected = subprocess.run(
            ["docker", "inspect", container, "--format", "{{.State.Health.Status}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        healthy = inspected.stdout.strip()
        if healthy in ("healthy", "unhealthy"):
            break
        time.sleep(2)
    assert healthy == "healthy", f"container state: {healthy}"

    log = subprocess.run(
        ["docker", "inspect", container, "--format", "{{json .State.Health.Log}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    probes = json.loads(log.stdout or "[]")
    assert probes and probes[-1]["ExitCode"] == 0, probes
    return container, healthy, probes


def _attachments(container: str) -> dict:
    inspected = subprocess.run(
        ["docker", "inspect", container, "--format", "{{json .NetworkSettings.Networks}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(inspected.stdout)


def _mounted_volumes(container: str) -> set[str]:
    mounts = subprocess.run(
        ["docker", "inspect", container, "--format", "{{range .Mounts}}{{.Name}} {{end}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return set(mounts.stdout.split())


@requires_recette
def test_recette_without_any_network_variable_the_stack_deploys_on_its_default_network(
    tmp_path: Path,
) -> None:
    """Criterion 1 on a REAL daemon — the part `docker compose config` cannot
    see: with all three network variables unset, `up` must not merely resolve,
    it must deploy. Compose creates the project's own `<project>_default`
    network, the container becomes healthy on it, and `down` removes that
    network while the three prefixed volumes survive."""
    _require_docker_compose()
    _require_docker_daemon()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    stamp = time.strftime("%Y%m%d%H%M%S")
    project = f"vysion-defrec-{stamp}"
    network = f"{project}_default"
    kwargs = {
        "TLS_HOSTNAME": "vysion.recette.test",
        "VYSION_VOLUME_PREFIX": f"{project}-",
        "BIND_ADDRESS": "127.0.0.1",
        "HTTPS_PORT": str(_free_port()),
    }
    production_before = {name for name in _volume_names() if name in STABLE_VOLUMES}

    try:
        # No DOCKER_NETWORK, no DOCKER_NETWORK_EXTERNAL, no IPV4_ADDRESS.
        up = _compose(project, empty_env, "up", "-d", **kwargs)
        assert up.returncode == 0, up.stdout + up.stderr

        container, healthy, probes = _wait_for_a_healthy_container(project, empty_env, kwargs)
        attachments = _attachments(container)
        assert network in attachments, sorted(attachments)
        # Nothing imposed: the daemon assigns the address itself.
        assert attachments[network]["IPAddress"], attachments
        print(
            f"recette {project}: default network={network} "
            f"ip={attachments[network]['IPAddress']} healthy={healthy} probes={len(probes)}"
        )
        assert _mounted_volumes(container) == {f"{project}-{name}" for name in STABLE_VOLUMES}
        assert {name for name in _volume_names() if name in STABLE_VOLUMES} == production_before

        down = _compose(project, empty_env, "down", **kwargs)
        assert down.returncode == 0, down.stdout + down.stderr
        assert _project_containers(project) == []
        # Compose-managed: the default network belongs to the stack and leaves
        # with it, exactly like the historical behaviour.
        assert network not in _network_names(), sorted(_network_names())
        assert {name for name in _volume_names() if name in STABLE_VOLUMES} == production_before
        for name in STABLE_VOLUMES:
            assert f"{project}-{name}" in _volume_names()
    finally:
        _compose(project, empty_env, "down", **kwargs)
        subprocess.run(["docker", "network", "rm", network], capture_output=True, text=True)
        for name in STABLE_VOLUMES:
            subprocess.run(
                ["docker", "volume", "rm", f"{project}-{name}"],
                capture_output=True,
                text=True,
            )


@requires_recette
def test_recette_the_container_joins_the_existing_network_with_the_requested_ipv4(
    tmp_path: Path,
) -> None:
    """Criteria 2 and 3, on a real daemon: an external test network with its
    own subnet, the container attached with the requested address and
    healthy, then `down` — the external network survives and the three
    production volumes are never touched."""
    _require_docker_compose()
    _require_docker_daemon()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    stamp = time.strftime("%Y%m%d%H%M%S")
    project = f"vysion-netrec-{stamp}"
    network = f"{project}-net"
    subnet = _free_subnet()
    address = str(subnet.network_address + 10)
    env = _recette_env(project, subnet, address, _free_port())
    kwargs = _recette_kwargs(env)

    production_before = {name for name in _volume_names() if name in STABLE_VOLUMES}
    created = subprocess.run(
        ["docker", "network", "create", "--subnet", str(subnet), network],
        capture_output=True,
        text=True,
        check=False,
    )
    assert created.returncode == 0, created.stdout + created.stderr

    try:
        up = _compose(project, empty_env, "up", "-d", **kwargs)
        assert up.returncode == 0, up.stdout + up.stderr

        # Wait for the healthcheck: the recette proves a deployable stack,
        # not only a syntactically valid one.
        container, healthy, probes = _wait_for_a_healthy_container(project, empty_env, kwargs)

        attachments = _attachments(container)
        assert network in attachments, sorted(attachments)
        assert attachments[network]["IPAddress"] == address

        # Opt-in recette: one line of evidence when run with -s.
        print(
            f"recette {project}: network={network} subnet={subnet} ip={address} "
            f"healthy={healthy} probes={len(probes)}"
        )
        assert _mounted_volumes(container) == {f"{project}-{name}" for name in STABLE_VOLUMES}
        # The stable production volumes are untouched by the recette.
        assert {name for name in _volume_names() if name in STABLE_VOLUMES} == production_before

        down = _compose(project, empty_env, "down", **kwargs)
        assert down.returncode == 0, down.stdout + down.stderr
        assert _project_containers(project) == []
        # Criterion 3: an external network is never removed by `down`, and
        # the three volumes keep their names.
        assert network in _network_names()
        assert {name for name in _volume_names() if name in STABLE_VOLUMES} == production_before
        for name in STABLE_VOLUMES:
            assert f"{project}-{name}" in _volume_names()
    finally:
        _compose(project, empty_env, "down", **kwargs)
        subprocess.run(["docker", "network", "rm", network], capture_output=True, text=True)
        for name in STABLE_VOLUMES:
            subprocess.run(
                ["docker", "volume", "rm", f"{project}-{name}"],
                capture_output=True,
                text=True,
            )


@requires_recette
def test_recette_an_absent_network_and_an_address_outside_the_subnet_are_refused(
    tmp_path: Path,
) -> None:
    """Criterion 4: both misconfigurations fail explicitly, before any
    container of the stack exists."""
    _require_docker_compose()
    _require_docker_daemon()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    stamp = time.strftime("%Y%m%d%H%M%S")
    project = f"vysion-negrec-{stamp}"
    hostname = {"TLS_HOSTNAME": "vysion.recette.test"}

    absent = _compose(
        project,
        empty_env,
        "create",
        **hostname,
        DOCKER_NETWORK=f"{project}-absent",
        DOCKER_NETWORK_EXTERNAL="true",
    )
    output = absent.stdout + absent.stderr
    assert absent.returncode != 0, output
    assert "declared as external, but could not be found" in output, output
    assert _project_containers(project) == []

    network = f"{project}-net"
    subnet = _free_subnet()
    created = subprocess.run(
        ["docker", "network", "create", "--subnet", str(subnet), network],
        capture_output=True,
        text=True,
        check=False,
    )
    assert created.returncode == 0, created.stdout + created.stderr
    # One address past the target subnet: outside it by construction.
    outside = str(ipaddress.ip_address(int(subnet.network_address) + subnet.num_addresses + 4))
    try:
        refused = _compose(
            project,
            empty_env,
            "create",
            **hostname,
            DOCKER_NETWORK=network,
            DOCKER_NETWORK_EXTERNAL="true",
            IPV4_ADDRESS=outside,
        )
        output = refused.stdout + refused.stderr
        assert refused.returncode != 0, output
        assert f"no configured subnet contains IP address {outside}" in output, output
        assert _project_containers(project) == []
    finally:
        _compose(project, empty_env, "down", **hostname)
        subprocess.run(["docker", "network", "rm", network], capture_output=True, text=True)

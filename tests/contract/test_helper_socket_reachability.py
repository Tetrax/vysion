"""Delivery proof for the helper socket: what ``compose.helper.yml`` renders
is what the running container actually sees.

The helper mode binds the host socket directory into a read-only container
whose ``/var/run`` is a tmpfs — and ``/var/run`` is a symlink to ``/run`` in
the image, so a bind mounted *under* ``/run`` is silently hidden: the
container stays healthy, ``docker inspect`` keeps announcing the bind, and the
socket is simply absent. That is the defect found when the certificate
administration of PR #16 reached a real host.

This test starts a real helper process on the host, runs the real image with
the mounts, the tmpfs and the environment compose renders, and asks
``CertificateHelperClient`` for a ``ping`` and a ``status`` through the socket
that path resolves to. It can only pass when the rendered path survives the
declared tmpfs, so it fails on the stack as deployed before the fix.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import yaml
from test_delivery_contract import ROOT, VALID_DIGEST, _render

from vysion.config import Settings

# The image under test: built from this very worktree, so the container user,
# the entrypoint and the filesystem are the deployed ones.
IMAGE = "vysion-helper-socket-contract:local"

# The probe runs inside the container and reports what the application would
# resolve: the environment when compose declares it, the in-image default of
# ``vysion.config.Settings`` otherwise. It proves visibility (the path exists
# and is a socket) and usability (``ping`` and ``status`` really answer).
PROBE_SOURCE = '''\
import json
import os
import stat

from vysion.certclient import CertificateHelperClient
from vysion.config import Settings

path = os.environ.get("VYSION_HELPER_SOCKET_PATH") or str(
    Settings.model_fields["helper_socket_path"].default
)
if not os.path.exists(path):
    raise SystemExit(f"socket absent in the container: {path}")
if not stat.S_ISSOCK(os.lstat(path).st_mode):
    raise SystemExit(f"not a unix socket: {path}")
client = CertificateHelperClient(path, timeout=10.0)
client.ping()
print(json.dumps({"path": path, "ping": "ok", "status": sorted(client.status())}))
'''


def _require_docker() -> None:
    if shutil.which("docker") is None:
        pytest.skip("the docker CLI is required to prove the helper socket is reachable")
    if subprocess.run(["docker", "info"], capture_output=True, check=False).returncode != 0:
        pytest.skip("a running docker daemon is required to prove the helper socket is reachable")
    compose_plugin = subprocess.run(
        ["docker", "compose", "version"], capture_output=True, check=False
    )
    if compose_plugin.returncode != 0:
        pytest.skip("the docker compose plugin is required to render compose.helper.yml")


@pytest.fixture(scope="module")
def contract_image() -> str:
    """Build the deployable image once for this test module."""
    _require_docker()
    build = subprocess.run(
        ["docker", "build", "--tag", IMAGE, "."],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stdout[-4000:] + build.stderr[-4000:]
    return IMAGE


@pytest.fixture(scope="module")
def container_identity(contract_image: str) -> tuple[int, int]:
    """The uid/gid the helper must admit: the image's own non-root user.

    The helper refuses every peer whose uid *and* gid do not match (root
    excepted), so the host side of this test has to know exactly who will
    connect — on a real host that is ``VYSION_PUID``/``VYSION_PGID``.
    """
    identity = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "id", contract_image],
        capture_output=True,
        text=True,
        check=False,
    )
    assert identity.returncode == 0, identity.stdout + identity.stderr
    uid = re.search(r"uid=(\d+)", identity.stdout)
    gid = re.search(r"gid=(\d+)", identity.stdout)
    assert uid and gid, identity.stdout
    assert uid.group(1) != "0", f"the container must not run as root: {identity.stdout}"
    return int(uid.group(1)), int(gid.group(1))


@pytest.fixture
def rendered_service(tmp_path: Path) -> dict:
    """The helper stack exactly as compose resolves it for a deployment."""
    _require_docker()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")
    rendered = _render(
        "compose.helper.yml",
        empty_env,
        IMAGE_DIGEST=VALID_DIGEST,
        TRUSTED_PROXY_CIDRS="127.0.0.1/32",
        VYSION_TLS_HOSTNAME="vysion.example",
    )
    assert rendered.returncode == 0, rendered.stdout + rendered.stderr
    return yaml.safe_load(rendered.stdout)["services"]["vysion"]


@pytest.fixture
def host_helper(tmp_path: Path, container_identity: tuple[int, int]) -> Path:
    """A real helper process serving a real Unix socket on the host."""
    uid, gid = container_identity
    # ``AF_UNIX`` paths stop at 108 bytes, which pytest's per-test directory
    # comfortably exceeds on a long home path: the socket gets its own short
    # directory (under TMPDIR, i.e. the session scratch space).
    directory = Path(tempfile.gettempdir()) / f"hs-{os.getpid()}-{int(time.time())}"
    directory.mkdir()
    socket_path = directory / "helper.sock"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "vysion.certhelper",
            "serve",
            "--socket",
            str(socket_path),
            "--certs-dir",
            str(tmp_path / "certs"),
            "--hostname",
            "vysion.example",
            "--uid",
            str(uid),
            "--gid",
            str(gid),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    deadline = time.monotonic() + 30.0
    while not socket_path.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(f"the helper exited early: {stdout}{stderr}")
        if time.monotonic() > deadline:
            process.terminate()
            raise AssertionError("the helper socket never appeared on the host")
        time.sleep(0.05)
    # On a real host the unit runs as root and leaves a 0750/0660
    # root:<gid> pair; this test is unprivileged, so the directory is only
    # made reachable by the container user. The mount stays read-only inside
    # the container — nothing here weakens what is being proved.
    directory.chmod(0o755)
    socket_path.chmod(0o666)
    yield socket_path
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        process.kill()
    with contextlib.suppress(OSError):
        socket_path.unlink()
    with contextlib.suppress(OSError):
        socket_path.parent.rmdir()


def test_the_rendered_helper_stack_reaches_the_host_socket_from_the_container(
    contract_image: str,
    rendered_service: dict,
    host_helper: Path,
    tmp_path: Path,
) -> None:
    """The socket the application asks for must exist inside the container.

    Declaration is not reachability: the stack used to announce a bind that
    the ``/var/run`` tmpfs mounted over, and the healthy container simply had
    no socket to talk to. Here the rendered mounts, tmpfs and environment are
    replayed against the real image with a real host socket behind them.
    """
    # The container under test is the deployed one: non-root and read-only.
    assert rendered_service.get("read_only") is True
    user = subprocess.run(
        ["docker", "inspect", "--format", "{{.Config.User}}", contract_image],
        capture_output=True,
        text=True,
        check=False,
    )
    assert user.returncode == 0, user.stdout + user.stderr
    assert user.stdout.strip() not in {"", "root", "0"}, user.stdout

    environment = rendered_service["environment"]
    # The path the application consumes: what compose declares, else the
    # in-image default of vysion.config.Settings (the probe resolves the same
    # way, so both sides agree on what "the socket" means).
    socket_path = environment.get("VYSION_HELPER_SOCKET_PATH") or str(
        Settings.model_fields["helper_socket_path"].default
    )
    socket_directory = os.path.dirname(socket_path)

    binds = [
        entry
        for entry in rendered_service.get("volumes", [])
        if isinstance(entry, dict) and entry.get("type") == "bind"
    ]
    helper_binds = [entry for entry in binds if entry["target"] == socket_directory]
    assert len(helper_binds) == 1, (
        f"compose must bind the helper directory at {socket_directory}, found {binds}"
    )
    assert helper_binds[0].get("read_only") is True, helper_binds[0]

    probe = tmp_path / "probe.py"
    probe.write_text(PROBE_SOURCE)
    # The process umask is tightened to 0077 elsewhere in the suite (the
    # state store does it), which would leave the probe unreadable for the
    # container user: the mode is decided here, never inherited.
    probe.chmod(0o644)

    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        f"vysion-helper-socket-{os.getpid()}-{time.time_ns()}",
        "--entrypoint",
        "python",
    ]
    if rendered_service.get("read_only"):
        command.append("--read-only")
    for entry in rendered_service.get("tmpfs", []):
        command.extend(["--tmpfs", str(entry)])
    for entry in rendered_service.get("cap_drop", []):
        command.extend(["--cap-drop", str(entry)])
    for entry in rendered_service.get("security_opt", []):
        command.extend(["--security-opt", str(entry)])
    if "pids_limit" in rendered_service:
        command.extend(["--pids-limit", str(rendered_service["pids_limit"])])
    if "mem_limit" in rendered_service:
        command.extend(["--memory", str(rendered_service["mem_limit"])])
    if "cpus" in rendered_service:
        command.extend(["--cpus", str(rendered_service["cpus"])])
    # Only the socket is re-pointed at this test's own host directory: the
    # named volumes carry application state (and must not be created on the
    # host by a test), and no port is published — the probe is a one-shot
    # command and the loopback port belongs to the deployed stack.
    command.extend(
        [
            "--mount",
            f"type=bind,source={host_helper.parent},target={socket_directory},readonly",
            "--mount",
            f"type=bind,source={probe},target=/probe.py,readonly",
        ]
    )
    for key, value in environment.items():
        command.extend(["--env", f"{key}={value}"])
    command.extend([IMAGE, "/probe.py"])

    probe_run = subprocess.run(command, capture_output=True, text=True, check=False)
    report = probe_run.stdout + probe_run.stderr
    assert probe_run.returncode == 0, report

    payload = json.loads(probe_run.stdout.strip().splitlines()[-1])
    assert payload["path"] == socket_path
    assert payload["ping"] == "ok"
    # A real status answer, not an error rendered as one.
    assert {"active", "generations", "staging"} <= set(payload["status"])

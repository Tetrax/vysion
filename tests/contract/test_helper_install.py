"""The documented fresh-host helper install, replayed in a sandbox.

Round 2 of the review blocked this card: ``docs/OPERATIONS.md`` copied only
``src`` into ``/opt/vysion`` while steps 3-5 invoked three scripts under
``/opt/vysion/deploy`` that were never installed there, and the hardened unit
whitelists ``ReadWritePaths=/var/lib/vysion`` although no step ever created
it — so a fresh host could not start the helper, let alone bootstrap, migrate
and install the Certbot hook.

The runbook's own sequence is therefore replayed here against a sandbox root:
install, service prerequisites, ``ping``, bootstrap, host-nginx migration and
the deploy hook, with a stub nginx and a local TLS server. Nothing under
``/etc`` is ever touched and no external call is made.
"""

from __future__ import annotations

import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parents[2]
INSTALL = ROOT / "deploy" / "vysion-cert-install.sh"
UNIT = ROOT / "deploy" / "vysion-cert-helper.service"
HOSTNAME = "vysion.example"
DEPLOY_SCRIPTS = (
    "vysion-cert-install.sh",
    "vysion-cert-bootstrap.sh",
    "vysion-cert-migrate-nginx.sh",
    "certbot-vysion-deploy.sh",
)

TLS_SERVER = """
import socket, ssl, sys, time
cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(8)
server.settimeout(20)
print("ready", flush=True)
deadline = time.time() + 20
while time.time() < deadline:
    try:
        connection, _ = server.accept()
    except socket.timeout:
        break
    try:
        with context.wrap_socket(connection, server_side=True) as tls:
            try:
                tls.recv(4096)
            except OSError:
                pass
    except OSError:
        pass
server.close()
"""

ORIGINAL_CONF = f"""\
server {{
    listen 443 ssl;
    server_name {HOSTNAME};
    ssl_certificate     /etc/letsencrypt/live/{HOSTNAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{HOSTNAME}/privkey.pem;
}}
"""


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _certificate(directory: Path, *, hostname: str = HOSTNAME) -> tuple[Path, Path]:
    """A Certbot-shaped lineage: ``fullchain.pem`` + ``privkey.pem``."""
    directory.mkdir(parents=True, exist_ok=True)
    certificate = directory / "fullchain.pem"
    key = directory / "privkey.pem"
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "30",
            "-subj", f"/CN={hostname}", "-addext", f"subjectAltName=DNS:{hostname}",
        ],  # fmt: skip
        cwd=directory,
        capture_output=True,
        timeout=60,
        env={"LC_ALL": "C"},
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return certificate, key


class FreshHost:
    """A miniature fresh VPS: every destination overridable, ``/etc`` untouchable."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path
        self.opt = tmp_path / "opt" / "vysion"
        self.etc = tmp_path / "etc" / "vysion"
        self.state = tmp_path / "var" / "lib" / "vysion"
        self.runtime = tmp_path / "run" / "vysion-cert-helper"
        self.nginx_log = tmp_path / "var" / "log" / "nginx"
        self.systemd = tmp_path / "etc" / "systemd" / "system"
        self.letsencrypt = tmp_path / "letsencrypt"
        self.live = self.letsencrypt / "live"
        self.hooks = self.letsencrypt / "renewal-hooks" / "deploy"
        self.certs = self.state / "certificates"
        self.socket_path = self.runtime / "helper.sock"
        self.env_file = self.etc / "cert-helper.env"
        self.conf_dir = tmp_path / "nginx"
        self.bin = tmp_path / "bin"
        self.calls = tmp_path / "nginx-calls.log"
        self.backups = tmp_path / "backups"
        self.conf_dir.mkdir()
        self.bin.mkdir()
        # Linux bounds AF_UNIX paths to 108 bytes: keep the socket reachable.
        assert len(str(self.socket_path)) < 100, str(self.socket_path)
        self.smoke_port = _free_port()
        self._tls: subprocess.Popen | None = None
        self._helper: subprocess.Popen | None = None
        self._write_stubs()

    # ------------------------------------------------------------------
    # sandbox plumbing
    # ------------------------------------------------------------------
    def _write_stubs(self) -> None:
        nginx = self.bin / "nginx"
        nginx.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$NGINX_STUB_LOG"\n'
            'if [ "$1" = "-t" ] && [ "${NGINX_STUB_T_FAIL:-0}" = "1" ]; then\n'
            '    echo "nginx: configuration test failed" >&2\n'
            "    exit 1\n"
            "fi\n"
            "exit 0\n"
        )
        nginx.chmod(0o755)
        systemctl = self.bin / "systemctl"
        systemctl.write_text("#!/bin/sh\nexit 1\n")  # no systemd in a sandbox
        systemctl.chmod(0o755)

    def install_env(self, **extra: str) -> dict[str, str]:
        environment = {
            **os.environ,
            "VYSION_OPT_DIR": str(self.opt),
            "VYSION_ETC_DIR": str(self.etc),
            "VYSION_STATE_DIR": str(self.state),
            "VYSION_RUNTIME_DIR": str(self.runtime),
            "VYSION_NGINX_LOG_DIR": str(self.nginx_log),
            "VYSION_SYSTEMD_DIR": str(self.systemd),
        }
        environment.update(extra)
        return environment

    def run_env(self, **extra: str) -> dict[str, str]:
        environment = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "VYSION_CERT_HELPER_ENV": str(self.env_file),
            "VYSION_LETSENCRYPT_LIVE_DIR": str(self.live),
            "VYSION_PYTHONPATH": str(self.opt / "src"),
            "VYSION_CERT_HELPER": f"{sys.executable} -m vysion.certhelper",
            "HELPER_CERTS_DIR": str(self.certs),
            "VYSION_TLS_HOSTNAME": HOSTNAME,
            "NGINX_CONF_DIR": str(self.conf_dir),
            "NGINX_BIN": str(self.bin / "nginx"),
            "VYSION_MIGRATE_BACKUP_ROOT": str(self.backups),
            "VYSION_NO_SYSTEMCTL": "1",
            "NGINX_STUB_LOG": str(self.calls),
            "SMOKE_HOST": "127.0.0.1",
            "SMOKE_PORT": str(self.smoke_port),
        }
        environment.update(extra)
        return environment

    def install(self, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sh", str(INSTALL)],
            env=self.install_env(**extra),
            capture_output=True,
            text=True,
            timeout=60,
        )

    def script(self, name: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sh", str(self.opt / "deploy" / name)],
            env=self.run_env(**extra),
            capture_output=True,
            text=True,
            timeout=60,
        )

    def write_env_file(self) -> None:
        """The documented ``$EDITOR`` step: hostname, ids and paths."""
        self.etc.mkdir(parents=True, exist_ok=True)
        self.env_file.write_text(
            f"VYSION_TLS_HOSTNAME={HOSTNAME}\n"
            f"VYSION_PUID={os.getuid()}\n"
            f"VYSION_PGID={os.getgid()}\n"
            f"HELPER_SOCKET={self.socket_path}\n"
            f"HELPER_CERTS_DIR={self.certs}\n"
            f"VYSION_PYTHONPATH={self.opt / 'src'}\n"
            f"VYSION_CERT_HELPER='{sys.executable} -m vysion.certhelper'\n"
        )

    def call_log(self) -> list[str]:
        if not self.calls.exists():
            return []
        return [line for line in self.calls.read_text().splitlines() if line]

    # ------------------------------------------------------------------
    # processes
    # ------------------------------------------------------------------
    def start_tls(self, certificate: Path, key: Path) -> None:
        self._tls = subprocess.Popen(
            [sys.executable, "-c", TLS_SERVER, str(certificate), str(key), str(self.smoke_port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert self._tls.stdout is not None
        assert self._tls.stdout.readline().strip() == "ready"

    def stop_tls(self) -> None:
        if self._tls is None:
            return
        self._tls.terminate()
        try:
            self._tls.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            self._tls.kill()
        self._tls = None

    def start_helper(self) -> None:
        """What the unit's ExecStart does: ``serve`` with the env file's ids."""
        unit = UNIT.read_text()
        assert "vysion.certhelper serve" in unit
        assert "${HELPER_SOCKET}" in unit and "${HELPER_CERTS_DIR}" in unit
        self._helper = subprocess.Popen(
            [
                sys.executable, "-m", "vysion.certhelper", "serve",
                "--socket", str(self.socket_path),
                "--certs-dir", str(self.certs),
                "--hostname", HOSTNAME,
                "--uid", str(os.getuid()),
                "--gid", str(os.getgid()),
            ],  # fmt: skip
            env=self.run_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.socket_path.exists():
                return
            if self._helper.poll() is not None:
                out, err = self._helper.communicate()
                raise AssertionError(f"helper exited early:\n{out}\n{err}")
            time.sleep(0.1)
        self.stop_helper()
        raise AssertionError("the helper socket never appeared")

    def stop_helper(self) -> None:
        if self._helper is None:
            return
        self._helper.terminate()
        try:
            self._helper.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            self._helper.kill()
        self._helper = None

    def ping(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "vysion.certhelper", "ping", "--socket", str(self.socket_path)],
            env=self.run_env(),
            capture_output=True,
            text=True,
            timeout=30,
        )


# ---------------------------------------------------------------------------
# the install sequence itself
# ---------------------------------------------------------------------------
def test_the_fresh_host_install_builds_everything_the_unit_requires(
    tmp_path: Path,
) -> None:
    host = FreshHost(tmp_path)

    result = host.install()

    assert result.returncode == 0, result.stdout + result.stderr
    # Every script the runbook invokes afterwards is installed and executable.
    for name in DEPLOY_SCRIPTS:
        installed = host.opt / "deploy" / name
        assert installed.is_file(), name
        assert os.access(installed, os.X_OK), name
    assert (host.opt / "src" / "vysion" / "certhelper.py").is_file()
    # The unit and its environment file.
    unit_copy = host.systemd / "vysion-cert-helper.service"
    assert unit_copy.read_text() == UNIT.read_text()
    assert stat.S_IMODE(unit_copy.stat().st_mode) == 0o644
    assert stat.S_IMODE(host.env_file.stat().st_mode) == 0o644
    assert "VYSION_TLS_HOSTNAME=" in host.env_file.read_text()
    # Normalised modes whatever the umask: sources readable, dirs traversable.
    assert stat.S_IMODE((host.opt / "src").stat().st_mode) == 0o755
    assert stat.S_IMODE((host.opt / "src" / "vysion" / "certhelper.py").stat().st_mode) == 0o644
    assert not (host.opt / "src" / "src").exists()

    # The paths the hardened unit whitelists must exist before service start.
    unit = UNIT.read_text()
    targets = {
        "/var/lib/vysion": host.state,
        "/var/log/nginx": host.nginx_log,
        "/run/vysion-cert-helper": host.runtime,
    }
    readwrite = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths"))
    for path in readwrite.partition("=")[2].split():
        assert path in targets, f"unmapped ReadWritePaths entry: {path}"
        assert targets[path].is_dir(), path
    assert stat.S_IMODE(host.state.stat().st_mode) == 0o750
    assert stat.S_IMODE(host.runtime.stat().st_mode) == 0o750
    # And the two other paths ExecStart reads.
    assert "EnvironmentFile=/etc/vysion/cert-helper.env" in unit
    assert "Environment=PYTHONPATH=/opt/vysion/src" in unit
    assert host.env_file.is_file() and (host.opt / "src").is_dir()
    # systemd manages the same directories itself, so a reboot cannot leave
    # ReadWritePaths pointing at a path nothing recreated.
    assert "StateDirectory=vysion" in unit
    assert "RuntimeDirectory=vysion-cert-helper" in unit


def test_the_install_sequence_is_idempotent_and_keeps_the_operator_env(
    tmp_path: Path,
) -> None:
    host = FreshHost(tmp_path)
    first = host.install()
    assert first.returncode == 0, first.stdout + first.stderr
    assert "env cree" in first.stdout

    # The operator edits the env file once; a re-install must never clobber it.
    operator_note = "# operator edit\nVYSION_TLS_HOSTNAME=operator.example\n"
    host.env_file.write_text(operator_note)

    second = host.install()
    assert second.returncode == 0, second.stdout + second.stderr
    assert "env conserve" in second.stdout
    assert host.env_file.read_text() == operator_note
    assert not (host.opt / "src" / "src").exists()
    for name in DEPLOY_SCRIPTS:
        assert os.access(host.opt / "deploy" / name, os.X_OK), name
    assert host.state.is_dir() and host.runtime.is_dir()


# ---------------------------------------------------------------------------
# the documented sequence, end to end
# ---------------------------------------------------------------------------
def test_the_documented_fresh_sequence_reaches_ping_bootstrap_migration_and_the_hook(
    tmp_path: Path,
) -> None:
    host = FreshHost(tmp_path)
    assert host.install().returncode == 0
    host.write_env_file()

    # Certbot already issued the certificate the host nginx serves today.
    certificate, key = _certificate(host.live / HOSTNAME)
    host.start_tls(certificate, key)
    host.start_helper()
    try:
        # 2. service up: the documented ping answers over the private socket.
        ping = host.ping()
        assert ping.returncode == 0, ping.stdout + ping.stderr
        assert "ok" in ping.stdout

        # 3. bootstrap: generation 1 = the certificate already served.
        bootstrap = host.script("vysion-cert-bootstrap.sh")
        assert bootstrap.returncode == 0, bootstrap.stdout + bootstrap.stderr
        assert "generation=1" in bootstrap.stdout
        assert (host.certs / "active" / "fullchain.pem").is_file()
        # `nginx -t` strictly before the reload, even from the installed copy.
        assert host.call_log()[:2] == ["-t", "-s reload"], host.call_log()

        # 4. migration: the host nginx moves onto the helper authority.
        conf = host.conf_dir / "vysion.conf"
        conf.write_text(ORIGINAL_CONF)
        migration = host.script("vysion-cert-migrate-nginx.sh")
        assert migration.returncode == 0, migration.stdout + migration.stderr
        assert f"{host.certs}/active/fullchain.pem" in conf.read_text()
        assert "/etc/letsencrypt/live/" not in conf.read_text()

        # 5. the Certbot hook, installed exactly as the runbook says.
        host.hooks.mkdir(parents=True, exist_ok=True)
        link = host.hooks / "vysion-helper.sh"
        link.symlink_to(host.opt / "deploy" / "certbot-vysion-deploy.sh")
        assert link.resolve() == (host.opt / "deploy" / "certbot-vysion-deploy.sh").resolve()

        # A renewal must converge on the same single authority: generation 2.
        renewed, renewed_key = _certificate(host.live / HOSTNAME)
        host.stop_tls()
        host.start_tls(renewed, renewed_key)
        hook = subprocess.run(
            ["sh", str(link)],
            env=host.run_env(RENEWED_LINEAGE=str(host.live / HOSTNAME)),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert hook.returncode == 0, hook.stdout + hook.stderr
        assert "generation=2" in hook.stdout
        generations = sorted(p.name for p in (host.certs / "generations").iterdir())
        assert generations == ["0001", "0002"]
        assert os.readlink(host.certs / "active") == "generations/0002"
    finally:
        host.stop_helper()
        host.stop_tls()

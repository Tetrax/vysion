"""Host nginx migration to the helper's certificate authority, sandboxed.

The helper writes its generations under ``$HELPER_CERTS_DIR`` while the VPS
nginx still reads the Certbot lineage: without a validated repoint, a manual
activation is rolled back because the fingerprint check sees the lineage. The
migration must repoint, ``nginx -t`` strictly before any reload, verify the
fingerprint that is really served, and restore the original configuration on
any failure — proven here against a sandbox tree, a stub nginx and a local
TLS server, never against ``/etc``.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "deploy" / "vysion-cert-migrate-nginx.sh"
HOSTNAME = "vysion.example"
LINEAGE = f"/etc/letsencrypt/live/{HOSTNAME}"

ORIGINAL_CONF = f"""\
server {{
    listen 443 ssl;
    server_name {HOSTNAME};
    ssl_certificate     {LINEAGE}/fullchain.pem;
    ssl_certificate_key {LINEAGE}/privkey.pem;
}}
"""

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
deadline = time.time() + 15
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


def _openssl(*args: str, cwd: Path) -> None:
    result = subprocess.run(
        ["openssl", *args], cwd=cwd, capture_output=True, timeout=60, env={"LC_ALL": "C"}
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def _certificate(directory: Path, *, hostname: str = HOSTNAME) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    key = directory / "leaf.key"
    cert = directory / "leaf.pem"
    _openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "30",
        "-subj", f"/CN={hostname}",
        "-addext", f"subjectAltName=DNS:{hostname}",
        cwd=directory,
    )  # fmt: skip
    return cert, key


class Sandbox:
    """A miniature VPS: config tree, helper generations, stub nginx."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path
        self.conf_dir = tmp_path / "nginx"
        self.conf_dir.mkdir()
        self.conf = self.conf_dir / "vysion.conf"
        self.conf.write_text(ORIGINAL_CONF)
        self.certs = tmp_path / "certs"
        self.calls = tmp_path / "nginx-calls.log"
        self.backups = tmp_path / "backups"
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        stub = self.bin / "nginx"
        stub.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$NGINX_STUB_LOG"\n'
            'if [ "$1" = "-t" ] && [ "${NGINX_STUB_T_FAIL:-0}" = "1" ]; then\n'
            '    echo "nginx: configuration test failed" >&2\n'
            "    exit 1\n"
            "fi\n"
            "exit 0\n"
        )
        stub.chmod(0o755)
        # The helper's served authority: generations/0001 behind `active`.
        cert, key = _certificate(tmp_path / "authority")
        generation = self.certs / "generations" / "0001"
        generation.mkdir(parents=True)
        (generation / "fullchain.pem").write_bytes(cert.read_bytes())
        (generation / "key.pem").write_bytes(key.read_bytes())
        (generation / "meta.json").write_text("{}")
        (self.certs / "active").symlink_to("generations/0001")
        self.active_cert = cert
        self.active_key = key

    def env(self, **overrides: str) -> dict[str, str]:
        environment = {
            **os.environ,
            "VYSION_CERT_HELPER_ENV": str(self.root / "absent.env"),
            "VYSION_TLS_HOSTNAME": HOSTNAME,
            "HELPER_CERTS_DIR": str(self.certs),
            "NGINX_CONF_DIR": str(self.conf_dir),
            "NGINX_BIN": str(self.bin / "nginx"),
            "VYSION_MIGRATE_BACKUP_ROOT": str(self.backups),
            "VYSION_NO_SYSTEMCTL": "1",
            "NGINX_STUB_LOG": str(self.calls),
            "SMOKE_HOST": "127.0.0.1",
            "SMOKE_PORT": "1",
        }
        environment.update(overrides)
        return environment

    def run(self, *args: str, **overrides: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sh", str(SCRIPT), *args],
            env=self.env(**overrides),
            capture_output=True,
            text=True,
            timeout=60,
        )

    def call_log(self) -> list[str]:
        if not self.calls.exists():
            return []
        return [line for line in self.calls.read_text().splitlines() if line]


def _serve(cert: Path, key: Path) -> tuple[subprocess.Popen, int]:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    process = subprocess.Popen(
        [sys.executable, "-c", TLS_SERVER, str(cert), str(key), str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    assert process.stdout.readline().strip() == "ready"
    return process, port


def _stop(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        process.kill()


def test_the_migration_repoints_nginx_and_verifies_what_is_served(
    tmp_path: Path,
) -> None:
    sandbox = Sandbox(tmp_path)
    server, port = _serve(sandbox.active_cert, sandbox.active_key)
    try:
        result = sandbox.run(SMOKE_PORT=str(port))
    finally:
        _stop(server)

    assert result.returncode == 0, result.stdout + result.stderr
    conf = sandbox.conf.read_text()
    assert f"{sandbox.certs}/active/fullchain.pem" in conf
    assert f"{sandbox.certs}/active/key.pem" in conf
    assert LINEAGE not in conf
    # `nginx -t` strictly before the reload, then the fingerprint probe.
    calls = sandbox.call_log()
    assert calls[0] == "-t"
    assert calls[1] == "-s reload"
    # A backup of the original configuration exists for manual rollback.
    backed_up = next(sandbox.backups.glob("*/vysion.conf"))
    assert backed_up.read_text() == ORIGINAL_CONF
    assert re.search(r"backup=\S+", result.stdout)


def test_a_failing_nginx_test_restores_the_config_without_any_reload(
    tmp_path: Path,
) -> None:
    sandbox = Sandbox(tmp_path)
    result = sandbox.run(NGINX_STUB_T_FAIL="1")

    assert result.returncode != 0
    assert sandbox.conf.read_text() == ORIGINAL_CONF
    calls = sandbox.call_log()
    assert calls == ["-t"], f"reload attempted after a failed test: {calls}"


def test_a_served_fingerprint_mismatch_restores_the_configuration(
    tmp_path: Path,
) -> None:
    sandbox = Sandbox(tmp_path)
    other_cert, other_key = _certificate(tmp_path / "other")
    server, port = _serve(other_cert, other_key)
    try:
        result = sandbox.run(SMOKE_PORT=str(port))
    finally:
        _stop(server)

    assert result.returncode != 0
    # Rolled back and reloaded with the original configuration.
    assert sandbox.conf.read_text() == ORIGINAL_CONF
    calls = sandbox.call_log()
    assert calls == ["-t", "-s reload", "-t", "-s reload"]


def test_the_migration_is_idempotent(tmp_path: Path) -> None:
    sandbox = Sandbox(tmp_path)
    sandbox.conf.write_text(
        ORIGINAL_CONF.replace(f"{LINEAGE}/fullchain.pem", f"{sandbox.certs}/active/fullchain.pem")
        .replace(f"{LINEAGE}/privkey.pem", f"{sandbox.certs}/active/key.pem")
    )
    before = sandbox.conf.read_text()

    result = sandbox.run()

    assert result.returncode == 0, result.stdout + result.stderr
    assert sandbox.conf.read_text() == before
    assert sandbox.call_log() == []


def test_the_migration_refuses_before_the_bootstrap_exists(tmp_path: Path) -> None:
    sandbox = Sandbox(tmp_path)
    (sandbox.certs / "active").unlink()

    result = sandbox.run()

    assert result.returncode != 0
    assert "bootstrap" in (result.stdout + result.stderr).lower()
    assert sandbox.conf.read_text() == ORIGINAL_CONF
    assert sandbox.call_log() == []


def test_restore_puts_the_original_configuration_back(tmp_path: Path) -> None:
    sandbox = Sandbox(tmp_path)
    server, port = _serve(sandbox.active_cert, sandbox.active_key)
    try:
        migrated = sandbox.run(SMOKE_PORT=str(port))
    finally:
        _stop(server)
    assert migrated.returncode == 0, migrated.stdout + migrated.stderr
    backup = re.search(r"backup=(\S+)", migrated.stdout).group(1)

    restored = sandbox.run("restore", backup)

    assert restored.returncode == 0, restored.stdout + restored.stderr
    assert sandbox.conf.read_text() == ORIGINAL_CONF
    assert sandbox.call_log()[-2:] == ["-t", "-s reload"]


def test_restore_rejects_an_unknown_backup(tmp_path: Path) -> None:
    sandbox = Sandbox(tmp_path)
    result = sandbox.run("restore", str(tmp_path / "nowhere"))

    assert result.returncode != 0
    assert sandbox.conf.read_text() == ORIGINAL_CONF


@pytest.mark.parametrize(
    "args",
    [
        (),  # no hostname anywhere
    ],
)
def test_without_a_hostname_nothing_is_touched(tmp_path: Path, args: tuple) -> None:
    sandbox = Sandbox(tmp_path)
    environment = sandbox.env()
    environment.pop("VYSION_TLS_HOSTNAME")
    result = subprocess.run(
        ["sh", str(SCRIPT), *args],
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode != 0
    assert sandbox.conf.read_text() == ORIGINAL_CONF
    assert sandbox.call_log() == []

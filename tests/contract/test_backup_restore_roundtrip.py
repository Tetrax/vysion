"""Backup/restore round-trip on disposable volumes with real fingerprints.

Review finding: backups must be taken across one coherent boundary and
proven on throwaway copies — never on the live volumes. This test seeds
prefixed volumes, quiesces a running holder container, backs up, mutates
everything, restores onto the same disposable volumes and asserts every
fingerprint comes back byte-identical.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from vysion.state import StateStore

ROOT = Path(__file__).parents[2]
ALPINE = "alpine:3.20.1@sha256:dabf91b69c191a1a0a1628fd6bdd029c0c4018041c7f052870bb13c5a222ae76"
BASES = ("vysion-state", "vysion-certs", "vysion-reports")


def _require_docker() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is required for the backup round-trip")
    probe = subprocess.run(["docker", "info"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("a running docker daemon is required for the backup round-trip")


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    import os

    return subprocess.run(
        args, capture_output=True, text=True, cwd=ROOT, env={**os.environ, **(env or {})},
        check=False,
    )


def _in_volume(volume: str, args: str) -> None:
    """Run a shell snippet with the volume mounted at /data."""
    result = _run("docker", "run", "--rm", "--read-only", "-v", f"{volume}:/data", ALPINE,
                  "sh", "-c", args)
    assert result.returncode == 0, result.stdout + result.stderr


def _cat_bytes(volume: str, member: str) -> bytes:
    """Read one member of a volume as bytes (base64 over stdout, so no
    root-owned copy ever lands in the caller's directory)."""
    import base64

    result = _run(
        "docker", "run", "--rm", "--read-only", "-v", f"{volume}:/data", ALPINE,
        "sh", "-c", f"base64 < '/data/{member}'",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return base64.b64decode(result.stdout)


def _write_bytes(volume: str, member: str, payload: bytes) -> None:
    import base64

    encoded = base64.b64encode(payload).decode()
    result = _run(
        "docker", "run", "--rm", "--read-only",
        "-e", f"PAYLOAD_B64={encoded}",
        "-v", f"{volume}:/data",
        ALPINE, "sh", "-c", 'printf "%s" "$PAYLOAD_B64" | base64 -d > "/data/' + member + '"',
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture()
def prefixed_volumes():
    """Disposable volumes with a unique prefix; always cleaned up."""
    _require_docker()
    prefix = f"ci-backup-{uuid.uuid4().hex[:8]}-"
    volumes = [f"{prefix}{base}" for base in BASES]
    holder = f"ci-backup-holder-{uuid.uuid4().hex[:8]}"
    created: list[str] = []
    try:
        yield prefix, volumes, holder
    finally:
        _run("docker", "rm", "-f", holder)
        for volume in created + volumes:
            _run("docker", "volume", "rm", "-f", volume)


def test_backup_quiesces_holders_and_restores_every_fingerprint(
    tmp_path: Path, prefixed_volumes
) -> None:
    prefix, volumes, holder = prefixed_volumes
    state_volume, certs_volume, reports_volume = volumes

    # ---------------------------------------------------------------- seed
    for volume in volumes:
        result = _run("docker", "volume", "create", volume)
        assert result.returncode == 0, result.stderr

    # A real administration database with a live session (state fingerprint).
    seed_state = tmp_path / "seed-state"
    store = StateStore(seed_state)
    assert store.create_admin("a-coherent-backup-password") is True
    session_token, _csrf = store.create_session(ttl_seconds=3600)
    db_payload = (seed_state / "vysion-state.db").read_bytes()
    _write_bytes(state_volume, "vysion-state.db", db_payload)

    # A certificate generation with its metadata (certificate fingerprint).
    cert_payload = b"-----BEGIN CERTIFICATE-----SYNTHETIC\n"
    meta_payload = b'{"sha256": "fingerprint-of-generation-1"}\n'
    _run("docker", "run", "--rm", "--read-only", "-v", f"{certs_volume}:/data", ALPINE,
         "sh", "-c", "mkdir -p /data/generations/0001")
    _write_bytes(certs_volume, "generations/0001/fullchain.pem", cert_payload)
    _write_bytes(certs_volume, "generations/0001/meta.json", meta_payload)
    _write_bytes(certs_volume, "active", b"generations/0001")

    # A report counter (report fingerprint).
    _write_bytes(reports_volume, "counter.txt", b"1\n")
    _run("docker", "run", "--rm", "--read-only", "-v", f"{reports_volume}:/data", ALPINE,
         "sh", "-c", "mkdir -p /data/br")
    _write_bytes(reports_volume, "br/report.json", b'{"counter": 1}\n')

    fingerprints = {
        "state": _sha256(_cat_bytes(state_volume, "vysion-state.db")),
        "cert": _sha256(_cat_bytes(certs_volume, "generations/0001/fullchain.pem")),
        "cert-meta": _sha256(_cat_bytes(certs_volume, "generations/0001/meta.json")),
        "counter": _cat_bytes(reports_volume, "counter.txt"),
        "report": _cat_bytes(reports_volume, "br/report.json"),
    }

    # ------------------------------------------- a live holder to quiesce
    result = _run(
        "docker", "run", "-d", "--name", holder,
        "-v", f"{reports_volume}:/data",
        ALPINE, "sh", "-c", "sleep 300",
    )
    assert result.returncode == 0, result.stderr
    running_before = _run("docker", "inspect", "-f", "{{.State.Running}}", holder)
    assert running_before.stdout.strip() == "true"

    # ----------------------------------------------------------- backup
    backup_dir = tmp_path / "backups"
    result = _run(
        "scripts/backup.sh", str(backup_dir),
        env={"VYSION_VOLUME_PREFIX": prefix},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "quiescing containers" in result.stderr, result.stderr
    archives = list(backup_dir.glob("vysion-*/"))
    assert len(archives) == 1
    for base in BASES:
        assert (archives[0] / f"{prefix}{base}.tar.gz").is_file(), base

    # The holder was stopped for the capture and started again afterwards.
    running_after = _run("docker", "inspect", "-f", "{{.State.Running}}", holder)
    assert running_after.stdout.strip() == "true", result.stdout + result.stderr

    # ------------------------------------------------- mutate everything
    _write_bytes(reports_volume, "counter.txt", b"2\n")
    _write_bytes(reports_volume, "br/report.json", b'{"counter": 2}\n')
    _write_bytes(certs_volume, "generations/0001/fullchain.pem", b"CERT-GENERATION-2\n")
    # Copy the live database out and write to it AFTER the backup point: a
    # torn or partial restore would then be visible in the fingerprint
    # comparison.
    host_db = tmp_path / "vysion-state.db"
    host_db.write_bytes(_cat_bytes(state_volume, "vysion-state.db"))
    reopened = StateStore(tmp_path)
    assert reopened.has_admin() is True
    reopened.create_session(ttl_seconds=3600)  # a write after the backup
    _write_bytes(state_volume, "vysion-state.db", host_db.read_bytes())

    # ---------------------------------------------------------- restore
    result = _run(
        "scripts/restore.sh", str(archives[0]),
        env={"VYSION_VOLUME_PREFIX": prefix},
    )
    assert result.returncode == 0, result.stdout + result.stderr

    # ------------------------------------------------------ fingerprints
    assert _sha256(_cat_bytes(state_volume, "vysion-state.db")) == fingerprints["state"]
    assert _sha256(_cat_bytes(certs_volume, "generations/0001/fullchain.pem")) == (
        fingerprints["cert"]
    )
    assert _sha256(_cat_bytes(certs_volume, "generations/0001/meta.json")) == (
        fingerprints["cert-meta"]
    )
    assert _cat_bytes(reports_volume, "counter.txt") == fingerprints["counter"]
    assert _cat_bytes(reports_volume, "br/report.json") == fingerprints["report"]

    # The restored state is still the real, openable administration database.
    check_dir = tmp_path / "check"
    check_dir.mkdir(exist_ok=True)
    (check_dir / "vysion-state.db").write_bytes(
        _cat_bytes(state_volume, "vysion-state.db")
    )
    check_store = StateStore(check_dir)
    assert check_store.has_admin() is True
    assert check_store.verify_password("a-coherent-backup-password") is True
    assert check_store.resolve_session(session_token) is not None

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
        env={"VYSION_VOLUME_PREFIX": prefix, "VYSION_BACKUP_PREFIX": prefix},
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


def test_restore_refuses_a_directory_without_any_expected_archive(tmp_path: Path) -> None:
    """Review round-2 finding 3: a control restore that finds no expected
    archive must FAIL instead of printing 'Restore complete' with exit 0.

    This path needs no docker at all: it fails before any volume exists."""
    result = _run("scripts/restore.sh", str(tmp_path))
    assert result.returncode != 0, result.stdout + result.stderr
    assert "no expected archive" in result.stderr, result.stderr


def test_restore_decouples_source_archives_from_the_target_volume_prefix(
    tmp_path: Path,
) -> None:
    """Review round-2 finding 3: where the archives come from
    (VYSION_BACKUP_PREFIX, the prefix the backup was taken with) and where
    they go (VYSION_VOLUME_PREFIX) are two independent names. The documented
    control path — a backup taken under one name, restored under another
    prefix on disposable volumes — must come back with every fingerprint."""
    _require_docker()
    source_prefix = f"ci-src-{uuid.uuid4().hex[:8]}-"
    target_prefix = f"ci-dst-{uuid.uuid4().hex[:8]}-"
    second_prefix = f"ci-dst2-{uuid.uuid4().hex[:8]}-"
    source_volumes = [f"{source_prefix}{base}" for base in ("vysion-state", "vysion-reports")]
    target_volumes = [
        f"{target_prefix}vysion-state",
        f"{target_prefix}vysion-reports",
        f"{second_prefix}vysion-state",
        f"{second_prefix}vysion-reports",
    ]
    try:
        for volume in source_volumes:
            result = _run("docker", "volume", "create", volume)
            assert result.returncode == 0, result.stderr

        # Fingerprints: a real administration database and a report counter.
        seed_state = tmp_path / "seed-state"
        store = StateStore(seed_state)
        assert store.create_admin("a-cross-prefix-password") is True
        _write_bytes(
            source_volumes[0], "vysion-state.db", (seed_state / "vysion-state.db").read_bytes()
        )
        _write_bytes(source_volumes[1], "counter.txt", b"7\n")
        expected_state = _sha256(_cat_bytes(source_volumes[0], "vysion-state.db"))
        expected_counter = _cat_bytes(source_volumes[1], "counter.txt")

        # ONE backup, taken under the source prefix.
        backup_dir = tmp_path / "backups"
        result = _run(
            "scripts/backup.sh", str(backup_dir),
            env={"VYSION_VOLUME_PREFIX": source_prefix},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        archives = sorted(backup_dir.glob("vysion-*/"))
        assert len(archives) == 1
        assert (archives[0] / f"{source_prefix}vysion-state.tar.gz").is_file()

        # (1) Restore under a DIFFERENT prefix: the source archives are
        # found by their own name, the volumes written are the target ones.
        result = _run(
            "scripts/restore.sh", str(archives[0]),
            env={
                "VYSION_BACKUP_PREFIX": source_prefix,
                "VYSION_VOLUME_PREFIX": target_prefix,
            },
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Restore complete" in result.stdout, result.stdout
        assert _sha256(_cat_bytes(f"{target_prefix}vysion-state", "vysion-state.db")) == (
            expected_state
        )
        assert _cat_bytes(f"{target_prefix}vysion-reports", "counter.txt") == expected_counter

        # (2) Production naming: a backup of the live volumes carries no
        # prefix at all (vysion-state.tar.gz, ...). Same archives, renamed
        # exactly as scripts/backup.sh writes them for the live names, must
        # restore into a fresh disposable prefix with no source prefix set.
        production_dir = tmp_path / "production"
        production_dir.mkdir()
        for archive in sorted(archives[0].glob("*.tar.gz")):
            shutil.copy(archive, production_dir / archive.name.removeprefix(source_prefix))
        assert (production_dir / "vysion-state.tar.gz").is_file()

        result = _run(
            "scripts/restore.sh", str(production_dir),
            env={"VYSION_VOLUME_PREFIX": second_prefix},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert _sha256(_cat_bytes(f"{second_prefix}vysion-state", "vysion-state.db")) == (
            expected_state
        )
        assert _cat_bytes(f"{second_prefix}vysion-reports", "counter.txt") == expected_counter
    finally:
        for volume in target_volumes + source_volumes:
            _run("docker", "volume", "rm", "-f", volume)

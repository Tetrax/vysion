"""Encrypted migration bundle: format, bounds, strict validation, rollback."""

from __future__ import annotations

import hashlib
import io
import json
import struct
import threading
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vysion.migration import (
    BAD_CONTENT,
    BAD_DIGEST,
    BAD_FORMAT,
    BAD_MANIFEST,
    BAD_SECRET,
    BAD_STATE,
    BAD_VERSION,
    FORMAT_VERSION,
    HEADER_BYTES,
    MAGIC,
    MAX_BUNDLE_BYTES,
    MAX_STATE_DB_BYTES,
    NONCE_BYTES,
    OVERSIZED,
    PASSPHRASE_CONTRACT,
    SALT_BYTES,
    STATE_ENTRY,
    TRANSIENT_TABLES,
    MigrationError,
    apply_state,
    build_bundle,
    parse_bundle,
    prepare_staged_state,
    restore_bundle,
)
from vysion.security import SCRYPT_DKLEN, SCRYPT_MAXMEM, SCRYPT_N, SCRYPT_P, SCRYPT_R
from vysion.state import StateStore

PASSPHRASE = "a-migration-passphrase"
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def state_bytes(tmp_path: Path, name: str, *, admin: bool = True) -> bytes:
    store = StateStore(tmp_path / name, clock=lambda: NOW)
    if admin:
        assert store.create_admin("correct horse battery staple")
    return (tmp_path / name / "vysion-state.db").read_bytes()


def manifest_for(parts: dict[str, bytes], **overrides) -> bytes:
    manifest: dict = {
        "format": "vysion-migration",
        "version": 1,
        "created_at": NOW.isoformat(),
        "vysion_version": "2.test",
        "excluded": ["reports"],
        "entries": [
            {"name": name, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
            for name, blob in parts.items()
        ],
    }
    manifest.update(overrides)
    return json.dumps(manifest, separators=(",", ":")).encode("utf-8")


def zip_bytes(entries: dict[str, bytes], *, names: list[str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in names or list(entries):
            archive.writestr(name, entries[name])
    return buffer.getvalue()


def seal(plaintext: bytes, passphrase: str = PASSPHRASE, *, version: int = 1) -> bytes:
    salt = b"\x01" * SALT_BYTES
    nonce = b"\x02" * NONCE_BYTES
    header = MAGIC + struct.pack(">H", version) + salt + nonce
    key = hashlib.scrypt(
        passphrase.encode(),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return header + AESGCM(key).encrypt(nonce, plaintext, header)


def wrap_zip(raw_zip: bytes, passphrase: str = PASSPHRASE, **seal_kwargs) -> bytes:
    return seal(raw_zip, passphrase, **seal_kwargs)


def valid_zip(tmp_path: Path) -> bytes:
    state = state_bytes(tmp_path, "source")
    return zip_bytes(
        {
            "manifest.json": manifest_for({"state/vysion-state.db": state}),
            "state/vysion-state.db": state,
        }
    )


def refusal(data: bytes, passphrase: str = PASSPHRASE) -> str:
    with pytest.raises(MigrationError) as captured:
        parse_bundle(data, passphrase)
    return str(captured.value)


def test_roundtrip_preserves_state_and_certificate(tmp_path: Path) -> None:
    state = state_bytes(tmp_path, "source")
    bundle = build_bundle(
        state_db=state,
        passphrase=PASSPHRASE,
        certificate=b"-----BEGIN CERTIFICATE-----\nleaf\n",
        private_key=b"-----BEGIN PRIVATE KEY-----\nkey\n",
        created_at=NOW,
    )
    payload = parse_bundle(bundle, PASSPHRASE)
    assert payload.state_db == state
    assert payload.certificate is not None and payload.private_key is not None
    assert payload.manifest["format"] == "vysion-migration"
    assert payload.manifest["version"] == FORMAT_VERSION
    # TTL reports are excluded by construction, stated in the manifest itself.
    assert payload.manifest["excluded"] == ["reports"]
    assert payload.manifest["created_at"] == NOW.isoformat()


def test_short_or_foreign_container_is_refused(tmp_path: Path) -> None:
    assert refusal(b"nonsense") == BAD_FORMAT
    assert refusal(b"") == BAD_FORMAT
    good = build_bundle(state_db=state_bytes(tmp_path, "s"), passphrase=PASSPHRASE)
    assert refusal(good[: HEADER_BYTES - 1]) == BAD_FORMAT
    tampered_version = MAGIC + struct.pack(">H", 99) + good[HEADER_BYTES:]
    assert refusal(tampered_version) == BAD_VERSION
    foreign_magic = b"OTHERMIG!" + good[len(MAGIC) :]
    assert refusal(foreign_magic) == BAD_FORMAT


def test_wrong_secret_and_any_tamper_share_one_refusal(tmp_path: Path) -> None:
    good = build_bundle(state_db=state_bytes(tmp_path, "s"), passphrase=PASSPHRASE)
    assert refusal(good, "not-the-passphrase-at-all") == BAD_SECRET
    flipped = bytearray(good)
    flipped[-1] ^= 0x01
    assert refusal(bytes(flipped)) == BAD_SECRET
    salt_tampered = (
        good[: len(MAGIC) + 2] + b"\xff" * SALT_BYTES + good[len(MAGIC) + 2 + SALT_BYTES :]
    )
    assert refusal(salt_tampered) == BAD_SECRET


def test_oversized_bundle_is_refused_before_any_derivation() -> None:
    assert refusal(b"V" * (MAX_BUNDLE_BYTES + 1)) == OVERSIZED


def test_state_bound_is_refused_at_build(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        build_bundle(state_db=b"0" * (MAX_STATE_DB_BYTES + 1), passphrase=PASSPHRASE)
    with pytest.raises(ValueError):
        # certificate and key must travel together
        build_bundle(state_db=b"db", passphrase=PASSPHRASE, certificate=b"leaf")


def test_passphrase_contract_applies_on_both_sides(tmp_path: Path) -> None:
    good = build_bundle(state_db=state_bytes(tmp_path, "s"), passphrase=PASSPHRASE)
    with pytest.raises(MigrationError) as captured:
        parse_bundle(good, "court")
    assert str(captured.value) == PASSPHRASE_CONTRACT


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"not json at all", BAD_MANIFEST),
        (b"[]", BAD_MANIFEST),
    ],
)
def test_unreadable_manifest_is_refused(tmp_path: Path, raw: bytes, expected: str) -> None:
    state = state_bytes(tmp_path, "source")
    payload = wrap_zip(zip_bytes({"manifest.json": raw, STATE_ENTRY: state}))
    assert refusal(payload) == expected


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: m.update(extra="key"),
        lambda m: m.update(format="something-else"),
        lambda m: m.update(excluded=[]),
        lambda m: m.update(version="1"),
        lambda m: m.update(created_at="not-a-date"),
        lambda m: m.update(entries=[{"name": STATE_ENTRY, "size": 1}]),
        lambda m: m["entries"][0].update(size=999),
        lambda m: m["entries"][0].update(sha256="zz"),
        lambda m: m["entries"].append({"name": "evil.txt", "size": 1, "sha256": "0" * 64}),
    ],
)
def test_manifest_mutations_are_refused(tmp_path: Path, mutation) -> None:
    state = state_bytes(tmp_path, "source")
    parts = {STATE_ENTRY: state}
    manifest = json.loads(manifest_for(parts))
    mutation(manifest)
    entries = {"manifest.json": json.dumps(manifest).encode(), STATE_ENTRY: state}
    assert refusal(wrap_zip(zip_bytes(entries))) in {BAD_MANIFEST, BAD_CONTENT}


def test_hash_mismatch_between_manifest_and_payload_is_refused(tmp_path: Path) -> None:
    state = state_bytes(tmp_path, "source")
    other = state_bytes(tmp_path, "other")
    # Manifest seals `other`, the archive actually carries `state`.
    entries = {"manifest.json": manifest_for({STATE_ENTRY: other}), STATE_ENTRY: state}
    assert refusal(wrap_zip(zip_bytes(entries))) == BAD_DIGEST


@pytest.mark.parametrize(
    "entry_name",
    [
        "../../etc/passwd",
        "/etc/passwd",
        "state\\vysion-state.db",
        "state/",
        "reports/vysion-state.db",
    ],
)
def test_unexpected_or_traversing_entries_are_refused(tmp_path: Path, entry_name: str) -> None:
    state = state_bytes(tmp_path, "source")
    entries = {"manifest.json": manifest_for({STATE_ENTRY: state}), STATE_ENTRY: state}
    entries[entry_name] = b"sneaky"
    # Manifest does not list it and the allowlist rejects the name outright.
    assert refusal(wrap_zip(zip_bytes(entries))) == BAD_CONTENT


def test_symlink_entry_is_refused(tmp_path: Path) -> None:
    state = state_bytes(tmp_path, "source")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            zipfile.ZipInfo("manifest.json"), manifest_for({STATE_ENTRY: state})
        )
        info = zipfile.ZipInfo("state/vysion-state.db")
        info.external_attr = (0o120777 << 16) | 0o010444  # symlink mode
        archive.writestr(info, state)
    assert refusal(wrap_zip(buffer.getvalue())) == BAD_CONTENT


def test_duplicate_entries_and_unknown_compression_are_refused(tmp_path: Path) -> None:
    state = state_bytes(tmp_path, "source")
    entries = {"manifest.json": manifest_for({STATE_ENTRY: state}), STATE_ENTRY: state}
    duplicated = wrap_zip(zip_bytes(entries, names=[STATE_ENTRY, STATE_ENTRY, "manifest.json"]))
    assert refusal(duplicated) == BAD_CONTENT
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, blob in entries.items():
            archive.writestr(name, blob, compress_type=zipfile.ZIP_LZMA)
    assert refusal(wrap_zip(buffer.getvalue())) == BAD_CONTENT


def test_missing_state_or_half_certificate_is_refused(tmp_path: Path) -> None:
    state = state_bytes(tmp_path, "source")
    only_manifest = wrap_zip(zip_bytes({"manifest.json": manifest_for({STATE_ENTRY: state})}))
    assert refusal(only_manifest) == BAD_CONTENT
    with_cert = zip_bytes(
        {
            "manifest.json": manifest_for(
                {STATE_ENTRY: state, "certs/fullchain.pem": b"leaf"}
            ),
            STATE_ENTRY: state,
            "certs/fullchain.pem": b"leaf",
        }
    )
    assert refusal(wrap_zip(with_cert)) == BAD_CONTENT


def test_declared_size_beyond_the_bound_is_refused(tmp_path: Path) -> None:
    state = state_bytes(tmp_path, "source")
    manifest = json.loads(manifest_for({STATE_ENTRY: state}))
    manifest["entries"][0]["size"] = MAX_STATE_DB_BYTES + 1
    # The manifest size must match the ZIP header exactly: a mismatch is
    # refused before any payload is trusted.
    entries = {"manifest.json": json.dumps(manifest).encode(), STATE_ENTRY: state}
    assert refusal(wrap_zip(zip_bytes(entries))) == BAD_MANIFEST


def test_foreign_or_corrupt_state_database_is_refused(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(MigrationError) as captured:
        prepare_staged_state(b"", staging)
    assert str(captured.value) == BAD_STATE
    with pytest.raises(MigrationError) as captured:
        prepare_staged_state(b"\x00" * 512, staging)
    assert str(captured.value) == BAD_STATE

    # A structurally valid SQLite database that is not Vysion: refused.
    import sqlite3 as _sqlite3

    foreign = tmp_path / "foreign.db"
    connection = _sqlite3.connect(foreign)
    connection.execute("CREATE TABLE users (id INTEGER)")
    connection.commit()
    connection.close()
    with pytest.raises(MigrationError) as captured:
        prepare_staged_state(foreign.read_bytes(), staging)
    assert str(captured.value) == BAD_STATE


def test_state_without_administrator_is_refused(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    empty = state_bytes(tmp_path, "fresh", admin=False)
    with pytest.raises(MigrationError) as captured:
        prepare_staged_state(empty, staging)
    assert str(captured.value) == BAD_STATE


def test_future_schema_version_is_refused(tmp_path: Path) -> None:
    import sqlite3 as _sqlite3

    source = state_bytes(tmp_path, "source")
    upgraded = tmp_path / "upgraded.db"
    upgraded.write_bytes(source)
    connection = _sqlite3.connect(upgraded)
    connection.execute(
        "UPDATE meta SET value = ? WHERE key = 'schema_version'",
        (StateStore.SCHEMA_VERSION + 1,),
    )
    connection.commit()
    connection.close()
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(MigrationError) as captured:
        prepare_staged_state(upgraded.read_bytes(), staging)
    assert str(captured.value) == BAD_STATE


def test_transient_rows_are_purged_but_admin_and_email_survive(tmp_path: Path) -> None:
    import sqlite3 as _sqlite3

    store = StateStore(tmp_path / "source", clock=lambda: NOW)
    assert store.create_admin("correct horse battery staple")
    store.create_session(3600)
    store.create_recovery_token(purpose="recovery", ttl_seconds=3600, revision="r1")
    store.register_failure("test-scope", threshold=5, lock_seconds=900)
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        smtp_host="mail.example",
        smtp_username="u",
    )

    staging = tmp_path / "staging"
    staging.mkdir()
    staged = prepare_staged_state(
        (tmp_path / "source" / "vysion-state.db").read_bytes(), staging
    )
    connection = _sqlite3.connect(staged)
    for table in TRANSIENT_TABLES:
        assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    assert connection.execute("SELECT 1 FROM admin WHERE id = 1").fetchone() is not None
    assert connection.execute("SELECT COUNT(*) FROM email").fetchone()[0] == 1
    connection.close()


def test_apply_swaps_bytes_atomically_and_cleans_the_backup(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    live = StateStore(state_directory, clock=lambda: NOW)
    assert not live.has_admin()
    original = (state_directory / "vysion-state.db").read_bytes()

    candidate_source = tmp_path / "candidate"
    StateStore(candidate_source, clock=lambda: NOW).create_admin(
        "correct horse battery staple"
    )
    staging = tmp_path / "staging"
    staging.mkdir()
    staged = prepare_staged_state(
        (candidate_source / "vysion-state.db").read_bytes(), staging
    )

    apply_state(state_directory, staged, lock=threading.Lock())
    assert StateStore(state_directory, clock=lambda: NOW).has_admin() is True
    assert original != (state_directory / "vysion-state.db").read_bytes()
    backups = list(state_directory.glob("*.pre-restore-*"))
    assert backups == []
    assert (state_directory / "vysion-state.db").stat().st_mode & 0o777 == 0o600


def test_failure_during_application_rolls_back_byte_for_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_directory = tmp_path / "state"
    StateStore(state_directory, clock=lambda: NOW)
    original = (state_directory / "vysion-state.db").read_bytes()

    candidate_source = tmp_path / "candidate"
    StateStore(candidate_source, clock=lambda: NOW).create_admin(
        "correct horse battery staple"
    )
    staging = tmp_path / "staging"
    staging.mkdir()
    staged = prepare_staged_state(
        (candidate_source / "vysion-state.db").read_bytes(), staging
    )

    def explode(_state_directory: Path) -> bool:
        raise RuntimeError("simulated crash after the swap")

    monkeypatch.setattr("vysion.migration._verify_restored_state", explode)
    with pytest.raises(MigrationError) as captured:
        apply_state(state_directory, staged, lock=threading.Lock())
    assert str(captured.value) == "restauration interrompue : état initial conservé"
    # Byte-identical original: first-run is exactly what it was before.
    assert (state_directory / "vysion-state.db").read_bytes() == original
    assert StateStore.probe_has_admin(state_directory) is False
    assert list(state_directory.glob("*.pre-restore-*")) == []
    # And the instance still accepts normal enrollment afterwards.
    assert StateStore(state_directory, clock=lambda: NOW).create_admin(
        "correct horse battery staple"
    )


def test_restore_refuses_an_instance_that_already_has_an_admin(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    store = StateStore(state_directory, clock=lambda: NOW)
    store.create_admin("correct horse battery staple")
    before = (state_directory / "vysion-state.db").read_bytes()

    bundle = build_bundle(
        state_db=state_bytes(tmp_path, "other"), passphrase=PASSPHRASE, created_at=NOW
    )
    with pytest.raises(MigrationError) as captured:
        restore_bundle(
            state_directory=state_directory,
            data=bundle,
            passphrase=PASSPHRASE,
            lock=threading.Lock(),
        )
    assert str(captured.value) == "instance déjà initialisée : restauration impossible"
    assert (state_directory / "vysion-state.db").read_bytes() == before
    assert list(state_directory.glob(".migration-staging-*")) == []


def test_full_restore_report_and_staging_cleanup(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    StateStore(state_directory, clock=lambda: NOW)

    source = tmp_path / "source"
    source_store = StateStore(source, clock=lambda: NOW)
    source_store.create_admin("correct horse battery staple")
    bundle = build_bundle(
        state_db=(source / "vysion-state.db").read_bytes(),
        passphrase=PASSPHRASE,
        created_at=NOW,
    )

    report = restore_bundle(
        state_directory=state_directory,
        data=bundle,
        passphrase=PASSPHRASE,
        lock=threading.Lock(),
    )
    assert report == {
        "status": "restored",
        "certificate": {
            "included": False,
            "imported": False,
            "generation": None,
            "sha256": None,
            "reason": None,
        },
        "reports_included": False,
    }
    assert StateStore(state_directory, clock=lambda: NOW).verify_password(
        "correct horse battery staple"
    )
    assert list(state_directory.glob(".migration-staging-*")) == []

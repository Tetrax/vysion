"""Encrypted migration bundle: versioned container, strict restore.

The bundle is the only path that carries durable admin state (SQLite),
optional TLS material and nothing else out of or into an instance:

* container — magic + format version + scrypt parameters pinned by the
  format version + random salt/nonce, AES-256-GCM with the header bound as
  associated data: a tampered header or payload never decrypts, and an
  unknown magic/version is refused before any key is derived;
* payload — one in-memory ZIP with an exact entry allowlist, bounded
  declared sizes (zip-bomb refusal), no directory/symlink/duplicate entry,
  and a strict manifest (format, version, sizes, SHA-256 per entry,
  TTL reports explicitly listed as excluded);
* state restore — the candidate database is staged in a private directory,
  proved to match the canonical Vysion schema object for object (integrity
  check, schema version, exact stored CREATE statements of every object,
  admin row), stripped of transient rows (sessions, recovery tokens,
  lockouts, certificate tickets), proved fully usable through the
  application's own StateStore, then swapped in atomically with a
  byte-identical rollback on any verification failure.

Every refusal is a fixed, operator-safe message: no bundle byte, path or
ever the passphrase is echoed. Cryptography stays delegated to recognized
libraries (``hashlib.scrypt`` for the KDF, ``cryptography`` AESGCM for the
authenticated cipher); nothing here invents primitive construction.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import sqlite3
import stat
import struct
import threading
import zipfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vysion.build_info import VYSION_VERSION
from vysion.certificates import CertificateError, activate_staged
from vysion.security import (
    MAX_PASSWORD_BYTES,
    MIN_PASSWORD_BYTES,
    SCRYPT_DKLEN,
    SCRYPT_MAXMEM,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
)
from vysion.state import DATABASE_MODE, DATABASE_NAME, StateError, StateStore

# --------------------------------------------------------------------------
# container
# --------------------------------------------------------------------------
MAGIC = b"VYSIONMIG"
FORMAT_VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
HEADER_BYTES = len(MAGIC) + 2 + SALT_BYTES + NONCE_BYTES

MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_STATE_DB_BYTES = 16 * 1024 * 1024
MAX_CERTIFICATE_PART_BYTES = 512 * 1024
MAX_PAYLOAD_BYTES = MAX_STATE_DB_BYTES + 2 * MAX_CERTIFICATE_PART_BYTES
MAX_ZIP_ENTRIES = 4
ALLOWED_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})

# Fixed operator-safe refusals: never echo bundle content.
BAD_FORMAT = "format de sauvegarde non reconnu"
BAD_VERSION = "version de sauvegarde non prise en charge"
BAD_SECRET = "sauvegarde altérée ou passphrase incorrecte"
OVERSIZED = "sauvegarde surdimensionnée"
BAD_ARCHIVE = "archive de sauvegarde illisible"
BAD_MANIFEST = "manifeste de sauvegarde invalide"
BAD_CONTENT = "contenu de sauvegarde refusé"
BAD_DIGEST = "empreinte de sauvegarde incorrecte"
BAD_STATE = "base d'état de la sauvegarde incohérente ou étrangère"
APPLY_FAILED = "restauration interrompue : état initial conservé"
RESTORE_DONE = "instance déjà initialisée : restauration impossible"
PASSPHRASE_CONTRACT = "passphrase refusée : 12 à 1024 octets UTF-8"
NO_CERTIFICATE_MANAGED = (
    "certificat de la sauvegarde non importé : gestion TLS non locale de cette instance"
)

MANIFEST_NAME = "manifest.json"
STATE_ENTRY = "state/vysion-state.db"
CERTIFICATE_ENTRY = "certs/fullchain.pem"
PRIVATE_KEY_ENTRY = "certs/key.pem"
PAYLOAD_ENTRIES = (STATE_ENTRY, CERTIFICATE_ENTRY, PRIVATE_KEY_ENTRY)
ENTRY_LIMITS = {
    MANIFEST_NAME: MAX_MANIFEST_BYTES,
    STATE_ENTRY: MAX_STATE_DB_BYTES,
    CERTIFICATE_ENTRY: MAX_CERTIFICATE_PART_BYTES,
    PRIVATE_KEY_ENTRY: MAX_CERTIFICATE_PART_BYTES,
}
MANIFEST_FORMAT = "vysion-migration"
MANIFEST_KEYS = frozenset(
    {"format", "version", "created_at", "vysion_version", "excluded", "entries"}
)
MANIFEST_ENTRY_KEYS = frozenset({"name", "size", "sha256"})
EXCLUDED_BY_DEFAULT = ["reports"]

STATE_REQUIRED_TABLES = (
    "meta",
    "admin",
    "sessions",
    "lockouts",
    "recovery_tokens",
    "smtp",
    "email",
    "certificate_tickets",
)
TRANSIENT_TABLES = ("sessions", "recovery_tokens", "lockouts", "certificate_tickets")


class MigrationError(ValueError):
    """A refusal with a fixed message safe for an operator UI or a log."""


@dataclass(frozen=True)
class BundlePayload:
    """What an authenticated, validated bundle carries."""

    state_db: bytes
    certificate: bytes | None
    private_key: bytes | None
    manifest: dict[str, Any]


def _require_passphrase(passphrase: str) -> None:
    if not isinstance(passphrase, str):
        raise MigrationError(PASSPHRASE_CONTRACT)
    encoded = passphrase.encode("utf-8")
    if not MIN_PASSWORD_BYTES <= len(encoded) <= MAX_PASSWORD_BYTES:
        raise MigrationError(PASSPHRASE_CONTRACT)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _manifest_entry(name: str, payload: bytes) -> dict[str, Any]:
    return {"name": name, "size": len(payload), "sha256": _sha256(payload)}


def _dumps_manifest(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")


# --------------------------------------------------------------------------
# build (export side)
# --------------------------------------------------------------------------
def build_bundle(
    *,
    state_db: bytes,
    passphrase: str,
    certificate: bytes | None = None,
    private_key: bytes | None = None,
    created_at: datetime | None = None,
) -> bytes:
    """Seal one migration bundle. Bounds are refused, never truncated."""
    _require_passphrase(passphrase)
    if (certificate is None) != (private_key is None):
        raise ValueError("certificate and private key must travel together")
    if len(state_db) > MAX_STATE_DB_BYTES:
        raise ValueError("state database exceeds the migration bound")
    if certificate is not None and (
        len(certificate) > MAX_CERTIFICATE_PART_BYTES
        or len(private_key or b"") > MAX_CERTIFICATE_PART_BYTES
    ):
        raise ValueError("certificate material exceeds the migration bound")

    parts: dict[str, bytes] = {STATE_ENTRY: state_db}
    if certificate is not None and private_key is not None:
        parts[CERTIFICATE_ENTRY] = certificate
        parts[PRIVATE_KEY_ENTRY] = private_key
    timestamp = created_at or datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    manifest = {
        "format": MANIFEST_FORMAT,
        "version": FORMAT_VERSION,
        "created_at": timestamp.astimezone(UTC).isoformat(),
        "vysion_version": VYSION_VERSION,
        "excluded": list(EXCLUDED_BY_DEFAULT),
        "entries": [
            _manifest_entry(name, parts[name])
            for name in (STATE_ENTRY, CERTIFICATE_ENTRY, PRIVATE_KEY_ENTRY)
            if name in parts
        ],
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            zipfile.ZipInfo(MANIFEST_NAME), _dumps_manifest(manifest),
            compress_type=zipfile.ZIP_DEFLATED,
        )  # fmt: skip
        for name in (STATE_ENTRY, CERTIFICATE_ENTRY, PRIVATE_KEY_ENTRY):
            if name in parts:
                archive.writestr(
                    zipfile.ZipInfo(name), parts[name],
                    compress_type=zipfile.ZIP_DEFLATED,
                )  # fmt: skip

    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    header = MAGIC + struct.pack(">H", FORMAT_VERSION) + salt + nonce
    sealed = AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, buffer.getvalue(), header)
    bundle = header + sealed
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise ValueError("bundle exceeds the migration bound")
    return bundle


# --------------------------------------------------------------------------
# parse (import side)
# --------------------------------------------------------------------------
def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MigrationError(BAD_MANIFEST)
        result[key] = value
    return result


def _read_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Read exactly the declared size: a lying header is a refusal."""
    limit = info.file_size
    chunks: list[bytes] = []
    remaining = limit + 1
    with archive.open(info) as stream:
        while remaining > 0:
            chunk = stream.read(min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) != limit:
        raise MigrationError(BAD_CONTENT)
    return payload


def _validate_zip(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    if len(names) > MAX_ZIP_ENTRIES or len(names) != len(set(names)):
        raise MigrationError(BAD_CONTENT)
    resolved: dict[str, zipfile.ZipInfo] = {}
    total = 0
    for info in infos:
        name = info.filename
        # The allowlist is exact: traversal, absolute paths, backslashes,
        # directory entries and any unexpected member are refused here.
        if name not in ENTRY_LIMITS or name in resolved:
            raise MigrationError(BAD_CONTENT)
        if info.is_dir():
            raise MigrationError(BAD_CONTENT)
        file_type = stat.S_IFMT(info.external_attr >> 16)
        if file_type not in (0, stat.S_IFREG):
            # Symlinks and special nodes are never part of a bundle.
            raise MigrationError(BAD_CONTENT)
        if info.compress_type not in ALLOWED_COMPRESSION:
            raise MigrationError(BAD_CONTENT)
        if info.file_size > ENTRY_LIMITS[name]:
            raise MigrationError(OVERSIZED)
        total += info.file_size
        if total > MAX_PAYLOAD_BYTES + MAX_MANIFEST_BYTES:
            raise MigrationError(OVERSIZED)
        resolved[name] = info
    if MANIFEST_NAME not in resolved or STATE_ENTRY not in resolved:
        raise MigrationError(BAD_CONTENT)
    has_leaf = CERTIFICATE_ENTRY in resolved
    has_key = PRIVATE_KEY_ENTRY in resolved
    if has_leaf != has_key:
        raise MigrationError(BAD_CONTENT)
    return resolved


def _parse_manifest(raw: bytes, resolved: dict[str, zipfile.ZipInfo]) -> dict[str, Any]:
    if len(raw) > MAX_MANIFEST_BYTES:
        raise MigrationError(OVERSIZED)
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationError(BAD_MANIFEST) from exc
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        raise MigrationError(BAD_MANIFEST)
    if manifest["format"] != MANIFEST_FORMAT or type(manifest["version"]) is not int:
        raise MigrationError(BAD_MANIFEST)
    if manifest["version"] != FORMAT_VERSION:
        raise MigrationError(BAD_VERSION)
    if manifest["excluded"] != EXCLUDED_BY_DEFAULT:
        raise MigrationError(BAD_MANIFEST)
    if not isinstance(manifest["created_at"], str) or len(manifest["created_at"]) > 64:
        raise MigrationError(BAD_MANIFEST)
    try:
        datetime.fromisoformat(manifest["created_at"])
    except ValueError as exc:
        raise MigrationError(BAD_MANIFEST) from exc
    if not isinstance(manifest["vysion_version"], str) or len(manifest["vysion_version"]) > 64:
        raise MigrationError(BAD_MANIFEST)
    entries = manifest["entries"]
    if not isinstance(entries, list):
        raise MigrationError(BAD_MANIFEST)
    listed: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != MANIFEST_ENTRY_KEYS:
            raise MigrationError(BAD_MANIFEST)
        name = entry["name"]
        if not isinstance(name, str) or name not in ENTRY_LIMITS or name in listed:
            raise MigrationError(BAD_MANIFEST)
        if type(entry["size"]) is not int or entry["size"] < 0:
            raise MigrationError(BAD_MANIFEST)
        digest = entry["sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise MigrationError(BAD_MANIFEST)
        listed[name] = entry
    expected = set(resolved) - {MANIFEST_NAME}
    if set(listed) != expected:
        raise MigrationError(BAD_MANIFEST)
    for name, entry in listed.items():
        if entry["size"] != resolved[name].file_size:
            raise MigrationError(BAD_MANIFEST)
    return manifest


def parse_bundle(data: bytes, passphrase: str) -> BundlePayload:
    """Authenticate, decrypt and strictly validate a bundle."""
    _require_passphrase(passphrase)
    if len(data) > MAX_BUNDLE_BYTES:
        raise MigrationError(OVERSIZED)
    if len(data) < HEADER_BYTES + TAG_BYTES or not data.startswith(MAGIC):
        raise MigrationError(BAD_FORMAT)
    version = struct.unpack(">H", data[len(MAGIC) : len(MAGIC) + 2])[0]
    if version != FORMAT_VERSION:
        raise MigrationError(BAD_VERSION)
    offset = len(MAGIC) + 2
    salt = data[offset : offset + SALT_BYTES]
    nonce = data[offset + SALT_BYTES : offset + SALT_BYTES + NONCE_BYTES]
    header = data[:HEADER_BYTES]
    key = _derive_key(passphrase, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, data[HEADER_BYTES:], header)
    except InvalidTag as exc:
        # Wrong passphrase and tampered bytes are deliberately indistinguishable.
        raise MigrationError(BAD_SECRET) from exc

    try:
        archive = zipfile.ZipFile(io.BytesIO(plaintext))
    except (zipfile.BadZipFile, OSError) as exc:
        raise MigrationError(BAD_ARCHIVE) from exc
    with archive:
        try:
            resolved = _validate_zip(archive)
            manifest_raw = _read_entry(archive, resolved[MANIFEST_NAME])
            manifest = _parse_manifest(manifest_raw, resolved)
            parts = {
                name: (_read_entry(archive, info), info)
                for name, info in resolved.items()
                if name != MANIFEST_NAME
            }
        except zipfile.BadZipFile as exc:
            # A corrupt member (CRC) behind a well-formed directory is a
            # fixed archive refusal, never an unhandled 500.
            raise MigrationError(BAD_ARCHIVE) from exc
    listed = {entry["name"]: entry for entry in manifest["entries"]}
    for name, (payload, _info) in parts.items():
        if _sha256(payload) != listed[name]["sha256"]:
            raise MigrationError(BAD_DIGEST)
    return BundlePayload(
        state_db=parts[STATE_ENTRY][0],
        certificate=parts.get(CERTIFICATE_ENTRY, (None, None))[0],
        private_key=parts.get(PRIVATE_KEY_ENTRY, (None, None))[0],
        manifest=manifest,
    )


# --------------------------------------------------------------------------
# state staging and atomic application
# --------------------------------------------------------------------------
def prepare_staged_state(state_db: bytes, staging_directory: Path) -> Path:
    """Prove the candidate is a coherent, initialized Vysion state.

    Refused: foreign or corrupt database, unknown schema version, any
    deviation from the canonical schema — missing table, look-alike table
    with arbitrary columns, unexpected view/trigger/index — an instance
    without an administrator (there is nothing to migrate then), or a
    candidate that does not reopen and serve reads through the
    application's own StateStore. Transient rows — sessions, recovery
    tokens, lockouts, certificate tickets — are purged so nothing from the
    previous instance can ever authenticate against the restored one.
    """
    if len(state_db) > MAX_STATE_DB_BYTES:
        raise MigrationError(OVERSIZED)
    staged = staging_directory / DATABASE_NAME
    descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, DATABASE_MODE)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(state_db)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    try:
        connection = sqlite3.connect(staged, timeout=10.0)
    except sqlite3.Error as exc:  # pragma: no cover - staging is a private dir
        staged.unlink(missing_ok=True)
        raise MigrationError(BAD_STATE) from exc
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or str(integrity[0]) != "ok":
            raise MigrationError(BAD_STATE)
        row = connection.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        if row is None:
            raise MigrationError(BAD_STATE)
        try:
            version = int(row[0])
        except (TypeError, ValueError) as exc:
            raise MigrationError(BAD_STATE) from exc
        if not 1 <= version <= StateStore.SCHEMA_VERSION:
            raise MigrationError(BAD_STATE)
        tables = {
            str(entry[0])
            for entry in connection.execute("SELECT name FROM sqlite_master")
            if entry[0] is not None
        }
        if not set(STATE_REQUIRED_TABLES).issubset(tables):
            raise MigrationError(BAD_STATE)
        try:
            # Object for object, the stored CREATE statements this
            # application itself executes: columns, constraints and defaults
            # come from the very text SQLite parsed, and any object we never
            # created (view, trigger, extra table or index) is a refusal.
            StateStore.require_canonical_schema(connection)
        except StateError as exc:
            raise MigrationError(BAD_STATE) from exc
        admin = connection.execute("SELECT 1 FROM admin WHERE id = 1").fetchone()
        if admin is None:
            raise MigrationError(BAD_STATE)
        for table in TRANSIENT_TABLES:
            connection.execute(f"DELETE FROM {table}")
        connection.commit()
        admin = connection.execute("SELECT 1 FROM admin WHERE id = 1").fetchone()
        if admin is None:  # pragma: no cover - delete cannot remove admin
            raise MigrationError(BAD_STATE)
    except MigrationError:
        staged.unlink(missing_ok=True)
        raise
    except sqlite3.Error as exc:
        staged.unlink(missing_ok=True)
        raise MigrationError(BAD_STATE) from exc
    finally:
        connection.close()
    staged.chmod(DATABASE_MODE)
    _require_usable_state(staging_directory, staged)
    return staged


def _require_usable_state(staging_directory: Path, staged: Path) -> None:
    """Open the staged database exactly as the application will.

    Structural validity is not usability: this runs the real StateStore
    constructor (schema read, migration, transient purge) plus the reads a
    restored instance lives on — administrator row, e-mail row typing,
    session list — against the staged copy, before any live byte is
    touched. A candidate that cannot serve the instance never becomes the
    state the instance serves; the staging file is removed and the original
    database stays in place.
    """
    try:
        store = StateStore(staging_directory)
        store.admin_revision()
        store.email_config()
        store.list_sessions()
    except (StateError, sqlite3.Error, OSError, ValueError, TypeError, KeyError) as exc:
        staged.unlink(missing_ok=True)
        raise MigrationError(BAD_STATE) from exc


def _verify_restored_state(state_directory: Path) -> bool:
    return StateStore.probe_has_admin(state_directory)


def apply_state(
    state_directory: Path,
    staged_database: Path,
    *,
    lock: threading.Lock,
) -> None:
    """Swap the candidate database in atomically, verifiably, reversibly.

    Under the shared first-run lock: a candidate can only land on an
    instance that still has no administrator (the enrollment race is
    decided here, not by two separate reads). The current database is
    copied aside first; the candidate then ``os.replace``s it in a single
    atomic step (no partially written state file is ever observable), and
    the result is re-verified. Any failure restores the previous bytes
    exactly and reports a fixed message — a failed restore can never leave
    a half-applied instance behind.
    """
    target = state_directory / DATABASE_NAME
    backup = state_directory / f"{DATABASE_NAME}.pre-restore-{secrets.token_hex(6)}"
    replaced = False
    with lock:
        if StateStore.probe_has_admin(state_directory):
            raise MigrationError(RESTORE_DONE)
        try:
            shutil.copy2(target, backup)
            os.replace(staged_database, target)
            target.chmod(DATABASE_MODE)
            replaced = True
            if not _verify_restored_state(state_directory):
                raise MigrationError(APPLY_FAILED)
        except BaseException as exc:
            try:
                if replaced:
                    os.replace(backup, target)
                    target.chmod(DATABASE_MODE)
                else:
                    backup.unlink(missing_ok=True)
                # The original bytes are back by construction; probe that
                # the restored database is at least readable again.
                StateStore.probe_has_admin(state_directory)
            except StateError:
                # Rollback left an instance that fails closed, loudly.
                raise
            except BaseException as rollback_failure:
                raise MigrationError(APPLY_FAILED) from rollback_failure
            raise MigrationError(APPLY_FAILED) from exc
        with suppress(OSError):
            backup.unlink()


# --------------------------------------------------------------------------
# full restore (route entry point)
# --------------------------------------------------------------------------
def _certificate_outcome(
    store: Any,
    payload: BundlePayload,
    hostname: str,
) -> tuple[bool, str | None]:
    """Stage the bundled certificate; a refusal keeps the bootstrap one."""
    if payload.certificate is None or payload.private_key is None:
        return False, "aucun certificat dans la sauvegarde"
    try:
        store.validate(
            certificate=payload.certificate,
            private_key=payload.private_key,
            hostname=hostname,
        )
    except CertificateError as exc:
        store.discard_staged()
        return False, str(exc)
    return True, None


def restore_bundle(
    *,
    state_directory: Path,
    data: bytes,
    passphrase: str,
    lock: threading.Lock,
    certificate_store: Any = None,
    hostname: str = "",
    reloader: Any = None,
    smoker: Any = None,
) -> dict[str, Any]:
    """Full first-run restore: authenticate, stage, swap, then activate."""
    payload = parse_bundle(data, passphrase)
    staging = state_directory / f".migration-staging-{secrets.token_hex(8)}"
    staging.mkdir(mode=0o700)
    staged_database: Path | None = None
    staged_certificate = False
    applied = False
    certificate_report: dict[str, Any] = {
        "included": payload.certificate is not None,
        "imported": False,
        "generation": None,
        "sha256": None,
        "reason": None,
    }
    try:
        staged_database = prepare_staged_state(payload.state_db, staging)
        if payload.certificate is not None and certificate_store is not None:
            staged_certificate, error = _certificate_outcome(
                certificate_store, payload, hostname
            )
            if error:
                certificate_report["reason"] = error
        elif payload.certificate is not None:
            certificate_report["reason"] = NO_CERTIFICATE_MANAGED

        apply_state(
            state_directory,
            staged_database,
            lock=lock,
        )
        applied = True

        if staged_certificate and certificate_store is not None:
            if reloader is None or smoker is None:
                certificate_report["reason"] = "activation indisponible : hooks TLS non configurés"
                certificate_store.discard_staged()
            else:
                try:
                    generation, served = activate_staged(
                        certificate_store, reloader=reloader, smoker=smoker
                    )
                except CertificateError as exc:
                    # activate_staged already rolled the pointer back to the
                    # bootstrap generation: the restored state stays usable.
                    certificate_report["reason"] = str(exc)
                else:
                    certificate_report.update(
                        imported=True,
                        generation=generation.number,
                        sha256=served,
                        reason=None,
                    )
    finally:
        if not applied and certificate_store is not None and staged_certificate:
            certificate_store.discard_staged()
        shutil.rmtree(staging, ignore_errors=True)
    return {
        "status": "restored",
        "certificate": certificate_report,
        "reports_included": False,
    }

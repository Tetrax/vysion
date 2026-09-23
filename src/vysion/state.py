"""Durable administration state in a private, versioned SQLite database.

The state volume is separate from the ephemeral, TTL-purged reports volume:
credentials, sessions, lockouts, recovery tokens and the optional SMTP secret
must survive recreate, backup and rollback. Every unusable state fails closed:
an unreadable database never reads as "no administrator yet", so anonymous
first-run enrollment can never be reopened by corrupting the volume.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vysion.security import hash_password, token_digest, verify_password
from vysion.storage.reports import Clock, utc_now

DATABASE_NAME = "vysion-state.db"
DIRECTORY_MODE = 0o700
DATABASE_MODE = 0o600
# A database file that already exists must carry a Vysion schema. The only
# tolerated "not yet" state is the instant another process is initializing
# the file it just created: wait for its commit, bounded, then fail closed.
EXISTING_STATE_WAIT_SECONDS = 3.0
EXISTING_STATE_POLL_SECONDS = 0.02


class StateError(RuntimeError):
    """The durable state cannot be used; privileged operations must refuse."""


@dataclass(frozen=True)
class SessionRecord:
    token_hash: str
    csrf_token: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    from_address: str
    starttls: bool
    username: str | None = None
    password: str | None = None
    recovery_email: str | None = None
    timeout_seconds: int = 10

    def public_status(self) -> dict[str, Any]:
        """Projection returned over HTTP: never contains the secret."""
        return {
            "configured": True,
            "host": self.host,
            "port": self.port,
            "from": self.from_address,
            "starttls": self.starttls,
            "username": self.username,
            "password_configured": self.password is not None,
        }


EMAIL_TRANSPORTS = ("smtp", "microsoft365")
SMTP_SECURITIES = ("starttls", "tls", "none")


@dataclass(frozen=True)
class EmailConfig:
    """The single durable email row: one selected transport and its material.

    Only one transport is ever populated at a time, so a saved configuration
    can never carry the previous transport's secret along. The secrets stay
    write-only: :meth:`public_status` is the only projection that leaves this
    module over HTTP, and it reports presence, never a value.
    """

    transport: str
    from_address: str
    recovery_email: str | None = None
    timeout_seconds: int = 10
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_security: str | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    m365_tenant_id: str | None = None
    m365_client_id: str | None = None
    m365_client_secret: str | None = None
    m365_mailbox: str | None = None

    @property
    def secret(self) -> str | None:
        """The write-only credential of the selected transport, if any."""
        if self.transport == "microsoft365":
            return self.m365_client_secret
        return self.smtp_password

    @property
    def complete(self) -> bool:
        """Everything a real send through this transport requires."""
        if not self.from_address:
            return False
        if self.transport == "microsoft365":
            return bool(self.m365_tenant_id and self.m365_client_id and self.m365_client_secret)
        return bool(self.smtp_host and self.smtp_port)

    def public_status(self) -> dict[str, Any]:
        """Projection returned over HTTP: no secret and no configured value."""
        return {
            "configured": True,
            "transport": self.transport,
            "provenance": "state",
            "secret_configured": bool(self.secret),
            "recovery_email_configured": bool(self.recovery_email),
        }


class StateStore:
    """Single-account admin state: atomic first-run, sessions, lockouts."""

    SCHEMA_VERSION = 1

    def __init__(self, directory: Path | str, *, clock: Clock = utc_now) -> None:
        self._directory = Path(directory)
        self._clock = clock
        # State, certificate material and reports must never be world-readable
        # whatever the inherited umask is.
        os.umask(0o077)
        try:
            self._directory.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
            self._directory.chmod(DIRECTORY_MODE)
        except OSError as exc:
            raise StateError("state directory is unavailable") from exc
        self._path = self._directory / DATABASE_NAME
        created_by_us = self._create_database_file()
        try:
            if not created_by_us:
                self._require_existing_vysion_schema()
            with self._connection() as connection:
                self._migrate(connection)
            self.purge_expired_sessions()
        except StateError:
            raise
        except sqlite3.Error as exc:
            raise StateError("state database is unreadable") from exc

    # ------------------------------------------------------------------
    # infrastructure
    # ------------------------------------------------------------------
    @staticmethod
    def digest_token(token: str) -> str:
        return token_digest(token)

    @classmethod
    def probe_has_admin(cls, directory: Path | str) -> bool:
        """Read-only probe; a corrupt state raises instead of reading as empty."""
        path = Path(directory) / DATABASE_NAME
        if not path.is_file():
            return False
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=5.0
            )
            row = connection.execute("SELECT 1 FROM admin LIMIT 1").fetchone()
        except sqlite3.Error as exc:
            raise StateError("state database is unreadable") from exc
        finally:
            if connection is not None:
                connection.close()
        return row is not None

    def schema_version(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
        if row is None:
            raise StateError("state database has no schema version")
        return int(row["value"])

    def _create_database_file(self) -> bool:
        """Create the database exclusively; True only for the creating call."""
        if self._path.exists():
            try:
                self._path.chmod(DATABASE_MODE)
            except OSError as exc:
                raise StateError("state database permissions are unusable") from exc
            return False
        try:
            descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT | os.O_EXCL, DATABASE_MODE)
        except FileExistsError:
            return False
        except OSError as exc:
            raise StateError("state database cannot be created") from exc
        os.close(descriptor)
        return True

    def _existing_schema_version(self) -> int | None:
        """Read-only probe of the schema version of an already-present file."""
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"file:{self._path.resolve().as_posix()}?mode=ro", uri=True, timeout=5.0
            )
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.Error:
            return None
        finally:
            if connection is not None:
                connection.close()
        if row is None:
            return None
        try:
            return int(row[0])
        except (TypeError, ValueError):
            return None

    def _require_existing_vysion_schema(self) -> None:
        """A present database must be a Vysion state database, full stop.

        Only a genuinely absent file may initialize the schema. A zero-byte
        file, a foreign SQLite database or any present-but-uninitialized
        state fails closed: it can never read as \"no administrator yet\" and
        therefore never reopens anonymous first-run enrollment. The bounded
        wait exists solely for the process that created the file microseconds
        ago and has not committed its schema yet (first-run race).
        """
        deadline = time.monotonic() + EXISTING_STATE_WAIT_SECONDS
        while True:
            version = self._existing_schema_version()
            if version is not None and version >= 1:
                return
            if time.monotonic() >= deadline:
                raise StateError(
                    "state database exists but is not a Vysion state database"
                )
            time.sleep(EXISTING_STATE_POLL_SECONDS)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        try:
            connection = sqlite3.connect(
                self._path,
                timeout=10.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error as exc:
            raise StateError("state database is unavailable") from exc
        try:
            yield connection
        except sqlite3.Error as exc:
            raise StateError("state database operation failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _commit(connection: sqlite3.Connection) -> None:
        connection.execute("COMMIT")

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        # A missing transaction is not an error worth surfacing.
        with suppress(sqlite3.Error):  # pragma: no cover - transaction already gone
            connection.execute("ROLLBACK")

    def create_certificate_ticket(
        self, *, session_hash: str, content_digest: str, ttl_seconds: int
    ) -> str:
        """Issue a single-use activation ticket bound to one session."""
        raw_token = secrets.token_urlsafe(32)
        now = self._now_ts()
        with self._connection() as connection:
            self._begin(connection)
            connection.execute(
                "DELETE FROM certificate_tickets WHERE expires_at <= ?",
                (now,),
            )
            connection.execute(
                """
                INSERT INTO certificate_tickets
                    (digest, session_hash, content_digest, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    token_digest(raw_token),
                    session_hash,
                    content_digest,
                    now,
                    now + ttl_seconds,
                ),
            )
            self._commit(connection)
        return raw_token

    def consume_certificate_ticket(
        self, raw_token: str, *, session_hash: str, content_digest: str
    ) -> bool:
        """Consume atomically: single use, same session, same staged digest."""
        digest = token_digest(raw_token)
        now = self._now_ts()
        with self._connection() as connection:
            self._begin(connection)
            cursor = connection.execute(
                """
                DELETE FROM certificate_tickets
                WHERE digest = ? AND session_hash = ? AND content_digest = ?
                  AND expires_at > ?
                """,
                (digest, session_hash, content_digest, now),
            )
            self._commit(connection)
            return cursor.rowcount == 1

    def _migrate(self, connection: sqlite3.Connection) -> None:
        self._begin(connection)
        try:
            try:
                row = connection.execute(
                    "SELECT value FROM meta WHERE key = 'schema_version'"
                ).fetchone()
            except sqlite3.OperationalError as exc:
                # Only a missing table means "fresh state"; any other
                # operational failure (including a corrupt file, which raises
                # DatabaseError) must keep failing closed.
                if not str(exc).startswith("no such table"):
                    raise
                row = None
            version = int(row["value"]) if row is not None else 0
            if version > self.SCHEMA_VERSION:
                raise StateError(
                    f"state schema {version} is newer than "
                    f"{self.SCHEMA_VERSION}; refusing to continue"
                )
            if version < 1:
                self._create_schema(connection)
                version = 1
                connection.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                    (str(version),),
                )
            # Addendum table: single-use certificate activation tickets. The
            # CREATE is unconditional so pre-existing schema-1 databases get
            # it on their next open as well.
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS certificate_tickets (
                    digest TEXT PRIMARY KEY,
                    session_hash TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )
            # Addendum table: the single transport-agnostic email row. The
            # CREATE is unconditional so pre-existing schema-1 databases get
            # it on their next open as well — the schema version deliberately
            # stays at 1 so an older binary keeps reading the same file.
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS email (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    transport TEXT NOT NULL,
                    from_address TEXT NOT NULL,
                    recovery_email TEXT,
                    timeout_seconds INTEGER NOT NULL DEFAULT 10,
                    smtp_host TEXT,
                    smtp_port INTEGER,
                    smtp_security TEXT,
                    smtp_username TEXT,
                    smtp_password TEXT,
                    m365_tenant_id TEXT,
                    m365_client_id TEXT,
                    m365_client_secret TEXT,
                    m365_mailbox TEXT
                )
                """
            )
            # One-shot adoption of a pre-email database: only while the email
            # table is still empty, so a stale smtp row can never overwrite a
            # configuration saved later through the admin surface.
            connection.execute(
                """
                INSERT INTO email (
                    id, transport, from_address, recovery_email,
                    timeout_seconds, smtp_host, smtp_port, smtp_security,
                    smtp_username, smtp_password
                )
                SELECT 1, 'smtp', from_address, recovery_email, 10, host, port,
                       CASE WHEN starttls = 1 THEN 'starttls' ELSE 'none' END,
                       username, password
                FROM smtp
                WHERE id = 1 AND NOT EXISTS (SELECT 1 FROM email)
                """
            )
            self._commit(connection)
        except BaseException:
            self._rollback(connection)
            raise

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        # Statement by statement: executescript would implicitly commit the
        # surrounding first-run transaction.
        statements = """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_algo TEXT NOT NULL,
                scrypt_n INTEGER NOT NULL,
                scrypt_r INTEGER NOT NULL,
                scrypt_p INTEGER NOT NULL,
                salt TEXT NOT NULL,
                digest TEXT NOT NULL,
                revision TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS lockouts (
                scope TEXT PRIMARY KEY,
                failures INTEGER NOT NULL,
                locked_until INTEGER
            );
            CREATE TABLE IF NOT EXISTS recovery_tokens (
                digest TEXT PRIMARY KEY,
                purpose TEXT NOT NULL,
                revision TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS smtp (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                from_address TEXT NOT NULL,
                starttls INTEGER NOT NULL,
                username TEXT,
                password TEXT,
                recovery_email TEXT
            );
            CREATE TABLE IF NOT EXISTS email (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                transport TEXT NOT NULL,
                from_address TEXT NOT NULL,
                recovery_email TEXT,
                timeout_seconds INTEGER NOT NULL DEFAULT 10,
                smtp_host TEXT,
                smtp_port INTEGER,
                smtp_security TEXT,
                smtp_username TEXT,
                smtp_password TEXT,
                m365_tenant_id TEXT,
                m365_client_id TEXT,
                m365_client_secret TEXT,
                m365_mailbox TEXT
            );
            """
        for statement in (part for part in statements.split(";") if part.strip()):
            connection.execute(statement)

    # ------------------------------------------------------------------
    # time helpers
    # ------------------------------------------------------------------
    def _now(self) -> datetime:
        current = self._clock()
        if current.tzinfo is None:
            return current.replace(tzinfo=UTC)
        return current

    def _now_ts(self) -> int:
        return int(self._now().timestamp())

    @staticmethod
    def _to_datetime(value: int) -> datetime:
        return datetime.fromtimestamp(value, UTC)

    # ------------------------------------------------------------------
    # administrator account
    # ------------------------------------------------------------------
    def has_admin(self) -> bool:
        with self._connection() as connection:
            row = connection.execute("SELECT 1 FROM admin WHERE id = 1").fetchone()
        return row is not None

    def create_admin(self, password: str) -> bool:
        """Atomic first-run: exactly one caller can ever win this insert."""
        record = hash_password(password)
        now = self._now_ts()
        revision = secrets.token_urlsafe(16)
        with self._connection() as connection:
            self._begin(connection)
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO admin (
                        id, password_algo, scrypt_n, scrypt_r, scrypt_p,
                        salt, digest, revision, created_at, updated_at
                    ) VALUES (1, :algorithm, :n, :r, :p, :salt, :digest,
                              :revision, :now, :now)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    {
                        **record,
                        "revision": revision,
                        "now": now,
                    },
                )
                created = cursor.rowcount == 1
                self._commit(connection)
            except BaseException:
                self._rollback(connection)
                raise
        return created

    def _admin_row(self, connection: sqlite3.Connection) -> sqlite3.Row | None:
        return connection.execute("SELECT * FROM admin WHERE id = 1").fetchone()

    def verify_password(self, password: str) -> bool:
        with self._connection() as connection:
            row = self._admin_row(connection)
        if row is None:
            return False
        record = {
            "algorithm": row["password_algo"],
            "n": row["scrypt_n"],
            "r": row["scrypt_r"],
            "p": row["scrypt_p"],
            "salt": row["salt"],
            "digest": row["digest"],
        }
        try:
            return verify_password(password, record)
        except ValueError:
            # Fail closed: a tampered record never authenticates and never
            # reopens first-run enrollment (the account row still exists).
            return False

    def set_password(self, password: str) -> bool:
        """Replace the password, rotate the revision and revoke every session."""
        record = hash_password(password)
        now = self._now_ts()
        revision = secrets.token_urlsafe(16)
        with self._connection() as connection:
            self._begin(connection)
            try:
                cursor = connection.execute(
                    """
                    UPDATE admin
                    SET password_algo = :algorithm,
                        scrypt_n = :n,
                        scrypt_r = :r,
                        scrypt_p = :p,
                        salt = :salt,
                        digest = :digest,
                        revision = :revision,
                        updated_at = :now
                    WHERE id = 1
                    """,
                    {**record, "revision": revision, "now": now},
                )
                updated = cursor.rowcount == 1
                if updated:
                    connection.execute("DELETE FROM sessions")
                self._commit(connection)
            except BaseException:
                self._rollback(connection)
                raise
        return updated

    def admin_revision(self) -> str | None:
        with self._connection() as connection:
            row = self._admin_row(connection)
        return None if row is None else str(row["revision"])

    # ------------------------------------------------------------------
    # sessions
    # ------------------------------------------------------------------
    def create_session(self, ttl_seconds: int) -> tuple[str, str]:
        if ttl_seconds <= 0:
            raise ValueError("session TTL must be positive")
        raw_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        now = self._now_ts()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO sessions (token_hash, csrf_token, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (token_digest(raw_token), csrf_token, now, now + ttl_seconds),
            )
        return raw_token, csrf_token

    def resolve_session(self, raw_token: str) -> SessionRecord | None:
        digest = token_digest(raw_token)
        now = self._now_ts()
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT token_hash, csrf_token, created_at, expires_at, revoked_at
                FROM sessions WHERE token_hash = ?
                """,
                (digest,),
            ).fetchone()
            if row is None:
                return None
            if row["revoked_at"] is not None:
                return None
            if int(row["expires_at"]) <= now:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
                return None
        return SessionRecord(
            token_hash=str(row["token_hash"]),
            csrf_token=str(row["csrf_token"]),
            created_at=self._to_datetime(int(row["created_at"])),
            expires_at=self._to_datetime(int(row["expires_at"])),
        )

    def revoke_session(self, raw_token: str) -> bool:
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_digest(raw_token),)
            )
            return cursor.rowcount == 1

    def revoke_all_sessions(self) -> int:
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM sessions")
            return int(cursor.rowcount)

    def list_sessions(self) -> list[SessionRecord]:
        now = self._now_ts()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT token_hash, csrf_token, created_at, expires_at
                FROM sessions WHERE revoked_at IS NULL AND expires_at > ?
                ORDER BY created_at
                """,
                (now,),
            ).fetchall()
        return [
            SessionRecord(
                token_hash=str(row["token_hash"]),
                csrf_token=str(row["csrf_token"]),
                created_at=self._to_datetime(int(row["created_at"])),
                expires_at=self._to_datetime(int(row["expires_at"])),
            )
            for row in rows
        ]

    def purge_expired_sessions(self) -> int:
        now = self._now_ts()
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL",
                (now,),
            )
            return int(cursor.rowcount)

    # ------------------------------------------------------------------
    # lockouts / rate limiting
    # ------------------------------------------------------------------
    def register_failure(self, scope: str, *, threshold: int, lock_seconds: int) -> int | None:
        """Record one failure; returns the lock duration when it triggers."""
        if threshold <= 0 or lock_seconds <= 0:
            raise ValueError("lockout policy must be strictly positive")
        now = self._now_ts()
        with self._connection() as connection:
            self._begin(connection)
            try:
                row = connection.execute(
                    "SELECT failures, locked_until FROM lockouts WHERE scope = ?",
                    (scope,),
                ).fetchone()
                if (
                    row is not None
                    and row["locked_until"] is not None
                    and int(row["locked_until"]) > now
                ):
                    remaining = int(row["locked_until"]) - now
                    self._commit(connection)
                    return remaining
                failures = (int(row["failures"]) if row is not None else 0) + 1
                if failures >= threshold:
                    locked_until = now + lock_seconds
                    connection.execute(
                        """
                        INSERT INTO lockouts (scope, failures, locked_until)
                        VALUES (?, 0, ?)
                        ON CONFLICT (scope) DO UPDATE SET
                            failures = 0, locked_until = excluded.locked_until
                        """,
                        (scope, locked_until),
                    )
                    self._commit(connection)
                    return lock_seconds
                connection.execute(
                    """
                    INSERT INTO lockouts (scope, failures, locked_until)
                    VALUES (?, ?, NULL)
                    ON CONFLICT (scope) DO UPDATE SET
                        failures = excluded.failures
                    """,
                    (scope, failures),
                )
                self._commit(connection)
            except BaseException:
                self._rollback(connection)
                raise
        return None

    def lock_remaining(self, scope: str) -> int | None:
        now = self._now_ts()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT locked_until FROM lockouts WHERE scope = ?", (scope,)
            ).fetchone()
        if row is None or row["locked_until"] is None:
            return None
        remaining = int(row["locked_until"]) - now
        return remaining if remaining > 0 else None

    def clear_failures(self, scope: str) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM lockouts WHERE scope = ?", (scope,))

    # ------------------------------------------------------------------
    # recovery tokens
    # ------------------------------------------------------------------
    def create_recovery_token(self, *, purpose: str, ttl_seconds: int, revision: str) -> str:
        if ttl_seconds <= 0:
            raise ValueError("recovery TTL must be positive")
        raw_token = secrets.token_urlsafe(32)
        now = self._now_ts()
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM recovery_tokens WHERE expires_at <= ?",
                (now,),
            )
            connection.execute(
                """
                INSERT INTO recovery_tokens (
                    digest, purpose, revision, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (token_digest(raw_token), purpose, revision, now, now + ttl_seconds),
            )
        return raw_token

    def consume_recovery_token(self, token: str, *, purpose: str, revision: str) -> bool:
        now = self._now_ts()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE recovery_tokens SET used_at = ?
                WHERE digest = ? AND purpose = ? AND revision = ?
                  AND used_at IS NULL AND expires_at > ?
                """,
                (now, token_digest(token), purpose, revision, now),
            )
            return cursor.rowcount == 1

    # ------------------------------------------------------------------
    # optional email transport (secrets stay write-only in this private state)
    # ------------------------------------------------------------------
    def email_config(self) -> EmailConfig | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM email WHERE id = 1").fetchone()
        if row is None:
            return None
        try:
            return EmailConfig(
                transport=str(row["transport"]),
                from_address=str(row["from_address"]),
                recovery_email=row["recovery_email"],
                timeout_seconds=int(row["timeout_seconds"]),
                smtp_host=row["smtp_host"],
                smtp_port=int(row["smtp_port"]) if row["smtp_port"] is not None else None,
                smtp_security=row["smtp_security"],
                smtp_username=row["smtp_username"],
                smtp_password=row["smtp_password"],
                m365_tenant_id=row["m365_tenant_id"],
                m365_client_id=row["m365_client_id"],
                m365_client_secret=row["m365_client_secret"],
                m365_mailbox=row["m365_mailbox"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError("state database is unreadable") from exc

    def email_public_status(self) -> dict[str, Any]:
        """What the admin surface may show: configured or not, never a value."""
        config = self.email_config()
        if config is None:
            return {
                "configured": False,
                "transport": None,
                "provenance": None,
                "secret_configured": False,
                "recovery_email_configured": False,
            }
        return config.public_status()

    def set_email_config(
        self,
        *,
        transport: str,
        from_address: str,
        recovery_email: str | None = None,
        timeout_seconds: int = 10,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_security: str | None = None,
        smtp_username: str | None = None,
        smtp_password: str | None = None,
        m365_tenant_id: str | None = None,
        m365_client_id: str | None = None,
        m365_client_secret: str | None = None,
        m365_mailbox: str | None = None,
    ) -> None:
        """Persist exactly one transport; the other one is cleared."""
        if transport not in EMAIL_TRANSPORTS:
            raise ValueError(f"unsupported email transport: {transport!r}")
        if transport == "smtp":
            m365_tenant_id = m365_client_id = m365_client_secret = m365_mailbox = None
        else:
            smtp_host = smtp_port = smtp_security = None
            smtp_username = smtp_password = None
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO email (
                    id, transport, from_address, recovery_email, timeout_seconds,
                    smtp_host, smtp_port, smtp_security, smtp_username,
                    smtp_password, m365_tenant_id, m365_client_id,
                    m365_client_secret, m365_mailbox
                )
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET
                    transport = excluded.transport,
                    from_address = excluded.from_address,
                    recovery_email = excluded.recovery_email,
                    timeout_seconds = excluded.timeout_seconds,
                    smtp_host = excluded.smtp_host,
                    smtp_port = excluded.smtp_port,
                    smtp_security = excluded.smtp_security,
                    smtp_username = excluded.smtp_username,
                    smtp_password = excluded.smtp_password,
                    m365_tenant_id = excluded.m365_tenant_id,
                    m365_client_id = excluded.m365_client_id,
                    m365_client_secret = excluded.m365_client_secret,
                    m365_mailbox = excluded.m365_mailbox
                """,
                (
                    transport,
                    from_address,
                    recovery_email,
                    int(timeout_seconds),
                    smtp_host,
                    int(smtp_port) if smtp_port is not None else None,
                    smtp_security,
                    smtp_username,
                    smtp_password,
                    m365_tenant_id,
                    m365_client_id,
                    m365_client_secret,
                    m365_mailbox,
                ),
            )

    def clear_email_config(self) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM email WHERE id = 1")

    def smtp_config(self) -> SmtpConfig | None:
        """Legacy SMTP view; None while another transport is selected."""
        config = self.email_config()
        if config is None or config.transport != "smtp" or not config.smtp_host:
            return None
        return SmtpConfig(
            host=config.smtp_host,
            port=config.smtp_port if config.smtp_port is not None else 587,
            from_address=config.from_address,
            starttls=(config.smtp_security or "none") == "starttls",
            username=config.smtp_username,
            password=config.smtp_password,
            recovery_email=config.recovery_email,
            timeout_seconds=config.timeout_seconds,
        )

    def set_smtp_config(
        self,
        *,
        host: str,
        port: int,
        from_address: str,
        starttls: bool,
        username: str | None = None,
        password: str | None = None,
        recovery_email: str | None = None,
    ) -> None:
        self.set_email_config(
            transport="smtp",
            from_address=from_address,
            recovery_email=recovery_email,
            smtp_host=host,
            smtp_port=port,
            smtp_security="starttls" if starttls else "none",
            smtp_username=username,
            smtp_password=password,
        )

    def clear_smtp_config(self) -> None:
        self.clear_email_config()

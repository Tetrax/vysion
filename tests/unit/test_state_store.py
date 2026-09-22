"""Durable admin state: schema, atomic first-run, fail-closed corruption."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vysion.state import StateError, StateStore


def fixed_clock(value: datetime):
    return lambda: value


def test_state_store_creates_a_private_directory_and_database(tmp_path: Path) -> None:
    state = tmp_path / "state"
    StateStore(state)

    database = state / "vysion-state.db"
    assert database.is_file()
    assert (state.stat().st_mode & 0o777) == 0o700
    assert (database.stat().st_mode & 0o777) == 0o600


def test_first_admin_is_created_exactly_once(tmp_path: Path) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    store = StateStore(tmp_path / "state", clock=fixed_clock(now))

    assert store.has_admin() is False
    assert store.create_admin("correct horse battery staple") is True
    assert store.has_admin() is True
    # A second attempt must never replace or duplicate the account.
    assert store.create_admin("another password entirely") is False
    assert store.verify_password("correct horse battery staple") is True
    assert store.verify_password("another password entirely") is False


def test_concurrent_first_run_creates_exactly_one_admin(tmp_path: Path) -> None:
    state = tmp_path / "state"
    barrier = threading.Barrier(8)
    results: list[bool] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            store = StateStore(state)
            barrier.wait(timeout=10)
            created = store.create_admin("racing-password-1234")
            with lock:
                results.append(created)
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, errors
    assert sorted(results) == [False] * 7 + [True]
    store = StateStore(state)
    assert store.has_admin() is True
    assert store.verify_password("racing-password-1234") is True


def test_corrupt_state_fails_closed_and_never_reopens_first_run(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "vysion-state.db").write_bytes(b"not a sqlite database at all\n")

    with pytest.raises(StateError):
        StateStore(state)

    # Even a direct probe must refuse: an invalid state never reads as
    # "no administrator yet", which would reopen anonymous enrollment.
    with pytest.raises(StateError):
        StateStore.probe_has_admin(state)


def test_future_schema_version_is_refused(tmp_path: Path) -> None:
    state = tmp_path / "state"
    StateStore(state)
    connection = sqlite3.connect(state / "vysion-state.db")
    connection.execute("UPDATE meta SET value = '999' WHERE key = 'schema_version'")
    connection.commit()
    connection.close()

    with pytest.raises(StateError):
        StateStore(state)


def test_sessions_stare_only_a_digest_and_expire(tmp_path: Path) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    store = StateStore(tmp_path / "state", clock=fixed_clock(now))

    raw, csrf = store.create_session(ttl_seconds=600)
    assert len(raw) >= 40
    assert store.resolve_session(raw) is not None
    assert store.resolve_session(raw).csrf_token == csrf
    # The raw token must never be recoverable from storage.
    connection = sqlite3.connect(tmp_path / "state" / "vysion-state.db")
    rows = connection.execute("SELECT token_hash FROM sessions").fetchall()
    connection.close()
    assert [row[0] for row in rows] == [StateStore.digest_token(raw)]
    assert raw not in rows[0][0]

    later = now + timedelta(seconds=601)
    expired = StateStore(tmp_path / "state", clock=fixed_clock(later))
    assert expired.resolve_session(raw) is None


def test_revoke_all_sessions_invalidates_every_session(tmp_path: Path) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    store = StateStore(tmp_path / "state", clock=fixed_clock(now))
    first, _ = store.create_session(ttl_seconds=600)
    second, _ = store.create_session(ttl_seconds=600)

    assert store.revoke_all_sessions() == 2
    assert store.resolve_session(first) is None
    assert store.resolve_session(second) is None


def test_password_change_bumps_the_revision_and_revokes_sessions(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    store = StateStore(tmp_path / "state", clock=fixed_clock(now))
    store.create_admin("first-password-123")
    before, _ = store.create_session(ttl_seconds=600)
    revision_before = store.admin_revision()

    assert store.set_password("second-password-456") is True
    assert store.verify_password("first-password-123") is False
    assert store.verify_password("second-password-456") is True
    assert store.admin_revision() != revision_before
    assert store.resolve_session(before) is None


def test_lockouts_track_account_and_client_scopes_independently(tmp_path: Path) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    store = StateStore(tmp_path / "state", clock=fixed_clock(now))

    for _ in range(4):
        assert store.register_failure("account:admin", threshold=5, lock_seconds=900) is None
    retry_after = store.register_failure("account:admin", threshold=5, lock_seconds=900)
    assert retry_after == 900
    assert store.lock_remaining("account:admin") == 900
    # A different scope stays usable.
    assert store.lock_remaining("client:198.51.100.7") is None

    # The lock is durable: reopening the store keeps it until it expires.
    still_locked = StateStore(tmp_path / "state", clock=fixed_clock(now))
    assert still_locked.lock_remaining("account:admin") == 900

    released = StateStore(tmp_path / "state", clock=fixed_clock(now + timedelta(seconds=901)))
    assert released.lock_remaining("account:admin") is None
    released.clear_failures("account:admin")
    # Counter cleared: the next failure starts from scratch instead of
    # immediately re-locking.
    assert released.register_failure("account:admin", threshold=5, lock_seconds=900) is None


def test_successful_login_clears_the_account_counter(tmp_path: Path) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    store = StateStore(tmp_path / "state", clock=fixed_clock(now))
    for _ in range(4):
        store.register_failure("account:admin", threshold=5, lock_seconds=900)
    store.clear_failures("account:admin")
    assert store.register_failure("account:admin", threshold=5, lock_seconds=900) is None


def test_recovery_tokens_are_hashed_single_use_and_bounded(tmp_path: Path) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    store = StateStore(tmp_path / "state", clock=fixed_clock(now))
    store.create_admin("a-valid-password-123")
    revision = store.admin_revision()

    raw = store.create_recovery_token(purpose="reset", ttl_seconds=900, revision=revision)
    connection = sqlite3.connect(tmp_path / "state" / "vysion-state.db")
    stored = connection.execute("SELECT digest FROM recovery_tokens").fetchall()
    connection.close()
    assert stored == [(StateStore.digest_token(raw),)]
    assert raw.encode() not in stored[0][0].encode()

    assert store.consume_recovery_token(raw, purpose="reset", revision=revision) is True
    # Single use: the second attempt fails even with the same revision.
    assert store.consume_recovery_token(raw, purpose="reset", revision=revision) is False

    other = store.create_recovery_token(purpose="reset", ttl_seconds=900, revision=revision)
    expired = StateStore(tmp_path / "state", clock=fixed_clock(now + timedelta(seconds=901)))
    assert expired.consume_recovery_token(other, purpose="reset", revision=revision) is False


def test_smtp_secret_is_stored_but_never_returned(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state")

    assert store.smtp_config() is None
    store.set_smtp_config(
        host="smtp.internal.example",
        port=587,
        from_address="vysion@internal.example",
        starttls=True,
        password="write-only-secret",
    )
    loaded = store.smtp_config()
    assert loaded is not None
    assert loaded.host == "smtp.internal.example"
    assert loaded.password == "write-only-secret"
    # The status projection exposed over HTTP carries no secret material.
    assert "password" not in loaded.public_status()
    assert "write-only-secret" not in str(loaded.public_status())

    store.clear_smtp_config()
    assert store.smtp_config() is None


def test_state_survives_a_reopen_as_after_a_container_recreate(tmp_path: Path) -> None:
    now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    state = tmp_path / "state"
    first = StateStore(state, clock=fixed_clock(now))
    first.create_admin("persisted-password-12")
    token, _ = first.create_session(ttl_seconds=600)
    first.set_smtp_config(
        host="smtp.internal.example",
        port=25,
        from_address="vysion@internal.example",
        starttls=False,
        password=None,
    )

    reopened = StateStore(state, clock=fixed_clock(now))
    assert reopened.has_admin() is True
    assert reopened.verify_password("persisted-password-12") is True
    assert reopened.resolve_session(token) is not None
    assert reopened.smtp_config() is not None
    assert reopened.schema_version() == StateStore.SCHEMA_VERSION

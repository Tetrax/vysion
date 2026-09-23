"""Durable email transport state: one row, two transports, write-only secrets.

The public projection must never carry a secret, a pre-existing schema-1
database must keep working, and switching transports must not leave the other
transport's material behind.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from vysion.state import DATABASE_NAME, StateError, StateStore


def _directory(tmp_path):
    return tmp_path / "vysion-state"


def test_email_config_is_absent_until_an_operator_saves_one(tmp_path):
    store = StateStore(_directory(tmp_path))
    assert store.email_config() is None
    status = store.email_public_status()
    assert status["configured"] is False
    assert status["transport"] is None
    assert status["provenance"] is None


def test_smtp_transport_round_trips_with_its_secret(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        recovery_email="ops@example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_security="starttls",
        smtp_username="vysion@example.com",
        smtp_password="smtp-secret",
    )
    loaded = StateStore(_directory(tmp_path)).email_config()
    assert loaded is not None
    assert loaded.transport == "smtp"
    assert loaded.smtp_host == "smtp.example.com"
    assert loaded.smtp_port == 587
    assert loaded.smtp_security == "starttls"
    assert loaded.smtp_username == "vysion@example.com"
    assert loaded.smtp_password == "smtp-secret"
    assert loaded.recovery_email == "ops@example.com"


def test_microsoft365_transport_round_trips_with_its_secret(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(
        transport="microsoft365",
        from_address="vysion@example.com",
        recovery_email="ops@example.com",
        m365_tenant_id="00000000-0000-4000-8000-000000000000",
        m365_client_id="11111111-1111-4111-8111-111111111111",
        m365_client_secret="graph-secret",
        m365_mailbox="vysion@example.com",
    )
    loaded = StateStore(_directory(tmp_path)).email_config()
    assert loaded is not None
    assert loaded.transport == "microsoft365"
    assert loaded.m365_tenant_id == "00000000-0000-4000-8000-000000000000"
    assert loaded.m365_client_id == "11111111-1111-4111-8111-111111111111"
    assert loaded.m365_client_secret == "graph-secret"
    assert loaded.m365_mailbox == "vysion@example.com"
    # The unused transport carries no material at all.
    assert loaded.smtp_host is None
    assert loaded.smtp_password is None


def test_switching_transport_drops_the_previous_transport_material(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_security="starttls",
        smtp_password="smtp-secret",
    )
    store.set_email_config(
        transport="microsoft365",
        from_address="vysion@example.com",
        m365_tenant_id="00000000-0000-4000-8000-000000000000",
        m365_client_id="11111111-1111-4111-8111-111111111111",
        m365_client_secret="graph-secret",
    )
    loaded = store.email_config()
    assert loaded is not None
    assert loaded.transport == "microsoft365"
    assert loaded.smtp_host is None
    assert loaded.smtp_password is None
    assert loaded.smtp_username is None


def test_public_status_never_carries_a_secret(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_email_config(
        transport="microsoft365",
        from_address="vysion@example.com",
        recovery_email="ops@example.com",
        m365_tenant_id="00000000-0000-4000-8000-000000000000",
        m365_client_id="11111111-1111-4111-8111-111111111111",
        m365_client_secret="graph-secret",
    )
    status = store.email_public_status()
    rendered = json.dumps(status)
    assert status["configured"] is True
    assert status["transport"] == "microsoft365"
    assert status["provenance"] == "state"
    assert status["secret_configured"] is True
    assert status["recovery_email_configured"] is True
    assert "graph-secret" not in rendered
    assert "secret" not in {
        key for key in status if key not in {"secret_configured"}
    } - {"secret_configured"}
    assert "client_secret" not in rendered
    assert "password" not in rendered


def test_a_pre_email_database_migrates_without_a_schema_bump(tmp_path):
    """A schema-1 database that predates the email table must keep working."""
    directory = _directory(tmp_path)
    store = StateStore(directory)
    store.set_smtp_config(
        host="smtp.example.com",
        port=587,
        from_address="vysion@example.com",
        starttls=True,
        username="vysion@example.com",
        password="legacy-secret",
        recovery_email="ops@example.com",
    )
    # Rebuild exactly the historical shape: smtp row, no email table.
    path = directory / DATABASE_NAME
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TABLE email")
        connection.execute("DELETE FROM smtp")
        connection.execute(
            """
            INSERT INTO smtp (
                id, host, port, from_address, starttls, username, password,
                recovery_email
            ) VALUES (1, 'smtp.example.com', 587, 'vysion@example.com', 1,
                      'vysion@example.com', 'legacy-secret', 'ops@example.com')
            """
        )
        connection.commit()
        # Prove the historical shape really has no email table yet.
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("SELECT 1 FROM email")
    finally:
        connection.close()

    reopened = StateStore(directory)
    assert reopened.schema_version() == 1
    migrated = reopened.email_config()
    assert migrated is not None
    assert migrated.transport == "smtp"
    assert migrated.smtp_host == "smtp.example.com"
    assert migrated.smtp_password == "legacy-secret"
    assert migrated.recovery_email == "ops@example.com"
    # The legacy accessor keeps answering for the migrated state.
    legacy = reopened.smtp_config()
    assert legacy is not None
    assert legacy.host == "smtp.example.com"
    assert legacy.password == "legacy-secret"


def test_the_migration_is_idempotent_across_reopens(tmp_path):
    directory = _directory(tmp_path)
    store = StateStore(directory)
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        smtp_host="smtp.example.com",
        smtp_port=2525,
        smtp_security="tls",
        smtp_password="first-secret",
    )
    for _ in range(3):
        reopened = StateStore(directory)
        loaded = reopened.email_config()
        assert loaded is not None
        assert loaded.smtp_host == "smtp.example.com"
        assert loaded.smtp_password == "first-secret"
        assert reopened.schema_version() == 1


def test_legacy_smtp_accessors_write_and_clear_the_email_row(tmp_path):
    store = StateStore(_directory(tmp_path))
    assert store.smtp_config() is None
    store.set_smtp_config(
        host="smtp.example.com",
        port=587,
        from_address="vysion@example.com",
        starttls=True,
        username="vysion@example.com",
        password="legacy-secret",
        recovery_email="ops@example.com",
    )
    config = store.email_config()
    assert config is not None
    assert config.transport == "smtp"
    assert config.smtp_security == "starttls"
    store.clear_smtp_config()
    assert store.smtp_config() is None
    assert store.email_config() is None


def test_passwordless_smtp_stays_explicitly_unencrypted(tmp_path):
    store = StateStore(_directory(tmp_path))
    store.set_smtp_config(
        host="localhost",
        port=25,
        from_address="vysion@example.com",
        starttls=False,
    )
    config = store.email_config()
    assert config is not None
    assert config.smtp_security == "none"
    legacy = store.smtp_config()
    assert legacy is not None
    assert legacy.starttls is False


def test_a_corrupt_email_row_fails_closed(tmp_path):
    directory = _directory(tmp_path)
    store = StateStore(directory)
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_security="starttls",
    )
    connection = sqlite3.connect(directory / DATABASE_NAME)
    try:
        connection.execute("UPDATE email SET smtp_port = 'not-a-port'")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises((StateError, ValueError)):
        StateStore(directory).email_config()

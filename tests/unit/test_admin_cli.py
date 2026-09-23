"""Break-glass CLI: status, first admin, password reset, SMTP settings.

Every secret travels through stdin, never through argv, and nothing is ever
printed back. This is the fallback when no recovery transport is configured.
"""

from __future__ import annotations

import io

import pytest

from vysion.admin_cli import main
from vysion.state import StateStore


def run(*args: str, stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(args), stdin=io.StringIO(stdin), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_status_reports_first_run_then_the_created_account(tmp_path) -> None:
    state = str(tmp_path / "state")

    code, out, err = run("status", "--state-dir", state)

    assert code == 0
    assert "setup_required=true" in out
    assert "admin=absent" in out
    assert err == ""

    code, out, err = run(
        "create-admin", "--state-dir", state, stdin="a-first-admin-password\n"
    )
    assert code == 0, err

    code, out, _ = run("status", "--state-dir", state)
    assert code == 0
    assert "setup_required=false" in out
    assert "admin=present" in out


def test_status_never_prints_a_secret(tmp_path) -> None:
    state = str(tmp_path / "state")
    run("create-admin", "--state-dir", state, stdin="a-first-admin-password\n")
    run(
        "configure-smtp",
        "--state-dir",
        state,
        "--host",
        "smtp.internal.example",
        "--port",
        "587",
        "--from",
        "vysion@internal.example",
        "--recovery-email",
        "operator@internal.example",
        stdin="write-only-secret\n",
    )

    _, out, _ = run("status", "--state-dir", state)

    assert "write-only-secret" not in out
    assert "smtp=configured" in out
    assert "recovery=enabled" in out


def test_create_admin_refuses_to_replace_an_existing_account(tmp_path) -> None:
    state = str(tmp_path / "state")
    run("create-admin", "--state-dir", state, stdin="a-first-admin-password\n")

    code, out, err = run("create-admin", "--state-dir", state, stdin="another-password\n")

    assert code != 0
    assert "admin=present" in err or "deja" in err
    store = StateStore(tmp_path / "state")
    assert store.verify_password("a-first-admin-password") is True


def test_reset_password_revokes_every_session(tmp_path) -> None:
    state = str(tmp_path / "state")
    run("create-admin", "--state-dir", state, stdin="a-first-admin-password\n")
    store = StateStore(tmp_path / "state")
    raw_token, _ = store.create_session(43_200)
    assert store.resolve_session(raw_token) is not None

    code, out, err = run(
        "reset-password", "--state-dir", state, stdin="a-brand-new-password\n"
    )

    assert code == 0, err
    # The command must report the sessions it actually killed, not a
    # trailing no-op revocation after set_password already deleted them.
    assert "sessions_revoquees=1" in out
    store = StateStore(tmp_path / "state")
    assert store.verify_password("a-first-admin-password") is False
    assert store.verify_password("a-brand-new-password") is True
    assert store.resolve_session(raw_token) is None


def test_reset_password_needs_an_existing_account(tmp_path) -> None:
    code, _, err = run(
        "reset-password", "--state-dir", str(tmp_path / "state"), stdin="a-password\n"
    )

    assert code != 0
    assert "setup" in err or "absent" in err


def test_break_glass_works_without_any_smtp_transport(tmp_path) -> None:
    state = str(tmp_path / "state")
    run("create-admin", "--state-dir", state, stdin="a-first-admin-password\n")

    _, out, _ = run("status", "--state-dir", state)
    assert "recovery=disabled" in out

    code, _, err = run(
        "reset-password", "--state-dir", state, stdin="a-brand-new-password\n"
    )
    assert code == 0, err


def test_weak_passwords_are_refused_and_change_nothing(tmp_path) -> None:
    state = str(tmp_path / "state")

    code, _, err = run("create-admin", "--state-dir", state, stdin="too-short\n")

    assert code != 0
    assert "12" in err
    store = StateStore(tmp_path / "state")
    assert store.has_admin() is False


def test_empty_stdin_is_refused(tmp_path) -> None:
    code, _, err = run(
        "create-admin", "--state-dir", str(tmp_path / "state"), stdin=""
    )

    assert code != 0
    assert "stdin" in err


@pytest.mark.parametrize("command", ["status", "create-admin", "reset-password"])
def test_missing_state_argument_is_a_usage_error(command: str) -> None:
    code, _, err = run(command)

    assert code == 2
    assert err

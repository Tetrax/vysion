"""Break-glass CLI: status, first admin, password reset, SMTP configuration.

Passwords and secrets are read from stdin only, never from argv: nothing
secret appears in a process listing, a shell history or an operations log.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path
from typing import TextIO

from vysion.security import MAX_PASSWORD_BYTES, MIN_PASSWORD_BYTES
from vysion.state import StateError, StateStore

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

PASSWORD_CONTRACT = (
    f"mot de passe refuse : {MIN_PASSWORD_BYTES} a {MAX_PASSWORD_BYTES} octets UTF-8"
)
MISSING_STATE_DIR = (
    "state directory required: pass --state-dir or set VYSION_STATE_DIRECTORY"
)


def _state_directory(explicit: str | None) -> Path:
    """Explicit argument, then the environment, never an implicit default."""
    if explicit:
        return Path(explicit)
    from_env = os.environ.get("VYSION_STATE_DIRECTORY")
    if from_env:
        return Path(from_env)
    raise ValueError(MISSING_STATE_DIR)


def _read_secret(stream: TextIO) -> str:
    """One secret from stdin; an empty line is a refusal, not a default."""
    value = stream.readline().rstrip("\r\n")
    if not value:
        raise ValueError("secret vide lu sur stdin")
    return value


def cmd_status(args: argparse.Namespace, stdin: TextIO) -> tuple[int, str]:
    store = StateStore(_state_directory(args.state_dir))
    smtp = store.smtp_config()
    email = store.email_config()
    has_admin = store.has_admin()
    lines = [
        f"setup_required={'false' if has_admin else 'true'}",
        f"admin={'present' if has_admin else 'absent'}",
        f"sessions={len(store.list_sessions())}",
        f"schema_version={store.schema_version()}",
        f"smtp={'configured' if smtp else 'unconfigured'}",
        f"email={email.transport if email else 'unconfigured'}",
        f"recovery={'enabled' if email and email.recovery_email else 'disabled'}",
    ]
    return EXIT_OK, "\n".join(lines) + "\n"


def cmd_create_admin(args: argparse.Namespace, stdin: TextIO) -> tuple[int, str]:
    store = StateStore(_state_directory(args.state_dir))
    if store.has_admin():
        return EXIT_FAILURE, "admin=present : creation refusee\n"
    try:
        secret = _read_secret(stdin)
        created = store.create_admin(secret)
    except ValueError as exc:
        detail = PASSWORD_CONTRACT if "password" in str(exc) else str(exc)
        return EXIT_FAILURE, f"refus : {detail}\n"
    if not created:
        return EXIT_FAILURE, "admin=present : creation refusee\n"
    return EXIT_OK, "admin=present setup_required=false\n"


def cmd_reset_password(args: argparse.Namespace, stdin: TextIO) -> tuple[int, str]:
    store = StateStore(_state_directory(args.state_dir))
    if not store.has_admin():
        return EXIT_FAILURE, "admin=absent : setup web requis\n"
    sessions_before = len(store.list_sessions())
    try:
        secret = _read_secret(stdin)
        store.set_password(secret)
    except ValueError as exc:
        detail = PASSWORD_CONTRACT if "password" in str(exc) else str(exc)
        return EXIT_FAILURE, f"refus : {detail}\n"
    # set_password already revokes every session inside the same command:
    # report what this command actually killed, then sweep anything a
    # racing request could have created in between.
    revoked = sessions_before - len(store.list_sessions())
    revoked += store.revoke_all_sessions()
    return EXIT_OK, f"mot de passe reinitialise, sessions_revoquees={revoked}\n"


def cmd_configure_smtp(args: argparse.Namespace, stdin: TextIO) -> tuple[int, str]:
    store = StateStore(_state_directory(args.state_dir))
    try:
        secret = _read_secret(stdin)
    except ValueError:
        secret = None  # passwordless SMTP stays a valid, explicit choice
    store.set_smtp_config(
        host=args.host,
        port=args.port,
        from_address=args.from_address,
        starttls=not args.no_starttls,
        username=args.username,
        password=secret,
        recovery_email=args.recovery_email,
    )
    return EXIT_OK, "smtp=configured\n"


COMMANDS = {
    "status": cmd_status,
    "create-admin": cmd_create_admin,
    "reset-password": cmd_reset_password,
    "configure-smtp": cmd_configure_smtp,
}


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    # Declared on every subcommand too (SUPPRESS so it never overwrites the
    # value given before the subcommand).
    common.add_argument("--state-dir", default=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(
        prog="vysion-admin",
        description="Vysion administration hors-ligne (secrets lus sur stdin).",
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="repertoire d'etat durable (defaut: $VYSION_STATE_DIRECTORY)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "status", parents=[common], help="etat du compte et de la configuration"
    )
    subparsers.add_parser(
        "create-admin",
        parents=[common],
        help="creer le premier administrateur (si aucun n'existe)",
    )
    subparsers.add_parser(
        "reset-password",
        parents=[common],
        help="reinitialiser le mot de passe et revoker les sessions",
    )
    configure = subparsers.add_parser(
        "configure-smtp",
        parents=[common],
        help="configurer le transport de recuperation",
    )
    configure.add_argument("--host", required=True)
    configure.add_argument("--port", type=int, default=587)
    configure.add_argument("--from", dest="from_address", required=True)
    configure.add_argument("--username", default=None)
    configure.add_argument("--recovery-email", default=None)
    configure.add_argument("--no-starttls", action="store_true")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Testable entry point; production reads/writes the real std streams."""
    stdin = sys.stdin if stdin is None else stdin
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    parser = build_parser()
    try:
        # argparse reports its own usage errors on stderr.
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as exc:
        return int(exc.code or EXIT_USAGE)
    try:
        code, message = COMMANDS[args.command](args, stdin)
    except ValueError as exc:
        print(str(exc), file=err)
        return EXIT_USAGE
    except StateError as exc:
        print(f"etat indisponible : {exc}", file=err)
        return EXIT_FAILURE
    print(message, end="", file=out if code == EXIT_OK else err)
    return code


def cli() -> None:  # pragma: no cover - console script entry point
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover
    cli()

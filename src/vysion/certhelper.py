"""Root certificate helper: the single authority for served TLS material.

In ``helper`` mode the container is non-root and cannot touch
``/etc/letsencrypt`` or reload the host's nginx. It therefore asks this
service — running as root on the host — over a private Unix socket.

Design rules, mirrored from the proven Hub and FortiUpgrade helpers:

* the socket is ``0660 root:<container gid>`` inside a ``0750`` directory,
  and every connection is checked with ``SO_PEERCRED`` (uid **and** gid);
* only four actions exist, each with one exact shape: no path, no lineage
  and no shell command can ever arrive over the socket;
* validation, immutable generations and the atomic ``active`` pointer are the
  very same :mod:`vysion.certificates` engine the ``local`` mode uses — one
  implementation, one authority;
* ``nginx -t`` runs strictly before any reload, and the fingerprint that is
  actually served is read back, with an automatic rollback on any mismatch;
* the Certbot lineage is imported through that same mechanism, so Certbot
  stays the ACME authority while the generations stay the serving authority.

Nothing in this module ever returns or logs key material.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from vysion.certclient import CertificateHelperClient
from vysion.certificates import (
    CertificateError,
    CertificateStore,
    activate_staged,
    certificate_status_payload,
    tls_fingerprint_smoker,
)
from vysion.certprotocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    expect_action,
    expect_version,
    receive_message,
    send_message,
)
from vysion.clocks import utc_now

DEFAULT_SOCKET = "/run/vysion-cert-helper/helper.sock"
DEFAULT_CERTS_DIRECTORY = "/var/lib/vysion/certificates"
DEFAULT_STAGING_TTL_SECONDS = 600
# Certbot's own layout: only a directory named ``live`` may be imported, so a
# forged path can never be promoted into a generation.
CERTBOT_LIVE_PARENT = "live"
# First choice reloads through systemd, second choice asks the master
# directly: whichever exists wins, but ``nginx -t`` has already passed.
NGINX_RELOAD_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("systemctl", "reload", "nginx"),
    ("nginx", "-s", "reload"),
)

VALIDATE_FIELDS = {
    "v",
    "action",
    "certificate",
    "private_key",
    "passphrase",
    "hostname",
}
ACTIVATE_FIELDS = {"v", "action", "digest"}
TWO_FIELDS = {"v", "action"}

PEER_REFUSAL = "pair non autorise"
UNEXPECTED_ACTION = "action inconnue"
UNEXPECTED_HOSTNAME = "hostname inattendu pour ce service"
BAD_DIGEST = "digest de candidat invalide"
INTERNAL_FAILURE = "operation impossible"


def _peer_allowed(uid: int, gid: int, *, allowed_uid: int, allowed_gid: int) -> bool:
    """Only the container itself — or root, which owns this service — connects."""
    if uid == 0:
        return True
    return uid == allowed_uid and gid == allowed_gid


def _execute(command: Sequence[str]) -> tuple[int, str]:
    """Run one command; returns its exit code and a bounded, loggable tail."""
    environment = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        result = subprocess.run([*command], capture_output=True, timeout=30, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc:  # noqa: PERF203 - one attempt
        return -1, str(exc)
    detail = (result.stderr + result.stdout).decode("utf-8", "replace")
    return int(result.returncode), detail[-400:]


def host_nginx_reloader() -> None:
    """``nginx -t`` strictly first, then a reload — never the other way round."""
    code, detail = _execute(("nginx", "-t"))
    if code != 0:
        raise CertificateError(f"nginx -t a echoue : {detail.strip()}")
    for command in NGINX_RELOAD_COMMANDS:
        code, detail = _execute(command)
        if code == 0:
            return
    raise CertificateError(f"rechargement de nginx impossible : {detail.strip()}")


class VysionCertHelper:
    """Answers the four certificate actions over one private Unix socket."""

    def __init__(
        self,
        *,
        socket_path: str | Path,
        certs_directory: str | Path,
        allowed_uid: int,
        allowed_gid: int,
        hostname: str,
        reloader: Any = None,
        smoker: Any = None,
        staging_ttl_seconds: int = DEFAULT_STAGING_TTL_SECONDS,
        clock=utc_now,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.certs_directory = Path(certs_directory)
        self._allowed_uid = int(allowed_uid)
        self._allowed_gid = int(allowed_gid)
        self._hostname = hostname.strip().lower()
        self._ttl = int(staging_ttl_seconds)
        self._listener: socket.socket | None = None
        self._closed = False
        self.store = CertificateStore(self.certs_directory, clock=clock)
        self.reloader = reloader if reloader is not None else host_nginx_reloader
        self.smoker = (
            smoker if smoker is not None else tls_fingerprint_smoker(self._hostname)
        )

    # ------------------------------------------------------------------
    # socket lifecycle
    # ------------------------------------------------------------------
    def open_socket(self) -> None:
        directory = self.socket_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        # Explicit chmod: the process umask (the state store tightens it to
        # 0077) must not decide how private the socket ends up being.
        os.chmod(directory, 0o750)
        with contextlib.suppress(FileNotFoundError, NotADirectoryError):
            self.socket_path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
        except OSError:
            listener.close()
            raise
        os.chmod(self.socket_path, 0o660)
        if os.geteuid() == 0:
            os.chown(directory, 0, self._allowed_gid)
            os.chown(self.socket_path, 0, self._allowed_gid)
        listener.listen(16)
        self._listener = listener
        self._closed = False

    def close(self) -> None:
        self._closed = True
        if self._listener is not None:
            with contextlib.suppress(OSError):
                self._listener.close()
            self._listener = None
        with contextlib.suppress(OSError, FileNotFoundError):
            self.socket_path.unlink()

    def serve_forever(self) -> None:
        while not self._closed and self._listener is not None:
            try:
                connection, _peer = self._listener.accept()
            except OSError:
                return
            with connection, contextlib.suppress(Exception):
                self.handle_connection(connection)

    # ------------------------------------------------------------------
    # one connection
    # ------------------------------------------------------------------
    def _peer_ok(self, connection: socket.socket) -> bool:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        # struct ucred is {pid, uid, gid} — the pid leads.
        _pid, uid, gid = struct.unpack("3i", raw)
        return _peer_allowed(
            uid, gid, allowed_uid=self._allowed_uid, allowed_gid=self._allowed_gid
        )

    def handle_connection(self, connection: socket.socket) -> None:
        if not self._peer_ok(connection):
            self._send(
                connection,
                {"ok": False, "kind": "protocol", "error": PEER_REFUSAL},
            )
            return
        try:
            message = receive_message(
                connection, max_bytes=MAX_REQUEST_BYTES, timeout=10.0
            )
        except (ProtocolError, OSError):
            return
        self._send(connection, self.answer(message))

    def _send(self, connection: socket.socket, response: dict[str, Any]) -> None:
        with contextlib.suppress(ProtocolError, OSError):
            send_message(
                connection,
                response,
                max_bytes=MAX_RESPONSE_BYTES,
                timeout=10.0,
            )

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    @staticmethod
    def _validated_action(message: dict[str, Any]) -> str:
        expect_version(message)
        action = message.get("action")
        if action == "ping":
            expect_action(message, "ping", TWO_FIELDS)
        elif action == "status":
            expect_action(message, "status", TWO_FIELDS)
        elif action == "validate":
            expect_action(message, "validate", VALIDATE_FIELDS)
        elif action == "activate":
            expect_action(message, "activate", ACTIVATE_FIELDS)
        else:
            raise ProtocolError(UNEXPECTED_ACTION)
        return str(action)

    def answer(self, message: dict[str, Any]) -> dict[str, Any]:
        """Dispatch one already-framed request; never leaks an internal detail."""
        try:
            self._purge_stale_staging()
            action = self._validated_action(message)
            if action == "ping":
                return {"ok": True, "version": PROTOCOL_VERSION}
            if action == "status":
                return {
                    "ok": True,
                    **certificate_status_payload(self.store),
                    "staged_digest": self.store.staged_digest(),
                }
            if action == "validate":
                return self._validate(message)
            return self._activate(message)
        except ProtocolError as exc:
            # Fixed wording only: the peer's own payload is never echoed.
            return {"ok": False, "kind": "protocol", "error": str(exc)}
        except CertificateError as exc:
            # Operator-facing validation and reload diagnostics, never a key.
            return {"ok": False, "kind": "certificate", "error": str(exc)}
        except Exception:  # noqa: BLE001 - reported, never surfaced verbatim
            return {"ok": False, "kind": "unavailable", "error": INTERNAL_FAILURE}

    @staticmethod
    def _field(message: dict[str, Any], name: str) -> Any:
        if name not in message:
            raise ProtocolError(UNEXPECTED_ACTION)
        return message.get(name)

    def _validate(self, message: dict[str, Any]) -> dict[str, Any]:
        hostname = self._field(message, "hostname")
        if not isinstance(hostname, str) or hostname.strip().lower() != self._hostname:
            raise ProtocolError(UNEXPECTED_HOSTNAME)
        certificate = self._b64(message, "certificate")
        raw_key = self._field(message, "private_key")
        private_key = None if raw_key is None else self._b64(message, "private_key")
        passphrase = self._field(message, "passphrase")
        if passphrase is not None and not isinstance(passphrase, str):
            raise ProtocolError("passphrase invalide")
        metadata = self.store.validate(
            certificate=certificate,
            private_key=private_key,
            hostname=self._hostname,
            passphrase=passphrase,
        )
        digest = self.store.staged_digest()
        if not digest:  # pragma: no cover - validate always stages
            raise CertificateError("staging du candidat impossible")
        return {"ok": True, "certificate": metadata.as_dict(), "digest": digest}

    @staticmethod
    def _b64(message: dict[str, Any], name: str) -> bytes:
        value = message.get(name)
        if not isinstance(value, str):
            raise ProtocolError("champ de certificat invalide")
        try:
            return base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as exc:
            raise ProtocolError("champ de certificat invalide") from exc

    def _activate(self, message: dict[str, Any]) -> dict[str, Any]:
        digest = self._field(message, "digest")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ProtocolError(BAD_DIGEST)
        # The helper re-reads the staging itself: a candidate replaced or
        # expired between validation and activation can never be promoted.
        if self.store.staged_digest() != digest:
            raise CertificateError("le candidat en staging a change ou a expire")
        generation, served = activate_staged(
            self.store, reloader=self.reloader, smoker=self.smoker
        )
        return {
            "ok": True,
            "generation": generation.number,
            "certificate": generation.metadata.as_dict(),
            "served_sha256": served,
        }

    def _purge_stale_staging(self) -> None:
        staging = self.certs_directory / "staging"
        try:
            age = time.time() - staging.stat().st_mtime
        except OSError:
            return
        if age > self._ttl:
            shutil.rmtree(staging, ignore_errors=True)


# ---------------------------------------------------------------------------
# command line: ping, status, install, renew, serve
# ---------------------------------------------------------------------------
def _import_lineage(
    store: CertificateStore,
    *,
    lineage: Path,
    hostname: str,
    reloader: Any,
    smoker: Any,
) -> int:
    """Promote a Certbot lineage through the same mechanism the UI uses.

    Idempotent by construction: if the lineage already is the served
    certificate, staging is dropped and nothing is activated, so a repeated
    deploy hook never stacks generations.
    """
    try:
        certificate = (lineage / "fullchain.pem").read_bytes()
        private_key = (lineage / "privkey.pem").read_bytes()
    except OSError as exc:
        raise CertificateError(f"lineage illisible : {exc}") from exc
    metadata = store.validate(
        certificate=certificate,
        private_key=private_key,
        hostname=hostname,
        passphrase=None,
    )
    active = store.active()
    if active is not None and active.metadata.sha256 == metadata.sha256:
        store.discard_staged()
        print("deja servie : aucune generation creee")
        return 0
    generation, served = activate_staged(
        store, reloader=reloader, smoker=smoker
    )
    print(f"generation={generation.number} served_sha256={served}")
    return 0


def _lineage_directory(value: str | None) -> Path:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("lineage requis (--lineage ou $RENEWED_LINEAGE)")
    path = Path(raw)
    # Only Certbot's own layout may be imported: an arbitrary directory can
    # never be promoted into a served generation.
    if path.parent.name != CERTBOT_LIVE_PARENT:
        raise ValueError("lineage hors de l'arborescence live de certbot")
    return path


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--socket", default=DEFAULT_SOCKET)
    common.add_argument("--certs-dir", default=DEFAULT_CERTS_DIRECTORY)
    common.add_argument("--hostname", default=os.environ.get("VYSION_TLS_HOSTNAME", ""))
    parser = argparse.ArgumentParser(
        prog="vysion-cert-helper",
        description="Helper TLS racine Vysion (aucun secret en ligne de commande).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve", parents=[common], help="servir la socket")
    serve.add_argument("--uid", type=int, default=int(os.environ.get("VYSION_PUID", "0")))
    serve.add_argument("--gid", type=int, default=int(os.environ.get("VYSION_PGID", "0")))
    serve.add_argument("--staging-ttl", type=int, default=DEFAULT_STAGING_TTL_SECONDS)
    subparsers.add_parser("ping", parents=[common], help="verifier la socket")
    subparsers.add_parser("status", parents=[common], help="lire l'etat des certificats")
    for name, help_text in (
        ("install", "importer le lineage actuel (bootstrap idempotent)"),
        ("renew", "reimporter le lineage renouvele (deploy hook idempotent)"),
    ):
        command = subparsers.add_parser(name, parents=[common], help=help_text)
        command.add_argument("--lineage", default=None)
    return parser


def main(
    argv: list[str] | None = None,
    *,
    reloader: Any = None,
    smoker: Any = None,
) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    reload_hook = reloader if reloader is not None else host_nginx_reloader
    try:
        if args.command == "serve":
            helper = VysionCertHelper(
                socket_path=args.socket,
                certs_directory=args.certs_dir,
                allowed_uid=args.uid,
                allowed_gid=args.gid,
                hostname=args.hostname,
                reloader=reload_hook,
                staging_ttl_seconds=args.staging_ttl,
            )
            helper.open_socket()
            print(f"socket={helper.socket_path}")
            try:
                helper.serve_forever()
            except KeyboardInterrupt:  # pragma: no cover - interactive
                helper.close()
            return 0
        if args.command in {"ping", "status"}:
            client = CertificateHelperClient(args.socket, timeout=10.0)
            if args.command == "ping":
                client.ping()
                print("ok")
            else:
                print(client.status())
            return 0
        hostname = (args.hostname or "").strip().lower()
        if not hostname:
            raise ValueError("hostname requis (--hostname ou $VYSION_TLS_HOSTNAME)")
        lineage = _lineage_directory(args.lineage or os.environ.get("RENEWED_LINEAGE"))
        store = CertificateStore(args.certs_dir)
        smoke = (
            smoker
            if smoker is not None
            else tls_fingerprint_smoker(hostname)
        )
        return _import_lineage(
            store, lineage=lineage, hostname=hostname, reloader=reload_hook, smoker=smoke
        )
    except (CertificateError, ValueError) as exc:
        print(f"refus : {exc}", file=sys.stderr)
        return 1


def cli() -> None:  # pragma: no cover - console script entry point
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover
    cli()

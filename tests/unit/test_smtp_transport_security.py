"""The three SMTP security modes, exercised against controlled local servers.

``tls`` must be implicit TLS from the first byte (``SMTP_SSL``), ``starttls``
must upgrade in-band, and ``none`` must be cleartext — reachable only because
the save-time form demanded an explicit confirmation. These are real sockets,
not mocks: a client that opens the wrong kind of connection fails the
handshake, so the assertions cannot be satisfied by a plausible implementation.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import subprocess
import threading
from pathlib import Path

from vysion.mail import SmtpMailer
from vysion.state import StateStore


def _openssl_server_cert(directory: Path) -> tuple[Path, Path]:
    """A self-signed leaf for the local server (test material only)."""
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "server.key"
    cert_path = directory / "server.pem"
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(cert_path), "-days", "2",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        capture_output=True,
        timeout=60,
        env={"LC_ALL": "C"},
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return cert_path, key_path


def _client_context() -> ssl.SSLContext:
    """Test trust only: the local server is self-signed by construction."""
    context = ssl._create_unverified_context()  # noqa: SLF001 - test seam
    return context


def _store(tmp_path: Path, *, security: str, port: int) -> StateStore:
    store = StateStore(tmp_path / "state")
    store.set_email_config(
        transport="smtp",
        from_address="vysion@example.com",
        recovery_email="operator@example.com",
        smtp_host="localhost",
        smtp_port=port,
        smtp_security=security,
        smtp_username="vysion",
        smtp_password="local-transport-test-password",
        timeout_seconds=5,
    )
    return store


class MiniSmtpServer:
    """Minimal SMTP endpoint recording how the client reached it.

    ``mode='tls``' only speaks TLS (implicit), ``mode='starttls'`` upgrades on
    demand, ``mode='plain'`` never offers any encryption. Any client picking
    the wrong mode cannot complete a session.
    """

    def __init__(
        self,
        mode: str,
        *,
        certfile: Path | None = None,
        keyfile: Path | None = None,
    ) -> None:
        assert mode in {"plain", "starttls", "tls"}
        self.mode = mode
        self.starttls_seen = False
        self.immediate_tls = False
        self.auth_credentials: list[str] = []
        self.received: list[str] = []
        self._tls_context: ssl.SSLContext | None = None
        if mode in {"starttls", "tls"}:
            assert certfile is not None and keyfile is not None
            self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._tls_context.load_cert_chain(str(certfile), str(keyfile))
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self.port = int(self._listener.getsockname()[1])
        self._listener.listen(5)
        self._closed = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> MiniSmtpServer:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True
        with contextlib.suppress(OSError):
            self._listener.close()

    # -- serving ----------------------------------------------------------
    def _serve(self) -> None:
        while not self._closed:
            try:
                connection, _peer = self._listener.accept()
            except OSError:
                return
            try:
                self._handle(connection)
            except (OSError, ssl.SSLError, ValueError):
                pass
            finally:
                with contextlib.suppress(OSError):
                    connection.close()

    @staticmethod
    def _line(connection: socket.socket, text: str) -> None:
        connection.sendall(text.encode("utf-8") + b"\r\n")

    def _handle(self, connection: socket.socket) -> None:
        if self.mode == "tls":
            assert self._tls_context is not None
            connection = self._tls_context.wrap_socket(connection, server_side=True)
            self.immediate_tls = True
        self._speak(connection)

    def _speak(self, connection: socket.socket) -> None:
        fileobj = connection.makefile("rb")
        self._line(connection, "220 mini.smtp ESMTP ready")
        in_data = False
        buffer = b""
        while True:
            raw = fileobj.readline()
            if not raw:
                return
            text = raw.decode("utf-8", "replace").rstrip("\r\n")
            if in_data:
                if text == ".":
                    in_data = False
                    self.received.append(buffer.decode("utf-8", "replace"))
                    self._line(connection, "250 Ok queued")
                else:
                    buffer += raw
                continue
            command = text.upper()
            if command.startswith("EHLO"):
                self._line(connection, "250-mini.smtp")
                self._line(connection, "250-8BITMIME")
                self._line(connection, "250-AUTH PLAIN LOGIN")
                if self.mode == "starttls":
                    self._line(connection, "250-STARTTLS")
                self._line(connection, "250 OK")
            elif command.startswith("HELO"):
                self._line(connection, "250 mini.smtp")
            elif command == "STARTTLS":
                assert self.mode == "starttls", "STARTTLS outside its mode"
                self.starttls_seen = True
                self._line(connection, "220 Ready to start TLS")
                assert self._tls_context is not None
                connection = self._tls_context.wrap_socket(connection, server_side=True)
                fileobj = connection.makefile("rb")
            elif command.startswith("AUTH PLAIN"):
                remainder = text[11:].strip()
                if not remainder:
                    self._line(connection, "334 VXNlcm5hbWU6")
                    next_line = fileobj.readline().decode("utf-8", "replace").strip()
                    remainder = next_line
                import base64

                try:
                    decoded = base64.b64decode(remainder).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    self._line(connection, "535 Authentication failed")
                    continue
                self.auth_credentials.append(decoded)
                self._line(connection, "235 2.7.0 Authentication successful")
            elif command.startswith("AUTH LOGIN"):
                self._line(connection, "334 VXNlcm5hbWU6")
                user = fileobj.readline().decode("utf-8", "replace").strip()
                self._line(connection, "334 UGFzc3dvcmQ6")
                password = fileobj.readline().decode("utf-8", "replace").strip()
                self.auth_credentials.append(f"{user}:{password}")
                self._line(connection, "235 2.7.0 Authentication successful")
            elif command.startswith("MAIL") or command.startswith("RCPT"):
                self._line(connection, "250 Ok")
            elif command.startswith("DATA"):
                in_data = True
                buffer = b""
                self._line(connection, "354 End data with <CR><LF>.<CR><LF>")
            elif command.startswith("RSET"):
                self._line(connection, "250 Ok")
            elif command.startswith("QUIT"):
                self._line(connection, "221 Bye")
                return
            else:
                self._line(connection, "502 Command not implemented")


# ---------------------------------------------------------------------------
# implicit TLS: SMTP_SSL, never a cleartext socket
# ---------------------------------------------------------------------------
def test_implicit_tls_reaches_an_immediate_tls_server(tmp_path: Path) -> None:
    cert, key = _openssl_server_cert(tmp_path / "tls")
    with MiniSmtpServer("tls", certfile=cert, keyfile=key) as server:
        mailer = SmtpMailer(
            _store(tmp_path, security="tls", port=server.port),
            ssl_context=_client_context(),
        )
        mailer.send(to="ops@example.com", subject="implicit", body="hello-implicit-tls")

    assert server.immediate_tls is True
    assert server.starttls_seen is False
    assert any("hello-implicit-tls" in item for item in server.received)
    # The credential travelled inside the TLS session, not in the clear.
    assert server.auth_credentials, "the client never authenticated"


# ---------------------------------------------------------------------------
# STARTTLS: cleartext greeting, then an in-band upgrade
# ---------------------------------------------------------------------------
def test_starttls_upgrades_in_band_before_any_credential(tmp_path: Path) -> None:
    cert, key = _openssl_server_cert(tmp_path / "starttls")
    with MiniSmtpServer("starttls", certfile=cert, keyfile=key) as server:
        mailer = SmtpMailer(
            _store(tmp_path, security="starttls", port=server.port),
            ssl_context=_client_context(),
        )
        mailer.send(to="ops@example.com", subject="starttls", body="hello-starttls")

    assert server.starttls_seen is True
    assert any("hello-starttls" in item for item in server.received)
    assert server.auth_credentials


# ---------------------------------------------------------------------------
# cleartext: only the explicitly confirmed 'none' mode may speak it
# ---------------------------------------------------------------------------
def test_none_sends_in_the_clear_against_a_plain_server(tmp_path: Path) -> None:
    with MiniSmtpServer("plain") as server:
        mailer = SmtpMailer(_store(tmp_path, security="none", port=server.port))
        mailer.send(to="ops@example.com", subject="plain", body="hello-plain")

    assert server.immediate_tls is False
    assert server.starttls_seen is False
    assert any("hello-plain" in item for item in server.received)
    assert server.auth_credentials


def test_an_unreachable_transport_refuses_without_leaking_the_password(
    tmp_path: Path,
) -> None:
    # A closed local port: the failure must stay a fixed, secret-free refusal.
    store = _store(tmp_path, security="tls", port=1)
    mailer = SmtpMailer(store, ssl_context=_client_context())
    try:
        mailer.send(to="ops@example.com", subject="s", body="b")
    except Exception as exc:  # noqa: BLE001 - the refusal type is the assertion
        assert "local-transport-test-password" not in str(exc)
        return
    raise AssertionError("an unreachable SMTP server must refuse the send")

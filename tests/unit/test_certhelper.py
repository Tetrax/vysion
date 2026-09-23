"""The root certificate helper: peer check, bounded actions, one authority.

Everything an administrator does in ``helper`` mode ends up here: the
container only asks, this service owns the material, runs ``nginx -t``
before every reload and verifies the fingerprint that is actually served.
"""

from __future__ import annotations

import base64
import os
import stat
import subprocess
import threading
import time
from pathlib import Path

import pytest

from vysion.certclient import CertificateHelperClient, CertificateHelperUnavailable
from vysion.certhelper import (
    NGINX_RELOAD_COMMANDS,
    VysionCertHelper,
    _peer_allowed,
    host_nginx_reloader,
    main,
)
from vysion.certificates import CertificateError
from vysion.certprotocol import PROTOCOL_VERSION, send_message

HOSTNAME = "vysion.example"


def openssl(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["openssl", *args], cwd=cwd, capture_output=True, timeout=60, env={"LC_ALL": "C"}
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return result


def make_certificate(directory: Path, *, hostname: str = HOSTNAME) -> tuple[bytes, bytes]:
    key_path = directory / "leaf.key"
    cert_path = directory / "leaf.pem"
    openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key_path), "-out", str(cert_path), "-days", "30",
        "-subj", f"/CN={hostname}",
        "-addext", f"subjectAltName=DNS:{hostname}",
        cwd=directory,
    )  # fmt: skip
    return cert_path.read_bytes(), key_path.read_bytes()


class Recorder:
    """Stands in for nginx: records reloads, can fail on demand."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[str] = []
        self.fail = fail

    def reloader(self) -> None:
        self.calls.append("reload")
        if self.fail:
            raise CertificateError("nginx -t a échoué")


def build_helper(tmp_path: Path, **overrides) -> tuple[VysionCertHelper, Recorder]:
    recorder = Recorder()
    values = {
        "socket_path": tmp_path / "run" / "helper.sock",
        "certs_directory": tmp_path / "certs",
        "allowed_uid": os.getuid(),
        "allowed_gid": os.getgid(),
        "hostname": HOSTNAME,
        "reloader": recorder.reloader,
        "staging_ttl_seconds": 600,
    }
    values.update(overrides)
    helper = VysionCertHelper(**values)
    helper.open_socket()
    return helper, recorder


def start(helper: VysionCertHelper) -> threading.Thread:
    thread = threading.Thread(target=helper.serve_forever, daemon=True)
    thread.start()
    return thread


def client(helper: VysionCertHelper) -> CertificateHelperClient:
    return CertificateHelperClient(helper.socket_path, timeout=5.0)


def raw(helper: VysionCertHelper, message: dict) -> dict:
    """Speak the protocol directly, bypassing the well-behaved client."""
    import socket as socket_module

    connection = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    connection.settimeout(5.0)
    try:
        connection.connect(str(helper.socket_path))
        send_message(connection, message, timeout=5.0)
        from vysion.certprotocol import receive_message

        return receive_message(connection, timeout=5.0)
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# peer verification
# ---------------------------------------------------------------------------
def test_only_the_helper_owner_and_root_may_talk_to_the_socket() -> None:
    assert _peer_allowed(0, 0, allowed_uid=10001, allowed_gid=10001) is True
    assert _peer_allowed(10001, 10001, allowed_uid=10001, allowed_gid=10001) is True
    # Right uid, wrong group: refused.
    assert _peer_allowed(10001, 10005, allowed_uid=10001, allowed_gid=10001) is False
    # Right group, wrong uid: refused.
    assert _peer_allowed(10005, 10001, allowed_uid=10001, allowed_gid=10001) is False
    assert _peer_allowed(10005, 10005, allowed_uid=10001, allowed_gid=10001) is False


def test_the_socket_directory_and_socket_are_group_private(tmp_path: Path) -> None:
    helper, _recorder = build_helper(tmp_path)
    try:
        directory = helper.socket_path.parent
        assert stat.S_IMODE(directory.stat().st_mode) == 0o750
        assert stat.S_IMODE(helper.socket_path.stat().st_mode) == 0o660
    finally:
        helper.close()


# ---------------------------------------------------------------------------
# actions
# ---------------------------------------------------------------------------
def test_ping_answers_the_protocol_version(tmp_path: Path) -> None:
    helper, _recorder = build_helper(tmp_path)
    start(helper)
    try:
        client(helper).ping()
    finally:
        helper.close()


def test_status_reports_the_store_and_the_staged_digest(tmp_path: Path) -> None:
    helper, _recorder = build_helper(tmp_path)
    start(helper)
    try:
        cert, key = make_certificate(tmp_path)
        helper.store.validate(
            certificate=cert, private_key=key, hostname=HOSTNAME, passphrase=None
        )
        status = client(helper).status()
    finally:
        helper.close()

    assert status["active"] is None
    assert status["staging"]["hostname"] == HOSTNAME
    assert len(status["staged_digest"]) == 64


def test_validate_stages_and_returns_metadata_only(tmp_path: Path) -> None:
    helper, _recorder = build_helper(tmp_path)
    start(helper)
    try:
        cert, key = make_certificate(tmp_path)
        metadata, digest = client(helper).validate(
            certificate=cert, private_key=key, hostname=HOSTNAME, passphrase=None
        )
    finally:
        helper.close()

    assert metadata.hostname == HOSTNAME
    assert len(digest) == 64
    # Nothing private ever crosses the socket.
    private_dir = helper.certs_directory / "staging"
    assert private_dir.is_dir()
    staged_key = (private_dir / "key.pem").read_bytes()
    assert b"PRIVATE" in staged_key  # it stays on the helper's own volume


def test_validate_refuses_a_foreign_hostname(tmp_path: Path) -> None:
    helper, _recorder = build_helper(tmp_path)
    start(helper)
    try:
        cert, key = make_certificate(tmp_path, hostname="other.example")
        with pytest.raises(CertificateError) as caught:
            client(helper).validate(
                certificate=cert, private_key=key, hostname=HOSTNAME, passphrase=None
            )
    finally:
        helper.close()
    assert "SAN" in str(caught.value)


def test_activation_promotes_and_reports_the_served_fingerprint(tmp_path: Path) -> None:
    helper, recorder = build_helper(tmp_path)
    # The smoker answers with what nginx really serves: the promoted cert.
    helper.smoker = lambda: helper.store.active().metadata.sha256  # type: ignore[method-assign]
    start(helper)
    try:
        cert, key = make_certificate(tmp_path)
        _metadata, digest = client(helper).validate(
            certificate=cert, private_key=key, hostname=HOSTNAME, passphrase=None
        )
        generation, certificate, served = client(helper).activate(digest)
        status = client(helper).status()
    finally:
        helper.close()

    assert generation == 1
    assert served == certificate["sha256"]
    assert recorder.calls == ["reload"]
    assert status["active"]["number"] == 1
    assert status["staging"] is None
    assert status["staged_digest"] is None


def test_activation_refuses_a_digest_that_is_no_longer_staged(
    tmp_path: Path,
) -> None:
    helper, recorder = build_helper(tmp_path)
    start(helper)
    try:
        cert, key = make_certificate(tmp_path)
        _metadata, digest = client(helper).validate(
            certificate=cert, private_key=key, hostname=HOSTNAME, passphrase=None
        )
        # Someone edits the staged files after validation.
        staged_key = helper.certs_directory / "staging" / "key.pem"
        staged_key.write_bytes(staged_key.read_bytes() + b"\n# tampered\n")
        with pytest.raises(CertificateError):
            client(helper).activate(digest)
    finally:
        helper.close()

    assert recorder.calls == []
    assert helper.store.active() is None


def test_activation_refuses_an_unknown_digest(tmp_path: Path) -> None:
    helper, _recorder = build_helper(tmp_path)
    start(helper)
    try:
        cert, key = make_certificate(tmp_path)
        client(helper).validate(
            certificate=cert, private_key=key, hostname=HOSTNAME, passphrase=None
        )
        with pytest.raises(CertificateError):
            client(helper).activate("f" * 64)
    finally:
        helper.close()
    assert helper.store.active() is None


def test_activation_failure_rolls_back_and_reports_it(tmp_path: Path) -> None:
    helper, recorder = build_helper(tmp_path)
    recorder.fail = True
    helper.smoker = lambda: "unused"  # type: ignore[method-assign]
    start(helper)
    try:
        cert, key = make_certificate(tmp_path)
        _metadata, digest = client(helper).validate(
            certificate=cert, private_key=key, hostname=HOSTNAME, passphrase=None
        )
        with pytest.raises(CertificateError) as caught:
            client(helper).activate(digest)
    finally:
        helper.close()

    assert "rollback" in str(caught.value)
    assert helper.store.active() is None


def test_a_stale_staging_is_purged_after_the_ttl(tmp_path: Path) -> None:
    helper, _recorder = build_helper(tmp_path, staging_ttl_seconds=1)
    start(helper)
    try:
        cert, key = make_certificate(tmp_path)
        client(helper).validate(
            certificate=cert, private_key=key, hostname=HOSTNAME, passphrase=None
        )
        staging = helper.certs_directory / "staging"
        assert staging.is_dir()
        # Backdate the candidate beyond the TTL.
        stale = time.time() - 60
        os.utime(staging, (stale, stale))
        status = client(helper).status()
    finally:
        helper.close()

    assert status["staged_digest"] is None
    assert status["staging"] is None
    assert not staging.exists()


# ---------------------------------------------------------------------------
# strict shapes: nothing but the four actions, nothing but their fields
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "message",
    [
        {"v": 99, "action": "ping"},
        {"v": PROTOCOL_VERSION, "action": "install"},
        {"v": PROTOCOL_VERSION, "action": "renew"},
        {"v": PROTOCOL_VERSION, "action": "rm"},
        {"v": PROTOCOL_VERSION, "action": "status", "extra": 1},
        {"v": PROTOCOL_VERSION, "action": "activate", "lineage": "/etc/letsencrypt"},
        {"action": "status"},
    ],
)
def test_unexpected_requests_are_refused(tmp_path: Path, message: dict) -> None:
    helper, _recorder = build_helper(tmp_path)
    start(helper)
    try:
        answer = raw(helper, message)
    finally:
        helper.close()

    assert answer["ok"] is False
    assert answer["kind"] == "protocol"
    # The peer's own payload is never echoed back.
    assert "lineage" not in answer.get("error", "")


def test_a_refused_peer_gets_nothing_useful(tmp_path: Path) -> None:
    helper, _recorder = build_helper(tmp_path, allowed_uid=os.getuid() + 1)
    start(helper)
    try:
        with pytest.raises(CertificateHelperUnavailable):
            client(helper).status()
    finally:
        helper.close()


def test_a_key_never_appears_in_any_answer(tmp_path: Path) -> None:
    helper, _recorder = build_helper(tmp_path)
    start(helper)
    try:
        cert, key = make_certificate(tmp_path)
        answers = [
            raw(helper, {"v": PROTOCOL_VERSION, "action": "status"}),
            raw(helper, {"v": PROTOCOL_VERSION, "action": "ping"}),
            raw(
                helper,
                {
                    "v": PROTOCOL_VERSION,
                    "action": "validate",
                    "certificate": base64.b64encode(cert).decode(),
                    "private_key": base64.b64encode(key).decode(),
                    "passphrase": None,
                    "hostname": HOSTNAME,
                },
            ),
        ]
    finally:
        helper.close()

    for answer in answers:
        rendered = repr(answer)
        assert "PRIVATE" not in rendered
        assert key.decode("utf-8").splitlines()[1] not in rendered


# ---------------------------------------------------------------------------
# nginx: -t strictly before any reload
# ---------------------------------------------------------------------------
def test_nginx_is_tested_before_it_is_reloaded(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):  # noqa: ANN001, ANN202
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr("vysion.certhelper.subprocess.run", fake_run)
    host_nginx_reloader()

    assert [entry[0] for entry in calls] == ["nginx", *NGINX_RELOAD_COMMANDS[0][:1]]
    assert calls[0][1] == "-t"
    assert calls[0] != calls[1]


def test_a_failing_nginx_test_never_reaches_a_reload(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):  # noqa: ANN001, ANN202
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 1, b"", b"nginx: config broken")

    monkeypatch.setattr("vysion.certhelper.subprocess.run", fake_run)
    with pytest.raises(CertificateError):
        host_nginx_reloader()

    assert len(calls) == 1
    assert calls[0][0] == "nginx"
    assert calls[0][1] == "-t"


# ---------------------------------------------------------------------------
# certbot lineage import: one authority, idempotent
# ---------------------------------------------------------------------------
def _lineage(tmp_path: Path, *, hostname: str = HOSTNAME) -> Path:
    directory = tmp_path / "live" / hostname
    directory.mkdir(parents=True, exist_ok=True)
    cert, key = make_certificate(directory, hostname=hostname)
    (directory / "fullchain.pem").write_bytes(cert)
    (directory / "privkey.pem").write_bytes(key)
    return directory


def test_the_bootstrap_import_creates_the_first_generation(tmp_path: Path) -> None:
    helper, recorder = build_helper(tmp_path)
    helper.close()
    lineage = _lineage(tmp_path)

    result = main(
        [
            "install",
            "--lineage",
            str(lineage),
            "--certs-dir",
            str(helper.certs_directory),
            "--hostname",
            HOSTNAME,
        ],
        reloader=recorder.reloader,
        smoker=lambda: helper.store.active().metadata.sha256,
    )

    assert result == 0
    store = helper.store
    assert [item.number for item in store.generations()] == [1]
    assert store.active() is not None
    # The reloader ran, so the reload happened after a successful `nginx -t`.
    assert recorder.calls == ["reload"]


def test_the_lineage_import_is_idempotent(tmp_path: Path) -> None:
    helper, recorder = build_helper(tmp_path)
    helper.close()
    lineage = _lineage(tmp_path)
    arguments = [
        "--lineage",
        str(lineage),
        "--certs-dir",
        str(helper.certs_directory),
        "--hostname",
        HOSTNAME,
    ]
    smoke = lambda: helper.store.active().metadata.sha256  # noqa: E731

    assert main(["install", *arguments], reloader=recorder.reloader, smoker=smoke) == 0
    assert main(["renew", *arguments], reloader=recorder.reloader, smoker=smoke) == 0
    assert main(["install", *arguments], reloader=recorder.reloader, smoker=smoke) == 0

    store = helper.store
    # One authority, one generation: repeated runs never stack duplicates.
    assert [item.number for item in store.generations()] == [1]
    assert store.active() is not None
    assert store.staged_digest() is None
    assert recorder.calls == ["reload"]  # only the first run reloaded


def test_the_lineage_import_refuses_a_path_outside_the_certbot_tree(
    tmp_path: Path,
) -> None:
    helper, recorder = build_helper(tmp_path)
    helper.close()
    forged = tmp_path / "forged"
    forged.mkdir()
    cert, key = make_certificate(forged)
    (forged / "fullchain.pem").write_bytes(cert)
    (forged / "privkey.pem").write_bytes(key)

    result = main(
        [
            "renew",
            "--lineage",
            str(forged),
            "--certs-dir",
            str(helper.certs_directory),
            "--hostname",
            HOSTNAME,
        ],
        reloader=recorder.reloader,
        smoker=lambda: helper.store.active().metadata.sha256,
    )

    assert result != 0
    assert helper.store.generations() == []
    assert recorder.calls == []

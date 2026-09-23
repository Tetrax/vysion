"""Cross-process serialization of certificate activation.

A manual activation (admin socket or local mode) and Certbot's deploy hook
(``certhelper renew``, a separate process) share one store: generation
numbering, the ``active`` pointer, the reload and any rollback must happen in
one critical section or a renewal can race an activation and serve — or roll
back — the wrong certificate.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from test_certhelper import HOSTNAME, make_certificate

from vysion.certhelper import main as helper_main
from vysion.certificates import CertificateStore

ROOT = Path(__file__).parents[2]
CHILD_ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "LC_ALL": "C"}


def _child(script: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=CHILD_ENV,
    )


def _lineage(tmp_path: Path, cert: bytes, key: bytes) -> Path:
    directory = tmp_path / "live" / HOSTNAME
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "fullchain.pem").write_bytes(cert)
    (directory / "privkey.pem").write_bytes(key)
    return directory


def test_the_store_lock_is_shared_between_processes(tmp_path: Path) -> None:
    """An exclusive section held here must block another process there."""
    certs = tmp_path / "certs"
    store = CertificateStore(certs)
    child = None
    # This process grabs the lock first, then starts a process that wants it.
    with store.exclusive():
        child = _child(
            f"""
            import time
            from vysion.certificates import CertificateStore
            store = CertificateStore({str(certs)!r})
            with store.exclusive():
                acquired = time.monotonic()
            print(f"{{acquired:.3f}}", flush=True)
            """
        )
        time.sleep(0.8)  # the child boots and blocks on the held lock
    released = time.monotonic()
    stdout, stderr = child.communicate(timeout=30)
    assert child.returncode == 0, stderr
    child_acquired = float(stdout.strip())

    # The child only entered after this process let go.
    assert child_acquired >= released - 0.1, (
        f"child acquired the lock at {child_acquired} but it was released at {released}"
    )
    assert (certs / ".lock").exists()


def test_a_renew_cannot_race_a_manual_activation(tmp_path: Path) -> None:
    """The two real paths — admin activation and the Certbot deploy hook —
    run in different processes against the same store and must serialize."""
    certs = tmp_path / "certs"
    certs.mkdir()
    (tmp_path / "admin").mkdir()
    (tmp_path / "renew").mkdir()
    admin_cert, admin_key = make_certificate(tmp_path / "admin")
    renew_cert, renew_key = make_certificate(tmp_path / "renew")
    lineage = _lineage(tmp_path, renew_cert, renew_key)

    # Process A plays the admin: manual activation whose reload is slow, the
    # window in which an unsynchronized renewal would interleave.
    admin = _child(
        f"""
        import time
        from pathlib import Path
        from vysion.certificates import CertificateStore, activate_staged

        store = CertificateStore({str(certs)!r})
        with store.exclusive():
            store.validate(
                certificate=Path({str(tmp_path / "admin" / "leaf.pem")!r}).read_bytes(),
                private_key=Path({str(tmp_path / "admin" / "leaf.key")!r}).read_bytes(),
                hostname={HOSTNAME!r},
                passphrase=None,
            )
            activate_staged(
                store,
                reloader=lambda: time.sleep(1.0),
                smoker=lambda: store.active().metadata.sha256,
            )
        print("activated", flush=True)
        """
    )
    time.sleep(0.3)  # A is inside its critical section (slow reload)

    def fast_reloader() -> None:
        return None

    renew_store = CertificateStore(certs)
    started = time.monotonic()
    result = helper_main(
        [
            "renew",
            "--lineage",
            str(lineage),
            "--certs-dir",
            str(certs),
            "--hostname",
            HOSTNAME,
        ],
        reloader=fast_reloader,
        smoker=lambda: renew_store.active().metadata.sha256,
    )
    elapsed = time.monotonic() - started
    admin_stdout, admin_stderr = admin.communicate(timeout=60)

    assert admin.returncode == 0, admin_stderr
    assert result == 0

    # The renewal had to wait for the activation to finish its critical
    # section: the slow reload held the lock for a full second.
    assert elapsed >= 0.6, f"renew ran concurrently with the activation ({elapsed:.2f}s)"
    assert "activated" in admin_stdout

    store = CertificateStore(certs)
    numbers = [item.number for item in store.generations()]
    assert numbers == [1, 2], f"raced numbering produced {numbers}"
    active = store.active()
    assert active is not None
    # The renewal was the last writer: its certificate is the served one.
    assert active.number == 2
    assert active.metadata.sha256 == store.generations()[-1].metadata.sha256
    # Nobody left a half-consumed candidate behind.
    assert store.staged_digest() is None


def test_an_exclusive_section_is_reentrant_within_one_thread(tmp_path: Path) -> None:
    """``_import_lineage`` wraps ``activate_staged``: nesting must not
    deadlock on the same store instance."""
    store = CertificateStore(tmp_path / "certs")
    # One statement, two entries on the same thread: the second must not
    # deadlock against the descriptor the first one holds.
    with store.exclusive(), store.exclusive():
        pass

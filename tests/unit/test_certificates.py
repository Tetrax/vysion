"""Certificate staging, validation, atomic activation and rollback."""

from __future__ import annotations

import json
import stat
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest

from vysion.certificates import (
    CertificateError,
    CertificateStore,
    activate_staged,
    nginx_reloader,
)
from vysion.storage.reports import utc_now

HOSTNAME = "vysion.example"


def openssl(*args: str, cwd: Path, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["openssl", *args], cwd=cwd, input=stdin, capture_output=True, timeout=60
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return result


def make_certificate(
    tmp_path: Path,
    *,
    name: str = "leaf",
    hostname: str = HOSTNAME,
    extra_dns: tuple[str, ...] = (),
    days: int = 30,
) -> tuple[bytes, bytes]:
    """Self-signed leaf with an explicit SAN; returns (certificate, key)."""
    key_path = tmp_path / f"{name}.key"
    cert_path = tmp_path / f"{name}.pem"
    dns_names = (hostname, *extra_dns)
    san = ",".join(f"DNS:{dns}" for dns in dns_names)
    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        str(days),
        "-subj",
        f"/CN={hostname}",
        "-addext",
        f"subjectAltName={san}",
        cwd=tmp_path,
    )
    return cert_path.read_bytes(), key_path.read_bytes()


def make_ca(tmp_path: Path, *, name: str = "ca") -> tuple[bytes, bytes]:
    key_path = tmp_path / f"{name}.key"
    cert_path = tmp_path / f"{name}.pem"
    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "3650",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-subj",
        f"/CN=Test CA {name}",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        cwd=tmp_path,
    )
    return cert_path.read_bytes(), key_path.read_bytes()


def make_signed_leaf(
    tmp_path: Path, ca_cert: bytes, ca_key: bytes, *, hostname: str = HOSTNAME
) -> tuple[bytes, bytes]:
    ca_cert_path = tmp_path / "ca.pem"
    ca_key_path = tmp_path / "ca.key"
    ca_cert_path.write_bytes(ca_cert)
    ca_key_path.write_bytes(ca_key)
    key_path = tmp_path / "leaf.key"
    csr_path = tmp_path / "leaf.csr"
    cert_path = tmp_path / "leaf.pem"
    ext_path = tmp_path / "leaf.ext"
    ext_path.write_text(f"subjectAltName=DNS:{hostname}\nbasicConstraints=CA:FALSE\n")
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(csr_path),
        "-subj",
        f"/CN={hostname}",
        cwd=tmp_path,
    )
    openssl(
        "x509",
        "-req",
        "-in",
        str(csr_path),
        "-CA",
        str(ca_cert_path),
        "-CAkey",
        str(ca_key_path),
        "-CAcreateserial",
        "-days",
        "30",
        "-extfile",
        str(ext_path),
        "-out",
        str(cert_path),
        cwd=tmp_path,
    )
    return cert_path.read_bytes(), key_path.read_bytes()


def make_intermediate(
    tmp_path: Path, ca_cert: bytes, ca_key: bytes, *, name: str = "intermediate"
) -> tuple[bytes, bytes]:
    """Intermediate CA signed by ``ca_cert`` (root -> intermediate -> leaf)."""
    issuer_cert_path = tmp_path / "issuer.pem"
    issuer_key_path = tmp_path / "issuer.key"
    issuer_cert_path.write_bytes(ca_cert)
    issuer_key_path.write_bytes(ca_key)
    key_path = tmp_path / f"{name}.key"
    csr_path = tmp_path / f"{name}.csr"
    cert_path = tmp_path / f"{name}.pem"
    ext_path = tmp_path / f"{name}.ext"
    ext_path.write_text(
        "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
    )
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(csr_path),
        "-subj",
        f"/CN=Intermediate {name}",
        cwd=tmp_path,
    )
    openssl(
        "x509",
        "-req",
        "-in",
        str(csr_path),
        "-CA",
        str(issuer_cert_path),
        "-CAkey",
        str(issuer_key_path),
        "-CAcreateserial",
        "-days",
        "1825",
        "-extfile",
        str(ext_path),
        "-out",
        str(cert_path),
        cwd=tmp_path,
    )
    return cert_path.read_bytes(), key_path.read_bytes()


def make_pkcs12(
    tmp_path: Path, cert: bytes, key: bytes, ca: bytes | None, password: str
) -> bytes:
    cert_path = tmp_path / "bundle.pem"
    key_path = tmp_path / "bundle.key"
    cert_path.write_bytes(cert)
    key_path.write_bytes(key)
    args = [
        "pkcs12",
        "-export",
        "-out",
        str(tmp_path / "bundle.p12"),
        "-inkey",
        str(key_path),
        "-in",
        str(cert_path),
        "-passout",
        f"pass:{password}",
    ]
    if ca is not None:
        ca_path = tmp_path / "bundle-ca.pem"
        ca_path.write_bytes(ca)
        args.extend(["-certfile", str(ca_path)])
    openssl(*args, cwd=tmp_path)
    return (tmp_path / "bundle.p12").read_bytes()


def store_for(tmp_path: Path, *, clock=None) -> CertificateStore:
    kwargs = {} if clock is None else {"clock": clock}
    return CertificateStore(tmp_path / "certs", **kwargs)


class MutableClock:
    def __init__(self, instant):
        self.current = instant

    def __call__(self):
        return self.current

    def shift(self, days: int) -> None:
        self.current = self.current + timedelta(days=days)


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def test_valid_self_signed_certificate_is_staged_with_metadata(tmp_path: Path) -> None:
    cert, key = make_certificate(tmp_path)
    store = store_for(tmp_path)

    metadata = store.validate(
        certificate=cert, private_key=key, hostname=HOSTNAME
    )

    assert metadata.hostname == HOSTNAME
    assert metadata.chain_length == 1
    assert HOSTNAME in metadata.sans
    assert metadata.not_after > metadata.not_before
    assert len(metadata.sha256) == 64
    assert store.active() is None
    assert store.staged_digest() is not None

    staged = store.certs_directory / "staging"
    assert stat.S_IMODE(staged.stat().st_mode) == 0o700
    key_mode = stat.S_IMODE((staged / "key.pem").stat().st_mode)
    assert key_mode == 0o600
    meta = json.loads((staged / "meta.json").read_text())
    assert "PRIVATE KEY" not in json.dumps(meta)
    assert meta["sha256"] == metadata.sha256


def test_metadata_and_listing_never_expose_the_private_key(tmp_path: Path) -> None:
    cert, key = make_certificate(tmp_path)
    store = store_for(tmp_path)

    metadata = store.validate(certificate=cert, private_key=key, hostname=HOSTNAME)

    dumped = repr(metadata) + json.dumps(metadata.as_dict())
    assert "PRIVATE" not in dumped
    assert key.decode() not in dumped


def test_hostname_mismatch_is_refused(tmp_path: Path) -> None:
    cert, key = make_certificate(tmp_path, hostname="other.example")
    store = store_for(tmp_path)

    with pytest.raises(CertificateError) as excinfo:
        store.validate(certificate=cert, private_key=key, hostname=HOSTNAME)

    assert "SAN" in str(excinfo.value)
    assert store.staged_digest() is None


def test_expired_certificate_is_refused(tmp_path: Path) -> None:
    cert, key = make_certificate(tmp_path, days=30)
    clock = MutableClock(utc_now())
    clock.shift(40)
    store = store_for(tmp_path, clock=clock)

    with pytest.raises(CertificateError) as excinfo:
        store.validate(certificate=cert, private_key=key, hostname=HOSTNAME)

    assert "expir" in str(excinfo.value)


def test_not_yet_valid_certificate_is_refused(tmp_path: Path) -> None:
    cert, key = make_certificate(tmp_path, days=30)
    clock = MutableClock(utc_now())
    clock.shift(-5)
    store = store_for(tmp_path, clock=clock)

    with pytest.raises(CertificateError) as excinfo:
        store.validate(certificate=cert, private_key=key, hostname=HOSTNAME)

    assert "valid" in str(excinfo.value)


def test_mismatched_private_key_is_refused(tmp_path: Path) -> None:
    cert, _key = make_certificate(tmp_path, name="leaf")
    _other_cert, other_key = make_certificate(tmp_path, name="other")
    store = store_for(tmp_path)

    with pytest.raises(CertificateError) as excinfo:
        store.validate(certificate=cert, private_key=other_key, hostname=HOSTNAME)

    assert "clé" in str(excinfo.value)


def test_missing_private_key_is_refused(tmp_path: Path) -> None:
    cert, _key = make_certificate(tmp_path)
    store = store_for(tmp_path)

    with pytest.raises(CertificateError) as excinfo:
        store.validate(certificate=cert, private_key=None, hostname=HOSTNAME)

    assert "clé" in str(excinfo.value)


def test_garbage_payload_is_refused(tmp_path: Path) -> None:
    store = store_for(tmp_path)

    with pytest.raises(CertificateError):
        store.validate(
            certificate=b"definitely not a certificate\n",
            private_key=b"nor a key\n",
            hostname=HOSTNAME,
        )

    assert store.staged_digest() is None


def test_complete_chain_validates_and_reports_both_certificates(
    tmp_path: Path,
) -> None:
    ca_cert, ca_key = make_ca(tmp_path)
    leaf_cert, leaf_key = make_signed_leaf(tmp_path, ca_cert, ca_key)
    store = store_for(tmp_path)

    metadata = store.validate(
        certificate=leaf_cert + ca_cert, private_key=leaf_key, hostname=HOSTNAME
    )

    assert metadata.chain_length == 2


def test_incoherent_chain_is_refused(tmp_path: Path) -> None:
    _other_ca_cert, _other_ca_key = make_ca(tmp_path, name="other")
    ca_cert, ca_key = make_ca(tmp_path, name="signer")
    leaf_cert, leaf_key = make_signed_leaf(tmp_path, ca_cert, ca_key)
    unrelated_cert, _ = make_ca(tmp_path, name="unrelated")
    store = store_for(tmp_path)

    with pytest.raises(CertificateError) as excinfo:
        store.validate(
            certificate=leaf_cert + unrelated_cert,
            private_key=leaf_key,
            hostname=HOSTNAME,
        )

    assert "chaîne" in str(excinfo.value)


def test_ca_issued_fullchain_without_the_root_is_accepted(tmp_path: Path) -> None:
    """Review finding: the served fullchain of a real CA deployment is
    leaf + intermediate(s); clients hold the root themselves. Requiring the
    uploaded bundle to reach a self-signed root rejected every normal
    certificate. The bundle must terminate coherently at any supplied
    issuer while unrelated chains stay refused."""
    root_cert, root_key = make_ca(tmp_path, name="root")
    intermediate_cert, intermediate_key = make_intermediate(tmp_path, root_cert, root_key)
    leaf_cert, leaf_key = make_signed_leaf(tmp_path, intermediate_cert, intermediate_key)
    store = store_for(tmp_path)

    metadata = store.validate(
        certificate=leaf_cert + intermediate_cert,
        private_key=leaf_key,
        hostname=HOSTNAME,
    )
    assert metadata.chain_length == 2

    # The full three-level bundle keeps validating as well.
    metadata = store.validate(
        certificate=leaf_cert + intermediate_cert + root_cert,
        private_key=leaf_key,
        hostname=HOSTNAME,
    )
    assert metadata.chain_length == 3

    # And a leaf signed by yet another CA stays refused.
    other_cert, other_key = make_ca(tmp_path, name="stranger")
    stranger_cert, stranger_key = make_signed_leaf(tmp_path, other_cert, other_key)
    with pytest.raises(CertificateError):
        store.validate(
            certificate=stranger_cert + intermediate_cert,
            private_key=stranger_key,
            hostname=HOSTNAME,
        )

    # A lone CA-issued leaf (no issuer supplied at all) is not servable.
    with pytest.raises(CertificateError):
        store.validate(
            certificate=leaf_cert, private_key=leaf_key, hostname=HOSTNAME
        )


def test_pkcs12_fullchain_without_the_root_is_accepted(tmp_path: Path) -> None:
    """Same rule through the PKCS#12 path: leaf + intermediate inside the
    archive, root omitted, must validate."""
    root_cert, root_key = make_ca(tmp_path, name="root")
    intermediate_cert, intermediate_key = make_intermediate(tmp_path, root_cert, root_key)
    leaf_cert, leaf_key = make_signed_leaf(tmp_path, intermediate_cert, intermediate_key)
    archive = make_pkcs12(
        tmp_path, leaf_cert, leaf_key, intermediate_cert, "store-secret"
    )
    store = store_for(tmp_path)

    metadata = store.validate(
        certificate=archive, private_key=None, passphrase="store-secret",
        hostname=HOSTNAME,
    )

    assert metadata.chain_length == 2


def test_pkcs12_archive_validates_with_its_passphrase(tmp_path: Path) -> None:
    ca_cert, ca_key = make_ca(tmp_path)
    leaf_cert, leaf_key = make_signed_leaf(tmp_path, ca_cert, ca_key)
    archive = make_pkcs12(tmp_path, leaf_cert, leaf_key, ca_cert, "store-secret")
    store = store_for(tmp_path)

    metadata = store.validate(
        certificate=archive, private_key=None, passphrase="store-secret",
        hostname=HOSTNAME,
    )

    assert metadata.chain_length >= 1
    # The passphrase must never appear in anything the caller can read back.
    assert "store-secret" not in repr(metadata.as_dict())


def test_protected_pkcs12_with_a_wrong_passphrase_is_refused(
    tmp_path: Path,
) -> None:
    cert, key = make_certificate(tmp_path)
    archive = make_pkcs12(tmp_path, cert, key, None, "store-secret")
    store = store_for(tmp_path)

    with pytest.raises(CertificateError) as excinfo:
        store.validate(
            certificate=archive, private_key=None, passphrase="wrong-secret",
            hostname=HOSTNAME,
        )

    assert store.staged_digest() is None
    assert "PKCS#12" in str(excinfo.value) or "passphrase" in str(excinfo.value).lower()


def test_reimport_purges_the_previous_staging_and_keeps_the_active_one(
    tmp_path: Path,
) -> None:
    first_cert, first_key = make_certificate(tmp_path, name="first")
    second_cert, second_key = make_certificate(tmp_path, name="second")
    store = store_for(tmp_path)
    store.validate(certificate=first_cert, private_key=first_key, hostname=HOSTNAME)
    store.promote()
    active_after_first = store.active()
    assert active_after_first is not None

    store.validate(
        certificate=second_cert, private_key=second_key, hostname=HOSTNAME
    )

    assert store.active().number == active_after_first.number
    assert store.staged_digest() is not None
    meta = json.loads(
        (store.certs_directory / "staging" / "meta.json").read_text()
    )
    assert meta["sha256"] != active_after_first.metadata.sha256


# ---------------------------------------------------------------------------
# atomic activation, rollback
# ---------------------------------------------------------------------------
def test_promote_creates_a_generation_and_flips_the_pointer(tmp_path: Path) -> None:
    cert, key = make_certificate(tmp_path)
    store = store_for(tmp_path)
    store.validate(certificate=cert, private_key=key, hostname=HOSTNAME)

    generation = store.promote()

    assert generation.number == 1
    assert store.active().number == 1
    assert (generation.path / "fullchain.pem").is_file()
    assert (generation.path / "key.pem").is_file()
    assert store.staged_digest() is None  # staging is consumed
    # The listing reads the metadata back without any private material.
    listed = store.generations()
    assert [item.number for item in listed] == [1]
    assert "PRIVATE" not in json.dumps(listed[0].metadata.as_dict())


def test_activation_succeeds_when_reload_and_smoke_pass(tmp_path: Path) -> None:
    cert, key = make_certificate(tmp_path)
    store = store_for(tmp_path)
    store.validate(certificate=cert, private_key=key, hostname=HOSTNAME)
    calls: list[str] = []

    generation, served = activate_staged(
        store,
        reloader=lambda: calls.append("reload"),
        smoker=lambda: calls.append("smoke") or store.active().metadata.sha256,
    )

    assert generation.number == 1
    assert served == generation.metadata.sha256
    assert calls == ["reload", "smoke"]
    assert store.active().number == 1


def test_smoke_mismatch_rolls_back_to_the_previous_generation(
    tmp_path: Path,
) -> None:
    first_cert, first_key = make_certificate(tmp_path, name="first")
    second_cert, second_key = make_certificate(tmp_path, name="second")
    store = store_for(tmp_path)
    store.validate(certificate=first_cert, private_key=first_key, hostname=HOSTNAME)
    store.promote()
    store.validate(
        certificate=second_cert, private_key=second_key, hostname=HOSTNAME
    )
    reloads: list[str] = []

    with pytest.raises(CertificateError) as excinfo:
        activate_staged(
            store,
            reloader=lambda: reloads.append("reload"),
            smoker=lambda: "0" * 64,
            sleeper=lambda _seconds: None,
        )

    assert "rollback" in str(excinfo.value)
    assert store.active().number == 1
    assert store.active().metadata.sha256 != "0" * 64
    # Once to load the candidate, once to restore the previous generation.
    assert reloads == ["reload", "reload"]


def test_reload_failure_rolls_back_to_the_previous_generation(
    tmp_path: Path,
) -> None:
    first_cert, first_key = make_certificate(tmp_path, name="first")
    second_cert, second_key = make_certificate(tmp_path, name="second")
    store = store_for(tmp_path)
    store.validate(certificate=first_cert, private_key=first_key, hostname=HOSTNAME)
    store.promote()
    store.validate(
        certificate=second_cert, private_key=second_key, hostname=HOSTNAME
    )

    def broken_reloader() -> None:
        raise RuntimeError("nginx -t a échoué")

    with pytest.raises(CertificateError) as excinfo:
        activate_staged(store, reloader=broken_reloader, smoker=lambda: "unused")

    assert "rollback" in str(excinfo.value)
    assert store.active().number == 1
    assert store.active().metadata.sha256 == (
        store.generations()[0].metadata.sha256
    )


def test_rollback_restores_the_pointer_even_when_the_second_reload_fails(
    tmp_path: Path,
) -> None:
    first_cert, first_key = make_certificate(tmp_path, name="first")
    second_cert, second_key = make_certificate(tmp_path, name="second")
    store = store_for(tmp_path)
    store.validate(certificate=first_cert, private_key=first_key, hostname=HOSTNAME)
    store.promote()
    store.validate(
        certificate=second_cert, private_key=second_key, hostname=HOSTNAME
    )

    def always_broken() -> None:
        raise RuntimeError("reload impossible")

    with pytest.raises(CertificateError) as excinfo:
        activate_staged(store, reloader=always_broken, smoker=lambda: "unused")

    # The pointer itself must be restored whatever happened to the reload.
    assert store.active().number == 1
    assert "échec" in str(excinfo.value) or "rollback" in str(excinfo.value)


def test_stale_workers_right_after_reload_still_activate(tmp_path: Path) -> None:
    """Right after `nginx -s reload` the previous workers can still answer a
    fresh TLS handshake for a few milliseconds: the activation check must
    poll until the new certificate is actually served instead of declaring a
    false mismatch and rolling back a perfectly valid activation."""
    cert, key = make_certificate(tmp_path)
    store = store_for(tmp_path)
    store.validate(certificate=cert, private_key=key, hostname=HOSTNAME)
    calls: list[str] = []
    delays: list[float] = []
    answers = iter(["a" * 64, "b" * 64, None])  # two stale probes, then match

    def smoker() -> str:
        calls.append("smoke")
        pending = next(answers, None)
        if pending is None:
            return store.active().metadata.sha256
        return pending

    generation, served = activate_staged(
        store,
        reloader=lambda: calls.append("reload"),
        smoker=smoker,
        sleeper=delays.append,
    )

    assert served == generation.metadata.sha256
    assert calls == ["reload", "smoke", "smoke", "smoke"]
    assert delays and all(delay > 0 for delay in delays)


def test_probes_that_never_match_roll_back_after_the_bounded_wait(
    tmp_path: Path,
) -> None:
    first_cert, first_key = make_certificate(tmp_path, name="first")
    second_cert, second_key = make_certificate(tmp_path, name="second")
    store = store_for(tmp_path)
    store.validate(certificate=first_cert, private_key=first_key, hostname=HOSTNAME)
    store.promote()
    store.validate(
        certificate=second_cert, private_key=second_key, hostname=HOSTNAME
    )
    reloads: list[str] = []
    delays: list[float] = []

    with pytest.raises(CertificateError) as excinfo:
        activate_staged(
            store,
            reloader=lambda: reloads.append("reload"),
            smoker=lambda: "0" * 64,
            sleeper=delays.append,
        )

    # The wait is bounded: the settle window must not hang an operator.
    assert 1 <= len(delays) <= 20
    assert all(delay > 0 for delay in delays)
    assert "rollback" in str(excinfo.value)
    # The previous real generation is served again, pointer intact.
    assert store.active() is not None
    assert store.active().number == 1
    assert reloads == ["reload", "reload"]


def test_nginx_reloader_tests_the_standalone_config_it_reloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`nginx -t` without `-c` validates /etc/nginx/nginx.conf — the proxy
    config, which references no certificate at all — so a missing or broken
    active certificate would pass the check while the running standalone
    master silently fails the reload."""
    seen: list[list[str]] = []

    def fake_run(args, **_kwargs):  # noqa: ANN001 - mirrors subprocess.run
        seen.append(list(args))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr("vysion.certificates.subprocess.run", fake_run)
    nginx_reloader()

    assert seen == [
        ["nginx", "-t", "-c", "/etc/nginx/nginx-standalone.conf"],
        ["nginx", "-s", "reload", "-c", "/etc/nginx/nginx-standalone.conf"],
    ]


def test_a_generation_without_metadata_is_never_the_active_one(
    tmp_path: Path,
) -> None:
    """A directory planted by hand (legacy bootstrap) has no meta.json: it
    must never count as a generation, or activation would roll back to
    nothing. The entrypoint therefore bootstraps through validate+promote."""
    store = store_for(tmp_path)
    legacy = store.certs_directory / "generations" / "0001"
    legacy.mkdir(parents=True)
    cert, key = make_certificate(tmp_path, name="legacy")
    (legacy / "fullchain.pem").write_bytes(cert)
    (legacy / "key.pem").write_bytes(key)
    (store.certs_directory / "active").symlink_to("generations/0001")

    assert store.active() is None
    assert store.generations() == []

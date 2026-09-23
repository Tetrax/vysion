"""Certificate staging, validation, atomic activation and rollback.

Certificates and private keys live only under the dedicated certificate
volume: staging is private (0700/0600), generations are immutable, and the
``active`` pointer flips atomically. Nothing here ever returns key material,
and no secret ever reaches a process argument.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vysion.storage.reports import Clock, utc_now

OPENSSL_TIMEOUT_SECONDS = 20
# nginx keeps its previous workers alive for a moment after a reload: they
# can still answer a fresh TLS handshake with the old certificate. The
# activation check therefore polls instead of trusting one immediate probe.
RELOAD_SETTLE_ATTEMPTS = 20
RELOAD_SETTLE_DELAY_SECONDS = 0.25
STANDALONE_NGINX_CONFIG = "/etc/nginx/nginx-standalone.conf"
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}  # fmt: skip
CERTIFICATE_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


class CertificateError(ValueError):
    """A certificate was refused; the message is safe for an operator UI."""


@dataclass(frozen=True)
class CertificateMetadata:
    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    sha256: str
    sans: tuple[str, ...]
    chain_length: int
    hostname: str

    def as_dict(self) -> dict[str, Any]:
        """Public projection only: never any private material."""
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "sha256": self.sha256,
            "sans": list(self.sans),
            "chain_length": self.chain_length,
            "hostname": self.hostname,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CertificateMetadata:
        return cls(
            subject=str(data["subject"]),
            issuer=str(data["issuer"]),
            serial=str(data["serial"]),
            not_before=datetime.fromisoformat(str(data["not_before"])),
            not_after=datetime.fromisoformat(str(data["not_after"])),
            sha256=str(data["sha256"]),
            sans=tuple(str(item) for item in data.get("sans", ())),
            chain_length=int(data["chain_length"]),
            hostname=str(data["hostname"]),
        )


@dataclass(frozen=True)
class Generation:
    number: int
    path: Path
    metadata: CertificateMetadata


def _parse_openssl_date(value: str) -> datetime:
    """Parse ``MMM dd HH:MM:SS YYYY GMT`` without depending on any locale."""
    match = re.match(
        r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})",
        value.strip(),
    )
    if match is None:
        raise CertificateError("date de certificat illisible")
    month, day, hour, minute, second, year = match.groups()
    if month not in MONTHS:
        raise CertificateError("date de certificat illisible")
    return datetime(
        int(year), MONTHS[month], int(day), int(hour), int(minute), int(second),
        tzinfo=UTC,
    )  # fmt: skip


def _split_certificate_blocks(payload: bytes) -> list[bytes]:
    return [
        block + b"\n" for block in CERTIFICATE_BLOCK.findall(payload)
    ]  # findall returns the whole match (no groups) # fmt: skip


def _hostname_matches(sans: tuple[str, ...], hostname: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    if not host:
        return False
    for entry in sans:
        pattern = entry.strip().lower().rstrip(".")
        if not pattern:
            continue
        if pattern == host:
            return True
        if pattern.startswith("*."):
            # RFC 6125 single-label wildcard: *.example matches a.example,
            # never example.example nor the apex itself.
            suffix = pattern[1:]
            if host.endswith(suffix):
                label = host[: -len(suffix)]
                if label and "." not in label:
                    return True
    return False


class CertificateStore:
    """Private staging, immutable generations, atomic ``active`` pointer."""

    def __init__(
        self, directory: Path | str, *, clock: Clock = utc_now, openssl: str = "openssl"
    ) -> None:
        self.certs_directory = Path(directory)
        self._clock = clock
        self._openssl = openssl
        self._private_init(self.certs_directory)
        self._generations_directory = self.certs_directory / "generations"
        self._private_init(self._generations_directory)

    @staticmethod
    def _private_init(directory: Path) -> None:
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        except OSError as exc:
            raise CertificateError("répertoire de certificats indisponible") from exc

    # ------------------------------------------------------------------
    # subprocess plumbing (no secret ever in argv)
    # ------------------------------------------------------------------
    def _run(
        self, *args: str, stdin: bytes | None = None, cwd: Path | None = None
    ) -> subprocess.CompletedProcess:
        executable = shutil.which(self._openssl)
        if executable is None:
            raise CertificateError("openssl introuvable : validation impossible")
        environment = dict(os.environ, LC_ALL="C", LANG="C")
        try:
            return subprocess.run(
                [executable, *args],
                input=stdin,
                capture_output=True,
                timeout=OPENSSL_TIMEOUT_SECONDS,
                cwd=str(cwd) if cwd else None,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CertificateError("analyse du certificat impossible") from exc

    # ------------------------------------------------------------------
    # layout helpers
    # ------------------------------------------------------------------
    @property
    def _staging(self) -> Path:
        return self.certs_directory / "staging"

    @property
    def _pointer(self) -> Path:
        return self.certs_directory / "active"

    def staged_digest(self) -> str | None:
        """Digest of the staged candidate (fullchain + key), None when absent."""
        fullchain = self._staging / "fullchain.pem"
        key = self._staging / "key.pem"
        if not (fullchain.is_file() and key.is_file()):
            return None
        digest = hashlib.sha256()
        digest.update(fullchain.read_bytes())
        digest.update(b"\0")
        digest.update(key.read_bytes())
        return digest.hexdigest()

    def staged_metadata(self) -> CertificateMetadata | None:
        """Public metadata of the staged candidate, None when absent."""
        return self._read_metadata(self._staging)

    def active(self) -> Generation | None:
        pointer = self._pointer
        if not pointer.is_symlink():
            return None
        try:
            target = os.readlink(pointer)
            number = int(Path(target).name)
        except (OSError, ValueError):
            return None
        path = self._generations_directory / Path(target).name
        metadata = self._read_metadata(path)
        if metadata is None:
            return None
        return Generation(number=number, path=path, metadata=metadata)

    def generations(self) -> list[Generation]:
        found: list[Generation] = []
        if not self._generations_directory.is_dir():
            return found
        for entry in sorted(self._generations_directory.iterdir()):
            if not entry.is_dir() or not entry.name.isdigit():
                continue
            metadata = self._read_metadata(entry)
            if metadata is None:
                continue
            found.append(Generation(number=int(entry.name), path=entry, metadata=metadata))
        return found

    @staticmethod
    def _read_metadata(path: Path) -> CertificateMetadata | None:
        meta_path = path / "meta.json"
        if not meta_path.is_file():
            return None
        try:
            return CertificateMetadata.from_dict(json.loads(meta_path.read_text()))
        except (ValueError, KeyError, OSError):
            return None

    def _write_private_file(self, path: Path, payload: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)
        path.chmod(0o600)

    # ------------------------------------------------------------------
    # validation
    # ------------------------------------------------------------------
    def validate(
        self,
        *,
        certificate: bytes,
        private_key: bytes | None,
        hostname: str,
        passphrase: str | None = None,
    ) -> CertificateMetadata:
        hostname = (hostname or "").strip()
        if not hostname:
            raise CertificateError("hostname requis pour valider un certificat")

        build = self.certs_directory / f".staging-build-{secrets.token_hex(6)}"
        self._private_init(build)
        try:
            blocks, key_pem = self._materialize(
                certificate, private_key, passphrase=passphrase, build=build
            )
            ordered = self._order_chain(blocks, key_pem, passphrase=passphrase)
            (build / "fullchain.pem").write_bytes(b"".join(ordered))
            (build / "fullchain.pem").chmod(0o600)
            (build / "key.pem").write_bytes(key_pem)
            (build / "key.pem").chmod(0o600)
            metadata = self._inspect(build, ordered, hostname=hostname, passphrase=passphrase)
            self._write_private_file(
                build / "meta.json",
                json.dumps(metadata.as_dict(), indent=2).encode("utf-8"),
            )
            self._publish(build)
        except BaseException:
            shutil.rmtree(build, ignore_errors=True)
            raise
        return metadata

    def _materialize(
        self,
        certificate: bytes,
        private_key: bytes | None,
        *,
        passphrase: str | None,
        build: Path,
    ) -> tuple[list[bytes], bytes]:
        if b"-----BEGIN CERTIFICATE" in certificate:
            blocks = _split_certificate_blocks(certificate)
            if not blocks:
                raise CertificateError("aucun certificat lisible dans le fichier fourni")
            if private_key is None or not private_key.strip():
                raise CertificateError(
                    "clé privée manquante : fournissez la clé PEM ou une archive PKCS#12"
                )
            return blocks, private_key
        if private_key is not None and b"-----BEGIN" in private_key:
            # A key without any certificate is never enough.
            raise CertificateError("aucun certificat lisible dans le fichier fourni")
        return self._extract_pkcs12(certificate, passphrase=passphrase, build=build)

    def _extract_pkcs12(
        self, payload: bytes, *, passphrase: str | None, build: Path
    ) -> tuple[list[bytes], bytes]:
        archive = build / "archive.p12"
        self._write_private_file(archive, payload)
        key_path = build / "extracted-key.pem"
        certs_path = build / "extracted-certs.pem"
        # The passphrase travels on stdin (fd:0), never in argv.
        stdin = f"{passphrase or ''}\n".encode()
        key_result = self._run(
            "pkcs12",
            "-in",
            str(archive),
            "-nocerts",
            "-nodes",
            "-passin",
            "fd:0",
            "-out",
            str(key_path),
            stdin=stdin,
        )
        if key_result.returncode != 0:
            raise CertificateError(
                "archive PKCS#12 illisible (passphrase incorrecte ou contenu invalide)"
            )
        certs_result = self._run(
            "pkcs12",
            "-in",
            str(archive),
            "-nokeys",
            "-passin",
            "fd:0",
            "-out",
            str(certs_path),
            stdin=stdin,
        )
        if certs_result.returncode != 0:
            raise CertificateError(
                "archive PKCS#12 illisible (passphrase incorrecte ou contenu invalide)"
            )
        blocks = _split_certificate_blocks(certs_path.read_bytes())
        if not blocks:
            raise CertificateError("archive PKCS#12 sans certificat")
        return blocks, key_path.read_bytes()

    def _order_chain(
        self, blocks: list[bytes], key_pem: bytes, *, passphrase: str | None
    ) -> list[bytes]:
        """Leaf first: the certificate whose public key matches the private key."""
        key_path = self.certs_directory / f".key-probe-{secrets.token_hex(6)}"
        self._write_private_file(key_path, key_pem)
        try:
            for index, block in enumerate(blocks):
                probe = self.certs_directory / f".cert-probe-{secrets.token_hex(6)}"
                self._write_private_file(probe, block)
                try:
                    self._load_tls(probe, key_path, passphrase)
                except CertificateError:
                    continue
                finally:
                    probe.unlink(missing_ok=True)
                return [block, *blocks[:index], *blocks[index + 1 :]]
        finally:
            key_path.unlink(missing_ok=True)
        raise CertificateError("la clé privée ne correspond à aucun certificat de l'archive")

    @staticmethod
    def _load_tls(cert_path: Path, key_path: Path, passphrase: str | None) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(
                certfile=str(cert_path),
                keyfile=str(key_path),
                password=(lambda: passphrase) if passphrase else None,
            )
        except ssl.SSLError as exc:
            raise CertificateError(
                "la clé privée ne correspond pas au certificat ou est illisible"
            ) from exc
        except (OSError, ValueError) as exc:
            raise CertificateError("chargement TLS impossible : contenu invalide") from exc

    def _inspect(
        self, build: Path, ordered: list[bytes], *, hostname: str, passphrase: str | None
    ) -> CertificateMetadata:
        leaf_path = build / "leaf.pem"
        leaf_path.write_bytes(ordered[0])
        leaf_path.chmod(0o600)

        # 1. Key/certificate pairing and TLS loading of the full chain.
        self._load_tls(build / "fullchain.pem", build / "key.pem", passphrase)

        # 2. Public metadata.
        details = self._run(
            "x509",
            "-in",
            str(leaf_path),
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-dates",
            "-fingerprint",
            "-sha256",
        )
        if details.returncode != 0:
            raise CertificateError("analyse du certificat impossible")
        text = details.stdout.decode("utf-8", "replace")
        values: dict[str, str] = {}
        for line in text.splitlines():
            for key in ("subject", "issuer", "serial", "notBefore", "notAfter"):
                if line.startswith(f"{key}="):
                    values[key] = line[len(key) + 1 :]
            if "=" in line and "ingerprint" in line:
                values["fingerprint"] = line.split("=", 1)[1]
        required = ("subject", "issuer", "serial", "notBefore", "notAfter", "fingerprint")
        if any(key not in values for key in required):
            raise CertificateError("analyse du certificat impossible")
        fingerprint = values["fingerprint"].replace(":", "").strip().lower()
        if len(fingerprint) != 64:
            raise CertificateError("analyse du certificat impossible")

        # 3. Validity window against the injected clock.
        not_before = _parse_openssl_date(values["notBefore"])
        not_after = _parse_openssl_date(values["notAfter"])
        now = self._clock()
        if now < not_before:
            raise CertificateError("certificat pas encore valide (date de début future)")
        if now > not_after:
            raise CertificateError("certificat expiré")

        # 4. SAN versus the requested hostname.
        sans = self._read_sans(leaf_path)
        if not _hostname_matches(sans, hostname):
            raise CertificateError(
                f"le SAN du certificat ne correspond pas à l'hostname {hostname}"
            )

        # 5. Chain coherence with exactly what would be served.
        self._verify_chain(build, ordered)

        return CertificateMetadata(
            subject=values["subject"].strip(),
            issuer=values["issuer"].strip(),
            serial=values["serial"].strip(),
            not_before=not_before,
            not_after=not_after,
            sha256=fingerprint,
            sans=sans,
            chain_length=len(ordered),
            hostname=hostname,
        )

    def _read_sans(self, leaf_path: Path) -> tuple[str, ...]:
        result = self._run("x509", "-in", str(leaf_path), "-noout", "-ext", "subjectAltName")
        if result.returncode != 0:
            return ()
        text = result.stdout.decode("utf-8", "replace")
        entries: list[str] = []
        for _kind, value in re.findall(
            r"(DNS|IP(?:\sAddress)?):\s*([^\s,]+)", text, flags=re.IGNORECASE
        ):
            entry = value.strip().strip('"')
            if entry and entry not in entries:
                entries.append(entry)
        return tuple(entries)

    def _verify_chain(self, build: Path, ordered: list[bytes]) -> None:
        leaf_path = build / "verify-leaf.pem"
        leaf_path.write_bytes(ordered[0])
        leaf_path.chmod(0o600)
        if len(ordered) == 1:
            # A lone certificate must be self-signed to be servable as a
            # chain: no partial chain here, so a CA-issued leaf without any
            # issuer stays refused.
            ca_path = leaf_path
            partial: tuple[str, ...] = ()
        else:
            ca_path = build / "verify-ca.pem"
            ca_path.write_bytes(b"".join(ordered[1:]))
            ca_path.chmod(0o600)
            # A served fullchain stops at the last intermediate: the root
            # lives in the clients' trust stores, not in the bundle. Any
            # supplied certificate may anchor the chain (partial chain), but
            # every signature up to it must still verify — an unrelated or
            # broken chain keeps failing.
            partial = ("-partial_chain",)
        result = self._run("verify", "-CAfile", str(ca_path), *partial, str(leaf_path))
        if result.returncode != 0:
            output = (result.stdout + result.stderr).decode("utf-8", "replace")
            detail = next(
                (line.strip() for line in output.splitlines() if "error" in line),
                "certificat non signé par la chaîne fournie",
            )
            raise CertificateError(f"chaîne de certificats incohérente : {detail[:160]}")

    def _publish(self, build: Path) -> None:
        """Replace the staging directory with the validated candidate."""
        staging = self._staging
        previous = self.certs_directory / f".staging-old-{secrets.token_hex(6)}"
        if staging.exists():
            os.replace(staging, previous)
            shutil.rmtree(previous, ignore_errors=True)
        os.replace(build, staging)
        staging.chmod(0o700)

    # ------------------------------------------------------------------
    # generations and activation
    # ------------------------------------------------------------------
    def _next_number(self) -> int:
        existing = [
            int(entry.name)
            for entry in self._generations_directory.iterdir()
            if entry.is_dir() and entry.name.isdigit()
        ]
        return max(existing, default=0) + 1

    def _set_pointer(self, number: int | None) -> None:
        pointer = self._pointer
        if number is None:
            pointer.unlink(missing_ok=True)
            return
        temporary = self.certs_directory / f".active-{secrets.token_hex(6)}"
        os.symlink(f"generations/{number:04d}", temporary)
        os.replace(temporary, pointer)

    def promote(self) -> Generation:
        """Consume the staged candidate into a new immutable generation."""
        staging = self._staging
        if not (staging / "fullchain.pem").is_file():
            raise CertificateError("aucun candidat en staging à activer")
        number = self._next_number()
        target = self._generations_directory / f"{number:04d}"
        if target.exists():
            raise CertificateError("génération de certificat déjà presente")
        os.replace(staging, target)
        target.chmod(0o700)
        metadata = self._read_metadata(target)
        if metadata is None:
            # Keep the pointer untouched when the candidate was not readable.
            raise CertificateError("métadonnées de génération illisibles")
        self._set_pointer(number)
        return Generation(number=number, path=target, metadata=metadata)

    def restore(self, generation: Generation | None) -> None:
        """Point ``active`` back at a previous generation (or nowhere)."""
        if generation is None:
            self._set_pointer(None)
        else:
            self._set_pointer(generation.number)


def _normalize_fingerprint(value: str) -> str:
    return value.replace(":", "").strip().lower()


def activate_staged(
    store: CertificateStore,
    *,
    reloader: Callable[[], None],
    smoker: Callable[[], str],
    sleeper: Callable[[float], None] = time.sleep,
) -> tuple[Generation, str]:
    """Promote, reload, verify what is actually served, roll back on failure.

    The served certificate is polled across a bounded settle window: right
    after the reload the previous workers can still answer, so a single
    immediate probe would race the propagation and declare a false mismatch.
    """
    if store.staged_digest() is None:
        raise CertificateError("aucun candidat en staging : validez d'abord un certificat")
    previous = store.active()
    generation = store.promote()
    rollback_notes: list[str] = []

    def rollback() -> None:
        store.restore(previous)
        try:
            reloader()
        except Exception as exc:  # noqa: BLE001 - reported, never hidden
            rollback_notes.append(f"rechargement de restauration : {exc}")

    try:
        reloader()
    except Exception as exc:
        rollback()
        raise CertificateError(
            f"activation annulée : rechargement impossible ({exc}) ; rollback effectué"
            + (f" ; {' ; '.join(rollback_notes)}" if rollback_notes else "")
        ) from exc

    served: str | None = None
    saw_answer = False
    probe_error: Exception | None = None
    for attempt in range(RELOAD_SETTLE_ATTEMPTS):
        if attempt:
            sleeper(RELOAD_SETTLE_DELAY_SECONDS)
        try:
            candidate = _normalize_fingerprint(smoker())
        except Exception as exc:  # noqa: BLE001 - transient during the reload
            probe_error = exc
            continue
        saw_answer = True
        if candidate == generation.metadata.sha256:
            served = candidate
            break

    if served is None:
        rollback()
        note = f" ; {' ; '.join(rollback_notes)}" if rollback_notes else ""
        if saw_answer:
            raise CertificateError(
                "activation annulée : le certificat servi ne correspond pas au certificat"
                " activé ; rollback effectué" + note
            )
        raise CertificateError(
            "activation annulée : vérification du certificat servi impossible"
            f" ({probe_error}) ; rollback effectué" + note
        ) from probe_error
    return generation, served


def nginx_reloader() -> None:
    """Validate the standalone nginx configuration, then reload the master.

    ``-c`` is mandatory: without it ``nginx -t`` reads
    ``/etc/nginx/nginx.conf`` — the proxy-mode config that references no
    certificate — and would pass while the running standalone master
    rejects the reload.
    """
    for args in (
        ("nginx", "-t", "-c", STANDALONE_NGINX_CONFIG),
        ("nginx", "-s", "reload", "-c", STANDALONE_NGINX_CONFIG),
    ):
        environment = dict(os.environ, LC_ALL="C", LANG="C")
        try:
            result = subprocess.run(
                [*args],
                capture_output=True,
                timeout=15,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CertificateError(f"{' '.join(args)} impossible : {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr + result.stdout).decode("utf-8", "replace")[-400:]
            raise CertificateError(f"{' '.join(args)} a échoué : {detail.strip()}")


def tls_fingerprint_smoker(
    hostname: str, *, host: str = "127.0.0.1", port: int = 443, timeout: float = 5.0
) -> Callable[[], str]:
    """Closure that returns the SHA-256 of the certificate actually served."""

    def smoke() -> str:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as connection,
                context.wrap_socket(connection, server_hostname=hostname) as tls_socket,
            ):
                der = tls_socket.getpeercert(binary_form=True)
        except OSError as exc:
            raise CertificateError(f"contact TLS impossible sur {host}:{port} : {exc}") from exc
        if not der:
            raise CertificateError("aucun certificat servi par le backend TLS")
        return hashlib.sha256(der).hexdigest()

    return smoke

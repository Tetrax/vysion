import re
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Same DNS/hostname syntax the audit already enforces on FortiGate hostnames:
# labels of 1 to 63 characters, letters/digits/hyphen, 253 characters overall.
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)"
    r"(\.([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?))*$"
)

# The authoritative browser origin: scheme + authority, nothing else. No
# path, no query, no fragment, no userinfo — exactly what an Origin header
# and a reset link are built from.
PUBLIC_ORIGIN_PATTERN = re.compile(
    r"^(?P<scheme>https?)://"
    r"(?P<host>\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)"
    r"(?::(?P<port>\d{1,5}))?$"
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VYSION_", frozen=True)

    report_directory: Path = Path("/app/data/reports")
    report_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    max_upload_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=5 * 1024 * 1024)
    fortiguard_status_url: str = "https://www.fortiguard.com/"

    # Durable admin state: a volume of its own, never inside the TTL-purged
    # reports directory. When it is not set explicitly it resolves next to the
    # reports directory, so a stack only has to mount the sibling volume.
    state_directory: Path | None = None
    # Certificate generations, only mounted in the standalone TLS mode.
    certs_directory: Path = Path("/app/certs")
    session_ttl_seconds: int = Field(default=43_200, ge=300, le=86_400)
    # Forwarded headers are believed only when they come from these networks.
    trusted_proxy_cidrs: str = "127.0.0.1/32"
    tls_backend: str = Field(default="none", pattern="^(none|local|helper)$")
    tls_hostname: str = ""
    # Private Unix socket of the root certificate helper (helper mode only).
    helper_socket_path: Path = Path("/run/vysion-cert-helper/helper.sock")
    # The one authority an admin mutation, an exact-Origin check and an
    # emailed reset link are allowed to use (e.g. https://vysion.example.com).
    # Empty in the proxy/VPS modes unless the operator configures it; derived
    # from tls_hostname in the standalone mode where that name is mandatory.
    public_origin: str = ""

    @model_validator(mode="after")
    def _require_hostname_when_managed(self) -> "Settings":
        if self.tls_backend in {"local", "helper"}:
            hostname = self.tls_hostname.strip().lower()
            if not HOSTNAME_PATTERN.fullmatch(hostname):
                raise ValueError(
                    f"tls_hostname must be a valid DNS name when tls_backend is {self.tls_backend}"
                )
            object.__setattr__(self, "tls_hostname", hostname)
        return self

    @model_validator(mode="after")
    def _normalize_public_origin(self) -> "Settings":
        origin = (self.public_origin or "").strip().lower()
        if not origin:
            # Standalone always knows the name it serves: derive the
            # authoritative origin instead of trusting any Host header.
            if self.tls_backend == "local":
                origin = f"https://{self.tls_hostname}"
            object.__setattr__(self, "public_origin", origin)
            return self
        match = PUBLIC_ORIGIN_PATTERN.fullmatch(origin)
        if match is None:
            raise ValueError(
                "public_origin must be a bare origin: http(s)://host[:port]"
            )
        port = match.group("port")
        scheme = match.group("scheme")
        if port is not None and not 1 <= int(port) <= 65535:
            raise ValueError("public_origin port must be between 1 and 65535")
        # Browsers never send a default port in Host/Origin: canonicalize so
        # the exact comparison cannot be bypassed by writing :443/:80.
        if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
            origin = f"{scheme}://{match.group('host')}"
        object.__setattr__(self, "public_origin", origin)
        return self

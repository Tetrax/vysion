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
    tls_backend: str = Field(default="none", pattern="^(none|local)$")
    tls_hostname: str = ""

    @model_validator(mode="after")
    def _require_hostname_with_local_backend(self) -> "Settings":
        if self.tls_backend == "local":
            hostname = self.tls_hostname.strip().lower()
            if not HOSTNAME_PATTERN.fullmatch(hostname):
                raise ValueError("tls_hostname must be a valid DNS name when tls_backend is local")
            object.__setattr__(self, "tls_hostname", hostname)
        return self

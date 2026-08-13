from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VYSION_", frozen=True)

    report_directory: Path = Path("/app/data/reports")
    report_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    max_upload_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=5 * 1024 * 1024)
    fortiguard_status_url: str = "https://www.fortiguard.com/"

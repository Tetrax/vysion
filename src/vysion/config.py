from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VYSION_", frozen=True)

    report_directory: Path = Path("/app/data/reports")
    report_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    max_upload_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=5 * 1024 * 1024)
    api_token: str | None = None
    fortiguard_status_url: str = "https://www.fortiguard.com/"

    @field_validator("api_token", mode="before")
    @classmethod
    def normalize_api_token(cls, value: object) -> str | None:
        if value is None or value == "":
            return None
        if not isinstance(value, str) or len(value) < 16:
            raise ValueError("api_token must contain at least 16 characters")
        return value

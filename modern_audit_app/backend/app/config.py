from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Settings for the audit application
    # No longer needs legacy_path - functions are now in the app

    model_config = {
        "env_prefix": "AUDIT_",
        "case_sensitive": False,
    }


@lru_cache
def get_settings() -> Settings:
    return Settings()



"""
Adapter to load and call the legacy audit functions from `.venv/main_audit.py`.
This keeps feature parity while we modernize the app.
"""
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Optional

from app.config import get_settings


from functools import lru_cache


class LegacyAdapter:
    def __init__(self, module: ModuleType):
        self.module = module

    @classmethod
    @lru_cache(maxsize=1)
    def load(cls) -> "LegacyAdapter":
        settings = get_settings()
        legacy_path: Path = settings.legacy_path
        if not legacy_path.exists():
            raise FileNotFoundError(f"Legacy audit file not found at {legacy_path}")

        spec = spec_from_file_location("legacy_audit", legacy_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Unable to load legacy audit module")

        module = module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[arg-type]
        return cls(module)

    def get(self, name: str) -> Callable[..., Any]:
        try:
            return getattr(self.module, name)
        except AttributeError as exc:
            raise RuntimeError(f"Legacy function '{name}' not found") from exc

    # Convenience helpers
    def lire_config(self, path: Path):
        return self.get("lire_config_fortigate")(path)

    def extract_hostname(self, lines):
        return self.get("extraire_hostname")(lines)

    def extract_model_version(self, lines):
        return self.get("extraire_modele_version_fortigate")(lines)


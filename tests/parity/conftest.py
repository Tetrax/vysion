"""Environnement requis par le harnais de parité V1/V2.

Les tests de ce dossier exécutent l'oracle legacy dans un environnement isolé,
qui n'est pas embarqué dans le dépôt :

- interpréteur dédié : ``.legacy-venv`` à la racine du dépôt (surchargeable via
  ``VYSION_LEGACY_PYTHON``). Recette de provisionnement (manifest
  ``tools/parity/legacy-oracle-manifest.json``) :

      uv venv --python 3.12 .legacy-venv
      uv pip install --python .legacy-venv/bin/python -r tools/parity/legacy-requirements.lock

- source gelée de l'oracle (``legacy_functions.py``, hors dépôt) : le chemin par
  défaut est surchargeable via ``VYSION_LEGACY_SOURCE``.

Si l'un des deux manque, les tests concernés sont explicitement ignorés avec la
raison et la recette de provisionnement, au lieu d'échouer sur un environnement
implicite.
"""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))

DEFAULT_LEGACY_SOURCE = Path(
    "/home/tetrax/workspace/vysion/audit-fgt-vysion/backend/app/audit/legacy_functions.py"
)
DEFAULT_LEGACY_PYTHON = ROOT / ".legacy-venv" / "bin" / "python"


def legacy_python() -> Path:
    override = os.environ.get("VYSION_LEGACY_PYTHON")
    return Path(override) if override else DEFAULT_LEGACY_PYTHON


def legacy_source() -> Path:
    override = os.environ.get("VYSION_LEGACY_SOURCE")
    return Path(override) if override else DEFAULT_LEGACY_SOURCE


def _missing_parts() -> list[str]:
    missing = []
    if not legacy_python().is_file():
        missing.append(f"interpréteur legacy absent: {legacy_python()}")
    if not legacy_source().is_file():
        missing.append(f"source legacy absente: {legacy_source()}")
    return missing


LEGACY_SKIP_REASON = (
    "oracle legacy non provisionné — provisionner l'interpréteur dédié "
    "(uv venv --python 3.12 .legacy-venv && uv pip install --python "
    ".legacy-venv/bin/python -r tools/parity/legacy-requirements.lock, recette de "
    "tools/parity/legacy-oracle-manifest.json) et fournir la source gelée via "
    "VYSION_LEGACY_SOURCE si elle n'est pas au chemin par défaut"
)


@pytest.fixture(scope="session")
def legacy_oracle():
    from tools.parity.legacy_oracle import LegacyOracle

    missing = _missing_parts()
    if missing:
        pytest.skip(LEGACY_SKIP_REASON + " (" + "; ".join(missing) + ")")
    return LegacyOracle(python=legacy_python(), source=legacy_source())
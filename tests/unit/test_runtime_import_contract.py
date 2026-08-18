from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_network_parity_imports_without_p1_sdwan_evidence_helper() -> None:
    repository = Path(__file__).parents[2]
    script = """
import importlib
import sys
import types

module = types.ModuleType("vysion.audit.controls._evidence")
module.evidence_for_directive = lambda *args, **kwargs: None
module.evidence_for_section = lambda *args, **kwargs: None
module.section_for = lambda *args, **kwargs: None
sys.modules[module.__name__] = module
importlib.import_module("vysion.audit.controls.network_parity")
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(repository / "src")
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

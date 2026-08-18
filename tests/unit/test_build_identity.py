from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_build_identity_reads_shared_version_and_injected_revision() -> None:
    repository = Path(__file__).parents[2]
    expected_version = (repository / "VERSION").read_text(encoding="utf-8").strip()
    expected_revision = "test-revision-123"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(repository / "src")
    environment["VYSION_REVISION"] = expected_revision
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from vysion.build_info import VYSION_REVISION, VYSION_VERSION; "
            "print(VYSION_VERSION); print(VYSION_REVISION)",
        ],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [expected_version, expected_revision]

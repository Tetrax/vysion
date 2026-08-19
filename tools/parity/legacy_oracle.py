import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class LegacyOracleError(RuntimeError):
    """Raised when the isolated legacy worker cannot return a valid result."""


@dataclass(frozen=True, slots=True)
class LegacyOracle:
    python: Path
    source: Path
    timeout_seconds: int = 30

    def run(
        self,
        capability: str,
        *,
        config: str | None = None,
        args: list[Any] | None = None,
    ) -> Any:
        request = {
            "source": str(self.source.resolve()),
            "capability": capability,
            "config": config,
            "args": args,
        }
        worker = Path(__file__).with_name("legacy_worker.py")
        try:
            completed = subprocess.run(
                [str(self.python), "-I", str(worker)],
                input=json.dumps(request, ensure_ascii=False),
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LegacyOracleError(f"legacy worker failed: {error}") from error

        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            detail = completed.stderr.strip() or completed.stdout.strip() or "no worker output"
            raise LegacyOracleError(f"legacy worker protocol error: {detail}") from error

        if completed.returncode != 0 or not response.get("ok"):
            detail = response.get("error") or completed.stderr.strip() or "unknown worker error"
            raise LegacyOracleError(str(detail))
        return response["result"]

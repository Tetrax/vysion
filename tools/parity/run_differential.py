import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))

from tools.parity.corpus import real_reference_cases, synthetic_cases  # noqa: E402
from tools.parity.differential import DifferentialHarness  # noqa: E402
from tools.parity.legacy_oracle import LegacyOracle  # noqa: E402
from vysion.audit.parser import FortiGateParser  # noqa: E402

DEFAULT_ORACLE_SOURCE = Path(
    "/home/tetrax/workspace/vysion/audit-fgt-vysion/backend/app/audit/legacy_functions.py"
)
DEFAULT_LEGACY_PYTHON = Path(".legacy-venv/bin/python")


def run(
    *,
    output: Path,
    real_config: Path | None = None,
    oracle_source: Path = DEFAULT_ORACLE_SOURCE,
    legacy_python: Path = DEFAULT_LEGACY_PYTHON,
) -> dict[str, Any]:
    oracle = LegacyOracle(python=legacy_python, source=oracle_source)
    harness = DifferentialHarness(oracle)
    if real_config is None:
        corpus_name = "synthetic"
        cases = synthetic_cases()
        redact = False
        projection_summary = None
    else:
        corpus_name = "real-reference-redacted"
        raw = real_config.read_text(encoding="utf-8")
        cases = real_reference_cases(raw)
        redact = True
        projection_summary = {
            "active_interface_count": len(FortiGateParser().parse(raw).interfaces)
        }

    report = {"schema_version": 1, "corpus": corpus_name}
    if projection_summary is not None:
        report["projection_summary"] = projection_summary
    report.update(harness.run_cases(cases, redact=redact))
    normalized = json.loads(json.dumps(report, ensure_ascii=False, sort_keys=True))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the isolated V1/V2 differential corpus")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--real-config", type=Path)
    parser.add_argument("--oracle-source", type=Path, default=DEFAULT_ORACLE_SOURCE)
    parser.add_argument("--legacy-python", type=Path, default=DEFAULT_LEGACY_PYTHON)
    args = parser.parse_args()
    report = run(
        output=args.output,
        real_config=args.real_config,
        oracle_source=args.oracle_source,
        legacy_python=args.legacy_python,
    )
    print(json.dumps(report["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

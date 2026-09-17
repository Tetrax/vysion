import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))

from tools.parity.run_differential import run  # noqa: E402


def test_runner_writes_replayable_synthetic_report(tmp_path: Path, legacy_oracle) -> None:
    output = tmp_path / "report.json"

    report = run(
        output=output,
        oracle_source=legacy_oracle.source,
        legacy_python=legacy_oracle.python,
    )

    assert report["corpus"] == "synthetic"
    assert report["summary"]["total"] == 10
    assert report["summary"]["semantic_equivalences"] == 1
    assert report["summary"]["unresolved_divergences"] == 0
    assert output.exists()
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_runner_records_only_redacted_projection_counts_for_real_input(
    tmp_path: Path, legacy_oracle
) -> None:
    source = tmp_path / "reference.conf"
    source.write_text(
        """#config-version=FGT60F-7.2.9-FW-build1-1:opmode=0
#buildno=1
#global_vdom=1
#conf_file_ver=1
config system interface
    edit "wan1"
        set status up
    next
    edit "modem"
        set status down
    next
end
""",
        encoding="utf-8",
    )

    report = run(
        output=tmp_path / "redacted.json",
        real_config=source,
        oracle_source=legacy_oracle.source,
        legacy_python=legacy_oracle.python,
    )

    assert report["projection_summary"] == {"active_interface_count": 1}
    assert all(item["legacy_message"] == "[redacted]" for item in report["results"])
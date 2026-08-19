import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))

from tools.parity.differential import DifferentialCase, DifferentialHarness  # noqa: E402
from tools.parity.legacy_oracle import LegacyOracle  # noqa: E402

ORACLE = LegacyOracle(
    python=Path(".legacy-venv/bin/python"),
    source=Path(
        "/home/tetrax/workspace/vysion/audit-fgt-vysion/backend/app/audit/legacy_functions.py"
    ),
)
BACKUP_HEADER = """\
#config-version=FGT60F-7.2.9-FW-build1-1:opmode=0
#buildno=1
#global_vdom=1
#conf_file_ver=1
"""


def test_differential_harness_reports_matching_guest_behavior() -> None:
    case = DifferentialCase(
        case_id="guest-present",
        legacy_callable="verifier_compte_guest",
        v2_control_id="IAM-GUEST-ACCOUNT-001",
        config=(
            BACKUP_HEADER
            + 'config user local\n    edit "guest"\n        set type password\n    next\nend\n'
        ),
    )

    result = DifferentialHarness(ORACLE).run_case(case)

    assert result.case_id == "guest-present"
    assert result.legacy_status == "FAIL"
    assert result.v2_status == "FAIL"
    assert result.transition == "FAIL->FAIL"
    assert result.match is True


def test_guest_absence_matches_v1_on_complete_user_local_namespace() -> None:
    case = DifferentialCase(
        case_id="guest-absent",
        legacy_callable="verifier_compte_guest",
        v2_control_id="IAM-GUEST-ACCOUNT-001",
        config=(
            BACKUP_HEADER
            + 'config user local\n    edit "analyst"\n        set type password\n    next\nend\n'
        ),
    )

    result = DifferentialHarness(ORACLE).run_case(case)

    assert result.legacy_status == "PASS"
    assert result.v2_status == "PASS"
    assert result.match is True


def test_differential_harness_keeps_status_divergence_visible() -> None:
    case = DifferentialCase(
        case_id="ssl-vpn-absent",
        legacy_callable="verifier_vpn_ssl_utilisation",
        v2_control_id="VPN-SSL-001",
        config=(
            BACKUP_HEADER
            + "config system global\n    set hostname parity.example\nend\n"
            + "config vpn ssl settings\n    set status disable\nend\n"
        ),
        accepted_transitions=("PASS->NOT_APPLICABLE",),
    )

    result = DifferentialHarness(ORACLE).run_case(case)

    assert result.legacy_status == "PASS"
    assert result.v2_status == "NOT_APPLICABLE"
    assert result.transition == "PASS->NOT_APPLICABLE"
    assert result.match is False
    assert result.classification == "SEMANTIC_EQUIVALENT"


def test_differential_harness_summarizes_a_batch_without_client_evidence() -> None:
    cases = (
        DifferentialCase(
            case_id="guest-present",
            legacy_callable="verifier_compte_guest",
            v2_control_id="IAM-GUEST-ACCOUNT-001",
            config=(
                BACKUP_HEADER
                + 'config user local\n    edit "guest"\n        set type password\n    next\nend\n'
            ),
        ),
        DifferentialCase(
            case_id="ssl-vpn-disabled",
            legacy_callable="verifier_vpn_ssl_utilisation",
            v2_control_id="VPN-SSL-001",
            config=(
                BACKUP_HEADER
                + "config vpn ssl settings\n    set status disable\nend\n"
            ),
            accepted_transitions=("PASS->NOT_APPLICABLE",),
        ),
    )

    report = DifferentialHarness(ORACLE).run_cases(cases, redact=True)

    assert report["summary"] == {
        "total": 2,
        "matches": 1,
        "divergences": 1,
        "semantic_equivalences": 1,
        "unresolved_divergences": 0,
    }
    assert report["results"][0]["legacy_message"] == "[redacted]"
    assert report["results"][0]["v2_evidence"] == []
    assert report["results"][0]["affected_objects"] == []

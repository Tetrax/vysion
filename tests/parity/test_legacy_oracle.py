import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))

from tools.parity.legacy_oracle import LegacyOracleError  # noqa: E402

CONFIG_WITHOUT_GUEST = """\
config user local
    edit "analyst"
        set type password
    next
end
"""


def test_legacy_oracle_replays_a_capability_deterministically(legacy_oracle) -> None:
    first = legacy_oracle.run("verifier_compte_guest", config=CONFIG_WITHOUT_GUEST)
    second = legacy_oracle.run("verifier_compte_guest", config=CONFIG_WITHOUT_GUEST)

    assert first == second
    assert first[1] is True
    assert "guest" in first[0].lower()


def test_legacy_oracle_rejects_unknown_capability(legacy_oracle) -> None:
    with pytest.raises(LegacyOracleError, match="not allowed"):
        legacy_oracle.run("creer_rapport_word", config=CONFIG_WITHOUT_GUEST)


def test_legacy_oracle_denies_unfrozen_network_access(legacy_oracle) -> None:
    with pytest.raises(LegacyOracleError, match="network access denied"):
        legacy_oracle.run("est_version_concernee_par_cve", args=["7.2.7"])
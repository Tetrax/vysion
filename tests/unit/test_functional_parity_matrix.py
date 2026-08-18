import re
from pathlib import Path


def test_functional_parity_matrix_has_exactly_59_unique_rows_and_two_real_blockers() -> None:
    document = (Path(__file__).parents[2] / "docs" / "V2_3_FUNCTIONAL_PARITY.md").read_text()
    matrix = document.split("## Matrice exhaustive des 59 capacités V1", 1)[1].split(
        "## Synthèse courante", 1
    )[0]
    rows = re.findall(r"^\|\s*(\d+)\s*\|.*?\|\s*([ABC])\s*\|", matrix, re.MULTILINE)

    assert [int(row_id) for row_id, _ in rows] == list(range(1, 60))
    assert [state for _, state in rows].count("A") == 57
    assert [state for _, state in rows].count("B") == 0
    assert [state for _, state in rows].count("C") == 2
    assert "Disposition réellement `MIGRATED` : **57 / 59**" in document

    dispositions = re.findall(
        r"^\|\s*(\d+)\s*\|.*?\|\s*`(MIGRATED|BLOCKED_EXTERNAL_SOURCE|BLOCKED_RUNTIME_DATA|LEGACY_REVIEW_REQUIRED)`\s*\|",
        document,
        re.MULTILINE,
    )
    assert sorted(int(row_id) for row_id, _ in dispositions) == list(range(1, 60))
    assert [state for _, state in dispositions].count("MIGRATED") == 57
    assert [state for _, state in dispositions].count("BLOCKED_EXTERNAL_SOURCE") == 1
    assert [state for _, state in dispositions].count("BLOCKED_RUNTIME_DATA") == 1
    assert [state for _, state in dispositions].count("LEGACY_REVIEW_REQUIRED") == 0

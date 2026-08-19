import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))

from tools.parity.corpus import real_reference_cases, synthetic_cases  # noqa: E402


def test_synthetic_corpus_is_bounded_and_deterministic() -> None:
    first = synthetic_cases()
    second = synthetic_cases()

    assert first == second
    assert len(first) == 10
    assert len({case.case_id for case in first}) == 10


def test_real_reference_cases_do_not_embed_or_persist_the_source_path() -> None:
    raw = "config system global\n    set hostname reference.example\nend\n"

    cases = real_reference_cases(raw)

    assert len(cases) == 7
    assert all(case.config == raw for case in cases)

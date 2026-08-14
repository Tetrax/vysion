from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_RULESET = Path(__file__).with_name("external_services.json")


@lru_cache(maxsize=1)
def _data() -> dict[str, object]:
    value = json.loads(_RULESET.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("external-services ruleset must be an object")
    return value


def label() -> str:
    data = _data()
    return f"{data['id']}@{data['version']}"


def expected_cti_resources(model: str) -> tuple[str, ...]:
    data = _data()["cti"]
    if not isinstance(data, dict):
        raise ValueError("cti ruleset must be an object")
    normalized = model.upper()
    key = next(
        (
            candidate
            for candidate in ("30E,50E", "60E,80E,40F")
            if normalized in candidate.split(",")
        ),
        "default",
    )
    values = data[key]
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("invalid CTI resource list")
    return tuple(values)


def expected_cti_ipv4(model: str) -> tuple[str, ...]:
    return tuple(value for value in expected_cti_resources(model) if value.startswith("IPV4"))


def expected_isdb(direction: str) -> tuple[str, ...]:
    data = _data()["isdb"]
    if not isinstance(data, dict) or direction not in {"incoming", "outgoing"}:
        raise ValueError("invalid ISDB direction")
    values = data[direction]
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("invalid ISDB list")
    return tuple(values)

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_RULESET = Path(__file__).with_name("dnsfilter_blocklists.json")


@lru_cache(maxsize=1)
def _load() -> dict[str, object]:
    payload = json.loads(_RULESET.read_text(encoding="utf-8"))
    if not isinstance(payload.get("id"), str) or not isinstance(payload.get("version"), str):
        raise ValueError("invalid DNS Filter ruleset identity")
    models = payload.get("models")
    default = payload.get("default")
    if not isinstance(models, dict) or not isinstance(default, list):
        raise ValueError("invalid DNS Filter ruleset mappings")
    if not all(
        isinstance(model, str)
        and isinstance(values, list)
        and values
        and all(isinstance(value, str) and value for value in values)
        for model, values in models.items()
    ):
        raise ValueError("invalid DNS Filter model mapping")
    if not default or not all(isinstance(value, str) and value for value in default):
        raise ValueError("invalid DNS Filter default mapping")
    return payload


def dnsfilter_ruleset_label() -> str:
    payload = _load()
    return f"{payload['id']}@{payload['version']}"


def required_dnsfilter_blocklists(model: str) -> frozenset[str]:
    payload = _load()
    normalized = model.upper().removeprefix("FORTIGATE").removeprefix("FGT").removeprefix("FG")
    models = payload["models"]
    assert isinstance(models, dict)
    values = models.get(normalized, payload["default"])
    assert isinstance(values, list)
    return frozenset(values)

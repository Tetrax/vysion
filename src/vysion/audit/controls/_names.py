from collections.abc import Iterable
from typing import Any


def unique_named(items: Iterable[Any]) -> tuple[dict[str, Any], frozenset[str]]:
    """Index named objects case-insensitively without resolving collisions."""
    resolved: dict[str, Any] = {}
    collisions: set[str] = set()
    for item in items:
        key = item.name.casefold()
        if key in resolved:
            collisions.add(key)
            resolved.pop(key)
        elif key not in collisions:
            resolved[key] = item
    return resolved, frozenset(collisions)

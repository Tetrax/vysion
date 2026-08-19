import importlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

SUPPORT_CALLABLES = {"est_version_concernee_par_cve"}
_NETWORK_ATTEMPTED = False


def _allowed_capabilities() -> set[str]:
    mapping_path = Path(__file__).parents[2] / "docs" / "V1_V2_CAPABILITY_MAP.json"
    payload = json.loads(mapping_path.read_text(encoding="utf-8"))
    return {
        item["legacy_callable"] for item in payload["legacy_capabilities"]
    } | SUPPORT_CALLABLES


def _deny_network(*_args: Any, **_kwargs: Any) -> Any:
    global _NETWORK_ATTEMPTED
    _NETWORK_ATTEMPTED = True
    raise RuntimeError("network access denied: provide a frozen external response")


def _load_legacy(source: Path) -> Any:
    backend = source.parents[2]
    sys.path.insert(0, str(backend))
    module = importlib.import_module("app.audit.legacy_functions")
    module.requests.get = _deny_network
    return module


def _run(request: dict[str, Any]) -> Any:
    capability = str(request["capability"])
    if capability not in _allowed_capabilities():
        raise ValueError(f"legacy capability not allowed: {capability}")

    source = Path(request["source"])
    if source.name != "legacy_functions.py" or not source.is_file():
        raise ValueError("invalid legacy oracle source")
    legacy = _load_legacy(source)
    target = getattr(legacy, capability)

    config = request.get("config")
    args = request.get("args")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".conf", delete=True
    ) as handle:
        if config is not None:
            handle.write(config)
            handle.flush()
            legacy.imported_filepath = handle.name
            legacy.imported_filename = Path(handle.name).name
            config_lines = config.splitlines(keepends=True)
        else:
            config_lines = None

        if args is None:
            call_args = [] if config_lines is None else [config_lines]
        else:
            call_args = [config_lines if value == "$CONFIG_LINES" else value for value in args]
        result = target(*call_args)
        if _NETWORK_ATTEMPTED:
            raise RuntimeError("network access denied: provide a frozen external response")
        return result


def main() -> int:
    try:
        request = json.loads(sys.stdin.read())
        result = _run(request)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as error:
        print(
            json.dumps(
                {"ok": False, "error": str(error), "error_type": type(error).__name__},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

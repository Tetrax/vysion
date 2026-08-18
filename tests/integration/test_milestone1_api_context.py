import json
from pathlib import Path

import httpx
import pytest

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.api.app import create_app
from vysion.config import Settings

CONFIGURATION = b"""config system global
    set hostname api-context.example
end
config system interface
    edit "wan1"
        set allowaccess ping https
    next
end
"""


class AvailableFortiGuard:
    async def check(self) -> FortiGuardResult:
        return FortiGuardResult(status=FortiGuardStatus.AVAILABLE, detail="fixture")


def api_client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://vysion.test",
    )


@pytest.mark.asyncio
async def test_api_builds_and_persists_context_from_repeatable_form_fields(
    tmp_path: Path,
) -> None:
    app = create_app(settings=Settings(report_directory=tmp_path), fortiguard=AvailableFortiGuard())

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits",
            files=[
                ("selected_wans", (None, "wan1")),
                ("selected_wans", (None, json.dumps(["wan2"]))),
                ("client", (None, "Client synthétique")),
                ("site", (None, "Paris-lab")),
                (
                    "operator_context",
                    (
                        None,
                        json.dumps(
                            {
                                "source": "operator-form",
                                "operator": "analyst@example.invalid",
                                "method": "manual-selection",
                            }
                        ),
                    ),
                ),
                ("ha_context", (None, "true")),
                ("mpls_context", (None, "unknown")),
                ("utm_license", (None, "false")),
                ("configuration", ("context.conf", CONFIGURATION, "text/plain")),
            ],
        )

        assert response.status_code == 201
        payload = response.json()

    assert payload["context"]["selected_wans"] == ["wan1", "wan2"]
    assert payload["context"]["client"] == "Client synthétique"
    assert payload["context"]["site"] == "Paris-lab"
    assert payload["context"]["ha"] is True
    assert payload["context"]["mpls"] is None
    assert payload["context"]["utm_license"] is False
    assert payload["context"]["operator_provenance"] == {
        "source": "operator-form",
        "operator": "analyst@example.invalid",
        "captured_at": None,
        "method": "manual-selection",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("selected_wans", "[not-json"),
        ("ha_context", "maybe"),
        ("operator_context", json.dumps({"unexpected": "field"})),
    ],
)
async def test_api_rejects_invalid_context_fields_without_persisting_a_report(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    app = create_app(settings=Settings(report_directory=tmp_path), fortiguard=AvailableFortiGuard())

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits",
            data={field: value},
            files={"configuration": ("context.conf", CONFIGURATION, "text/plain")},
        )

    assert response.status_code == 422
    assert not list(tmp_path.glob("*.json"))


@pytest.mark.asyncio
async def test_api_preserves_an_explicitly_empty_wan_selection(tmp_path: Path) -> None:
    app = create_app(settings=Settings(report_directory=tmp_path), fortiguard=AvailableFortiGuard())

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits",
            data={"selected_wans": "[]"},
            files={"configuration": ("context.conf", CONFIGURATION, "text/plain")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["context"]["selected_wans"] == []
    findings = {finding["control_id"]: finding for finding in payload["findings"]}
    assert findings["NET-WAN-MGMT-001"]["status"] == "UNKNOWN"

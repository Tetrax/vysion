import json
from pathlib import Path

import httpx
import pytest

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.api.app import create_app
from vysion.config import Settings

CONFIGURATION = b"""config system global
    set hostname business-context.example
end
config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
    next
    edit "lan1"
        set role lan
        set allowaccess ping
    next
end
config system zone
    edit "internet"
        set interface "wan1"
    next
end
config system sdwan
    edit "virtual-wan-link"
        set interface "wan1"
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
async def test_preview_exposes_only_primary_identity_plus_typed_wan_relations(
    tmp_path: Path,
) -> None:
    app = create_app(settings=Settings(report_directory=tmp_path), fortiguard=AvailableFortiGuard())

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits/preview",
            files={"configuration": ("business.conf", CONFIGURATION, "text/plain")},
        )

    assert response.status_code == 200
    payload = response.json()
    assert {
        "hostname",
        "model",
        "firmware_version",
        "interfaces",
        "zones",
        "sdwan_zones",
    } <= payload.keys()
    assert payload["interfaces"] == [
        {"name": "wan1", "role": "wan"},
        {"name": "lan1", "role": "lan"},
    ]
    assert payload["zones"] == [{"name": "internet", "interfaces": ["wan1"]}]
    assert payload["wan_relations"] == [{"interface": "wan1", "zone": "internet"}]
    assert payload["sdwan_zones"] == [
        {"name": "virtual-wan-link", "interfaces": ["wan1"]}
    ]


@pytest.mark.asyncio
async def test_api_persists_v1_context_and_resolves_zone_selection(
    tmp_path: Path,
) -> None:
    app = create_app(settings=Settings(report_directory=tmp_path), fortiguard=AvailableFortiGuard())

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits",
            data={
                "selected_wan_scopes": json.dumps(
                    [{"name": "internet", "kind": "zone"}]
                ),
                "client": "Client métier",
                "site": "Paris-DC1",
                "serial_number": "FGT60E123456789",
                "uptime": "42 days, 03:12:10",
                "unmatched_rules": "7",
                "ha_context": "true",
                "mpls_context": "false",
                "utm_license_status": "active",
                "utm_license_expiration": "2027-03-31",
                "utm_license_provenance": "FortiManager",
                "utm_license_manual": "false",
            },
            files={"configuration": ("business.conf", CONFIGURATION, "text/plain")},
        )

    assert response.status_code == 201
    context = response.json()["context"]
    assert context["client"] == "Client métier"
    assert context["site"] == "Paris-DC1"
    assert context["serial_number"] == "FGT60E123456789"
    assert context["uptime"] == "42 days, 03:12:10"
    assert context["rule_match_statistics"] == {
        "unmatched_rules": 7,
        "total_rules": None,
        "source": "operator",
        "method": "Firewall policy Hit Count <= 0",
    }
    assert context["ha"] is True
    assert context["mpls"] is False
    assert context["utm_license_details"] == {
        "status": "active",
        "expiration_date": "2027-03-31",
        "provenance": "FortiManager",
        "manual": False,
    }
    assert context["wan_selections"] == [
        {
            "name": "internet",
            "kind": "zone",
            "interfaces": ["wan1"],
        }
    ]
    assert context["selected_wans"] == ["internet"]
    report_json = response.json()
    assert "operator_comment" not in context
    assert "equipment" not in report_json
    assert "accounts" not in report_json


@pytest.mark.asyncio
async def test_api_rejects_conflicting_legacy_and_typed_wan_scopes(
    tmp_path: Path,
) -> None:
    app = create_app(settings=Settings(report_directory=tmp_path), fortiguard=AvailableFortiGuard())

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits",
            data={
                "selected_wans": json.dumps(["internet"]),
                "selected_wan_scopes": json.dumps(
                    [{"name": "wan1", "kind": "interface"}]
                ),
            },
            files={"configuration": ("business.conf", CONFIGURATION, "text/plain")},
        )

    assert response.status_code == 422

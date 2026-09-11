from pathlib import Path

import httpx
import pytest

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.api.app import create_app
from vysion.config import Settings

PREVIEW_CONFIGURATION = b"""#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0:vdom=0:user=admin
config system global
    set hostname preview-lab.example
end
config system interface
    edit "wan1"
        set alias "4G Bouygues"
        set ip 192.0.2.10 255.255.255.0
        set role wan
        set allowaccess ping
    next
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
        set role lan
        set allowaccess ping
    next
end
config system zone
    edit "internet"
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
async def test_preview_returns_safe_identity_interfaces_and_zones_without_persisting(
    tmp_path: Path,
) -> None:
    app = create_app(settings=Settings(report_directory=tmp_path), fortiguard=AvailableFortiGuard())

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits/preview",
            files={"configuration": ("preview.conf", PREVIEW_CONFIGURATION, "text/plain")},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["hostname"] == "preview-lab.example"
    assert payload["model"] == "60E"
    assert payload["firmware_version"] == "7.2.9"
    assert payload["interfaces"] == [
        {"name": "wan1", "role": "wan", "label": "4G Bouygues"},
        {"name": "port1", "role": "lan"},
    ]
    assert payload["zones"] == [{"name": "internet", "interfaces": ["wan1"]}]
    assert payload["sdwan_zones"] == []
    assert list(tmp_path.glob("*.json")) == []


@pytest.mark.asyncio
async def test_preview_exposes_only_certain_sdwan_zone_interfaces(tmp_path: Path) -> None:
    configuration = PREVIEW_CONFIGURATION + b'''config system sdwan
    edit "virtual-wan-link"
        set interface "wan1" "port1"
    next
end
'''
    app = create_app(settings=Settings(report_directory=tmp_path), fortiguard=AvailableFortiGuard())

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits/preview",
            files={"configuration": ("sdwan.conf", configuration, "text/plain")},
        )

    assert response.status_code == 200
    assert response.json()["sdwan_zones"] == [
        {
            "name": "virtual-wan-link",
            "interfaces": ["port1", "wan1"],
            "proof_state": "proven",
        }
    ]
    assert response.json()["sdwan_members"] == [
        {"name": "wan1", "zones": ["virtual-wan-link"]},
        {"name": "port1", "zones": ["virtual-wan-link"]},
    ]


@pytest.mark.asyncio
async def test_preview_rejects_oversized_upload_without_creating_a_report(tmp_path: Path) -> None:
    app = create_app(
        settings=Settings(report_directory=tmp_path, max_upload_bytes=1024),
        fortiguard=AvailableFortiGuard(),
    )

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits/preview",
            files={"configuration": ("large.conf", b"x" * 1025, "text/plain")},
        )

    assert response.status_code == 413
    assert list(tmp_path.glob("*.json")) == []


@pytest.mark.asyncio
async def test_preview_rejects_non_utf8_upload_without_creating_a_report(tmp_path: Path) -> None:
    app = create_app(settings=Settings(report_directory=tmp_path), fortiguard=AvailableFortiGuard())

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits/preview",
            files={"configuration": ("binary.conf", b"config system global\n\xff", "text/plain")},
        )

    assert response.status_code == 400
    assert list(tmp_path.glob("*.json")) == []

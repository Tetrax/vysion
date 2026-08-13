from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from uuid import UUID
from zipfile import ZipFile

import httpx
import pytest
from openpyxl import load_workbook

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.api.app import create_app
from vysion.config import Settings

SYNTHETIC_CONFIG = b"""\
# Synthetic fixture created for Vysion v2
config system global
    set hostname "api-lab.example"
end
config system interface
    edit "wan1"
        set ip 192.0.2.20 255.255.255.0
        set allowaccess ping https
    next
end
config system admin
    edit "secops"
        set two-factor fortitoken
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
async def test_api_stores_a_typed_json_report_under_uuid_and_serves_it(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    settings = Settings(report_directory=tmp_path, report_ttl_seconds=60)
    app = create_app(settings=settings, fortiguard=AvailableFortiGuard(), clock=lambda: now)

    async with api_client(app) as client:
        response = await client.post(
            "/api/audits",
            files={"configuration": ("synthetic.conf", SYNTHETIC_CONFIG, "text/plain")},
        )

        assert response.status_code == 201
        assert response.headers["cache-control"] == "no-store, private"
        payload = response.json()
        report_id = UUID(payload["report_id"], version=4)
        assert payload["expires_at"] == (now + timedelta(seconds=60)).isoformat().replace(
            "+00:00", "Z"
        )
        assert payload["fortiguard"]["status"] == "AVAILABLE"
        assert [finding["status"] for finding in payload["findings"]] == [
            "PASS",
            "PASS",
            "PASS",
        ]
        assert (tmp_path / f"{report_id}.json").is_file()

        stored = await client.get(f"/api/reports/{report_id}.json")
        assert stored.status_code == 200
        assert stored.headers["content-type"] == "application/json"
        assert stored.headers["cache-control"] == "no-store, private"
        assert stored.json() == payload


@pytest.mark.asyncio
async def test_api_generates_docx_from_the_stored_typed_report(tmp_path: Path) -> None:
    now = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    app = create_app(
        settings=Settings(report_directory=tmp_path, report_ttl_seconds=60),
        fortiguard=AvailableFortiGuard(),
        clock=lambda: now,
    )

    async with api_client(app) as client:
        created = await client.post(
            "/api/audits",
            files={"configuration": ("synthetic.conf", SYNTHETIC_CONFIG, "text/plain")},
        )
        report_id = UUID(created.json()["report_id"])

        response = await client.get(f"/api/reports/{report_id}.docx")

    assert response.status_code == 200
    assert response.headers["content-type"] == (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["content-disposition"] == (
        f'attachment; filename="vysion-{report_id}.docx"'
    )
    with ZipFile(BytesIO(response.content)) as package:
        document = package.read("word/document.xml").decode("utf-8")
    assert "Rapport d’audit Vysion" in document
    assert "synthetic.conf" in document
    assert "SYS-HOSTNAME-001" in document
    assert "AVAILABLE" in document


@pytest.mark.asyncio
async def test_api_generates_xlsx_from_the_stored_typed_report(tmp_path: Path) -> None:
    now = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    app = create_app(
        settings=Settings(report_directory=tmp_path, report_ttl_seconds=60),
        fortiguard=AvailableFortiGuard(),
        clock=lambda: now,
    )

    async with api_client(app) as client:
        created = await client.post(
            "/api/audits",
            files={"configuration": ("synthetic.conf", SYNTHETIC_CONFIG, "text/plain")},
        )
        report_id = UUID(created.json()["report_id"])

        response = await client.get(f"/api/reports/{report_id}.xlsx")

    assert response.status_code == 200
    assert response.headers["content-type"] == (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["content-disposition"] == (
        f'attachment; filename="vysion-{report_id}.xlsx"'
    )
    workbook = load_workbook(BytesIO(response.content), read_only=True, data_only=True)
    assert workbook.sheetnames == ["Synthèse", "Contrôles"]
    summary = {
        str(key): value
        for key, value in workbook["Synthèse"].iter_rows(
            min_row=1,
            max_col=2,
            values_only=True,
        )
    }
    assert summary["Source"] == "synthetic.conf"
    assert summary["FortiGuard"] == "AVAILABLE"
    controls = list(workbook["Contrôles"].iter_rows(values_only=True))
    assert controls[0] == ("Contrôle", "Titre", "Statut", "Constat", "Risque", "Recommandation")
    assert controls[1][0] == "SYS-HOSTNAME-001"
    assert controls[1][2] == "PASS"


@pytest.mark.asyncio
async def test_expired_report_is_deleted_and_returns_404(tmp_path: Path) -> None:
    current = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    settings = Settings(report_directory=tmp_path, report_ttl_seconds=60)
    app = create_app(settings=settings, fortiguard=AvailableFortiGuard(), clock=lambda: current)

    async with api_client(app) as client:
        created = (
            await client.post(
                "/api/audits",
                files={"configuration": ("synthetic.conf", SYNTHETIC_CONFIG, "text/plain")},
            )
        ).json()
        report_path = tmp_path / f"{created['report_id']}.json"

        current += timedelta(seconds=61)
        expired = await client.get(f"/api/reports/{created['report_id']}.json")

        assert expired.status_code == 404
        assert not report_path.exists()


@pytest.mark.asyncio
async def test_health_reports_application_readiness(tmp_path: Path) -> None:
    app = create_app(
        settings=Settings(report_directory=tmp_path),
        fortiguard=AvailableFortiGuard(),
    )

    async with api_client(app) as client:
        response = await client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "vysion", "version": "2"}

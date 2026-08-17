from pathlib import Path

import httpx
import pytest

from vysion.adapters.fortiguard import (
    FortiGuardClient,
    FortiGuardResult,
    FortiGuardStatus,
)
from vysion.api.app import create_app
from vysion.config import Settings

RAW_WITH_VERSION = (
    b"#config-version=FGT60E-7.2.9-FW-build1-1:opmode=0\n"
    b"config system global\n    set hostname edge\nend\n"
)


def _psirt_finding(payload: dict) -> dict:
    return next(item for item in payload["findings"] if item["control_id"] == "EXT-PSIRT-001")


def _assert_psirt_unknown_without_engine_finding(payload: dict) -> None:
    ids = [item["control_id"] for item in payload["findings"]]
    psirt = _psirt_finding(payload)

    assert psirt["status"] == "UNKNOWN"
    assert ids.index("EXT-PSIRT-001") == 24
    assert not any(control_id.startswith("ENGINE-") for control_id in ids)
    assert any(
        "vérification externe psirt" in evidence.casefold()
        for evidence in psirt["evidence"]
        if isinstance(evidence, str)
    )


@pytest.mark.asyncio
async def test_real_fortiguard_transport_runtime_error_keeps_audit_successful(
    tmp_path: Path,
) -> None:
    def broken(_: httpx.Request) -> httpx.Response:
        raise RuntimeError("synthetic transport failure")

    async with httpx.AsyncClient(transport=httpx.MockTransport(broken)) as http:
        app = create_app(
            settings=Settings(report_directory=tmp_path),
            fortiguard=FortiGuardClient(
                http=http,
                status_url="https://www.fortiguard.com/status",
            ),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://vysion.test",
        ) as client:
            response = await client.post(
                "/api/audits",
                files={"configuration": ("synthetic.conf", RAW_WITH_VERSION, "text/plain")},
            )

    assert response.status_code == 201
    payload = response.json()
    assert payload["context"]["psirt"]["status"] == "ERROR"
    _assert_psirt_unknown_without_engine_finding(payload)


class MalformedPsirtChecker:
    async def check(self) -> FortiGuardResult:
        return FortiGuardResult(status=FortiGuardStatus.AVAILABLE, detail="fixture")

    async def check_psirt(self, _: str) -> dict:
        return {"status": "PASS"}


@pytest.mark.asyncio
async def test_malformed_psirt_return_keeps_typed_unknown_finding(
    tmp_path: Path,
) -> None:
    app = create_app(
        settings=Settings(report_directory=tmp_path),
        fortiguard=MalformedPsirtChecker(),  # type: ignore[arg-type]
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://vysion.test",
    ) as client:
        response = await client.post(
            "/api/audits",
            files={"configuration": ("synthetic.conf", RAW_WITH_VERSION, "text/plain")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["context"]["psirt"]["status"] == "ERROR"
    _assert_psirt_unknown_without_engine_finding(payload)

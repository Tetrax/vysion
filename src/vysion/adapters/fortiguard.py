import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from urllib.parse import parse_qs, urlparse

import httpx
from pydantic import BaseModel, ConfigDict

from vysion.audit.models import ExternalObservationStatus, PsirtObservation


class FortiGuardStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


PSIRT_SOURCE = "https://www.fortiguard.com/psirt"
PSIRT_RULESET_ID = "fortiguard-psirt-critical-high"
PSIRT_RULESET_VERSION = "2026-08-13"


def error_psirt_observation(fortios_version: str) -> PsirtObservation:
    return PsirtObservation(
        status=ExternalObservationStatus.ERROR,
        fortios_version=fortios_version,
        source=PSIRT_SOURCE,
        ruleset_id=PSIRT_RULESET_ID,
        ruleset_version=PSIRT_RULESET_VERSION,
        observed_at=datetime.now(UTC),
        complete=False,
    )


class FortiGuardResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: FortiGuardStatus
    detail: str


class FortiGuardService(Protocol):
    async def check(self) -> FortiGuardResult: ...

    async def check_psirt(self, fortios_version: str) -> PsirtObservation: ...


class FortiGuardClient:
    def __init__(self, http: httpx.AsyncClient, status_url: str) -> None:
        self._http = http
        self._status_url = status_url

    async def check(self) -> FortiGuardResult:
        try:
            response = await self._http.get(self._status_url)
        except httpx.HTTPError as exc:
            return FortiGuardResult(
                status=FortiGuardStatus.UNKNOWN,
                detail=f"FortiGuard unavailable: {type(exc).__name__}",
            )
        if response.status_code != 200:
            return FortiGuardResult(
                status=FortiGuardStatus.ERROR,
                detail=f"FortiGuard returned HTTP {response.status_code}",
            )
        return FortiGuardResult(
            status=FortiGuardStatus.AVAILABLE,
            detail="FortiGuard reachable",
        )

    async def check_psirt(self, fortios_version: str) -> PsirtObservation:
        common = {
            "fortios_version": fortios_version,
            "source": PSIRT_SOURCE,
            "ruleset_id": PSIRT_RULESET_ID,
            "ruleset_version": PSIRT_RULESET_VERSION,
            "observed_at": datetime.now(UTC),
        }
        try:
            response = await self._http.get(
                PSIRT_SOURCE,
                params={
                    "filter": "1",
                    "product": "FortiOS-6K7K,FortiOS",
                    "version": fortios_version,
                    "severity": ["5", "4"],
                },
            )
        except httpx.HTTPError:
            return PsirtObservation(
                status=ExternalObservationStatus.UNKNOWN,
                complete=False,
                **common,
            )
        except Exception:
            return error_psirt_observation(fortios_version)
        if response.status_code != 200:
            return PsirtObservation(
                status=ExternalObservationStatus.UNKNOWN,
                complete=False,
                **common,
            )

        parsed = urlparse(str(response.url))
        query = parse_qs(parsed.query)
        correlated = (
            parsed.scheme == "https"
            and parsed.hostname == "www.fortiguard.com"
            and parsed.path.rstrip("/") == "/psirt"
            and query.get("filter") == ["1"]
            and query.get("product") == ["FortiOS-6K7K,FortiOS"]
            and query.get("version") == [fortios_version]
            and set(query.get("severity", [])) == {"4", "5"}
        )
        html = response.text
        expected_title = "<title>PSIRT Advisories | FortiGuard Labs</title>"
        if not correlated or expected_title not in html:
            return PsirtObservation(
                status=ExternalObservationStatus.UNKNOWN,
                complete=False,
                **common,
            )
        vulnerabilities = tuple(
            dict.fromkeys(
                match.upper()
                for match in re.findall(
                    r"\b(?:CVE-\d{4}-\d{4,7}|FG-IR-\d{2}-\d{3,4})\b",
                    html,
                    flags=re.IGNORECASE,
                )
            )
        )
        if vulnerabilities:
            return PsirtObservation(
                status=ExternalObservationStatus.FAIL,
                vulnerabilities=vulnerabilities,
                complete=True,
                **common,
            )
        no_results = re.search(
            r'<p\s+class="p-2 text-center"\s*>\s*No results\s*</p>',
            html,
            flags=re.IGNORECASE,
        )
        return PsirtObservation(
            status=(
                ExternalObservationStatus.PASS
                if no_results is not None
                else ExternalObservationStatus.UNKNOWN
            ),
            complete=no_results is not None,
            **common,
        )

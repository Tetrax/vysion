from enum import StrEnum
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict


class FortiGuardStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class FortiGuardResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: FortiGuardStatus
    detail: str


class FortiGuardService(Protocol):
    async def check(self) -> FortiGuardResult: ...


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

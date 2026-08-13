import httpx
import pytest

from vysion.adapters.fortiguard import FortiGuardClient, FortiGuardStatus


@pytest.mark.asyncio
async def test_fortiguard_transport_failure_is_unknown_not_pass() -> None:
    def unavailable(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("synthetic timeout")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as http:
        result = await FortiGuardClient(
            http=http,
            status_url="https://fortiguard.example/status",
        ).check()

    assert result.status is FortiGuardStatus.UNKNOWN
    assert result.detail == "FortiGuard unavailable: ConnectTimeout"


@pytest.mark.asyncio
async def test_fortiguard_unexpected_response_is_error_not_pass() -> None:
    def invalid(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="synthetic unavailable")

    async with httpx.AsyncClient(transport=httpx.MockTransport(invalid)) as http:
        result = await FortiGuardClient(
            http=http,
            status_url="https://fortiguard.example/status",
        ).check()

    assert result.status is FortiGuardStatus.ERROR
    assert result.detail == "FortiGuard returned HTTP 503"

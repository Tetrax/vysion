from datetime import datetime

import httpx
import pytest

from vysion.adapters.fortiguard import FortiGuardClient, FortiGuardStatus
from vysion.audit.models import ExternalObservationStatus


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


@pytest.mark.asyncio
async def test_fortiguard_psirt_correlated_no_results_is_complete_pass() -> None:
    def clean(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            text=(
                "<html><head><title>PSIRT Advisories | FortiGuard Labs</title></head>"
                '<body><p class="p-2 text-center">No results</p></body></html>'
            ),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(clean)) as http:
        result = await FortiGuardClient(
            http=http,
            status_url="https://www.fortiguard.com/",
        ).check_psirt("7.2.9")

    assert result.status is ExternalObservationStatus.PASS
    assert result.complete is True
    assert result.fortios_version == "7.2.9"
    assert isinstance(result.observed_at, datetime)


@pytest.mark.asyncio
async def test_fortiguard_psirt_cve_is_fail_but_unexpected_html_is_unknown() -> None:
    responses = iter(
        (
            '<title>PSIRT Advisories | FortiGuard Labs</title><div>CVE-2026-12345</div>',
            "<html>changed layout</html>",
        )
    )

    def response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request, text=next(responses))

    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as http:
        client = FortiGuardClient(http=http, status_url="https://www.fortiguard.com/")
        vulnerable = await client.check_psirt("7.2.9")
        unknown = await client.check_psirt("7.2.9")

    assert vulnerable.status is ExternalObservationStatus.FAIL
    assert vulnerable.vulnerabilities == ("CVE-2026-12345",)
    assert unknown.status is ExternalObservationStatus.UNKNOWN
    assert unknown.complete is False


@pytest.mark.asyncio
async def test_fortiguard_psirt_fg_ir_advisory_is_explicit_fail() -> None:
    def advisory(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            text=(
                "<title>PSIRT Advisories | FortiGuard Labs</title>"
                '<a class="cve">FG-IR-26-123</a>'
            ),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(advisory)) as http:
        result = await FortiGuardClient(
            http=http,
            status_url="https://www.fortiguard.com/",
        ).check_psirt("7.2.9")

    assert result.status is ExternalObservationStatus.FAIL
    assert result.vulnerabilities == ("FG-IR-26-123",)


@pytest.mark.asyncio
async def test_fortiguard_psirt_redirected_effective_url_is_unknown() -> None:
    def redirected(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.fortiguard.com":
            return httpx.Response(
                302,
                headers={"location": "https://example.invalid/psirt?version=7.2.9"},
            )
        return httpx.Response(
            200,
            text=(
                "<title>PSIRT Advisories | FortiGuard Labs</title>"
                '<p class="p-2 text-center">No results</p>'
            ),
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(redirected),
        follow_redirects=True,
    ) as http:
        result = await FortiGuardClient(
            http=http,
            status_url="https://www.fortiguard.com/",
        ).check_psirt("7.2.9")

    assert result.status is ExternalObservationStatus.UNKNOWN
    assert result.complete is False

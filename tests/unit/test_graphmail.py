"""Microsoft 365 application mail: fixed endpoints, whitelisted diagnostics.

No test here may open a real socket: every request goes through the injected
``urlopen`` seam, which is also what proves that no secret is ever echoed back
in an error message.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.parse
import urllib.request

import pytest

from vysion.graphmail import (
    GRAPH_SCOPE,
    SEND_ENDPOINT,
    TOKEN_ENDPOINT,
    GraphMailClient,
    GraphMailError,
    Message,
    clean_provider_error,
)

TENANT = "00000000-0000-4000-8000-000000000000"
CLIENT_ID = "11111111-1111-4111-8111-111111111111"
SECRET = "super-secret-value"
MAILBOX = "vysion@example.com"


class FakeResponse:
    def __init__(self, status: int, payload: bytes) -> None:
        self.status = status
        self._payload = payload
        self.closed = False

    def read(self) -> bytes:
        return self._payload

    def close(self) -> None:
        self.closed = True


def _client(calls: list, responses: list, *, timeout: float = 7.0, **kwargs):
    def urlopen(request, timeout=...):  # noqa: ARG001 - the seam under test
        calls.append((request, timeout))
        return responses.pop(0)

    return GraphMailClient(
        tenant_id=kwargs.get("tenant_id", TENANT),
        client_id=CLIENT_ID,
        client_secret=SECRET,
        mailbox=kwargs.get("mailbox", MAILBOX),
        from_address=kwargs.get("from_address", MAILBOX),
        timeout=timeout,
        urlopen=urlopen,
    )


TOKEN_PAYLOAD = json.dumps({"token_type": "Bearer", "access_token": "at-1"}).encode()
SEND_PAYLOAD = json.dumps({}).encode()


def test_the_token_request_uses_only_the_fixed_microsoft_endpoints():
    calls: list = []
    responses = [FakeResponse(200, TOKEN_PAYLOAD), FakeResponse(202, SEND_PAYLOAD)]
    client = _client(calls, responses)
    client.send(Message(to="ops@example.com", subject="s", body="b"))
    token_request, _timeout = calls[0]
    url = token_request.full_url
    assert url.startswith("https://login.microsoftonline.com/")
    assert url.endswith(f"/{TENANT}/oauth2/v2.0/token")
    assert TOKEN_ENDPOINT.format(tenant=TENANT) == url
    form = dict(urllib.parse.parse_qsl(token_request.data.decode()))
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == CLIENT_ID
    assert form["client_secret"] == SECRET
    assert form["scope"] == GRAPH_SCOPE
    # An application-only flow: nothing that would imply an interactive or
    # delegated login may ever appear in the token request.
    for forbidden in ("redirect_uri", "code", "password", "prompt", "username", "assertion"):
        assert forbidden not in form


def test_the_send_call_targets_the_configured_mailbox_over_graph():
    calls: list = []
    responses = [FakeResponse(200, TOKEN_PAYLOAD), FakeResponse(202, SEND_PAYLOAD)]
    client = _client(calls, responses, mailbox="releve@example.com")
    client.send(Message(to="ops@example.com", subject="Rapport", body="Contenu"))
    send_request, _timeout = calls[1]
    assert send_request.full_url == SEND_ENDPOINT.format(mailbox="releve@example.com")
    assert send_request.get_header("Authorization") == "Bearer at-1"
    body = json.loads(send_request.data.decode())
    assert body["saveToSentItems"] is False
    assert body["message"]["subject"] == "Rapport"
    assert body["message"]["body"]["content"] == "Contenu"
    recipients = body["message"]["toRecipients"]
    assert [entry["emailAddress"]["address"] for entry in recipients] == ["ops@example.com"]


def test_the_configured_timeout_bounds_every_request():
    calls: list = []
    responses = [FakeResponse(200, TOKEN_PAYLOAD), FakeResponse(202, SEND_PAYLOAD)]
    client = _client(calls, responses, timeout=3.5)
    client.send(Message(to="ops@example.com", subject="s", body="b"))
    assert [timeout for _request, timeout in calls] == [3.5, 3.5]


def test_a_whitelisted_aadsts_hint_is_the_only_thing_reported():
    raw = json.dumps(
        {
            "error": "invalid_client",
            "error_description": (
                "AADSTS7000218: The request body must contain the following "
                "parameter: 'client_secret'. Trace ID: abc-123"
            ),
        }
    )
    message = clean_provider_error(raw.encode(), 401)
    assert "AADSTS7000218" in message
    assert "abc-123" not in message
    assert "client_secret" not in message
    assert SECRET not in message


def test_an_unknown_code_never_leaks_the_provider_payload():
    raw = json.dumps(
        {"error": "unrecognized", "error_description": "AADSTS99999: internal detail"}
    )
    message = clean_provider_error(raw.encode(), 500)
    assert "AADSTS99999" not in message
    assert "internal detail" not in message


def test_an_html_error_page_is_reduced_to_a_status():
    message = clean_provider_error(b"<html><body>Gateway <b>502</b></body></html>", 502)
    assert "<html>" not in message
    assert "502" in message


def test_a_rejected_token_never_returns_nor_logs_the_secret():
    failure = urllib.error.HTTPError(
        TOKEN_ENDPOINT.format(tenant=TENANT),
        401,
        "Unauthorized",
        None,
        io.BytesIO(json.dumps({"error_description": "AADSTS7000218"}).encode()),
    )

    def urlopen(request, timeout=...):  # noqa: ARG001
        raise failure

    client = GraphMailClient(
        tenant_id=TENANT,
        client_id=CLIENT_ID,
        client_secret=SECRET,
        mailbox=MAILBOX,
        from_address=MAILBOX,
        urlopen=urlopen,
    )
    with pytest.raises(GraphMailError) as caught:
        client.send(Message(to="ops@example.com", subject="s", body="b"))
    rendered = str(caught.value)
    assert SECRET not in rendered
    assert "access_token" not in rendered


def test_an_unreachable_provider_fails_without_echoing_the_url_query():
    def urlopen(request, timeout=...):  # noqa: ARG001
        raise urllib.error.URLError("connection refused")

    client = GraphMailClient(
        tenant_id=TENANT,
        client_id=CLIENT_ID,
        client_secret=SECRET,
        mailbox=MAILBOX,
        from_address=MAILBOX,
        urlopen=urlopen,
    )
    with pytest.raises(GraphMailError) as caught:
        client.send(Message(to="ops@example.com", subject="s", body="b"))
    assert SECRET not in str(caught.value)


def test_a_missing_mailbox_falls_back_to_the_sender_address():
    calls: list = []
    responses = [FakeResponse(200, TOKEN_PAYLOAD), FakeResponse(202, SEND_PAYLOAD)]
    client = _client(calls, responses, mailbox="", from_address="vysion@example.com")
    client.send(Message(to="ops@example.com", subject="s", body="b"))
    send_request, _timeout = calls[1]
    assert send_request.full_url == SEND_ENDPOINT.format(mailbox="vysion@example.com")


def test_the_client_refuses_incomplete_credentials_before_any_request():
    calls: list = []
    with pytest.raises(GraphMailError):
        _client(calls, [], tenant_id="")
    assert calls == []

"""HTTP contract of the secured /api/admin surface and its non-regression.

The main audit flow (upload, preview, audit creation, report downloads by
UUID+TTL) must stay anonymous behind the existing network boundary; only the
administrator surface demands a session plus CSRF and Origin on mutations.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from vysion.adapters.fortiguard import FortiGuardResult, FortiGuardStatus
from vysion.api.app import create_app
from vysion.config import Settings
from vysion.security import MAX_PASSWORD_BYTES
from vysion.state import StateError

ORIGIN = "http://vysion.test"
STRONG_PASSWORD = "a-first-admin-password"
OTHER_PASSWORD = "a-second-admin-password"
SYNTHETIC_CONFIG = b"""\
config system global
    set hostname "admin-lab.example"
end
config system interface
    edit "wan1"
        set ip 192.0.2.20 255.255.255.0
        set role wan
        set allowaccess ping
    next
end
"""


class SilentFortiGuard:
    async def check(self) -> FortiGuardResult:
        return FortiGuardResult(status=FortiGuardStatus.AVAILABLE, detail="fixture")

    async def check_psirt(self, version: str):  # pragma: no cover - never reached
        return None


class RecordingMailer:
    """Test transport: captures what recovery would have sent."""

    def __init__(self) -> None:
        self.messages: list[dict[str, str]] = []

    def send(self, *, to: str, subject: str, body: str) -> None:
        self.messages.append({"to": to, "subject": subject, "body": body})


class MutableClock:
    def __init__(self, start: datetime) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current = self.current + timedelta(seconds=seconds)


class _PeerApp:
    """Force the direct peer the application observes (proxy trust tests)."""

    def __init__(self, app, peer: tuple[str, int]) -> None:
        self._app = app
        self._peer = peer

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") == "http":
            scope["client"] = self._peer
        await self._app(scope, receive, send)


def cookie_flags(header: str) -> dict[str, str | bool]:
    """Split a Set-Cookie header into attribute names/values (case-folded)."""
    flags: dict[str, str | bool] = {}
    for part in header.split(";")[1:]:
        item = part.strip()
        if not item:
            continue
        if "=" in item:
            name, value = item.split("=", 1)
            flags[name.strip().casefold()] = value.strip()
        else:
            flags[item.casefold()] = True
    return flags


def api_client(
    app,
    *,
    peer: tuple[str, int] = ("testclient", 50000),
    origin: str | None = ORIGIN,
    headers: dict[str, str] | None = None,
) -> httpx.AsyncClient:
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_PeerApp(app, peer)),
        base_url="http://vysion.test",
    )
    if origin is not None:
        client.headers["Origin"] = origin
    if headers:
        client.headers.update(headers)
    return client


def build_app(
    tmp_path: Path,
    *,
    clock=None,
    mailer=None,
    state_directory: Path | None = None,
    # Every admin mutation now needs an authoritative public origin, so the
    # fixture pins one by default (the authority the client sends). A test
    # that wants the unconfigured mode passes public_origin="" explicitly.
    public_origin: str | None = ORIGIN,
    trusted_proxy_cidrs: str | None = None,
):
    overrides: dict[str, str] = {}
    if public_origin is not None:
        overrides["public_origin"] = public_origin
    if trusted_proxy_cidrs is not None:
        overrides["trusted_proxy_cidrs"] = trusted_proxy_cidrs
    settings = Settings(
        report_directory=tmp_path / "reports",
        state_directory=state_directory or (tmp_path / "state"),
        **overrides,
    )
    return create_app(
        settings=settings,
        fortiguard=SilentFortiGuard(),
        **({"clock": clock} if clock else {}),
        **({"recovery_mailer": mailer} if mailer else {}),
    )


async def setup_admin(
    client: httpx.AsyncClient, password: str = STRONG_PASSWORD, *, origin: str = ORIGIN
):
    response = await client.post(
        "/api/admin/setup", json={"password": password}, headers={"Origin": origin}
    )
    assert response.status_code == 201, response.text
    return response


# ---------------------------------------------------------------------------
# Non-regression: the main audit flow stays anonymous
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_flow_stays_anonymous_without_any_session(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        preview = await client.post(
            "/api/audits/preview",
            files={"configuration": ("lab.conf", SYNTHETIC_CONFIG, "text/plain")},
        )
        created = await client.post(
            "/api/audits",
            files={"configuration": ("lab.conf", SYNTHETIC_CONFIG, "text/plain")},
            data={"context_source": "operator-form", "context_method": "manual"},
        )
        assert preview.status_code == 200, preview.text
        assert created.status_code == 201, created.text
        report_id = created.json()["report_id"]
        downloaded = await client.get(f"/api/reports/{report_id}.json")

    assert downloaded.status_code == 200, downloaded.text
    assert "set-cookie" not in {key.casefold() for key in preview.headers}
    assert "set-cookie" not in {key.casefold() for key in created.headers}


@pytest.mark.asyncio
async def test_health_stays_public(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        response = await client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# First run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_reports_first_run_state(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        response = await client.get("/api/admin/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["setup_required"] is True
    assert payload["authenticated"] is False
    assert payload["recovery_enabled"] is False
    assert payload["tls_backend"] == "none"


@pytest.mark.asyncio
async def test_setup_creates_the_single_administrator_and_signs_it_in(
    tmp_path: Path,
) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        created = await setup_admin(client)
        status = await client.get("/api/admin/status")
        session = await client.get("/api/admin/session")

    assert created.status_code == 201
    assert created.json()["csrf_token"]
    flags = cookie_flags(created.headers.get("set-cookie", ""))
    assert "vysion_session=" in created.headers["set-cookie"]
    assert flags["httponly"] is True
    assert flags["samesite"] == "strict"
    assert flags["path"] == "/"
    assert "secure" not in flags  # plain HTTP in this scenario
    assert status.json()["setup_required"] is False
    assert status.json()["authenticated"] is True
    assert session.status_code == 200
    assert session.json()["csrf_token"] == created.json()["csrf_token"]


@pytest.mark.asyncio
async def test_setup_refuses_a_weak_password_and_keeps_first_run_open(
    tmp_path: Path,
) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        weak = await client.post(
            "/api/admin/setup",
            json={"password": "short"},
            headers={"Origin": ORIGIN},
        )
        huge = await client.post(
            "/api/admin/setup",
            json={"password": "x" * (MAX_PASSWORD_BYTES + 1)},
            headers={"Origin": ORIGIN},
        )
        status = await client.get("/api/admin/status")

    assert weak.status_code == 422
    assert huge.status_code == 422
    assert status.json()["setup_required"] is True


@pytest.mark.asyncio
async def test_setup_is_refused_once_an_account_exists(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as first:
        await setup_admin(first)
    async with api_client(app) as second:
        replay = await second.post(
            "/api/admin/setup",
            json={"password": "another-admin-password"},
            headers={"Origin": ORIGIN},
        )

    assert replay.status_code == 409


def test_concurrent_setup_creates_exactly_one_admin(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    def attempt() -> int:
        async def run() -> int:
            async with api_client(app) as client:
                response = await client.post(
                    "/api/admin/setup",
                    json={"password": STRONG_PASSWORD},
                    headers={"Origin": ORIGIN},
                )
                return response.status_code

        return asyncio.run(run())

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(lambda _: attempt(), range(2)))

    assert statuses == [201, 409]


# ---------------------------------------------------------------------------
# Login, cookies, lockout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_rejects_a_bad_password_and_sets_a_strict_cookie(
    tmp_path: Path,
) -> None:
    app = build_app(tmp_path)
    async with api_client(app) as admin:
        await setup_admin(admin)

    async with api_client(app) as client:
        refused = await client.post(
            "/api/admin/login",
            json={"password": "definitely-not-the-password"},
            headers={"Origin": ORIGIN},
        )
        accepted = await client.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )

    assert refused.status_code == 401
    assert refused.json()["detail"] == "identifiants invalides"
    assert "set-cookie" not in {key.casefold() for key in refused.headers}
    assert accepted.status_code == 200
    assert accepted.json()["csrf_token"]
    flags = cookie_flags(accepted.headers["set-cookie"])
    assert flags["httponly"] is True
    assert flags["samesite"] == "strict"
    assert "secure" not in flags


@pytest.mark.asyncio
async def test_login_locks_the_account_after_five_failures(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 9, 22, 12, 0, tzinfo=UTC))
    app = build_app(tmp_path, clock=clock)
    async with api_client(app) as admin:
        await setup_admin(admin)

    async with api_client(app) as client:
        outcomes = []
        for attempt in range(5):
            response = await client.post(
                "/api/admin/login",
                json={"password": f"wrong-password-{attempt}"},
                headers={"Origin": ORIGIN},
            )
            outcomes.append(response.status_code)
        while_locked = await client.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        clock.advance(901)
        after_lock = await client.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )

    assert outcomes[:4] == [401, 401, 401, 401]
    assert outcomes[4] == 429
    assert while_locked.status_code == 429
    assert while_locked.headers.get("retry-after") == "900"
    assert after_lock.status_code == 200


@pytest.mark.asyncio
async def test_session_cookie_expires_after_the_configured_ttl(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 9, 22, 12, 0, tzinfo=UTC))
    app = build_app(tmp_path, clock=clock)
    async with api_client(app) as admin:
        await setup_admin(admin)

    async with api_client(app) as client:
        await client.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        before = await client.get("/api/admin/session")
        clock.advance(43_201)
        after = await client.get("/api/admin/session")

    assert before.status_code == 200
    assert after.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_the_session_and_clears_the_cookie(tmp_path: Path) -> None:
    app = build_app(tmp_path)
    async with api_client(app) as client:
        created = await setup_admin(client)
        csrf = created.json()["csrf_token"]
        closed = await client.post(
            "/api/admin/logout", headers={"X-CSRF-Token": csrf, "Origin": ORIGIN}
        )
        reused = await client.get("/api/admin/session")

    assert closed.status_code == 200
    assert cookie_flags(closed.headers.get("set-cookie", ""))["max-age"] == "0"
    assert reused.status_code == 401


# ---------------------------------------------------------------------------
# CSRF / Origin / trusted proxies
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_endpoints_refuse_anonymous_requests(tmp_path: Path) -> None:
    app = build_app(tmp_path)
    async with api_client(app) as admin:
        await setup_admin(admin)

    targets = [
        ("GET", "/api/admin/session", None),
        ("GET", "/api/admin/sessions", None),
        ("POST", "/api/admin/logout", {}),
        (
            "POST",
            "/api/admin/password",
            {"current_password": STRONG_PASSWORD, "password": OTHER_PASSWORD},
        ),
        ("POST", "/api/admin/sessions/revoke", {}),
    ]
    async with api_client(app) as anonymous:
        for method, path, body in targets:
            kwargs = {"json": body} if body is not None else {}
            response = await anonymous.request(method, path, headers={"Origin": ORIGIN}, **kwargs)
            assert response.status_code == 401, (method, path, response.status_code)


@pytest.mark.asyncio
async def test_mutations_require_csrf_and_an_exact_origin(tmp_path: Path) -> None:
    app = build_app(tmp_path)
    async with api_client(app) as signed_in:
        await setup_admin(signed_in)

    async with api_client(app) as client:
        await client.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        session = await client.get("/api/admin/session")
        live_csrf = session.json()["csrf_token"]

        no_csrf = await client.post("/api/admin/sessions/revoke", headers={"Origin": ORIGIN})
        session_token = client.cookies.get("vysion_session") or ""
        foreign = await client.post(
            "/api/admin/sessions/revoke",
            headers={"X-CSRF-Token": live_csrf, "Origin": "https://evil.example"},
        )

        # A session replayed without any Origin header (curl-style call).
        async with api_client(app, origin=None) as without_origin:
            no_origin = await without_origin.post(
                "/api/admin/sessions/revoke",
                headers={
                    "X-CSRF-Token": live_csrf,
                    "Cookie": f"vysion_session={session_token}",
                },
            )

        allowed = await client.post(
            "/api/admin/sessions/revoke",
            headers={"X-CSRF-Token": live_csrf, "Origin": ORIGIN},
        )
        reuse = await client.get("/api/admin/session")

    assert no_csrf.status_code == 403
    assert no_origin.status_code == 403
    assert foreign.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json()["revoked"] >= 1
    assert reuse.status_code == 401


@pytest.mark.asyncio
async def test_unauthenticated_mutations_still_require_an_exact_origin(
    tmp_path: Path,
) -> None:
    app = build_app(tmp_path)

    async with api_client(app, origin=None) as client:  # type: ignore[arg-type]
        client.headers.pop("Origin", None)
        no_origin = await client.post("/api/admin/setup", json={"password": STRONG_PASSWORD})
        wrong_origin = await client.post(
            "/api/admin/setup",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": "https://evil.example"},
        )

    assert no_origin.status_code == 403
    assert wrong_origin.status_code == 403


@pytest.mark.asyncio
async def test_admin_mutations_fail_closed_without_an_authoritative_origin(
    tmp_path: Path,
) -> None:
    """Review round-2 finding 1: PUBLIC_ORIGIN empty is the documented
    VPS/proxy default, and no mutation may then derive its authority from the
    caller-controlled Host. Setup, login and recovery are refused outright
    and first-run never opens under an arbitrary name (DNS rebinding or a
    permissive Host route)."""
    app = build_app(tmp_path, public_origin="")

    async with api_client(app) as client:
        setup = await client.post(
            "/api/admin/setup",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        poisoned = await client.post(
            "/api/admin/setup",
            json={"password": STRONG_PASSWORD},
            headers={
                "Host": "attacker.invalid",
                "Origin": "https://attacker.invalid",
            },
        )
        login = await client.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        recovery = await client.post(
            "/api/admin/recovery/request", headers={"Origin": ORIGIN}
        )
        status = await client.get("/api/admin/status")

    assert setup.status_code == 503
    assert poisoned.status_code == 503
    assert login.status_code == 503
    assert recovery.status_code == 503
    # First-run stayed closed: nothing exists under an unapproved authority.
    assert status.json()["setup_required"] is True
    assert status.json()["authenticated"] is False
    assert app.state.state_store.has_admin() is False


@pytest.mark.asyncio
async def test_setup_and_login_refuse_an_unapproved_authority(
    tmp_path: Path,
) -> None:
    """Review round-2 finding 1: even with an authority configured, no
    mutation proceeds under a Host/Origin pair that authority does not
    approve — the first-run cannot be completed and an existing account
    cannot be signed in from one."""
    app = build_app(tmp_path, public_origin="https://vysion.test")

    async with api_client(app) as client:
        poisoned = await client.post(
            "/api/admin/setup",
            json={"password": STRONG_PASSWORD},
            headers={
                "Host": "attacker.invalid",
                "Origin": "https://attacker.invalid",
            },
        )
        right_origin_wrong_host = await client.post(
            "/api/admin/setup",
            json={"password": STRONG_PASSWORD},
            headers={"Host": "attacker.invalid", "Origin": "https://vysion.test"},
        )
        status = await client.get("/api/admin/status")
        created = await client.post(
            "/api/admin/setup",
            json={"password": STRONG_PASSWORD},
            headers={"Host": "vysion.test", "Origin": "https://vysion.test"},
        )

    assert poisoned.status_code == 403
    assert right_origin_wrong_host.status_code == 403
    assert status.json()["setup_required"] is True
    assert created.status_code == 201, created.text

    async with api_client(app) as client:
        login_refused = await client.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Host": "attacker.invalid", "Origin": "https://vysion.test"},
        )
        login = await client.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Host": "vysion.test", "Origin": "https://vysion.test"},
        )

    assert login_refused.status_code == 403
    assert login.status_code == 200, login.text


@pytest.mark.asyncio
async def test_forwarded_headers_are_only_honoured_from_a_trusted_peer(
    tmp_path: Path,
) -> None:
    app = build_app(tmp_path, public_origin="https://vysion.test")
    async with api_client(app, origin="https://vysion.test") as admin:
        await setup_admin(admin, origin="https://vysion.test")

    trusted = api_client(
        app,
        peer=("127.0.0.1", 40000),
        origin="https://vysion.test",
        headers={"X-Forwarded-Proto": "https"},
    )
    async with trusted:
        accepted = await trusted.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": "https://vysion.test"},
        )
    assert accepted.status_code == 200
    assert cookie_flags(accepted.headers["set-cookie"])["secure"] is True

    untrusted = api_client(
        app,
        peer=("198.51.100.9", 40000),
        origin="https://vysion.test",
        headers={"X-Forwarded-Proto": "https"},
    )
    async with untrusted:
        claiming_https = await untrusted.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": "https://vysion.test"},
        )
        foreign_authority = await untrusted.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )
    # The peer is outside the trusted CIDRs: its https claim is ignored, the
    # connection stays plain http and the session cookie is never Secure.
    assert claiming_https.status_code == 200
    assert "secure" not in cookie_flags(claiming_https.headers["set-cookie"])
    # A foreign authority is refused whether or not the peer is trusted.
    assert foreign_authority.status_code == 403


# ---------------------------------------------------------------------------
# Blank X-Forwarded-Proto on a direct plain-HTTP hop (smoke-caught defect)


class _EmptySchemeApp:
    """Simulate uvicorn --proxy-headers with a blank X-Forwarded-Proto: the
    inner nginx used to pass the empty value through and uvicorn recorded an
    empty scope scheme, which the origin check must never believe."""

    def __init__(self, app, peer: tuple[str, int]) -> None:
        self._app = app
        self._peer = peer

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") == "http":
            scope["client"] = self._peer
            scope["scheme"] = ""
        await self._app(scope, receive, send)


@pytest.mark.asyncio
async def test_blank_forwarded_proto_from_the_local_proxy_never_breaks_origin(
    tmp_path: Path,
) -> None:
    """A direct plain-HTTP hop sends X-Forwarded-Proto: empty (or blank):
    setup and login must authenticate against the connection scheme instead
    of a poisoned empty scheme."""
    app = build_app(tmp_path)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_EmptySchemeApp(app, ("127.0.0.1", 41000))),
        base_url="http://vysion.test",
        headers={"Origin": ORIGIN},
    )
    async with client:
        client.headers["X-Forwarded-Proto"] = ""
        created = await client.post(
            "/api/admin/setup", json={"password": STRONG_PASSWORD}
        )
        client.headers["X-Forwarded-Proto"] = " "
        login = await client.post(
            "/api/admin/login", json={"password": STRONG_PASSWORD}
        )

    assert created.status_code == 201, created.text
    assert login.status_code == 200, login.text
    assert "secure" not in cookie_flags(login.headers["set-cookie"])


# ---------------------------------------------------------------------------
# The real nginx -> app forwarded-header contract (review finding 2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nginx_observed_hop_wins_over_a_forged_forwarded_chain(
    tmp_path: Path,
) -> None:
    """The bundled nginx reports the hop it observed in X-Real-IP; a client
    that varies only X-Forwarded-For must stay inside one rate-limit scope
    instead of buying a fresh bucket per attempt."""
    app = build_app(tmp_path)
    forged = ["6.6.6.6", "192.0.2.77", "203.0.113.50", "198.51.100.200", "192.0.2.200"]

    statuses = []
    for value in forged:
        async with api_client(
            app,
            peer=("127.0.0.1", 41000),
            origin=ORIGIN,
            headers={
                "X-Real-IP": "198.51.100.7",
                "X-Forwarded-For": value,
                "X-Forwarded-Proto": "http",
            },
        ) as client:
            response = await client.post(
                "/api/admin/setup", json={"password": "short"}
            )
            statuses.append(response.status_code)

    assert statuses == [422, 422, 422, 422, 429]

    # Another observed client keeps an independent bucket.
    async with api_client(
        app,
        peer=("127.0.0.1", 41000),
        origin=ORIGIN,
        headers={
            "X-Real-IP": "203.0.113.9",
            "X-Forwarded-For": "6.6.6.6",
            "X-Forwarded-Proto": "http",
        },
    ) as other:
        fresh = await other.post("/api/admin/setup", json={"password": "short"})
    assert fresh.status_code == 422


@pytest.mark.asyncio
async def test_trusted_external_proxy_hop_decides_client_and_scheme(
    tmp_path: Path,
) -> None:
    """When the hop nginx observed is an explicitly trusted external proxy,
    its forwarded chain picks the client (right-most untrusted hop) and its
    upstream scheme claim decides https."""
    app = build_app(
        tmp_path,
        public_origin="https://vysion.test",
        trusted_proxy_cidrs="10.0.0.0/8, 127.0.0.1/32",
    )

    # Rate-limit probes first, while first-run is still open: each weak
    # attempt must count against the client behind the trusted proxy.
    forged = ["6.6.6.6", "192.0.2.77", "203.0.113.50", "198.51.100.200", "192.0.2.200"]
    statuses = []
    for value in forged:
        async with api_client(
            app,
            peer=("127.0.0.1", 41000),
            origin="https://vysion.test",
            headers={
                "X-Real-IP": "10.0.0.5",
                "X-Forwarded-For": f"{value}, 203.0.113.9, 10.0.0.5",
                "X-Forwarded-Proto": "http",
            },
        ) as client:
            response = await client.post(
                "/api/admin/setup", json={"password": "short"}
            )
            statuses.append(response.status_code)
    # Locked on the client behind the trusted proxy (203.0.113.9), never on
    # the forged entries that sit to its left.
    assert statuses == [422, 422, 422, 422, 429]

    # Now create the administrator from a different (unlocked) scope and
    # sign in through the trusted hop: its scheme claim decides https.
    async with api_client(app, origin="https://vysion.test") as client:
        await setup_admin(client, origin="https://vysion.test")

    async with api_client(
        app,
        peer=("127.0.0.1", 41000),
        origin="https://vysion.test",
        headers={
            "X-Real-IP": "10.0.0.5",
            "X-Forwarded-For": "203.0.113.9, 10.0.0.5",
            "X-Forwarded-Proto": "http",
            "X-Forwarded-Client-Proto": "https",
        },
    ) as proxied:
        login = await proxied.post(
            "/api/admin/login", json={"password": STRONG_PASSWORD}
        )
    assert login.status_code == 200, login.text
    assert cookie_flags(login.headers["set-cookie"])["secure"] is True


@pytest.mark.asyncio
async def test_untrusted_hop_cannot_claim_https_through_the_client_proto(
    tmp_path: Path,
) -> None:
    """X-Forwarded-Client-Proto is the upstream claim: only a hop inside the
    trusted CIDRs may make it count. A direct client stays plain http — and
    no forwarded claim may borrow a different public authority either."""
    app = build_app(tmp_path)
    async with api_client(app) as client:
        await setup_admin(client)

    # Foreign authority (https is not the configured public origin): refused
    # before the forwarded claim is read at all.
    async with api_client(
        app,
        peer=("127.0.0.1", 41000),
        origin="https://vysion.test",
        headers={
            "X-Real-IP": "198.51.100.9",
            "X-Forwarded-Proto": "http",
            "X-Forwarded-Client-Proto": "https",
        },
    ) as direct:
        refused = await direct.post(
            "/api/admin/login", json={"password": STRONG_PASSWORD}
        )
    assert refused.status_code == 403

    # Approved authority, untrusted hop: the https claim still counts for
    # nothing, so the connection truth (http) wins and the cookie is plain.
    async with api_client(
        app,
        peer=("127.0.0.1", 41000),
        origin=ORIGIN,
        headers={
            "X-Real-IP": "198.51.100.9",
            "X-Forwarded-Proto": "http",
            "X-Forwarded-Client-Proto": "https",
        },
    ) as direct:
        plain = await direct.post(
            "/api/admin/login", json={"password": STRONG_PASSWORD}
        )
    assert plain.status_code == 200
    assert "secure" not in cookie_flags(plain.headers["set-cookie"])


# ---------------------------------------------------------------------------
# The VPS path: the hop the container observes is the Docker bridge gateway
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vps_default_trust_leaves_the_cookie_insecure_behind_the_edge(
    tmp_path: Path,
) -> None:
    """Review round-2 finding 2: a request that reaches the container over
    the published Docker port is observed from the bridge gateway, not from
    127.0.0.1. With the default trusted CIDR that hop is untrusted, the host
    edge's https declaration is ignored and the session cookie is NOT
    Secure — which is exactly why the VPS rollout must configure the
    observed hop explicitly instead of trusting a default."""
    app = build_app(tmp_path, public_origin="https://vysion.test")
    async with api_client(app, origin="https://vysion.test") as client:
        await setup_admin(client, origin="https://vysion.test")

    async with api_client(
        app,
        peer=("127.0.0.1", 41000),
        origin="https://vysion.test",
        headers={
            "X-Real-IP": "172.31.77.1",  # the observed Docker bridge gateway
            "X-Forwarded-Proto": "http",  # the container nginx's own scheme
            "X-Forwarded-Client-Proto": "https",  # the host edge's declaration
        },
    ) as edge:
        login = await edge.post(
            "/api/admin/login", json={"password": STRONG_PASSWORD}
        )

    assert login.status_code == 200, login.text
    assert "secure" not in cookie_flags(login.headers["set-cookie"])


@pytest.mark.asyncio
async def test_vps_observed_docker_hop_trusted_yields_a_secure_cookie(
    tmp_path: Path,
) -> None:
    """The documented VPS rollout sets TRUSTED_PROXY_CIDRS to the hop the
    container actually observes — discovered at deploy time, never an
    imposed subnet — so the host-terminated TLS edge yields a Secure
    session cookie."""
    app = build_app(
        tmp_path,
        public_origin="https://vysion.test",
        trusted_proxy_cidrs="172.31.77.1/32",  # the observed hop, explicit
    )
    async with api_client(app, origin="https://vysion.test") as client:
        await setup_admin(client, origin="https://vysion.test")

    async with api_client(
        app,
        peer=("127.0.0.1", 41000),
        origin="https://vysion.test",
        headers={
            "X-Real-IP": "172.31.77.1",
            "X-Forwarded-Proto": "http",
            "X-Forwarded-Client-Proto": "https",
        },
    ) as edge:
        login = await edge.post(
            "/api/admin/login", json={"password": STRONG_PASSWORD}
        )

    assert login.status_code == 200, login.text
    assert cookie_flags(login.headers["set-cookie"])["secure"] is True


# ---------------------------------------------------------------------------
# Account management
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_change_invalidates_every_session(tmp_path: Path) -> None:
    app = build_app(tmp_path)
    async with api_client(app) as client:
        created = await setup_admin(client)
        csrf = created.json()["csrf_token"]
        changed = await client.post(
            "/api/admin/password",
            json={"current_password": STRONG_PASSWORD, "password": OTHER_PASSWORD},
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )
        after_change = await client.get("/api/admin/session")

    async with api_client(app) as fresh:
        old = await fresh.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        new = await fresh.post(
            "/api/admin/login",
            json={"password": OTHER_PASSWORD},
            headers={"Origin": ORIGIN},
        )

    assert changed.status_code == 200
    assert after_change.status_code == 401
    assert old.status_code == 401
    assert new.status_code == 200


@pytest.mark.asyncio
async def test_password_change_requires_the_current_password(tmp_path: Path) -> None:
    app = build_app(tmp_path)
    async with api_client(app) as client:
        created = await setup_admin(client)
        csrf = created.json()["csrf_token"]
        refused = await client.post(
            "/api/admin/password",
            json={"current_password": "not-the-current-password", "password": OTHER_PASSWORD},
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )
        still_valid = await client.get("/api/admin/session")

    assert refused.status_code == 401
    assert still_valid.status_code == 200


@pytest.mark.asyncio
async def test_sessions_can_be_listed_and_all_revoked(tmp_path: Path) -> None:
    app = build_app(tmp_path)
    async with api_client(app) as first:
        await setup_admin(first)
    async with api_client(app) as second:
        await second.post(
            "/api/admin/login",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        session = await second.get("/api/admin/session")
        csrf = session.json()["csrf_token"]
        listed = await second.get("/api/admin/sessions")
        revoked = await second.post(
            "/api/admin/sessions/revoke",
            headers={"X-CSRF-Token": csrf, "Origin": ORIGIN},
        )
        after = await second.get("/api/admin/session")

    assert listed.status_code == 200
    assert len(listed.json()["sessions"]) >= 2
    assert revoked.json()["revoked"] >= 2
    assert after.status_code == 401


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recovery_is_unavailable_without_an_smtp_transport(
    tmp_path: Path,
) -> None:
    app = build_app(tmp_path)
    async with api_client(app) as admin:
        await setup_admin(admin)

    async with api_client(app) as client:
        request = await client.post("/api/admin/recovery/request", headers={"Origin": ORIGIN})
        confirm = await client.post(
            "/api/admin/recovery/confirm",
            json={"token": "any-token", "password": OTHER_PASSWORD},
            headers={"Origin": ORIGIN},
        )

    assert request.status_code == 503
    assert confirm.status_code == 400
    assert confirm.json()["detail"] == "jeton de récupération invalide"


@pytest.mark.asyncio
async def test_recovery_sends_a_single_use_token_and_resets_the_password(
    tmp_path: Path,
) -> None:
    mailer = RecordingMailer()
    app = build_app(tmp_path, mailer=mailer, public_origin=ORIGIN)
    async with api_client(app) as client:
        await setup_admin(client)

    # The transport is configured in the private state, never in the environment.
    store = app.state.state_store
    store.set_smtp_config(
        host="smtp.internal.example",
        port=587,
        from_address="vysion@internal.example",
        starttls=True,
        recovery_email="operator@internal.example",
        password="write-only-secret",
    )

    async with api_client(app) as client:
        requested = await client.post("/api/admin/recovery/request", headers={"Origin": ORIGIN})
        assert requested.status_code == 200, requested.text
        assert requested.json() == {"status": "pending"}

    assert len(mailer.messages) == 1
    message = mailer.messages[0]
    assert message["to"] == "operator@internal.example"
    assert "write-only-secret" not in message["body"]
    token = message["body"].split("token=", 1)[1].split()[0].strip("<>\"'")

    async with api_client(app) as client:
        confirmed = await client.post(
            "/api/admin/recovery/confirm",
            json={"token": token, "password": OTHER_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        reused = await client.post(
            "/api/admin/recovery/confirm",
            json={"token": token, "password": "a-third-admin-password"},
            headers={"Origin": ORIGIN},
        )

    assert confirmed.status_code == 200
    assert reused.status_code == 400

    # Every session was invalidated by the reset.
    async with api_client(app) as old_session:
        stale = await old_session.get("/api/admin/session")
    assert stale.status_code == 401

    async with api_client(app) as fresh:
        login = await fresh.post(
            "/api/admin/login",
            json={"password": OTHER_PASSWORD},
            headers={"Origin": ORIGIN},
        )
    assert login.status_code == 200


@pytest.mark.asyncio
async def test_recovery_request_answers_uniformly_and_is_rate_limited(
    tmp_path: Path,
) -> None:
    mailer = RecordingMailer()
    app = build_app(tmp_path, mailer=mailer, public_origin=ORIGIN)
    async with api_client(app) as admin:
        await setup_admin(admin)
    app.state.state_store.set_smtp_config(
        host="smtp.internal.example",
        port=587,
        from_address="vysion@internal.example",
        starttls=True,
        recovery_email="operator@internal.example",
    )

    async with api_client(app) as client:
        bodies = []
        statuses = []
        for _ in range(6):
            response = await client.post("/api/admin/recovery/request", headers={"Origin": ORIGIN})
            statuses.append(response.status_code)
            bodies.append(response.content)

        assert statuses[:4] == [200] * 4
        assert statuses[4:] == [429] * 2
        assert len(set(bodies[:4])) == 1
        assert len(mailer.messages) == 4


@pytest.mark.asyncio
async def test_recovery_confirmation_is_rate_limited(tmp_path: Path) -> None:
    app = build_app(tmp_path)
    async with api_client(app) as admin:
        await setup_admin(admin)

    async with api_client(app) as client:
        statuses = []
        for attempt in range(7):
            response = await client.post(
                "/api/admin/recovery/confirm",
                json={"token": f"guessed-token-{attempt}", "password": OTHER_PASSWORD},
                headers={"Origin": ORIGIN},
            )
            statuses.append(response.status_code)

    assert statuses[:4] == [400] * 4
    assert statuses[4:] == [429] * 3


@pytest.mark.asyncio
async def test_recovery_never_leaks_state_over_public_endpoints(tmp_path: Path) -> None:
    app = build_app(tmp_path, public_origin=ORIGIN)
    async with api_client(app) as admin:
        await setup_admin(admin)
    app.state.state_store.set_smtp_config(
        host="smtp.internal.example",
        port=587,
        from_address="vysion@internal.example",
        starttls=True,
        recovery_email="operator@internal.example",
        password="write-only-secret",
    )

    async with api_client(app) as anonymous:
        status = await anonymous.get("/api/admin/status")

    assert status.status_code == 200
    assert status.json()["recovery_enabled"] is True
    assert "write-only-secret" not in status.text
    assert "operator@internal.example" not in status.text


@pytest.mark.asyncio
async def test_recovery_request_refuses_a_poisoned_host_header(
    tmp_path: Path,
) -> None:
    """Review finding: neither the exact-Origin check nor the emailed reset
    link may derive their authority from the caller-controlled Host header.
    The configured public origin is the only authority."""
    mailer = RecordingMailer()
    app = build_app(tmp_path, mailer=mailer, public_origin="https://vysion.test")
    async with api_client(app) as client:
        created = await client.post(
            "/api/admin/setup",
            json={"password": STRONG_PASSWORD},
            headers={"Origin": "https://vysion.test"},
        )
    assert created.status_code == 201, created.text
    app.state.state_store.set_smtp_config(
        host="smtp.internal.example",
        port=587,
        from_address="vysion@internal.example",
        starttls=True,
        recovery_email="operator@internal.example",
    )

    async with api_client(app) as client:
        poisoned = await client.post(
            "/api/admin/recovery/request",
            headers={"Host": "attacker.example", "Origin": "https://attacker.example"},
        )
        right_origin_wrong_host = await client.post(
            "/api/admin/recovery/request",
            headers={"Host": "attacker.example", "Origin": "https://vysion.test"},
        )

    # Every unapproved authority is refused before a token can exist.
    assert poisoned.status_code == 403
    assert right_origin_wrong_host.status_code == 403
    assert len(mailer.messages) == 0

    async with api_client(app) as client:
        approved = await client.post(
            "/api/admin/recovery/request",
            headers={"Host": "vysion.test", "Origin": "https://vysion.test"},
        )

    assert approved.status_code == 200, approved.text
    assert len(mailer.messages) == 1
    body = mailer.messages[0]["body"]
    assert "https://vysion.test/admin/reset?token=" in body
    assert "attacker.example" not in body


@pytest.mark.asyncio
async def test_recovery_is_unavailable_without_a_configured_public_origin(
    tmp_path: Path,
) -> None:
    """Without an authoritative origin there is no address a reset link could
    safely be built from: recovery fails closed and sends nothing, while the
    status endpoint stops advertising it."""
    mailer = RecordingMailer()
    app = build_app(tmp_path, mailer=mailer, public_origin="")
    # Without an authoritative origin the HTTP first-run itself is refused
    # (503), so this scenario seeds the account directly in the private state.
    assert app.state.state_store.create_admin(STRONG_PASSWORD) is True
    app.state.state_store.set_smtp_config(
        host="smtp.internal.example",
        port=587,
        from_address="vysion@internal.example",
        starttls=True,
        recovery_email="operator@internal.example",
    )

    async with api_client(app) as client:
        status = await client.get("/api/admin/status")
        requested = await client.post(
            "/api/admin/recovery/request", headers={"Origin": ORIGIN}
        )

    assert status.json()["recovery_enabled"] is False
    assert requested.status_code == 503
    assert mailer.messages == []


# ---------------------------------------------------------------------------
# Bounds and fail-closed state
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_mutations_bound_the_request_body(tmp_path: Path) -> None:
    app = build_app(tmp_path)

    async with api_client(app) as client:
        oversized = await client.post(
            "/api/admin/login",
            content=b"x" * (2 * 1024 * 1024),
            headers={"Origin": ORIGIN, "Content-Type": "application/json"},
        )

        async def chunked_body():
            yield b'{"password":"a-first-admin-password"}'

        without_length = await client.post(
            "/api/admin/login",
            content=chunked_body(),
            headers={"Origin": ORIGIN, "Content-Type": "application/json"},
        )

    assert oversized.status_code == 413
    assert without_length.status_code == 411


def test_corrupt_state_fails_closed_before_any_route_can_reopen_first_run(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "vysion-state.db").write_bytes(b"definitely not a database\n")

    with pytest.raises(StateError):
        build_app(tmp_path, state_directory=state)


def test_present_but_empty_state_never_reopens_anonymous_enrollment(
    tmp_path: Path,
) -> None:
    """Review probe: a pre-existing zero-byte SQLite file must refuse the
    whole application instead of reading as ``setup_required=True``."""
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "vysion-state.db").write_bytes(b"")

    with pytest.raises(StateError):
        build_app(tmp_path, state_directory=state)

"""FastAPI contracts for platform organization and privacy administration."""

import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

import app.api.platform as platform_api
from app.auth.service import AuthDenied
from app.core.config import Environment
from app.tenancy.domains import DomainDenied

pytestmark = pytest.mark.skipif(
    os.environ.get("SKIP_SYNC_ASGI_TESTS") == "1",
    reason="Local sandbox cannot schedule Starlette's sync endpoint threadpool",
)

ACTOR = uuid4()
TENANT = uuid4()
CREATED = datetime(2026, 10, 28, 8, 0, tzinfo=UTC)


class FakeAuth:
    def current(self, token: str) -> SimpleNamespace:
        if token != "valid-platform-session":
            raise AuthDenied("invalid platform session")
        return SimpleNamespace(id=ACTOR)


class FakeDomains:
    control_engine = object()


class FakeOrganizations:
    deny_grant = False

    def __init__(self, _engine: object) -> None:
        pass

    def list(self, actor: UUID, *, query: str, limit: int, offset: int) -> dict[str, object]:
        assert actor == ACTOR
        if self.deny_grant:
            raise DomainDenied("grant unavailable")
        assert query == "Summit" and limit == 10 and offset == 0
        return {
            "organizations": [self._item()],
            "total": 1,
            "limit": limit,
            "offset": offset,
            "has_more": False,
            "internal": "must not serialize",
        }

    def get(self, actor: UUID, tenant_id: UUID) -> dict[str, object] | None:
        assert actor == ACTOR
        return self._item() if tenant_id == TENANT else None

    @staticmethod
    def _item() -> dict[str, object]:
        return {
            "id": str(TENANT),
            "name": "Summit Operations",
            "status": "active",
            "created_at": CREATED.isoformat(),
            "primary_organizer": "organizer@example.test",
            "invitation_delivery_status": "accepted_by_transport",
        }


class FakeNotices:
    def __init__(self, _engine: object, environment: Environment) -> None:
        assert environment == Environment.TEST

    @staticmethod
    def _notice(*, approved: bool = False, active: bool = False) -> dict[str, object]:
        return {
            "version": 1,
            "body": "Synthetic notice text",
            "lawful_basis": "synthetic-test-basis",
            "test_only": True,
            "created_at": CREATED.isoformat(),
            "created_by": str(ACTOR),
            "approved_at": CREATED.isoformat() if approved else None,
            "approved_by": str(ACTOR) if approved else None,
            "approval_reference": "approval-1" if approved else None,
            "active": active,
            "digest": "must not serialize",
        }

    def list(self, actor: UUID, tenant_id: UUID) -> dict[str, object]:
        assert actor == ACTOR and tenant_id == TENANT
        return {
            "organization_id": str(TENANT),
            "organization_name": "Summit Operations",
            "notices": [self._notice()],
        }

    def draft(
        self, actor: UUID, tenant_id: UUID, body: str, lawful_basis: str, test_only: bool
    ) -> dict[str, object]:
        assert (actor, tenant_id, body, lawful_basis, test_only) == (
            ACTOR,
            TENANT,
            "Synthetic notice text",
            "synthetic-test-basis",
            True,
        )
        return self._notice()

    def approve(
        self, actor: UUID, tenant_id: UUID, version: int, approval_reference: str
    ) -> dict[str, object]:
        assert (actor, tenant_id, version, approval_reference) == (
            ACTOR,
            TENANT,
            1,
            "approval-1",
        )
        return self._notice(approved=True)

    def activate(self, actor: UUID, tenant_id: UUID, version: int) -> dict[str, object]:
        assert (actor, tenant_id, version) == (ACTOR, TENANT, 1)
        return self._notice(approved=True, active=True)


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(platform_api, "PlatformOrganizations", FakeOrganizations)
    monkeypatch.setattr(platform_api, "PrivacyNotices", FakeNotices)
    app = FastAPI()
    app.state.platform_auth = FakeAuth()
    app.state.platform_control_engine = FakeDomains.control_engine
    app.state.domain_service = None
    app.state.settings = SimpleNamespace(app_env=Environment.TEST, privacy_notices_enabled=True)

    @app.middleware("http")
    async def trusted_origin(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.trusted_origin = "https://platform.example.test"
        return await call_next(request)

    app.include_router(platform_api.router)
    return TestClient(app, base_url="https://platform.example.test")


def authorize(client: TestClient) -> str:
    client.cookies.set(platform_api.PLATFORM_SESSION_COOKIE, "valid-platform-session")
    return client.get("/api/v1/platform/auth/csrf").json()["csrf_token"]


def test_organization_routes_require_cookie_and_platform_grant(
    client: TestClient,
) -> None:
    unauthorized = client.get("/api/v1/platform/organizations?q=Summit&limit=10")
    assert unauthorized.status_code == 401
    authorize(client)
    response = client.get("/api/v1/platform/organizations?q=Summit&limit=10")
    assert response.status_code == 200
    assert response.json() == {
        "organizations": [
            {
                "id": str(TENANT),
                "name": "Summit Operations",
                "status": "active",
                "created_at": "2026-10-28T08:00:00Z",
                "primary_organizer": "organizer@example.test",
                "invitation_delivery_status": "accepted_by_transport",
            }
        ],
        "total": 1,
        "limit": 10,
        "offset": 0,
        "has_more": False,
    }
    FakeOrganizations.deny_grant = True
    try:
        denied = client.get("/api/v1/platform/organizations?q=Summit&limit=10")
        assert denied.status_code == 403
        assert denied.json()["detail"]["code"] == "FORBIDDEN"
    finally:
        FakeOrganizations.deny_grant = False


def test_privacy_routes_enforce_csrf_validation_and_typed_serialization(
    client: TestClient,
) -> None:
    csrf = authorize(client)
    path = f"/api/v1/platform/organizations/{TENANT}/privacy-notices"
    listed = client.get(path)
    assert listed.status_code == 200
    notice = listed.json()["notices"][0]
    assert notice["created_by"] == str(ACTOR)
    assert notice["created_at"] == "2026-10-28T08:00:00Z"
    assert "digest" not in notice

    missing_csrf = client.post(
        path,
        json={
            "body": "Synthetic notice text",
            "lawful_basis": "synthetic-test-basis",
            "test_only": True,
        },
    )
    assert missing_csrf.status_code == 403
    headers = {"x-csrf-token": csrf, "origin": "https://platform.example.test"}
    invalid = client.post(path, headers=headers, json={"body": "", "lawful_basis": "x"})
    assert invalid.status_code == 422
    drafted = client.post(
        path,
        headers=headers,
        json={
            "body": "Synthetic notice text",
            "lawful_basis": "synthetic-test-basis",
            "test_only": True,
        },
    )
    assert drafted.status_code == 201
    assert drafted.json()["approved_at"] is None

    unconfirmed = client.post(
        f"{path}/1/approve",
        headers=headers,
        json={"approval_reference": "approval-1", "confirmed": False},
    )
    assert unconfirmed.status_code == 422
    approved = client.post(
        f"{path}/1/approve",
        headers=headers,
        json={"approval_reference": "approval-1", "confirmed": True},
    )
    assert approved.status_code == 200
    assert approved.json()["approved_by"] == str(ACTOR)
    activated = client.post(f"{path}/1/activate", headers=headers, json={"confirmed": True})
    assert activated.status_code == 200
    assert activated.json()["active"] is True


def test_dns_provisioning_stays_disabled_without_a_fallback_zone(client: TestClient) -> None:
    token = authorize(client)
    response = client.post(
        "/api/v1/platform/tenants",
        json={"name": "Shared organization", "slug": "shared"},
        headers={"x-csrf-token": token, "origin": "https://platform.example.test"},
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "DOMAINS_UNAVAILABLE"


def test_shared_metadata_requires_a_configured_platform_connection(client: TestClient) -> None:
    authorize(client)
    client.app.state.platform_control_engine = None
    response = client.get("/api/v1/platform/organizations")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "PLATFORM_UNAVAILABLE"


def test_privacy_endpoints_are_disabled_when_feature_is_unavailable(client: TestClient) -> None:
    client.app.state.settings.privacy_notices_enabled = False
    authorize(client)
    response = client.get(f"/api/v1/platform/organizations/{TENANT}/privacy-notices")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "COMING_SOON"

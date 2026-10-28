"""Render ingress authenticates authority independently of proxy IP addresses."""

import pytest
from fastapi import Depends, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from app.api.auth import csrf
from app.core.config import Settings
from app.main import create_app

SECRET = "synthetic-origin-secret"
EDGE = {
    "x-eventcheckin-origin-auth": SECRET,
    "x-eventcheckin-public-host": "platform.example.test",
    "x-eventcheckin-client-ip": "203.0.113.8",
}


@pytest.fixture
def client() -> TestClient:
    settings = Settings(
        app_env="production",
        database_url="postgresql+psycopg://runtime:synthetic@db.example/test?sslmode=verify-full",
        platform_host="platform.example.test",
        origin_auth_secret=SecretStr(SECRET),
        brevo_webhook_token=SecretStr("synthetic-webhook-token"),
    )
    engine = create_engine(
        "sqlite+pysqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    app = create_app(settings, engine)

    @app.get("/api/v1/shared/ingress-probe")
    async def probe(request: Request) -> dict[str, object]:
        return {
            "host": request.state.trusted_hostname,
            "origin": request.state.trusted_origin,
            "client_ip": request.state.client_address,
            "peer": request.client.host if request.client else None,
            "scheme": request.url.scheme,
            "leaked": any(k.startswith("x-eventcheckin-") for k in request.headers),
            "forwarded_host": request.headers.get("x-forwarded-host"),
        }

    @app.post("/api/v1/shared/csrf-probe", dependencies=[Depends(csrf)])
    async def csrf_probe() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app, base_url="https://origin.example.test", client=("10.42.1.9", 1234))


@pytest.mark.parametrize("path", ["/health", "/ready"])
def test_health_and_readiness_are_public(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 200


@pytest.mark.parametrize("headers", [{}, {**EDGE, "x-eventcheckin-origin-auth": "wrong"}])
def test_direct_origin_is_blocked(client: TestClient, headers: dict[str, str]) -> None:
    assert client.get("/api/v1/auth/csrf", headers=headers).status_code == 404
    assert client.get("/docs", headers=headers).status_code == 404


def test_authenticated_envelope_overwrites_untrusted_proxy_headers(client: TestClient) -> None:
    response = client.get("/api/v1/shared/ingress-probe", headers={
        **EDGE, "host": "render-internal.example", "forwarded": "host=hostile.example",
        "x-forwarded-host": "hostile.example", "x-forwarded-for": "1.2.3.4, 5.6.7.8",
        "x-forwarded-proto": "http", "x-real-ip": "1.2.3.4",
    })
    assert response.status_code == 200
    assert response.json() == {
        "host": "platform.example.test", "origin": "https://platform.example.test",
        "client_ip": "203.0.113.8", "peer": "203.0.113.8", "scheme": "https",
        "leaked": False, "forwarded_host": None,
    }


@pytest.mark.parametrize(("name", "value"), [
    ("x-eventcheckin-client-ip", "203.0.113.8, 1.2.3.4"),
    ("x-eventcheckin-client-ip", "invalid"),
    ("x-eventcheckin-client-ip", " 203.0.113.8"),
    ("x-eventcheckin-public-host", "platform.example.test:443"),
    ("x-eventcheckin-public-host", "user@platform.example.test"),
])
def test_invalid_authenticated_authority_rejected(
    client: TestClient, name: str, value: str,
) -> None:
    assert client.get("/api/v1/auth/csrf", headers={**EDGE, name: value}).status_code == 421


@pytest.mark.parametrize("name", list(EDGE))
def test_duplicate_envelope_headers_rejected(client: TestClient, name: str) -> None:
    response = client.get("/api/v1/auth/csrf", headers=[*EDGE.items(), (name, EDGE[name])])
    assert response.status_code == (404 if name == "x-eventcheckin-origin-auth" else 421)


def test_shared_tenant_context_remains_required(client: TestClient) -> None:
    response = client.get("/api/v1/auth/session", headers=EDGE)
    assert response.status_code == 421
    assert response.json()["detail"]["code"] == "TENANT_CONTEXT_REQUIRED"


def test_csrf_cookie_security_and_origin_enforcement(client: TestClient) -> None:
    response = client.get("/api/v1/auth/csrf", headers=EDGE)
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    token = response.json()["csrf_token"]
    headers = {**EDGE, "x-csrf-token": token, "origin": "https://hostile.example"}
    assert client.post("/api/v1/shared/csrf-probe", headers=headers).status_code == 403
    headers["origin"] = "https://platform.example.test"
    assert client.post("/api/v1/shared/csrf-probe", headers=headers).status_code == 200


def test_malformed_webhook_is_authenticated_before_parsing(client: TestClient) -> None:
    response = client.post("/api/v1/webhooks/brevo", content="{")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "WEBHOOK_AUTH_INVALID"


def test_empty_origin_secret_is_rejected() -> None:
    with pytest.raises(ValidationError, match="ORIGIN_AUTH_SECRET must not be empty"):
        Settings(
            app_env="test", database_url="postgresql+psycopg://runtime:local@localhost/test",
            origin_auth_secret=SecretStr(""),
        )

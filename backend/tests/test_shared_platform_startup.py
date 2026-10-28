"""Platform administration starts without claiming a tenant DNS namespace."""

from fastapi.testclient import TestClient
from test_config import shared_production_settings

from app.main import create_app
from app.tenancy.platform_auth import PlatformAuth


def test_shared_production_startup_registers_platform_without_domain_service() -> None:
    app = create_app(shared_production_settings())
    assert isinstance(app.state.platform_auth, PlatformAuth)
    assert app.state.platform_control_engine is not None
    assert app.state.domain_service is None
    edge = {
        "x-eventcheckin-origin-auth": "synthetic-origin-secret",
        "x-eventcheckin-public-host": "event-checkin-console.vercel.app",
        "x-eventcheckin-client-ip": "203.0.113.8",
    }
    with TestClient(app, base_url="https://event-checkin-console.vercel.app") as client:
        assert client.get("/health").status_code == 200
        csrf = client.get("/api/v1/platform/auth/csrf", headers=edge)
        assert csrf.status_code == 200
        response = client.post(
            "/api/v1/platform/tenants", json={"name": "Shared", "slug": "shared"},
            headers={**edge, "origin": "https://event-checkin-console.vercel.app",
                     "x-csrf-token": csrf.json()["csrf_token"]},
        )
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "DOMAINS_UNAVAILABLE"
        hostile = {**edge, "x-eventcheckin-public-host": "other.vercel.app"}
        assert client.get("/api/v1/platform/auth/csrf", headers=hostile).status_code == 421
        assert client.get("/api/v1/platform/auth/csrf").status_code == 404

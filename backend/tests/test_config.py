import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_production_requires_explicit_database_tls() -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="production", database_url="postgresql+psycopg://u:p@db/app")


def test_sqlite_is_not_accepted_for_runtime() -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="test", database_url="sqlite:///:memory:")


def test_remote_config_rejects_disabled_tls() -> None:
    with pytest.raises(ValidationError):
        Settings(
            app_env="staging",
            database_url="postgresql+psycopg://u:p@db.example/app?sslmode=disable",
        )


def test_production_requires_verified_database_identity_for_both_roles() -> None:
    runtime = "postgresql+psycopg://runtime:p@db.example/app?sslmode=verify-full"
    identity = "postgresql+psycopg://identity:p@db.example/app?sslmode=verify-full"
    with pytest.raises(ValidationError, match="sslmode=verify-full"):
        Settings(
            app_env="production",
            database_url=runtime.replace("verify-full", "require"),
            identity_database_url=identity,
            auth_encryption_key="key-placeholder",
        )
    with pytest.raises(ValidationError, match="sslmode=verify-full"):
        Settings(
            app_env="production",
            database_url=runtime,
            identity_database_url=identity.replace("verify-full", "require"),
            auth_encryption_key="key-placeholder",
        )
    Settings(
        app_env="production",
        database_url=runtime,
        identity_database_url=identity,
        auth_encryption_key="key-placeholder",
    )


def test_error_hides_database_password() -> None:
    with pytest.raises(ValidationError) as error:
        Settings(
            app_env="production",
            database_url="postgresql+psycopg://u:sensitive-value@localhost/app",
        )
    assert "sensitive-value" not in str(error.value)


def shared_production_settings(**overrides: object) -> Settings:
    data: dict[str, object] = {
        "app_env": "production",
        "database_url": "postgresql+psycopg://runtime:p@db.example/app?sslmode=verify-full",
        "identity_database_url": "postgresql+psycopg://identity:p@db.example/app?sslmode=verify-full",
        "platform_database_url": "postgresql+psycopg://platform:p@db.example/app?sslmode=verify-full",
        "platform_host": "event-checkin-console.vercel.app",
        "origin_auth_secret": "synthetic-origin-secret",
        "auth_encryption_key": "synthetic-key",
    }
    data.update(overrides)
    return Settings(**data)


def test_shared_host_platform_does_not_require_a_fallback_zone() -> None:
    settings = shared_production_settings()
    assert settings.fallback_domain_suffix is None
    assert settings.platform_host == "event-checkin-console.vercel.app"


def test_shared_host_still_requires_explicit_host_and_authenticated_ingress() -> None:
    with pytest.raises(ValidationError, match="requires PLATFORM_HOST"):
        shared_production_settings(platform_host=None)
    with pytest.raises(ValidationError, match="trusted ingress"):
        shared_production_settings(origin_auth_secret=None)


def test_optional_owned_zone_keeps_existing_namespace_validation() -> None:
    with pytest.raises(ValidationError, match="platform-owned fallback zone"):
        shared_production_settings(fallback_domain_suffix="events.example.test")
    settings = shared_production_settings(
        platform_host="platform.events.example.test", fallback_domain_suffix="events.example.test"
    )
    assert settings.fallback_domain_suffix == "events.example.test"

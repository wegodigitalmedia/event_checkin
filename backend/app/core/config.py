from enum import StrEnum
from functools import lru_cache
from ipaddress import ip_address
from urllib.parse import urlsplit

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Environment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    app_env: Environment
    database_url: SecretStr
    identity_database_url: SecretStr | None = None
    auth_encryption_key: SecretStr | None = None
    auth_key_id: str = "v1"
    compromised_password_corpus: str | None = None
    compromised_password_sha256: str | None = None
    email_smtp_host: str | None = None
    email_smtp_port: int = 1025
    email_from: str | None = None
    email_from_name: str = "Event Check-in"
    brevo_api_key: SecretStr | None = None
    brevo_webhook_token: SecretStr | None = None
    ticket_keyring_json: SecretStr | None = None
    ticket_active_key_version: int = 1
    ticket_issuance_enabled: bool = False
    registration_rate_hmac_key: SecretStr | None = None
    jobs_database_url: SecretStr | None = None
    dispatcher_database_url: SecretStr | None = None
    jobs_operator_database_url: SecretStr | None = None
    redis_url: SecretStr | None = None
    storage_endpoint_url: str | None = None
    storage_bucket: str | None = None
    storage_access_key: SecretStr | None = None
    storage_secret_key: SecretStr | None = None
    storage_region: str = "us-east-1"  # Local S3 signing default; not a production location.
    upload_url_seconds: int = 600
    download_url_seconds: int = 300
    platform_host: str | None = None
    local_public_origin: str | None = None
    fallback_domain_suffix: str | None = None
    platform_database_url: SecretStr | None = None
    bootstrap_database_url: SecretStr | None = None
    domain_worker_database_url: SecretStr | None = None
    domain_scheduler_database_url: SecretStr | None = None
    origin_auth_secret: SecretStr | None = None
    ingress_proxy_ips: str = ""
    local_domain_fixture: str | None = None
    log_level: str = "INFO"

    @field_validator(
        "database_url",
        "identity_database_url",
        "jobs_database_url",
        "dispatcher_database_url",
        "jobs_operator_database_url",
        "platform_database_url",
        "bootstrap_database_url",
        "domain_worker_database_url",
        "domain_scheduler_database_url",
    )
    @classmethod
    def require_postgres(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        if not value.get_secret_value().startswith("postgresql+psycopg://"):
            raise ValueError("DATABASE_URL must use the postgresql+psycopg driver")
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        value = value.upper()
        if value not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LOG_LEVEL is invalid")
        return value

    @model_validator(mode="after")
    def enforce_nonlocal_transport(self) -> "Settings":
        from app.db.session import normalize_hostname

        if not 1 <= self.upload_url_seconds <= 3600 or not 1 <= self.download_url_seconds <= 3600:
            raise ValueError("signed URL lifetime is outside the allowed range")
        if self.platform_host is not None:
            self.platform_host = normalize_hostname(self.platform_host)
        if self.local_public_origin is not None:
            if self.app_env != Environment.LOCAL or self.platform_host is None:
                raise ValueError("local public origin requires a local platform host")
            local_origin = urlsplit(self.local_public_origin)
            if (
                local_origin.scheme != "https"
                or local_origin.hostname != self.platform_host
                or local_origin.port is None
                or local_origin.username is not None
                or local_origin.password is not None
                or local_origin.path
                or local_origin.query
                or local_origin.fragment
                or self.local_public_origin != f"https://{self.platform_host}:{local_origin.port}"
            ):
                raise ValueError("local public origin must be the platform HTTPS origin")
        if self.fallback_domain_suffix is not None:
            self.fallback_domain_suffix = normalize_hostname(self.fallback_domain_suffix)
        if self.platform_host and self.fallback_domain_suffix:
            if not self.platform_host.endswith("." + self.fallback_domain_suffix):
                raise ValueError("platform host must be in the platform-owned fallback zone")
        if self.platform_database_url is not None:
            if not self.platform_host:
                raise ValueError("platform control plane requires PLATFORM_HOST")
            platform_user = make_url(self.platform_database_url.get_secret_value()).username
            for value in (
                self.database_url,
                self.identity_database_url,
                self.jobs_database_url,
                self.jobs_operator_database_url,
            ):
                if (
                    value is not None
                    and make_url(value.get_secret_value()).username == platform_user
                ):
                    raise ValueError("platform database role must be separate")
        if self.bootstrap_database_url is not None:
            bootstrap_user = make_url(self.bootstrap_database_url.get_secret_value()).username
            for value in (
                self.database_url,
                self.identity_database_url,
                self.platform_database_url,
            ):
                if (
                    value is not None
                    and make_url(value.get_secret_value()).username == bootstrap_user
                ):
                    raise ValueError("bootstrap database role must be separate")
        for name, candidate in (
            ("domain worker", self.domain_worker_database_url),
            ("domain scheduler", self.domain_scheduler_database_url),
        ):
            if candidate is None:
                continue
            username = make_url(candidate.get_secret_value()).username
            for other in (
                self.database_url,
                self.identity_database_url,
                self.platform_database_url,
                self.bootstrap_database_url,
                self.jobs_database_url,
                self.domain_scheduler_database_url
                if name == "domain worker"
                else self.domain_worker_database_url,
            ):
                if other is not None and make_url(other.get_secret_value()).username == username:
                    raise ValueError(f"{name} database role must be separate")
        if self.origin_auth_secret is not None and not self.origin_auth_secret.get_secret_value():
            raise ValueError("ORIGIN_AUTH_SECRET must not be empty")
        if self.ingress_proxy_ips:
            for peer in self.ingress_proxy_ips.split(","):
                ip_address(peer.strip())
        if self.local_domain_fixture is not None and self.app_env not in {
            Environment.LOCAL,
            Environment.TEST,
        }:
            raise ValueError("local domain fixture is forbidden outside local/test")
        if self.jobs_database_url is not None:
            jobs = make_url(self.jobs_database_url.get_secret_value())
            runtime = make_url(self.database_url.get_secret_value())
            if jobs.username == runtime.username:
                raise ValueError("job and tenant runtime database roles must differ")
        if self.jobs_operator_database_url is not None:
            operator = make_url(self.jobs_operator_database_url.get_secret_value())
            if operator.username == make_url(self.database_url.get_secret_value()).username:
                raise ValueError("operator and runtime database roles must differ")
            if (
                self.jobs_database_url is not None
                and operator.username
                == make_url(self.jobs_database_url.get_secret_value()).username
            ):
                raise ValueError("operator and worker database roles must differ")
        if self.dispatcher_database_url is not None:
            dispatcher = make_url(self.dispatcher_database_url.get_secret_value())
            other_users = [make_url(self.database_url.get_secret_value()).username]
            for value in (self.jobs_database_url, self.jobs_operator_database_url):
                if value is not None:
                    other_users.append(make_url(value.get_secret_value()).username)
            if dispatcher.username in other_users:
                raise ValueError("dispatcher database role must be separate")
        if self.identity_database_url is not None:
            identity = make_url(self.identity_database_url.get_secret_value())
            runtime = make_url(self.database_url.get_secret_value())
            if identity.username == runtime.username:
                raise ValueError("identity and tenant runtime database roles must differ")
        if self.app_env in {Environment.STAGING, Environment.PRODUCTION}:
            if (
                self.platform_database_url is not None
                and not self.ingress_proxy_ips
                and self.origin_auth_secret is None
            ):
                raise ValueError("remote platform control plane requires trusted ingress peers")
            if self.identity_database_url is not None and self.auth_encryption_key is None:
                raise ValueError("remote authentication requires AUTH_ENCRYPTION_KEY")
            for value in (
                self.database_url,
                self.identity_database_url,
                self.jobs_database_url,
                self.dispatcher_database_url,
                self.jobs_operator_database_url,
                self.platform_database_url,
                self.bootstrap_database_url,
                self.domain_worker_database_url,
                self.domain_scheduler_database_url,
            ):
                if value is None:
                    continue
                parsed = make_url(value.get_secret_value())
                if (
                    not parsed.password
                    or parsed.password == "REPLACE_ME"
                    or parsed.host == "DB_HOST"
                ):
                    raise ValueError("remote database URL contains an unset credential or host")
                if parsed.host in {"localhost", "127.0.0.1", "::1"}:
                    raise ValueError("remote environments cannot use a loopback database")
                if parsed.query.get("sslmode") not in {"require", "verify-ca", "verify-full"}:
                    raise ValueError("remote database URL requires a TLS enforcing sslmode")
                if (
                    self.app_env == Environment.PRODUCTION
                    and parsed.query.get("sslmode") != "verify-full"
                ):
                    raise ValueError("production database URL requires sslmode=verify-full")
            if self.ticket_issuance_enabled and (
                self.brevo_api_key is None
                or self.brevo_webhook_token is None
                or self.email_from is None
            ):
                raise ValueError(
                    "remote ticket issuance requires Brevo credentials, webhook token, and sender"
                )
        if self.brevo_api_key is not None and self.email_from is None:
            raise ValueError("Brevo delivery requires EMAIL_FROM")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]

import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from app.api.auth import router as auth_router
from app.api.branding import router as branding_router
from app.api.domains import router as domains_router
from app.api.events import router as events_router
from app.api.health import ReadinessResponse, health, readiness
from app.api.operations import event_router as event_operations_router
from app.api.operations import gate_router
from app.api.platform import router as platform_router
from app.api.registration import router as registration_router
from app.api.shared import router as shared_router
from app.api.tickets import bulk_router as tickets_bulk_router
from app.api.tickets import router as tickets_router
from app.api.webhooks import brevo_authorized
from app.api.webhooks import router as webhooks_router
from app.auth.corpus import CompromisedPasswordCorpus
from app.auth.email import BrevoEmailDelivery, DisabledEmailDelivery, SmtpEmailDelivery
from app.auth.service import AuthService
from app.branding.assets import BrandingStorage, S3BrandingStorage, UnavailableBrandingStorage
from app.branding.service import BrandingService
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.db.engine import build_engine
from app.delivery.brevo import BrevoTransactionalClient
from app.events.service import EventService
from app.operations.service import EventOperationsService
from app.registration.service import RegistrationService
from app.registration.throttle import DenyRegistrationLimiter, RedisRegistrationLimiter
from app.tenancy.authority import AuthorityDenied, canonical_authority, trusted_client_address
from app.tenancy.domains import DisabledDomainProvider, DomainService, FixtureDomainProvider
from app.tenancy.ingress import AuthenticatedOriginMiddleware
from app.tenancy.platform_auth import PlatformAuth
from app.tenancy.shared_host import CONTEXT_COOKIE, shared_host_tenant, verify_context
from app.tickets.crypto import TicketKeyring, TicketKeyUnavailable
from app.tickets.email import (
    BrevoTicketTransport,
    DisabledTicketTransport,
    LocalSmtpTicketTransport,
)
from app.tickets.service import TicketService
from app.worker.storage import s3_storage

request_logger = logging.getLogger("eventcheckin.requests")
REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    database_engine = engine or build_engine(settings)
    identity_engine = (
        create_engine(settings.identity_database_url.get_secret_value(), pool_pre_ping=True)
        if settings.identity_database_url
        else None
    )
    platform_engine = (
        create_engine(settings.platform_database_url.get_secret_value(), pool_pre_ping=True)
        if settings.platform_database_url
        else None
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        database_engine.dispose()
        if identity_engine is not None:
            identity_engine.dispose()
        if platform_engine is not None:
            platform_engine.dispose()

    app = FastAPI(title="Event Check-in API", version="0.1.0", lifespan=lifespan)

    @app.middleware("http")
    async def request_observability(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if REQUEST_ID.fullmatch(supplied) else str(uuid4())
        started = time.perf_counter()
        response = await call_next(request)
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        request_logger.info(
            "request_complete",
            extra={
                "request_id": request_id,
                "method": request.method,
                "route": route_path,
                "status_code": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        response.headers["X-Request-ID"] = request_id
        return response

    @app.middleware("http")
    async def trusted_authority(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.path == "/api/v1/webhooks/brevo":
            if not brevo_authorized(
                settings.brevo_webhook_token, request.headers.get("authorization")
            ):
                return JSONResponse(
                    status_code=401,
                    content={"detail": {"code": "WEBHOOK_AUTH_INVALID"}},
                )
            return await call_next(request)
        if request.url.path.startswith("/api/"):
            try:
                host, origin = canonical_authority(request, settings)
                client_address = trusted_client_address(request, settings)
            except AuthorityDenied:
                return JSONResponse(
                    status_code=421,
                    content={
                        "detail": {"code": "UNRECOGNIZED_HOST", "message": "Host is unavailable"}
                    },
                )
            tenant_host = host
            if (
                settings.platform_host
                and host == settings.platform_host
                and not request.url.path.startswith("/api/v1/platform")
            ):
                tenant_context = verify_context(settings, request.cookies.get(CONTEXT_COOKIE, ""))
                if tenant_context is not None:
                    tenant_host = shared_host_tenant(tenant_context)
                elif request.url.path not in {
                    "/api/v1/auth/csrf",
                    "/api/v1/auth/invitations/accept",
                    "/api/v1/auth/password-reset/complete",
                } and not request.url.path.startswith("/api/v1/shared/"):
                    return JSONResponse(
                        status_code=421,
                        content={
                            "detail": {
                                "code": "TENANT_CONTEXT_REQUIRED",
                                "message": "Choose an organization first",
                            }
                        },
                    )
            request.state.trusted_hostname = tenant_host
            request.state.trusted_origin = origin
            request.state.client_address = client_address
        return await call_next(request)

    @app.middleware("http")
    async def auth_cache_control(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        if request.url.path.startswith(
            (
                "/api/v1/auth",
                "/api/v1/shared",
                "/api/v1/platform",
                "/api/v1/domains",
                "/api/v1/events",
                "/api/v1/branding",
                "/api/v1/public",
                "/api/v1/gate",
                "/api/v1/webhooks",
            )
        ):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    app.include_router(auth_router)
    app.include_router(platform_router)
    app.include_router(domains_router)
    app.include_router(events_router)
    app.include_router(branding_router)
    app.include_router(registration_router)
    app.include_router(tickets_router)
    app.include_router(tickets_bulk_router)
    app.include_router(shared_router)
    app.include_router(event_operations_router)
    app.include_router(gate_router)
    app.include_router(webhooks_router)
    app.state.settings = settings
    app.state.auth_service = None
    app.state.platform_auth = None
    app.state.domain_service = None
    app.state.event_service = None
    app.state.branding_service = None
    app.state.registration_service = None
    app.state.ticket_service = None
    app.state.event_operations_service = None
    app.state.database_engine = database_engine
    app.state.platform_control_engine = platform_engine
    app.state.email_delivery = DisabledEmailDelivery()
    branding_storage: BrandingStorage = UnavailableBrandingStorage()
    if identity_engine is not None:
        email = (
            BrevoEmailDelivery(
                BrevoTransactionalClient(settings.brevo_api_key.get_secret_value()),
                settings.email_from,
                settings.email_from_name,
            )
            if settings.brevo_api_key and settings.email_from
            else SmtpEmailDelivery(
                settings.email_smtp_host, settings.email_smtp_port, settings.email_from
            )
            if settings.app_env.value in {"local", "test"}
            and settings.email_smtp_host
            and settings.email_from
            else DisabledEmailDelivery()
        )
        app.state.auth_service = AuthService(
            identity_engine,
            settings,
            CompromisedPasswordCorpus(
                settings.compromised_password_corpus, settings.compromised_password_sha256
            ),
            email,
        )
        app.state.email_delivery = email
        app.state.event_service = EventService(database_engine, app.state.auth_service)
        branding_storage = (
            S3BrandingStorage(s3_storage(settings))
            if settings.storage_bucket
            and settings.storage_access_key
            and settings.storage_secret_key
            else UnavailableBrandingStorage()
        )
        app.state.branding_service = BrandingService(
            database_engine, app.state.auth_service, branding_storage
        )
    try:
        ticket_keys = TicketKeyring.from_settings(settings)
    except TicketKeyUnavailable:
        ticket_keys = None
    ticket_transport = (
        BrevoTicketTransport(
            BrevoTransactionalClient(settings.brevo_api_key.get_secret_value()),
            settings.email_from,
        )
        if settings.brevo_api_key and settings.email_from
        else LocalSmtpTicketTransport(
            settings.email_smtp_host, settings.email_smtp_port, settings.email_from
        )
        if settings.app_env.value in {"local", "test"}
        and settings.email_smtp_host
        and settings.email_from
        else DisabledTicketTransport()
    )
    if ticket_keys is not None:
        app.state.ticket_service = TicketService(
            database_engine,
            app.state.auth_service,
            ticket_keys,
            ticket_transport,
            branding_storage,
        )
    if app.state.auth_service is not None:
        app.state.event_operations_service = EventOperationsService(
            database_engine, app.state.auth_service, ticket_keys
        )
    limiter = (
        RedisRegistrationLimiter(
            settings.redis_url.get_secret_value(),
            settings.registration_rate_hmac_key.get_secret_value().encode("utf-8"),
        )
        if settings.redis_url and settings.registration_rate_hmac_key
        else DenyRegistrationLimiter()
    )
    app.state.registration_service = RegistrationService(
        database_engine,
        limiter,
        issuance_ready=(
            ticket_keys is not None
            and not isinstance(ticket_transport, DisabledTicketTransport)
            and settings.redis_url is not None
            and settings.ticket_issuance_enabled
        ),
    )
    if platform_engine is not None and identity_engine is not None:
        app.state.platform_auth = PlatformAuth(identity_engine, settings)
        if settings.fallback_domain_suffix is not None:
            provider = (
                FixtureDomainProvider(settings.local_domain_fixture)
                if settings.local_domain_fixture and settings.app_env.value in {"local", "test"}
                else DisabledDomainProvider()
            )
            app.state.domain_service = DomainService(
                platform_engine,
                database_engine,
                app.state.auth_service,
                provider,
                settings.fallback_domain_suffix,
            )
    app.add_api_route("/health", health, methods=["GET"], include_in_schema=False)

    def readiness_route(response: Response) -> ReadinessResponse:
        return readiness(database_engine, response)

    app.add_api_route("/ready", readiness_route, methods=["GET"], include_in_schema=False)
    if settings.origin_auth_secret is not None:
        app.add_middleware(AuthenticatedOriginMiddleware, secret=settings.origin_auth_secret)
    return app


app = create_app()

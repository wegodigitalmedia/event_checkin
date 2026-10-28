"""M2-01 platform host routes; no tenant data access is exposed."""

from datetime import datetime
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from app.api.auth import clear_cookie, csrf, csrf_token, set_cookie
from app.auth.address import single_email_address
from app.auth.email import DeliveryUnavailable
from app.auth.policy import SESSION_MAX_AGE
from app.auth.service import AuthDenied
from app.tenancy.domains import DomainDenied, DomainService
from app.tenancy.platform_auth import PlatformAuth
from app.tenancy.platform_organizations import PlatformOrganizations
from app.tenancy.privacy_notices import PrivacyNoticeDenied, PrivacyNotices
from app.tenancy.shared_onboarding import SharedOnboarding

router = APIRouter(prefix="/api/v1/platform", tags=["platform provisioning"])
PLATFORM_SESSION_COOKIE = "__Host-ecs_platform_session"
PLATFORM_CHALLENGE_COOKIE = "__Host-ecs_platform_challenge"


def platform_auth(request: Request) -> PlatformAuth:
    result = getattr(request.app.state, "platform_auth", None)
    if result is None:
        raise HTTPException(
            503,
            detail={
                "code": "PLATFORM_UNAVAILABLE",
                "message": "Platform administration unavailable",
            },
        )
    return cast(PlatformAuth, result)


def domains(request: Request) -> DomainService:
    result = getattr(request.app.state, "domain_service", None)
    if result is None:
        raise HTTPException(
            503,
            detail={"code": "DOMAINS_UNAVAILABLE", "message": "Domain administration unavailable"},
        )
    return cast(DomainService, result)


def platform_control(request: Request) -> Engine:
    result = getattr(request.app.state, "platform_control_engine", None)
    if result is None:
        raise HTTPException(
            503,
            detail={
                "code": "PLATFORM_UNAVAILABLE",
                "message": "Platform administration unavailable",
            },
        )
    return cast(Engine, result)


Control = Annotated[Engine, Depends(platform_control)]
Auth = Annotated[PlatformAuth, Depends(platform_auth)]
Domains = Annotated[DomainService, Depends(domains)]


class LoginBody(BaseModel):
    email: str
    password: str


class VerifyBody(BaseModel):
    code: str
    recovery: bool = False


class ProvisionBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=1, max_length=63)


class OwnerBody(BaseModel):
    email: str


class SharedOrganizationBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    organizer_email: str
    organizer_name: str | None = Field(default=None, max_length=160)
    contact_phone: str | None = Field(default=None, max_length=40)
    event_name: str | None = Field(default=None, max_length=200)
    idempotency_key: UUID


class NoticeDraftBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=20_000)
    lawful_basis: str = Field(min_length=1, max_length=500)
    test_only: bool = False


class NoticeApprovalBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approval_reference: str = Field(min_length=1, max_length=500)
    confirmed: StrictBool


class NoticeActivationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: StrictBool


class OrganizationResponse(BaseModel):
    id: UUID
    name: str
    status: str
    created_at: datetime
    primary_organizer: str | None
    invitation_delivery_status: str | None


class OrganizationPageResponse(BaseModel):
    organizations: list[OrganizationResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    has_more: bool


class PrivacyNoticeResponse(BaseModel):
    version: int = Field(ge=1)
    body: str
    lawful_basis: str
    test_only: bool
    created_at: datetime
    created_by: UUID | None
    approved_at: datetime | None
    approved_by: UUID | None
    approval_reference: str | None
    active: bool


class PrivacyNoticeListResponse(BaseModel):
    organization_id: UUID
    organization_name: str
    notices: list[PrivacyNoticeResponse]


def notice_failure(exc: Exception) -> HTTPException:
    if isinstance(exc, AuthDenied):
        return HTTPException(401, detail={"code": "AUTH_DENIED", "message": "Sign in required"})
    if isinstance(exc, DomainDenied):
        return HTTPException(
            403, detail={"code": "FORBIDDEN", "message": "Platform approval access required"}
        )
    return HTTPException(409, detail={"code": "NOTICE_STATE", "message": str(exc)})


def notice_service(request: Request, control: Engine) -> PrivacyNotices:
    return PrivacyNotices(control, request.app.state.settings.app_env)


def fail(exc: Exception) -> HTTPException:
    if isinstance(exc, DeliveryUnavailable):
        return HTTPException(
            503, detail={"code": "EMAIL_UNAVAILABLE", "message": "Email delivery is unavailable"}
        )
    if isinstance(exc, AuthDenied):
        return HTTPException(
            401, detail={"code": "AUTH_DENIED", "message": "Authentication required"}
        )
    if isinstance(exc, DomainDenied):
        return HTTPException(409, detail={"code": "DOMAIN_STATE", "message": str(exc)})
    if isinstance(exc, IntegrityError):
        return HTTPException(
            409,
            detail={
                "code": "TENANT_OR_HOST_CLAIMED",
                "message": "Tenant or hostname is unavailable",
            },
        )
    return HTTPException(422, detail={"code": "INVALID_INPUT", "message": "Invalid request"})


@router.get("/auth/csrf")
def platform_csrf(response: Response) -> dict[str, str]:
    return csrf_token(response)


@router.post("/auth/login", dependencies=[Depends(csrf)])
def login(body: LoginBody, request: Request, response: Response, auth: Auth) -> dict[str, str]:
    try:
        state, raw = auth.login(
            single_email_address(body.email),
            body.password,
            request.client.host if request.client else "unknown",
        )
    except (AuthDenied, ValueError) as exc:
        raise fail(exc) from exc
    previous = request.cookies.get(PLATFORM_SESSION_COOKIE)
    if previous:
        auth.revoke(previous)
    previous_challenge = request.cookies.get(PLATFORM_CHALLENGE_COOKIE)
    if previous_challenge:
        auth.cancel_challenge(previous_challenge)
    clear_cookie(response, PLATFORM_SESSION_COOKIE)
    set_cookie(response, PLATFORM_CHALLENGE_COOKIE, raw, 5 * 60)
    return {"state": state}


@router.post("/auth/mfa/enroll", dependencies=[Depends(csrf)])
def enroll(request: Request, auth: Auth) -> dict[str, str]:
    try:
        return {"secret": auth.enroll(request.cookies.get(PLATFORM_CHALLENGE_COOKIE, ""))}
    except AuthDenied as exc:
        raise fail(exc) from exc


@router.post("/auth/mfa/verify", dependencies=[Depends(csrf)])
def verify(body: VerifyBody, request: Request, response: Response, auth: Auth) -> dict[str, object]:
    try:
        token, codes = auth.verify(
            request.cookies.get(PLATFORM_CHALLENGE_COOKIE, ""),
            body.code,
            body.recovery,
            request.client.host if request.client else "unknown",
        )
    except AuthDenied as exc:
        raise fail(exc) from exc
    clear_cookie(response, PLATFORM_CHALLENGE_COOKIE)
    set_cookie(response, PLATFORM_SESSION_COOKIE, token, SESSION_MAX_AGE)
    return {"state": "session", "recovery_codes": codes}


@router.get("/auth/session")
def session(request: Request, auth: Auth) -> dict[str, str]:
    try:
        user = auth.current(request.cookies.get(PLATFORM_SESSION_COOKIE, ""))
    except AuthDenied as exc:
        raise fail(exc) from exc
    return {"user_id": str(user.id), "email": user.email, "permission": "tenant.provision"}


@router.post("/auth/logout", dependencies=[Depends(csrf)])
def logout(request: Request, response: Response, auth: Auth) -> dict[str, str]:
    raw = request.cookies.get(PLATFORM_SESSION_COOKIE)
    if raw:
        auth.revoke(raw)
    challenge = request.cookies.get(PLATFORM_CHALLENGE_COOKIE)
    if challenge:
        auth.cancel_challenge(challenge)
    clear_cookie(response, PLATFORM_SESSION_COOKIE)
    clear_cookie(response, PLATFORM_CHALLENGE_COOKIE)
    return {"state": "logged_out"}


def actor(request: Request, auth: PlatformAuth) -> UUID:
    return auth.current(request.cookies.get(PLATFORM_SESSION_COOKIE, "")).id


@router.get("/organizations", response_model=OrganizationPageResponse)
def list_organizations(
    request: Request,
    auth: Auth,
    control: Control,
    q: str = Query(default="", max_length=100),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> OrganizationPageResponse:
    try:
        return OrganizationPageResponse.model_validate(
            PlatformOrganizations(control).list(
                actor(request, auth), query=q, limit=limit, offset=offset
            )
        )
    except (AuthDenied, DomainDenied) as exc:
        raise notice_failure(exc) from exc


@router.get("/organizations/{tenant_id}", response_model=OrganizationResponse)
def get_organization(
    tenant_id: UUID, request: Request, auth: Auth, control: Control
) -> OrganizationResponse:
    try:
        organization = PlatformOrganizations(control).get(
            actor(request, auth), tenant_id
        )
    except (AuthDenied, DomainDenied) as exc:
        raise notice_failure(exc) from exc
    if organization is None:
        raise HTTPException(
            404, detail={"code": "ORGANIZATION_NOT_FOUND", "message": "Organization unavailable"}
        )
    return OrganizationResponse.model_validate(organization)


@router.get(
    "/organizations/{tenant_id}/privacy-notices",
    response_model=PrivacyNoticeListResponse,
)
def list_privacy_notices(
    tenant_id: UUID, request: Request, auth: Auth, control: Control
) -> PrivacyNoticeListResponse:
    try:
        return PrivacyNoticeListResponse.model_validate(
            notice_service(request, control).list(actor(request, auth), tenant_id)
        )
    except (AuthDenied, DomainDenied, PrivacyNoticeDenied) as exc:
        raise notice_failure(exc) from exc


@router.post(
    "/organizations/{tenant_id}/privacy-notices",
    status_code=201,
    dependencies=[Depends(csrf)],
    response_model=PrivacyNoticeResponse,
)
def draft_privacy_notice(
    tenant_id: UUID, body: NoticeDraftBody, request: Request, auth: Auth, control: Control
) -> PrivacyNoticeResponse:
    try:
        return PrivacyNoticeResponse.model_validate(
            notice_service(request, control).draft(
                actor(request, auth), tenant_id, body.body, body.lawful_basis, body.test_only
            )
        )
    except (AuthDenied, DomainDenied, PrivacyNoticeDenied) as exc:
        raise notice_failure(exc) from exc


@router.post(
    "/organizations/{tenant_id}/privacy-notices/{version}/approve",
    dependencies=[Depends(csrf)],
    response_model=PrivacyNoticeResponse,
)
def approve_privacy_notice(
    tenant_id: UUID,
    version: int,
    body: NoticeApprovalBody,
    request: Request,
    auth: Auth,
    control: Control,
) -> PrivacyNoticeResponse:
    if not body.confirmed:
        raise HTTPException(
            422,
            detail={
                "code": "CONFIRMATION_REQUIRED",
                "message": "Confirm external approval before continuing",
            },
        )
    try:
        return PrivacyNoticeResponse.model_validate(
            notice_service(request, control).approve(
                actor(request, auth), tenant_id, version, body.approval_reference
            )
        )
    except (AuthDenied, DomainDenied, PrivacyNoticeDenied) as exc:
        raise notice_failure(exc) from exc


@router.post(
    "/organizations/{tenant_id}/privacy-notices/{version}/activate",
    dependencies=[Depends(csrf)],
    response_model=PrivacyNoticeResponse,
)
def activate_privacy_notice(
    tenant_id: UUID,
    version: int,
    body: NoticeActivationBody,
    request: Request,
    auth: Auth,
    control: Control,
) -> PrivacyNoticeResponse:
    if not body.confirmed:
        raise HTTPException(
            422,
            detail={
                "code": "CONFIRMATION_REQUIRED",
                "message": "Confirm activation before continuing",
            },
        )
    try:
        return PrivacyNoticeResponse.model_validate(
            notice_service(request, control).activate(actor(request, auth), tenant_id, version)
        )
    except (AuthDenied, DomainDenied, PrivacyNoticeDenied) as exc:
        raise notice_failure(exc) from exc


@router.post("/organizations", dependencies=[Depends(csrf)], status_code=201)
def create_shared_organization(
    body: SharedOrganizationBody,
    request: Request,
    auth: Auth,
    control: Control,
) -> dict[str, str]:
    try:
        return SharedOnboarding(control, request.app.state.email_delivery).create(
            actor=actor(request, auth),
            idempotency_key=body.idempotency_key,
            name=body.name,
            organizer_email=body.organizer_email,
            organizer_name=body.organizer_name,
            contact_phone=body.contact_phone,
            event_name=body.event_name,
            origin=request.state.trusted_origin,
        )
    except (AuthDenied, DomainDenied, ValueError, IntegrityError) as exc:
        raise fail(exc) from exc


@router.post("/organizations/{tenant_id}/invitation/resend", dependencies=[Depends(csrf)])
def resend_shared_organizer(
    tenant_id: UUID,
    request: Request,
    auth: Auth,
    control: Control,
) -> dict[str, str]:
    try:
        return SharedOnboarding(control, request.app.state.email_delivery).resend(
            actor(request, auth),
            tenant_id,
            request.state.trusted_origin,
        )
    except (AuthDenied, DomainDenied, ValueError) as exc:
        raise fail(exc) from exc


@router.post("/tenants", dependencies=[Depends(csrf)], status_code=201)
def provision(
    body: ProvisionBody, request: Request, auth: Auth, service: Domains
) -> dict[str, str]:
    try:
        tenant_id, domain_id, host, proof = service.provision(
            actor(request, auth), body.name, body.slug
        )
    except (AuthDenied, DomainDenied, ValueError, IntegrityError) as exc:
        raise fail(exc) from exc
    return {
        "tenant_id": str(tenant_id),
        "fallback_domain_id": str(domain_id),
        "fallback_hostname": host,
        "dns_record": f"_eventcheckin-verify.{host}",
        "dns_value": proof,
        "state": "provisioning",
    }


@router.post("/tenants/{tenant_id}/domains/{domain_id}/activate", dependencies=[Depends(csrf)])
def activate(
    tenant_id: UUID, domain_id: UUID, request: Request, auth: Auth, service: Domains
) -> dict[str, str]:
    try:
        service.activate(actor(request, auth), tenant_id, domain_id)
    except (AuthDenied, DomainDenied) as exc:
        raise fail(exc) from exc
    return {"state": "active"}


@router.get("/tenants/{tenant_id}/domains")
def tenant_domains(
    tenant_id: UUID, request: Request, auth: Auth, service: Domains
) -> dict[str, object]:
    try:
        rows = service.platform_status(actor(request, auth), tenant_id)
    except (AuthDenied, DomainDenied) as exc:
        raise fail(exc) from exc
    return {
        "domains": [
            {
                "id": str(row.id),
                "hostname": row.hostname,
                "kind": row.kind,
                "ownership": row.verification_state,
                "tls": row.tls_state,
                "routing": row.routing_state,
                "primary": row.is_primary,
                "serving": service.public_route_serving(row),
                "error_code": row.last_error_code,
            }
            for row in rows
        ]
    }


@router.post("/tenants/{tenant_id}/domains/{domain_id}/check", dependencies=[Depends(csrf)])
def check_domain(
    tenant_id: UUID, domain_id: UUID, request: Request, auth: Auth, service: Domains
) -> dict[str, str]:
    try:
        job_id = service.platform_request_check(actor(request, auth), tenant_id, domain_id)
    except (AuthDenied, DomainDenied) as exc:
        raise fail(exc) from exc
    return {"job_id": str(job_id), "state": "pending"}


@router.post("/tenants/{tenant_id}/domains/{domain_id}/renew", dependencies=[Depends(csrf)])
def renew_domain(
    tenant_id: UUID, domain_id: UUID, request: Request, auth: Auth, service: Domains
) -> dict[str, str]:
    try:
        proof = service.platform_renew_claim(actor(request, auth), tenant_id, domain_id)
    except (AuthDenied, DomainDenied) as exc:
        raise fail(exc) from exc
    return {"dns_value": proof, "state": "reserved"}


@router.post("/tenants/{tenant_id}/domains/{domain_id}/deactivate", dependencies=[Depends(csrf)])
def deactivate(
    tenant_id: UUID, domain_id: UUID, request: Request, auth: Auth, service: Domains
) -> dict[str, str]:
    try:
        service.deactivate(actor(request, auth), tenant_id, domain_id)
    except (AuthDenied, DomainDenied) as exc:
        raise fail(exc) from exc
    return {"state": "deactivated"}


@router.post("/tenants/{tenant_id}/owner-invitations", dependencies=[Depends(csrf)])
def first_owner(
    tenant_id: UUID, body: OwnerBody, request: Request, auth: Auth, service: Domains
) -> dict[str, str]:
    delivery = getattr(request.app.state, "email_delivery", None)
    if delivery is None:
        raise fail(DeliveryUnavailable("Delivery unavailable"))
    try:
        service.issue_first_owner(actor(request, auth), tenant_id, body.email, delivery)
    except (AuthDenied, DomainDenied, DeliveryUnavailable, ValueError) as exc:
        raise fail(exc) from exc
    return {"state": "invitation_requested"}


@router.post("/tenants/{tenant_id}/owner-invitations/reissue", dependencies=[Depends(csrf)])
def reissue_first_owner(
    tenant_id: UUID, request: Request, auth: Auth, service: Domains
) -> dict[str, str]:
    delivery = getattr(request.app.state, "email_delivery", None)
    if delivery is None:
        raise fail(DeliveryUnavailable("Delivery unavailable"))
    try:
        service.reissue_first_owner(actor(request, auth), tenant_id, delivery)
    except (AuthDenied, DomainDenied, DeliveryUnavailable) as exc:
        raise fail(exc) from exc
    return {"state": "invitation_reissued"}

"""One password entry point for platform and tenant staff on the shared host."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.api.auth import CHALLENGE_COOKIE, SESSION_COOKIE, clear_cookie, csrf, set_cookie
from app.api.platform import PLATFORM_CHALLENGE_COOKIE, PLATFORM_SESSION_COOKIE
from app.auth.address import single_email_address
from app.auth.email import DeliveryUnavailable
from app.auth.policy import SESSION_MAX_AGE
from app.auth.security import verify_password
from app.auth.service import AuthDenied, AuthService, utcnow
from app.db.models import PasswordCredential, User
from app.tenancy.platform_auth import PlatformAuth
from app.tenancy.shared_host import (
    CONTEXT_COOKIE,
    CONTEXT_LIFETIME,
    shared_host_tenant,
    sign_context,
)

router = APIRouter(prefix="/api/v1/shared", tags=["shared staff entry"])


class SharedLogin(BaseModel):
    email: str
    password: str
    context: str | None = None


class SharedReset(BaseModel):
    email: str


def services(request: Request) -> tuple[AuthService, PlatformAuth]:
    auth = getattr(request.app.state, "auth_service", None)
    platform = getattr(request.app.state, "platform_auth", None)
    if not isinstance(auth, AuthService) or not isinstance(platform, PlatformAuth):
        raise HTTPException(
            503, detail={"code": "AUTH_UNAVAILABLE", "message": "Sign in unavailable"}
        )
    if request.url.hostname != auth.settings.platform_host:
        raise HTTPException(404)
    return auth, platform


Services = Annotated[tuple[AuthService, PlatformAuth], Depends(services)]


@router.get("/context")
def shared_context(request: Request) -> dict[str, bool]:
    settings = request.app.state.settings
    return {"shared": request.url.hostname == settings.platform_host}


@router.post("/password-reset/request", dependencies=[Depends(csrf)])
def request_password_reset(body: SharedReset, request: Request, pair: Services) -> dict[str, str]:
    auth, _ = pair
    try:
        email = single_email_address(body.email)
    except ValueError:
        return {"message": "If the account is eligible, a reset link will be sent"}
    try:
        with Session(auth.engine) as limiter, limiter.begin():
            AuthService._limit(
                limiter, f"shared:reset:ip:{request.state.client_address}", utcnow(), 20
            )
            AuthService._limit(limiter, f"shared:reset:account:{email.casefold()}", utcnow(), 5)
    except AuthDenied:
        return {"message": "If the account is eligible, a reset link will be sent"}
    # A password is global to the staff identity. One active tenant membership
    # supplies the routing context; the email response never reveals membership.
    with Session(auth.engine) as db, db.begin():
        user = db.scalar(select(User).where(User.email == email))
        tenant = None
        if user is not None and user.status == "active":
            tenant = db.execute(
                text(
                    "SELECT tenant_id FROM shared_login_contexts(:user) ORDER BY tenant_id LIMIT 1"
                ),
                {"user": user.id},
            ).scalar_one_or_none()
    if tenant is not None:
        try:
            auth.request_reset(
                shared_host_tenant(tenant),
                email,
                request.state.client_address,
                request.state.trusted_origin,
                tenant,
            )
        except AuthDenied:
            pass
        except DeliveryUnavailable as exc:
            raise HTTPException(
                503, detail={"code": "DELIVERY_UNAVAILABLE", "message": str(exc)}
            ) from exc
    return {"message": "If the account is eligible, a reset link will be sent"}


@router.post("/login", dependencies=[Depends(csrf)])
def login(
    body: SharedLogin, request: Request, response: Response, pair: Services
) -> dict[str, object]:
    auth, platform = pair
    try:
        email = single_email_address(body.email)
    except ValueError as exc:
        raise HTTPException(
            422, detail={"code": "INVALID_EMAIL", "message": "Enter a valid email"}
        ) from exc
    ip = request.state.client_address
    account_key = f"shared:login:{email.casefold()}"
    ip_key = f"shared:login:ip:{ip}"
    try:
        with Session(auth.engine) as db, db.begin():
            AuthService._check_limit(db, account_key, utcnow())
            AuthService._check_limit(db, ip_key, utcnow())
            user = db.scalar(select(User).where(User.email == email))
            credential = db.get(PasswordCredential, user.id) if user else None
            if (
                user is None
                or user.status != "active"
                or not verify_password(
                    credential.password_hash if credential else None, body.password
                )
            ):
                raise AuthDenied("Invalid credentials")
            tenant_rows = db.execute(
                text("SELECT tenant_id,tenant_name,member_role FROM shared_login_contexts(:user)"),
                {"user": user.id},
            ).all()
            platform_access = PlatformAuth._granted(db, user.id)
            contexts = (
                [{"id": "platform", "name": "Platform Console", "role": "platform_admin"}]
                if platform_access
                else []
            ) + [
                {"id": str(row.tenant_id), "name": row.tenant_name, "role": row.member_role}
                for row in tenant_rows
            ]
            if not contexts:
                raise AuthDenied("Invalid credentials")
        with Session(auth.engine) as db, db.begin():
            AuthService._clear_limit(db, account_key)
            AuthService._clear_limit(db, ip_key)
    except AuthDenied as exc:
        try:
            with Session(auth.engine) as db, db.begin():
                AuthService._limit(db, account_key, utcnow())
                AuthService._limit(db, ip_key, utcnow(), 20)
        except AuthDenied:
            pass
        raise HTTPException(401, detail={"code": "AUTH_DENIED", "message": str(exc)}) from exc

    chosen = body.context or (str(contexts[0]["id"]) if len(contexts) == 1 else None)
    if chosen is None:
        return {"state": "select_context", "contexts": contexts}
    if chosen not in {str(item["id"]) for item in contexts}:
        raise HTTPException(403, detail={"code": "CONTEXT_DENIED", "message": "Access denied"})
    if chosen == "platform":
        try:
            state, token = platform.login(email, body.password, ip)
        except AuthDenied as exc:
            raise HTTPException(
                401, detail={"code": "AUTH_DENIED", "message": "Invalid credentials"}
            ) from exc
        clear_cookie(response, CONTEXT_COOKIE)
        clear_cookie(response, SESSION_COOKIE)
        clear_cookie(response, CHALLENGE_COOKIE)
        clear_cookie(response, PLATFORM_SESSION_COOKIE)
        clear_cookie(response, PLATFORM_CHALLENGE_COOKIE)
        set_cookie(
            response,
            PLATFORM_CHALLENGE_COOKIE if state != "session" else PLATFORM_SESSION_COOKIE,
            token,
            5 * 60 if state != "session" else SESSION_MAX_AGE,
        )
        return {"state": state, "destination": "platform"}
    tenant_id = UUID(chosen)
    try:
        state, token = auth.login(shared_host_tenant(tenant_id), email, body.password, ip)
    except AuthDenied as exc:
        raise HTTPException(
            401, detail={"code": "AUTH_DENIED", "message": "Invalid credentials"}
        ) from exc
    clear_cookie(response, SESSION_COOKIE)
    clear_cookie(response, CHALLENGE_COOKIE)
    set_cookie(response, CONTEXT_COOKIE, sign_context(auth.settings, tenant_id), CONTEXT_LIFETIME)
    set_cookie(
        response,
        SESSION_COOKIE if state == "session" else CHALLENGE_COOKIE,
        token,
        SESSION_MAX_AGE if state == "session" else 5 * 60,
    )
    return {
        "state": state,
        "destination": "tenant",
        "role": next(str(item["role"]) for item in contexts if item["id"] == chosen),
    }

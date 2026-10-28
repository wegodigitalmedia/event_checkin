"""Versioned M1-03 staff identity endpoints."""

import hmac
import secrets
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import AfterValidator, BaseModel, Field

from app.auth.address import single_email_address
from app.auth.corpus import CorpusUnavailable
from app.auth.email import DeliveryUnavailable
from app.auth.policy import SESSION_MAX_AGE
from app.auth.service import AuthDenied, AuthService, Forbidden
from app.tenancy.shared_host import (
    CONTEXT_COOKIE,
    CONTEXT_LIFETIME,
    shared_host_tenant,
    sign_context,
)

router = APIRouter(prefix="/api/v1/auth", tags=["staff authentication"])
SESSION_COOKIE = "__Host-ecs_session"
CHALLENGE_COOKIE = "__Host-ecs_challenge"
CSRF_COOKIE = "__Host-ecs_csrf"


def valid_email(value: str) -> str:
    return single_email_address(value)


EmailAddress = Annotated[str, AfterValidator(valid_email)]


class LoginBody(BaseModel):
    email: EmailAddress
    password: str


class MfaBody(BaseModel):
    code: str
    recovery: bool = False


class PasswordBody(BaseModel):
    token: str
    password: str = Field(min_length=12, max_length=128)
    tenant_id: UUID | None = None


class ResetRequestBody(BaseModel):
    email: EmailAddress


class InvitationBody(BaseModel):
    email: EmailAddress
    role: str
    event_id: UUID | None = None
    gate_id: UUID | None = None


class GateAssignmentBody(BaseModel):
    event_id: UUID
    gate_id: UUID


def service(request: Request) -> AuthService:
    auth = getattr(request.app.state, "auth_service", None)
    if auth is None:
        raise HTTPException(
            503, detail={"code": "AUTH_UNAVAILABLE", "message": "Authentication unavailable"}
        )
    return cast(AuthService, auth)


AuthDependency = Annotated[AuthService, Depends(service)]


def hostname(request: Request) -> str:
    host = getattr(request.state, "trusted_hostname", None)
    if host is None:
        raise HTTPException(400, detail={"code": "INVALID_HOST", "message": "Invalid host"})
    return cast(str, host)


def csrf(request: Request) -> None:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get("x-csrf-token", "")
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise HTTPException(
            403, detail={"code": "CSRF_INVALID", "message": "Request verification failed"}
        )
    origin = request.headers.get("origin")
    expected_origin = getattr(request.state, "trusted_origin", str(request.base_url))
    if origin and origin.rstrip("/") != expected_origin.rstrip("/"):
        raise HTTPException(
            403, detail={"code": "CSRF_INVALID", "message": "Request verification failed"}
        )


def set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/",
    )


def clear_cookie(response: Response, name: str) -> None:
    response.delete_cookie(name, secure=True, httponly=True, samesite="strict", path="/")


def handle_error(exc: Exception) -> HTTPException:
    if isinstance(exc, CorpusUnavailable):
        return HTTPException(
            503,
            detail={
                "code": "PASSWORD_SCREENING_UNAVAILABLE",
                "message": "Credential changes are temporarily unavailable",
            },
        )
    if isinstance(exc, DeliveryUnavailable):
        return HTTPException(
            503, detail={"code": "EMAIL_UNAVAILABLE", "message": "Email delivery is unavailable"}
        )
    if isinstance(exc, Forbidden):
        return HTTPException(403, detail={"code": "FORBIDDEN", "message": str(exc)})
    if isinstance(exc, AuthDenied):
        return HTTPException(401, detail={"code": "AUTH_DENIED", "message": str(exc)})
    if isinstance(exc, ValueError):
        return HTTPException(422, detail={"code": "INVALID_INPUT", "message": str(exc)})
    return HTTPException(500, detail={"code": "SERVER_ERROR", "message": "Request failed"})


@router.get("/csrf")
def csrf_token(response: Response) -> dict[str, str]:
    value = secrets.token_urlsafe(32)
    set_cookie(response, CSRF_COOKIE, value, 8 * 60 * 60)
    return {"csrf_token": value}


@router.post("/login", dependencies=[Depends(csrf)])
def login(
    body: LoginBody,
    request: Request,
    response: Response,
    auth: AuthDependency,
) -> dict[str, str]:
    try:
        state, token = auth.login(
            hostname(request),
            body.email,
            body.password,
            request.client.host if request.client else "unknown",
        )
    except (AuthDenied, ValueError) as exc:
        raise handle_error(exc) from exc
    previous = request.cookies.get(SESSION_COOKIE)
    if previous:
        auth.logout(previous)
    previous_challenge = request.cookies.get(CHALLENGE_COOKIE)
    if previous_challenge:
        auth.cancel_challenge(previous_challenge)
    clear_cookie(response, SESSION_COOKIE)
    clear_cookie(response, CHALLENGE_COOKIE)
    if state == "session":
        set_cookie(response, SESSION_COOKIE, token, SESSION_MAX_AGE)
    else:
        set_cookie(response, CHALLENGE_COOKIE, token, 5 * 60)
    return {"state": state}


@router.post("/logout", dependencies=[Depends(csrf)])
def logout(
    request: Request,
    response: Response,
    auth: AuthDependency,
) -> dict[str, str]:
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        auth.logout(raw)
    challenge = request.cookies.get(CHALLENGE_COOKIE)
    if challenge:
        auth.cancel_challenge(challenge)
    clear_cookie(response, SESSION_COOKIE)
    clear_cookie(response, CHALLENGE_COOKIE)
    clear_cookie(response, CONTEXT_COOKIE)
    return {"state": "logged_out"}


@router.get("/session")
def current_session(request: Request, auth: AuthDependency) -> dict[str, object]:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        raise HTTPException(401, detail={"code": "SESSION_EXPIRED", "message": "Sign in again"})
    try:
        user, member, session = auth.current(hostname(request), raw)
    except AuthDenied as exc:
        raise HTTPException(
            401, detail={"code": "SESSION_EXPIRED", "message": "Sign in again"}
        ) from exc
    return {
        "user_id": str(user.id),
        "email": user.email,
        "tenant_id": str(member.tenant_id),
        "role": member.role,
        "expires_at": session.absolute_expires_at.isoformat(),
    }


@router.post("/mfa/enroll", dependencies=[Depends(csrf)])
def mfa_enroll(
    request: Request,
    auth: AuthDependency,
) -> dict[str, str]:
    raw = request.cookies.get(CHALLENGE_COOKIE, "")
    try:
        secret = auth.enroll_totp(hostname(request), raw)
    except AuthDenied as exc:
        raise handle_error(exc) from exc
    return {"secret": secret, "algorithm": "SHA1", "digits": "6", "period": "30"}


@router.post("/mfa/verify", dependencies=[Depends(csrf)])
def mfa_verify(
    body: MfaBody,
    request: Request,
    response: Response,
    auth: AuthDependency,
) -> dict[str, object]:
    raw = request.cookies.get(CHALLENGE_COOKIE, "")
    try:
        token, codes = auth.verify_mfa(
            hostname(request),
            raw,
            body.code,
            body.recovery,
            request.client.host if request.client else "unknown",
        )
    except AuthDenied as exc:
        raise handle_error(exc) from exc
    clear_cookie(response, CHALLENGE_COOKIE)
    set_cookie(response, SESSION_COOKIE, token, SESSION_MAX_AGE)
    return {"state": "session", "recovery_codes": codes}


@router.post("/password-reset/request", dependencies=[Depends(csrf)])
def reset_request(
    body: ResetRequestBody,
    request: Request,
    auth: AuthDependency,
) -> dict[str, str]:
    try:
        auth.request_reset(
            hostname(request), body.email, request.client.host if request.client else "unknown"
        )
    except AuthDenied:
        pass  # Enumeration-resistant response; throttling still applies server-side.
    except DeliveryUnavailable as exc:
        raise handle_error(exc) from exc
    return {"message": "If the account is eligible, a reset link will be sent"}


@router.post("/password-reset/complete", dependencies=[Depends(csrf)])
def reset_complete(
    body: PasswordBody,
    request: Request,
    response: Response,
    auth: AuthDependency,
) -> dict[str, str]:
    try:
        shared = request.url.hostname == auth.settings.platform_host and body.tenant_id is not None
        target_host = (
            shared_host_tenant(body.tenant_id) if shared and body.tenant_id else hostname(request)
        )
        auth.complete_reset(
            target_host,
            body.token,
            body.password,
            request.client.host if request.client else "unknown",
        )
    except (AuthDenied, CorpusUnavailable, ValueError) as exc:
        raise handle_error(exc) from exc
    clear_cookie(response, SESSION_COOKIE)
    return {"state": "password_changed"}


@router.post("/invitations", dependencies=[Depends(csrf)])
def invite(
    body: InvitationBody,
    request: Request,
    auth: AuthDependency,
) -> dict[str, str]:
    raw = request.cookies.get(SESSION_COOKIE, "")
    try:
        auth.issue_invitation(
            hostname(request),
            raw,
            body.email,
            body.role,
            body.event_id,
            body.gate_id,
            request.state.trusted_origin,
        )
    except (AuthDenied, DeliveryUnavailable, ValueError) as exc:
        raise handle_error(exc) from exc
    return {"state": "invitation_requested"}


@router.post("/invitations/accept", dependencies=[Depends(csrf)])
def accept_invite(
    body: PasswordBody,
    request: Request,
    response: Response,
    auth: AuthDependency,
) -> dict[str, str]:
    try:
        shared = request.url.hostname == auth.settings.platform_host and body.tenant_id is not None
        target_host = (
            shared_host_tenant(body.tenant_id) if shared and body.tenant_id else hostname(request)
        )
        state, token = auth.accept_invitation(target_host, body.token, body.password)
    except (AuthDenied, CorpusUnavailable, ValueError) as exc:
        raise handle_error(exc) from exc
    previous = request.cookies.get(SESSION_COOKIE)
    if previous:
        auth.logout(previous)
    clear_cookie(response, SESSION_COOKIE)
    clear_cookie(response, CHALLENGE_COOKIE)
    if shared and body.tenant_id:
        set_cookie(
            response, CONTEXT_COOKIE, sign_context(auth.settings, body.tenant_id), CONTEXT_LIFETIME
        )
    if state == "session":
        set_cookie(response, SESSION_COOKIE, token, SESSION_MAX_AGE)
    else:
        set_cookie(response, CHALLENGE_COOKIE, token, 5 * 60)
    return {"state": state}


@router.post("/memberships/{user_id}/revoke", dependencies=[Depends(csrf)])
def revoke_membership(
    user_id: UUID,
    request: Request,
    auth: AuthDependency,
) -> dict[str, str]:
    try:
        auth.revoke_tenant_membership(
            hostname(request), request.cookies.get(SESSION_COOKIE, ""), user_id
        )
    except (AuthDenied, Forbidden) as exc:
        raise handle_error(exc) from exc
    return {"state": "revoked"}


@router.get("/gate-staff")
def gate_staff(request: Request, auth: AuthDependency) -> dict[str, object]:
    try:
        staff = auth.list_gate_staff(hostname(request), request.cookies.get(SESSION_COOKIE, ""))
    except (AuthDenied, Forbidden) as exc:
        raise handle_error(exc) from exc
    return {"staff": staff}


@router.post("/memberships/{user_id}/gate-assignment", dependencies=[Depends(csrf)])
def reassign_gate_staff(
    user_id: UUID,
    body: GateAssignmentBody,
    request: Request,
    auth: AuthDependency,
) -> dict[str, str]:
    try:
        auth.reassign_gate_staff(
            hostname(request),
            request.cookies.get(SESSION_COOKIE, ""),
            user_id,
            body.event_id,
            body.gate_id,
        )
    except (AuthDenied, Forbidden) as exc:
        raise handle_error(exc) from exc
    return {"state": "assignment_updated"}

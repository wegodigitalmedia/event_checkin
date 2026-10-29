"""Public event registration. The verified authority determines the tenant."""

from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from app.registration.service import (
    RegistrationInvalid,
    RegistrationLimited,
    RegistrationService,
    RegistrationUnavailable,
)

router = APIRouter(prefix="/api/v1/public/events", tags=["public registration"])


class RegistrationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(min_length=1, max_length=160)
    email: str = Field(min_length=3, max_length=254)
    phone: str = Field(min_length=3, max_length=40)
    custom_answers: dict[str, object] = Field(default_factory=dict)
    form_version: int = Field(ge=1)
    notice_version: int | None = Field(default=None, ge=1)
    notice_acknowledged: bool = False
    marketing_opt_in: bool = False


def service(request: Request) -> RegistrationService:
    result = getattr(request.app.state, "registration_service", None)
    if result is None:
        raise HTTPException(
            503,
            detail={"code": "REGISTRATION_UNAVAILABLE", "message": "Registration is unavailable"},
        )
    return cast(RegistrationService, result)


Service = Annotated[RegistrationService, Depends(service)]


@router.get("/{slug}")
def public_event(slug: str, request: Request, registrations: Service) -> dict[str, object]:
    try:
        return registrations.public_event(request.state.trusted_hostname, slug)
    except RegistrationUnavailable as exc:
        raise HTTPException(
            404, detail={"code": "EVENT_UNAVAILABLE", "message": "Event unavailable"}
        ) from exc


@router.post("/{slug}/registrations", status_code=202)
def register(
    slug: str, body: RegistrationBody, request: Request, registrations: Service
) -> dict[str, str]:
    # This endpoint uses no staff cookie. JSON requests from another origin are
    # denied explicitly as defense in depth against browser-driven abuse.
    origin = request.headers.get("origin")
    if origin is not None and origin != request.state.trusted_origin:
        raise HTTPException(
            403, detail={"code": "ORIGIN_DENIED", "message": "Use the event page to register"}
        )
    peer = cast(str, request.state.client_address)
    try:
        registrations.register(
            request.state.trusted_hostname,
            slug,
            peer,
            **body.model_dump(),
        )
    except RegistrationLimited as exc:
        raise HTTPException(
            429,
            detail={"code": "REGISTRATION_LIMITED", "message": "Please wait before trying again"},
        ) from exc
    except RegistrationUnavailable as exc:
        raise HTTPException(
            404, detail={"code": "EVENT_UNAVAILABLE", "message": "Registration is unavailable"}
        ) from exc
    except RegistrationInvalid as exc:
        raise HTTPException(
            422, detail={"code": "REGISTRATION_INVALID", "message": str(exc)}
        ) from exc
    return {
        "message": "If your registration can be completed, your ticket will arrive by email. "
        "Check spam or ask the organizer for delivery help."
    }

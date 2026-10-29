"""Public registration uses a verified host and one PostgreSQL transaction."""

import hashlib
import re
import unicodedata
from datetime import UTC, datetime
from uuid import UUID, uuid4

import idna
from sqlalchemy import select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from app.auth.address import single_email_address
from app.db.models import Event, EventFormVersion, Registration
from app.db.session import TenantResolutionError, tenant_session_for_domain
from app.events.service import SLUG
from app.registration.throttle import RegistrationRateLimiter
from app.worker.jobs import enqueue_job

PHONE = re.compile(r"^\+[1-9][0-9]{1,14}$")
PHONE_FORMATTING = re.compile(r"[ ()\-.]")


class RegistrationUnavailable(ValueError):
    """This public event or its approved registration policy is unavailable."""


class RegistrationInvalid(ValueError):
    """A visible registration field is invalid."""


class RegistrationLimited(ValueError):
    """The public submission rate exceeded its bound or limiter failed."""


def normalize_email(value: str) -> str:
    try:
        address = single_email_address(value)
        local, domain = address.rsplit("@", 1)
        if not local.isascii() or not (1 <= len(local) <= 64):
            raise ValueError("Unsupported mailbox")
        canonical_domain = idna.encode(domain, uts46=True, std3_rules=True).decode("ascii")
        result = local.lower() + "@" + canonical_domain.lower()
        if len(result) > 254:
            raise ValueError("Mailbox too long")
        return result
    except (ValueError, idna.IDNAError) as exc:
        raise RegistrationInvalid("Enter a valid email address") from exc


def normalize_phone(value: str) -> str:
    candidate = PHONE_FORMATTING.sub("", value.strip())
    if not PHONE.fullmatch(candidate):
        raise RegistrationInvalid("Use an international phone number beginning with +")
    return candidate


def normalize_name(value: str) -> str:
    name = unicodedata.normalize("NFC", value).strip()
    if not 1 <= len(name) <= 160 or any(ord(char) < 32 for char in name):
        raise RegistrationInvalid("Enter your full name")
    return name


def validate_answers(schema: dict[str, object], answers: dict[str, object]) -> dict[str, object]:
    fields = schema.get("fields")
    if not isinstance(fields, list) or len(fields) > 30 or not isinstance(answers, dict):
        raise RegistrationUnavailable("Registration form is unavailable")
    allowed = {field.get("key") for field in fields if isinstance(field, dict)}
    if set(answers) - allowed:
        raise RegistrationInvalid("Remove answers to questions no longer on this form")
    checked: dict[str, object] = {}
    for field in fields:
        if not isinstance(field, dict):
            raise RegistrationUnavailable("Registration form is unavailable")
        key, kind, required = field.get("key"), field.get("type"), field.get("required")
        if not isinstance(key, str) or not isinstance(kind, str) or not isinstance(required, bool):
            raise RegistrationUnavailable("Registration form is unavailable")
        value = answers.get(key)
        if kind == "checkbox":
            if value is None:
                value = False
            if not isinstance(value, bool) or (required and not value):
                raise RegistrationInvalid(f"Complete {field['label']}")
            checked[key] = value
            continue
        if value is None or value == "":
            if required:
                raise RegistrationInvalid(f"Complete {field['label']}")
            continue
        if not isinstance(value, str) or any(
            ord(char) < 32 and char not in "\n\r\t" for char in value
        ):
            raise RegistrationInvalid(f"Check {field['label']}")
        if kind == "select":
            options = field.get("options")
            if not isinstance(options, list) or value not in options:
                raise RegistrationInvalid(f"Select a valid {field['label']}")
        elif kind in {"text", "textarea"}:
            if not value.strip() or len(value) > (2000 if kind == "textarea" else 500):
                raise RegistrationInvalid(f"Check {field['label']}")
        else:
            raise RegistrationUnavailable("Registration form is unavailable")
        checked[key] = value.strip()
    return checked


def _notice(db: object, tenant: UUID) -> dict[str, object] | None:
    from sqlalchemy.orm import Session

    assert isinstance(db, Session)
    row = (
        db.execute(
            text("""SELECT version, body, lawful_basis, sha256 FROM registration_notice_versions
                WHERE tenant_id=:tenant AND active AND approved_at IS NOT NULL"""),
            {"tenant": tenant},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    if (
        not isinstance(row.body, str)
        or hashlib.sha256(row.body.encode("utf-8")).digest() != row.sha256
    ):
        return None
    return dict(row)


class RegistrationService:
    def __init__(
        self,
        engine: Engine,
        rate_limiter: RegistrationRateLimiter,
        issuance_ready: bool = False,
        privacy_notices_enabled: bool = True,
    ):
        self.engine = engine
        self.rate_limiter = rate_limiter
        self.issuance_ready = issuance_ready
        self.privacy_notices_enabled = privacy_notices_enabled

    def public_event(
        self, hostname: str, slug: str, now: datetime | None = None
    ) -> dict[str, object]:
        if not SLUG.fullmatch(slug):
            raise RegistrationUnavailable("Event unavailable")
        try:
            with tenant_session_for_domain(self.engine, hostname) as db:
                event = db.scalar(
                    select(Event).where(Event.slug == slug, Event.status == "published")
                )
                if event is None:
                    raise RegistrationUnavailable("Event unavailable")
                if event.registration_mode == "import_only":
                    raise RegistrationUnavailable(
                        "Online registration is unavailable for this event"
                    )
                instant = now or datetime.now(UTC)
                notice = _notice(db, event.tenant_id) if self.privacy_notices_enabled else None
                form = db.scalar(
                    select(EventFormVersion).where(
                        EventFormVersion.tenant_id == event.tenant_id,
                        EventFormVersion.event_id == event.id,
                        EventFormVersion.version == event.form_schema_version,
                    )
                )
                if form is None:
                    raise RegistrationUnavailable("Registration form unavailable")
                open_now = bool(
                    event.registration_opens_at
                    and event.registration_closes_at
                    and event.registration_opens_at <= instant < event.registration_closes_at
                )
                return {
                    "slug": event.slug,
                    "name": event.name,
                    "location": event.location,
                    "starts_at": event.starts_at.isoformat(),
                    "ends_at": event.ends_at.isoformat(),
                    "timezone": event.timezone,
                    "registration_opens_at": event.registration_opens_at.isoformat()
                    if event.registration_opens_at
                    else None,
                    "registration_closes_at": event.registration_closes_at.isoformat()
                    if event.registration_closes_at
                    else None,
                    "available": open_now
                    and (notice is not None or not self.privacy_notices_enabled)
                    and self.issuance_ready,
                    "form_schema": form.schema,
                    "form_version": form.version,
                    "privacy_notice": {
                        "version": notice["version"],
                        "body": notice["body"],
                    }
                    if notice
                    else None,
                }
        except TenantResolutionError as exc:
            raise RegistrationUnavailable("Event unavailable") from exc

    def register(
        self,
        hostname: str,
        slug: str,
        peer: str,
        *,
        full_name: str,
        email: str,
        phone: str,
        custom_answers: dict[str, object],
        form_version: int,
        notice_version: int | None,
        notice_acknowledged: bool,
        marketing_opt_in: bool = False,
    ) -> None:
        if not SLUG.fullmatch(slug):
            raise RegistrationUnavailable("Event unavailable")
        if not self.issuance_ready:
            raise RegistrationUnavailable("Registration is unavailable")
        name = normalize_name(full_name)
        mailbox = normalize_email(email)
        mobile = normalize_phone(phone)
        if (self.privacy_notices_enabled and not notice_acknowledged) or not isinstance(
            marketing_opt_in, bool
        ):
            raise RegistrationInvalid("Acknowledge the privacy notice to continue")
        try:
            # Resolve only the rate-limit scope first. Do not hold a database
            # transaction or row lock while waiting on Redis. The authoritative
            # transaction below resolves and checks every state again.
            with tenant_session_for_domain(self.engine, hostname) as scope_db:
                scope_event = scope_db.scalar(
                    select(Event).where(Event.slug == slug, Event.status == "published")
                )
                if scope_event is None:
                    raise RegistrationUnavailable("Event unavailable")
                if scope_event.registration_mode == "import_only":
                    raise RegistrationUnavailable(
                        "Online registration is unavailable for this event"
                    )
                rate_scope = (scope_event.tenant_id, scope_event.id)
            if not self.rate_limiter.allow(*rate_scope, peer):
                raise RegistrationLimited("Please wait before trying again")
            with tenant_session_for_domain(self.engine, hostname) as db:
                event = db.scalar(
                    select(Event)
                    .where(Event.slug == slug, Event.status == "published")
                    .with_for_update(read=True)
                )
                if event is None:
                    raise RegistrationUnavailable("Event unavailable")
                if event.registration_mode == "import_only":
                    raise RegistrationUnavailable(
                        "Online registration is unavailable for this event"
                    )
                now = db.scalar(text("SELECT clock_timestamp()"))
                if (
                    event.registration_opens_at is None
                    or event.registration_closes_at is None
                    or now is None
                    or not event.registration_opens_at <= now < event.registration_closes_at
                ):
                    raise RegistrationUnavailable("Registration is closed")
                notice = _notice(db, event.tenant_id) if self.privacy_notices_enabled else None
                if self.privacy_notices_enabled and notice is None:
                    raise RegistrationUnavailable("Registration is unavailable")
                if notice is not None and notice["version"] != notice_version:
                    raise RegistrationInvalid("Privacy notice changed. Refresh and review it")
                form = db.scalar(
                    select(EventFormVersion).where(
                        EventFormVersion.tenant_id == event.tenant_id,
                        EventFormVersion.event_id == event.id,
                        EventFormVersion.version == event.form_schema_version,
                    )
                )
                if form is None:
                    raise RegistrationUnavailable("Registration form unavailable")
                if form.version != form_version:
                    raise RegistrationInvalid("Form changed. Refresh and review it")
                answers = validate_answers(form.schema, custom_answers)
                registration_id = uuid4()
                db.add(
                    Registration(
                        id=registration_id,
                        tenant_id=event.tenant_id,
                        event_id=event.id,
                        full_name=name,
                        email=mailbox,
                        phone_e164=mobile,
                        custom_answers=answers,
                        form_schema_version=form.version,
                        source="self",
                        status="registered",
                    )
                )
                db.flush()
                if notice is not None:
                    db.execute(
                        text("""INSERT INTO registration_consents
                          (id,tenant_id,event_id,registration_id,notice_version,notice_digest,
                           lawful_basis,acknowledged_at,marketing_opt_in,source)
                          VALUES (:id,:tenant,:event,:registration,:version,:digest,
                                  :basis,clock_timestamp(),:marketing,'self')"""),
                        {
                            "id": uuid4(),
                            "tenant": event.tenant_id,
                            "event": event.id,
                            "registration": registration_id,
                            "version": notice_version,
                            "digest": notice["sha256"],
                            "basis": notice["lawful_basis"],
                            "marketing": marketing_opt_in,
                        },
                    )
                enqueue_job(
                    db,
                    tenant_id=event.tenant_id,
                    event_id=event.id,
                    job_type="ticket.issue",
                    idempotency_key=registration_id,
                )
        except TenantResolutionError as exc:
            raise RegistrationUnavailable("Event unavailable") from exc
        except IntegrityError as exc:
            # Independent event-scoped email and phone indexes decide races.
            # The public response is the same as an accepted submission.
            constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
            if constraint in {"uq_registrations_email_active", "uq_registrations_phone_active"}:
                return
            raise


def notice_digest(body: str) -> bytes:
    return hashlib.sha256(body.encode("utf-8")).digest()

"""Event configuration commands. PostgreSQL owns row locks and tenant isolation."""

import re
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.service import AuthService
from app.db.models import Event, EventConfigAudit, EventFormVersion, Gate
from app.db.session import authorized_tenant_session

SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
KEY = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
FIELD_TYPES = frozenset({"text", "textarea", "select", "checkbox"})
PURGE_AFTER = timedelta(days=90)


class EventInvalid(ValueError):
    """An event configuration or transition is invalid."""


class EventConflict(ValueError):
    """An optimistic revision or database uniqueness check failed."""


def event_slug(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")[:48].strip("-")
    return f"{base or 'event'}-{uuid4().hex[:8]}"


def utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EventInvalid("Dates require an explicit UTC offset")
    return value.astimezone(UTC)


def validate_timezone(value: str) -> str:
    try:
        zone = ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise EventInvalid("Use an IANA time zone") from exc
    if value.startswith(("Etc/", "posix/", "right/")) or zone.key != value:
        raise EventInvalid("Use a named IANA time zone")
    return value


def validate_windows(
    starts: datetime,
    ends: datetime,
    registration_open: datetime | None,
    registration_close: datetime | None,
    checkin_open: datetime | None,
    checkin_close: datetime | None,
) -> None:
    starts, ends = utc(starts), utc(ends)
    if ends <= starts:
        raise EventInvalid("Event end must follow start")
    if (registration_open is None) != (registration_close is None):
        raise EventInvalid("Set both registration dates")
    if registration_open is not None and registration_close is not None:
        if not (utc(registration_open) < utc(registration_close) <= ends):
            raise EventInvalid("Registration must close after opening and by event end")
    if (checkin_open is None) != (checkin_close is None):
        raise EventInvalid("Set both check-in dates")
    if checkin_open is not None and checkin_close is not None:
        if not (starts - timedelta(hours=4) <= utc(checkin_open) < utc(checkin_close) <= ends):
            raise EventInvalid(
                "Check-in may open up to four hours before start and must close by event end"
            )


def validate_form(schema: dict[str, object]) -> dict[str, object]:
    """Only bounded declarative fields. Answers and HTML are not interpreted here."""
    if set(schema) != {"fields"} or not isinstance(schema["fields"], list):
        raise EventInvalid("Form must contain a fields list")
    fields = schema["fields"]
    if len(fields) > 30:
        raise EventInvalid("Form supports at most 30 custom fields")
    seen: set[str] = set()
    for raw in fields:
        if not isinstance(raw, dict) or not {"key", "label", "type", "required"} <= raw.keys():
            raise EventInvalid("Each field needs key, label, type and required")
        if set(raw) - {"key", "label", "type", "required", "options"}:
            raise EventInvalid("Unknown form field property")
        key, label, kind, required = (raw["key"], raw["label"], raw["type"], raw["required"])
        if (
            not isinstance(key, str)
            or not KEY.fullmatch(key)
            or key in {"full_name", "email", "phone"}
            or key in seen
        ):
            raise EventInvalid("Form field key is invalid or repeated")
        if (
            not isinstance(label, str)
            or not (1 <= len(label.strip()) <= 120)
            or any(ord(char) < 32 for char in label)
            or "<" in label
            or ">" in label
        ):
            raise EventInvalid("Form field label is invalid")
        if not isinstance(kind, str) or kind not in FIELD_TYPES or not isinstance(required, bool):
            raise EventInvalid("Form field type or required flag is invalid")
        options = raw.get("options")
        if kind == "select":
            if not isinstance(options, list) or not 2 <= len(options) <= 30:
                raise EventInvalid("Select fields need 2 to 30 options")
            if any(
                not isinstance(option, str)
                or not 1 <= len(option.strip()) <= 120
                or any(ord(char) < 32 for char in option)
                or "<" in option
                or ">" in option
                for option in options
            ):
                raise EventInvalid("Select option is invalid")
            if len(set(options)) != len(options):
                raise EventInvalid("Select options must be unique")
        elif options is not None:
            raise EventInvalid("Only select fields accept options")
        seen.add(key)
    return schema


def readiness(event: Event, enabled_gates: int, now: datetime | None = None) -> list[str]:
    instant = now or datetime.now(UTC)
    missing: list[str] = []
    if event.registration_mode == "public" and (
        event.registration_opens_at is None or event.registration_closes_at is None
    ):
        missing.append("Set registration opening and closing dates.")
    if event.checkin_opens_at is None or event.checkin_closes_at is None:
        missing.append("Set the check-in window.")
    if event.ends_at <= instant:
        missing.append("Move the event end into the future.")
    if enabled_gates == 0:
        missing.append("Enable at least one gate.")
    if event.registration_mode == "public":
        try:
            validate_form(event.form_schema)
        except EventInvalid:
            missing.append("Complete the registration form.")
    return missing


class EventService:
    def __init__(self, engine: Engine, auth: AuthService):
        self.engine = engine
        self.auth = auth

    def _scope(
        self,
        host: str,
        token: str,
        event_id: UUID | None = None,
        permission: str = "event.manage",
        gate_id: UUID | None = None,
    ) -> tuple[UUID, UUID]:
        tenant = self.auth.authorize(host, token, permission, event_id, gate_id)
        actor, _, _ = self.auth.current(host, token)
        return tenant, actor.id

    @staticmethod
    def _event(db: Session, tenant: UUID, event_id: UUID, lock: bool = False) -> Event:
        query = select(Event).where(Event.tenant_id == tenant, Event.id == event_id)
        if lock:
            query = query.with_for_update()
        event = db.scalar(query)
        if event is None:
            raise EventInvalid("Event is unavailable")
        return event

    @staticmethod
    def _audit(
        db: Session,
        event: Event,
        actor: UUID,
        action: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        db.add(
            EventConfigAudit(
                tenant_id=event.tenant_id,
                event_id=event.id,
                actor_user_id=actor,
                action=action,
                metadata_json=metadata or {},
            )
        )

    @staticmethod
    def _check_revision(event: Event, expected: int) -> None:
        if event.revision != expected:
            raise EventConflict("Event changed. Refresh before saving")

    def create(
        self,
        host: str,
        token: str,
        *,
        slug: str | None = None,
        name: str,
        starts_at: datetime,
        ends_at: datetime,
        timezone: str,
        location: str | None = None,
        description: str | None = None,
        registration_mode: str = "public",
    ) -> Event:
        tenant, actor = self._scope(host, token)
        resolved_slug = slug if slug is not None else event_slug(name)
        if (
            not SLUG.fullmatch(resolved_slug)
            or not name.strip()
            or len(name) > 160
            or any(ord(char) < 32 for char in name)
            or registration_mode not in {"public", "import_only"}
            or (description is not None and len(description) > 2000)
            or (
                location is not None
                and (len(location) > 300 or any(ord(char) < 32 for char in location))
            )
        ):
            raise EventInvalid("Event slug or name is invalid")
        validate_timezone(timezone)
        validate_windows(starts_at, ends_at, None, None, None, None)
        with authorized_tenant_session(self.engine, tenant) as db:
            event = Event(
                tenant_id=tenant,
                slug=resolved_slug,
                name=name.strip(),
                description=description.strip() if description else None,
                starts_at=utc(starts_at),
                ends_at=utc(ends_at),
                timezone=timezone,
                location=location,
                status="draft",
                registration_mode=registration_mode,
                form_schema={"fields": []},
                form_schema_version=1,
                pii_purge_due_at=utc(ends_at) + PURGE_AFTER,
            )
            db.add(event)
            db.flush()
            self._audit(db, event, actor, "event.created")
            db.flush()
            db.expunge(event)
            return event

    def list_events(self, host: str, token: str) -> list[Event]:
        # An organizer can see only assigned events; scanners cannot list events.
        tenant, allowed_ids = self.auth.manageable_event_scope(host, token)
        if allowed_ids == []:
            return []
        with authorized_tenant_session(self.engine, tenant) as db:
            query = select(Event).where(Event.tenant_id == tenant)
            if allowed_ids is not None:
                query = query.where(Event.id.in_(allowed_ids))
            rows = db.scalars(query.order_by(Event.starts_at.desc()).limit(200)).all()
            for row in rows:
                db.expunge(row)
            return list(rows)

    def get(self, host: str, token: str, event_id: UUID) -> Event:
        tenant, _ = self._scope(host, token, event_id)
        with authorized_tenant_session(self.engine, tenant) as db:
            event = self._event(db, tenant, event_id)
            db.expunge(event)
            return event

    def edit(
        self,
        host: str,
        token: str,
        event_id: UUID,
        expected: int,
        *,
        name: str,
        location: str | None,
        starts_at: datetime,
        ends_at: datetime,
        timezone: str,
        description: str | None = None,
        registration_mode: str | None = None,
        registration_opens_at: datetime | None,
        registration_closes_at: datetime | None,
        checkin_opens_at: datetime | None,
        checkin_closes_at: datetime | None,
    ) -> Event:
        tenant, actor = self._scope(host, token, event_id)
        if (
            not name.strip()
            or len(name) > 160
            or any(ord(char) < 32 for char in name)
            or (
                registration_mode is not None and registration_mode not in {"public", "import_only"}
            )
            or (description is not None and len(description) > 2000)
            or (
                location is not None
                and (len(location) > 300 or any(ord(char) < 32 for char in location))
            )
        ):
            raise EventInvalid("Event name or location is invalid")
        validate_timezone(timezone)
        validate_windows(
            starts_at,
            ends_at,
            registration_opens_at,
            registration_closes_at,
            checkin_opens_at,
            checkin_closes_at,
        )
        with authorized_tenant_session(self.engine, tenant) as db:
            event = self._event(db, tenant, event_id, lock=True)
            self._check_revision(event, expected)
            if event.status not in {"draft", "published"}:
                raise EventInvalid("Event can no longer be edited")
            if event.status == "published" and (
                utc(starts_at) != event.starts_at
                or utc(ends_at) != event.ends_at
                or timezone != event.timezone
                or registration_opens_at != event.registration_opens_at
                or registration_closes_at != event.registration_closes_at
                or checkin_opens_at != event.checkin_opens_at
                or checkin_closes_at != event.checkin_closes_at
                or (registration_mode is not None and registration_mode != event.registration_mode)
            ):
                raise EventInvalid("Published schedule is fixed in v1")
            event.name, event.location = name.strip(), location
            if description is not None:
                event.description = description.strip() or None
            if event.status == "draft":
                if registration_mode is not None:
                    event.registration_mode = registration_mode
                event.starts_at, event.ends_at, event.timezone = (
                    utc(starts_at),
                    utc(ends_at),
                    timezone,
                )
                event.registration_opens_at = (
                    utc(registration_opens_at) if registration_opens_at else None
                )
                event.registration_closes_at = (
                    utc(registration_closes_at) if registration_closes_at else None
                )
                event.checkin_opens_at = utc(checkin_opens_at) if checkin_opens_at else None
                event.checkin_closes_at = utc(checkin_closes_at) if checkin_closes_at else None
                event.pii_purge_due_at = event.ends_at + PURGE_AFTER
            event.revision += 1
            self._audit(db, event, actor, "event.edited", {"revision": event.revision})
            db.flush()
            db.expunge(event)
            return event

    def set_form(
        self, host: str, token: str, event_id: UUID, expected: int, schema: dict[str, object]
    ) -> Event:
        tenant, actor = self._scope(host, token, event_id)
        validate_form(schema)
        with authorized_tenant_session(self.engine, tenant) as db:
            event = self._event(db, tenant, event_id, lock=True)
            self._check_revision(event, expected)
            if event.status != "draft":
                raise EventInvalid("Published form versions are immutable")
            if event.form_schema == schema:
                db.expunge(event)
                return event
            event.form_schema_version += 1
            event.form_schema = schema
            event.revision += 1
            db.add(
                EventFormVersion(
                    tenant_id=tenant,
                    event_id=event_id,
                    version=event.form_schema_version,
                    schema=schema,
                    created_by=actor,
                )
            )
            self._audit(
                db,
                event,
                actor,
                "event.form_version_created",
                {"version": event.form_schema_version},
            )
            db.flush()
            db.expunge(event)
            return event

    def inspect_readiness(self, host: str, token: str, event_id: UUID) -> list[str]:
        tenant, _ = self._scope(host, token, event_id)
        with authorized_tenant_session(self.engine, tenant) as db:
            event = self._event(db, tenant, event_id)
            gates = db.scalars(
                select(Gate).where(
                    Gate.tenant_id == tenant, Gate.event_id == event_id, Gate.status == "active"
                )
            ).all()
            return readiness(event, len(gates))

    def transition(
        self, host: str, token: str, event_id: UUID, expected: int, target: str
    ) -> Event:
        tenant, actor = self._scope(host, token, event_id)
        allowed = {"draft": {"published", "cancelled"}, "published": {"closed", "cancelled"}}
        with authorized_tenant_session(self.engine, tenant) as db:
            event = self._event(db, tenant, event_id, lock=True)
            self._check_revision(event, expected)
            if target not in allowed.get(event.status, set()):
                raise EventInvalid("Event transition is unavailable")
            if target == "published":
                gates = db.scalars(
                    select(Gate).where(
                        Gate.tenant_id == tenant, Gate.event_id == event_id, Gate.status == "active"
                    )
                ).all()
                missing = readiness(event, len(gates))
                if missing:
                    raise EventInvalid("Not ready: " + " ".join(missing))
            event.status = target
            event.revision += 1
            self._audit(db, event, actor, "event." + target, {"revision": event.revision})
            db.flush()
            db.expunge(event)
            return event

    def gates(self, host: str, token: str, event_id: UUID) -> list[Gate]:
        tenant, _ = self._scope(host, token, event_id)
        with authorized_tenant_session(self.engine, tenant) as db:
            self._event(db, tenant, event_id)
            rows = db.scalars(
                select(Gate)
                .where(Gate.tenant_id == tenant, Gate.event_id == event_id)
                .order_by(Gate.name)
            ).all()
            for row in rows:
                db.expunge(row)
            return list(rows)

    def save_gate(
        self,
        host: str,
        token: str,
        event_id: UUID,
        *,
        name: str,
        gate_id: UUID | None = None,
        enabled: bool = True,
    ) -> Gate:
        tenant, actor = self._scope(
            host, token, event_id, permission="gate.manage", gate_id=gate_id
        )
        if not name.strip() or len(name) > 80 or any(ord(char) < 32 for char in name):
            raise EventInvalid("Gate name is invalid")
        with authorized_tenant_session(self.engine, tenant) as db:
            event = self._event(db, tenant, event_id, lock=True)
            if event.status in {"closed", "cancelled"}:
                raise EventInvalid("Event no longer accepts gate changes")
            gate = (
                db.scalar(
                    select(Gate)
                    .where(Gate.tenant_id == tenant, Gate.event_id == event_id, Gate.id == gate_id)
                    .with_for_update()
                )
                if gate_id
                else None
            )
            if gate_id is not None and gate is None:
                raise EventInvalid("Gate is unavailable")
            action = "gate.edited"
            if gate is None:
                gate = Gate(
                    tenant_id=tenant,
                    event_id=event_id,
                    name=name.strip(),
                    status="active" if enabled else "inactive",
                )
                db.add(gate)
                action = "gate.created"
            else:
                gate.name, gate.status = name.strip(), "active" if enabled else "inactive"
            db.flush()
            self._audit(db, event, actor, action, {"gate_id": str(gate.id)})
            db.expunge(gate)
            return gate


__all__ = [
    "EventService",
    "EventInvalid",
    "EventConflict",
    "IntegrityError",
    "validate_form",
    "validate_windows",
]

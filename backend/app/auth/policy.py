"""Effective permission policy for the approved G-02 least-privilege matrix."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

Permission = str

TENANT_ADMIN = frozenset(
    {
        "tenant.settings",
        "tenant.domain.manage",
        "tenant.domain.recover",
        "staff.manage",
        "invitation.issue",
        "event.manage",
        "gate.manage",
        "checkin.perform",
        "report.view",
        "attendee.export",
        "billing.manage",
    }
)
ORGANIZER = frozenset(
    {"event.manage", "gate.manage", "checkin.perform", "report.view", "attendee.export"}
)
SUPERVISOR = frozenset({"gate.manage", "checkin.perform", "gate.report.view"})
SCANNER = frozenset({"checkin.perform"})
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "tenant_owner": TENANT_ADMIN,
    "tenant_admin": TENANT_ADMIN,
    "organizer": ORGANIZER,
    "manager": ORGANIZER,
    "gate_supervisor": SUPERVISOR,
    "gate_scanner": SCANNER,
    "gate_staff": SCANNER,
}


@dataclass(frozen=True)
class Assignment:
    event_id: UUID
    gate_id: UUID | None
    valid_from: datetime
    valid_until: datetime | None
    revoked_at: datetime | None


def permissions_for(role: str) -> frozenset[str]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def requires_mfa(role: str) -> bool:
    return bool(permissions_for(role) - SCANNER)


SESSION_MAX_AGE = 48 * 60 * 60
SESSION_DURATION = timedelta(seconds=SESSION_MAX_AGE)


def session_lifetime(role: str) -> tuple[timedelta, timedelta]:
    if role not in ROLE_PERMISSIONS:
        raise ValueError("Unknown role")
    return SESSION_DURATION, SESSION_DURATION


def permits(
    role: str,
    permission: Permission,
    assignments: list[Assignment],
    now: datetime,
    event_id: UUID | None = None,
    gate_id: UUID | None = None,
) -> bool:
    if permission not in permissions_for(role):
        return False
    if role in {"tenant_owner", "tenant_admin"}:
        return True
    if event_id is None:
        return False
    for item in assignments:
        if item.event_id != event_id or item.revoked_at is not None:
            continue
        if item.valid_from > now or (item.valid_until is not None and item.valid_until <= now):
            continue
        if role in {"gate_scanner", "gate_staff", "gate_supervisor"}:
            if gate_id is None or item.gate_id != gate_id:
                continue
        elif gate_id is not None and item.gate_id is not None and item.gate_id != gate_id:
            continue
        return True
    return False

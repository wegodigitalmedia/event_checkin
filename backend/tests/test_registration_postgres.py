"""M3-01 public host, policy, form, uniqueness and outbox on real PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from test_events_postgres import draft, owner
from test_tenancy_postgres import Harness

from app.events.service import EventService
from app.registration.service import (
    RegistrationInvalid,
    RegistrationService,
    RegistrationUnavailable,
    notice_digest,
)

pytestmark = pytest.mark.postgres
pytest_plugins = ("test_tenancy_postgres",)


class PermitLimiter:
    def allow(self, tenant_id: UUID, event_id: UUID, peer: str) -> bool:
        return True


def published(pg: Harness) -> tuple[UUID, str, str, UUID, int]:
    tenant, host, session = owner(pg)
    events = EventService(pg.runtime, pg.auth)
    event = draft(events, host, session, "register")
    now = datetime.now(UTC)
    edited = events.edit(
        host,
        session,
        event.id,
        event.revision,
        name=event.name,
        location=None,
        starts_at=event.starts_at,
        ends_at=event.ends_at,
        timezone=event.timezone,
        registration_opens_at=now - timedelta(hours=1),
        registration_closes_at=event.starts_at,
        checkin_opens_at=event.starts_at,
        checkin_closes_at=event.ends_at,
    )
    form = events.set_form(
        host,
        session,
        event.id,
        edited.revision,
        {
            "fields": [
                {
                    "key": "meal",
                    "label": "Meal",
                    "type": "select",
                    "required": True,
                    "options": ["Vegan", "Other"],
                }
            ],
        },
    )
    events.save_gate(host, session, event.id, name="Main gate")
    events.transition(host, session, event.id, form.revision, "published")
    return tenant, host, session, event.id, form.form_schema_version


def seed_notice(pg: Harness, tenant: UUID) -> None:
    # Synthetic test notice only; production requires separately approved copy.
    with pg.owner.begin() as db:
        db.execute(
            text("""INSERT INTO registration_notice_versions
          (tenant_id,version,body,lawful_basis,sha256,approved_at,active)
          VALUES (:tenant,1,'Synthetic test notice','test-basis',:digest,now(),true)"""),
            {"tenant": tenant, "digest": notice_digest("Synthetic test notice")},
        )


def submit(
    service: RegistrationService,
    host: str,
    version: int,
    *,
    email: str = "ada@example.test",
    phone: str = "+2348012345678",
) -> None:
    service.register(
        host,
        "register",
        "test-peer",
        full_name="Ada Lovelace",
        email=email,
        phone=phone,
        custom_answers={"meal": "Vegan"},
        form_version=version,
        notice_version=1,
        notice_acknowledged=True,
    )


def test_registration_is_policy_gated_and_commits_consent_and_outbox(pg: Harness) -> None:
    tenant, host, _session, event_id, version = published(pg)
    service = RegistrationService(pg.runtime, PermitLimiter(), issuance_ready=True)
    assert service.public_event(host, "register")["available"] is False
    with pytest.raises(RegistrationUnavailable):
        submit(service, host, version)
    seed_notice(pg, tenant)
    assert service.public_event(host, "register")["available"] is True
    with pytest.raises(RegistrationInvalid, match="Form changed"):
        submit(service, host, version + 1)
    submit(service, host, version)
    with pg.owner.connect() as db:
        stored = db.execute(
            text("""SELECT r.id,r.form_schema_version,r.email,r.phone_e164,
            c.notice_version,c.notice_digest,c.marketing_opt_in,c.lawful_basis
            FROM registrations r JOIN registration_consents c
              ON (c.tenant_id,c.event_id,c.registration_id)=(r.tenant_id,r.event_id,r.id)
            WHERE r.tenant_id=:tenant AND r.event_id=:event"""),
            {"tenant": tenant, "event": event_id},
        ).one()
        assert stored.form_schema_version == version
        assert stored.email == "ada@example.test"
        assert stored.phone_e164 == "+2348012345678"
        assert stored.notice_version == 1 and stored.marketing_opt_in is False
        assert stored.notice_digest == notice_digest("Synthetic test notice")
        assert stored.lawful_basis == "test-basis"
        assert (
            db.scalar(
                text("""SELECT count(*) FROM job_records
            WHERE tenant_id=:tenant AND event_id=:event AND job_type='ticket.issue'
              AND idempotency_key=:registration"""),
                {"tenant": tenant, "event": event_id, "registration": stored.id},
            )
            == 1
        )
        assert (
            db.scalar(
                text("""SELECT count(*) FROM outbox_events o
            JOIN job_records j ON j.id=o.job_id WHERE j.idempotency_key=:registration"""),
                {"registration": stored.id},
            )
            == 1
        )


def test_independent_contacts_are_unique_under_concurrent_submission(pg: Harness) -> None:
    tenant, host, _session, event_id, version = published(pg)
    seed_notice(pg, tenant)
    service = RegistrationService(pg.runtime, PermitLimiter(), issuance_ready=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(
            pool.map(
                lambda phone: submit(service, host, version, phone=phone),
                ("+2348012345678", "+2348012345679"),
            )
        )
    # Duplicate email with different phones and duplicate phone with different
    # emails both yield the same safe response and never emit another job.
    submit(service, host, version, email="other@example.test", phone="+2348012345678")
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("SELECT count(*) FROM registrations WHERE event_id=:id"), {"id": event_id}
            )
            == 1
        )
        assert (
            db.scalar(
                text("""SELECT count(*) FROM job_records
            WHERE event_id=:id AND job_type='ticket.issue'"""),
                {"id": event_id},
            )
            == 1
        )
    with pytest.raises(RegistrationUnavailable):
        service.public_event("unknown.example.test", "register")


def test_registration_evidence_roles_and_rls_are_narrow(pg: Harness) -> None:
    tenant, _host, _session, _event_id, _version = published(pg)
    with pg.owner.connect() as db:
        for table in ("registration_notice_versions", "registration_consents"):
            assert db.execute(
                text("""SELECT relrowsecurity,relforcerowsecurity
                FROM pg_class WHERE relname=:table"""),
                {"table": table},
            ).one() == (True, True)
    with pytest.raises(ProgrammingError):
        with pg.runtime.begin() as db:
            db.execute(
                text("SELECT set_config('app.tenant_id', :tenant, true)"), {"tenant": tenant}
            )
            db.execute(
                text("""INSERT INTO registration_notice_versions
                (tenant_id,version,body,lawful_basis,sha256,approved_at,active)
                VALUES (:tenant,99,'Unapproved','none',
                        decode(repeat('00',32),'hex'),now(),false)"""),
                {"tenant": tenant},
            )
    with pytest.raises(ProgrammingError):
        with pg.control.connect() as db:
            db.execute(text("SELECT * FROM registration_consents"))


def test_registration_works_without_notice_or_fabricated_consent(pg: Harness) -> None:
    tenant, host, _session, event_id, version = published(pg)
    service = RegistrationService(
        pg.runtime, PermitLimiter(), issuance_ready=True, privacy_notices_enabled=False
    )
    event = service.public_event(host, "register")
    assert event["available"] is True and event["privacy_notice"] is None
    service.register(
        host,
        "register",
        "synthetic-peer",
        full_name="Demo Attendee",
        email="no-notice@example.test",
        phone="+2348012345699",
        custom_answers={"meal": "Vegan"},
        form_version=version,
        notice_version=None,
        notice_acknowledged=False,
    )
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("SELECT count(*) FROM registrations WHERE event_id=:event"),
                {"event": event_id},
            )
            == 1
        )
        assert (
            db.scalar(
                text("SELECT count(*) FROM registration_consents WHERE event_id=:event"),
                {"event": event_id},
            )
            == 0
        )
        assert (
            db.scalar(
                text(
                    "SELECT count(*) FROM job_records "
                    "WHERE event_id=:event AND job_type='ticket.issue'"
                ),
                {"event": event_id},
            )
            == 1
        )

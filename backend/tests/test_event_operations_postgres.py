"""Real database checks for import evidence and five-gate atomic redemption."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from test_events_postgres import draft, owner
from test_registration_postgres import PermitLimiter, published, seed_notice
from test_tenancy_postgres import Harness

from app.db.models import JobRecord, Registration, Ticket
from app.db.session import authorized_tenant_session
from app.events.service import EventService
from app.operations.service import EventOperationsService, OperationDenied
from app.registration.service import RegistrationService
from app.tickets.crypto import TicketKeyring
from app.tickets.email import MemoryTicketTransport
from app.tickets.service import TicketService

pytestmark = pytest.mark.postgres
pytest_plugins = ("test_tenancy_postgres",)


def test_bulk_import_validates_duplicates_and_creates_ticket_jobs(pg: Harness) -> None:
    tenant, host, session, event_id, _version = published(pg)
    seed_notice(pg, tenant)
    operations = EventOperationsService(pg.runtime, pg.auth)
    upload = (
        b"full_name,email,phone,meal\n"
        b"Ada Lovelace,ada@example.test,+2348012345678,Vegan\n"
        b"Ada Duplicate,ada@example.test,+2348012345679,Vegan\n"
        b"Invalid Mail,not-an-email,+2348012345680,Other\n"
    )
    preview = operations.preview_import(host, session, event_id, "participants.csv", upload)
    import_id = UUID(str(preview["import_id"]))
    repeated_preview = operations.preview_import(
        host, session, event_id, "participants.csv", upload
    )
    assert repeated_preview["reused"] is True
    assert repeated_preview["import_id"] == preview["import_id"]
    mapping = {
        "full_name": "full_name",
        "email": "email",
        "phone": "phone",
        "custom": {"meal": "meal"},
    }
    checked = operations.validate_import(host, session, event_id, import_id, mapping)
    assert (checked["valid_count"], checked["duplicate_count"], checked["invalid_count"]) == (
        1,
        1,
        1,
    )
    queued = operations.commit_import(host, session, event_id, import_id, True)
    assert queued["status"] == "queued"
    assert operations.commit_import(host, session, event_id, import_id, True)["status"] == "queued"
    with Session(pg.owner) as db:
        job = db.scalar(
            select(JobRecord).where(
                JobRecord.job_type == "registration.import",
                JobRecord.idempotency_key == import_id,
            )
        )
        assert job is not None
        db.expunge(job)
    with authorized_tenant_session(pg.runtime, tenant) as db:
        operations.process_import_job(db, job)
    assert operations.import_status(host, session, event_id, import_id)["status"] == "completed"
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
                text("""SELECT count(*) FROM registration_consents
                 WHERE event_id=:event AND source='bulk' AND acknowledged_at IS NULL"""),
                {"event": event_id},
            )
            == 1
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
    assert "DUPLICATE_EMAIL_IN_FILE" in operations.import_errors_csv(
        host, session, event_id, import_id
    )
    transport = MemoryTicketTransport()
    tickets = TicketService(pg.runtime, pg.auth, TicketKeyring({1: b"i" * 32}, 1), transport)
    with Session(pg.owner) as db:
        issue = db.scalar(
            select(JobRecord).where(
                JobRecord.job_type == "ticket.issue", JobRecord.event_id == event_id
            )
        )
        assert issue is not None
        db.expunge(issue)
    with authorized_tenant_session(pg.runtime, tenant) as db:
        tickets.issue_job(db, issue)
    with Session(pg.owner) as db:
        delivery = db.scalar(
            select(JobRecord).where(
                JobRecord.job_type == "ticket.deliver", JobRecord.event_id == event_id
            )
        )
        assert delivery is not None
        db.expunge(delivery)
    with authorized_tenant_session(pg.runtime, tenant) as db:
        tickets.deliver_job(db, delivery)
    assert len(transport.messages) == 1


def test_import_requires_active_notice_and_explicit_authorization(pg: Harness) -> None:
    tenant, host, session, event_id, _ = published(pg)
    operations = EventOperationsService(pg.runtime, pg.auth)
    preview = operations.preview_import(
        host,
        session,
        event_id,
        "email-only.csv",
        b"email,meal\nsynthetic@example.test,Vegan\n",
    )
    import_id = UUID(str(preview["import_id"]))
    assert operations.import_policy_status(host, session, event_id)["available"] is False
    with pytest.raises(OperationDenied, match="platform administrator"):
        operations.validate_import(
            host,
            session,
            event_id,
            import_id,
            {"email": "email", "custom": {"meal": "meal"}},
        )
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("SELECT count(*) FROM registrations WHERE event_id=:event"),
                {"event": event_id},
            )
            == 0
        )

    seed_notice(pg, tenant)
    assert operations.import_policy_status(host, session, event_id)["available"] is True
    validated = operations.validate_import(
        host,
        session,
        event_id,
        import_id,
        {"email": "email", "custom": {"meal": "meal"}},
    )
    assert validated["valid_count"] == 1
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("SELECT count(*) FROM registrations WHERE event_id=:event"),
                {"event": event_id},
            )
            == 0
        )
    with pytest.raises(OperationDenied, match="Confirm your authority"):
        operations.commit_import(host, session, event_id, import_id, False)
    queued = operations.commit_import(host, session, event_id, import_id, True)
    assert queued["status"] == "queued"
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("""SELECT count(*) FROM participant_imports
            WHERE id=:import_id AND authorization_confirmed_at IS NOT NULL
            AND authorization_confirmed_by IS NOT NULL"""),
                {"import_id": import_id},
            )
            == 1
        )


def test_bulk_import_accepts_email_only_records(pg: Harness) -> None:
    tenant, host, session, event_id, _ = published(pg)
    seed_notice(pg, tenant)
    operations = EventOperationsService(pg.runtime, pg.auth)
    preview = operations.preview_import(
        host,
        session,
        event_id,
        "email-only.csv",
        b"full_name,email,meal\nSynthetic One,one@example.test,Vegan\n"
        b"Synthetic Two,two@example.test,Other\n",
    )
    import_id = UUID(str(preview["import_id"]))
    mapping = {"full_name": "full_name", "email": "email", "custom": {"meal": "meal"}}
    validated = operations.validate_import(host, session, event_id, import_id, mapping)
    assert validated["valid_count"] == 2
    operations.commit_import(host, session, event_id, import_id, True)
    with Session(pg.owner) as db:
        job = db.scalar(
            select(JobRecord).where(
                JobRecord.job_type == "registration.import",
                JobRecord.idempotency_key == import_id,
            )
        )
        assert job is not None
        db.expunge(job)
    with authorized_tenant_session(pg.runtime, tenant) as db:
        operations.process_import_job(db, job)
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text(
                    "SELECT count(*) FROM registrations "
                    "WHERE event_id=:event AND phone_e164 IS NULL"
                ),
                {"event": event_id},
            )
            == 2
        )
        assert (
            db.scalar(
                text(
                    "SELECT count(*) FROM job_records "
                    "WHERE event_id=:event AND job_type='ticket.issue'"
                ),
                {"event": event_id},
            )
            == 2
        )


def test_import_only_email_csv_requires_explicit_issue_and_send(pg: Harness) -> None:
    tenant, host, session = owner(pg)
    seed_notice(pg, tenant)
    events = EventService(pg.runtime, pg.auth)
    event = draft(events, host, session, "import-only")
    configured = events.edit(
        host,
        session,
        event.id,
        event.revision,
        name=event.name,
        location="Main Hall",
        starts_at=event.starts_at,
        ends_at=event.ends_at,
        timezone=event.timezone,
        registration_opens_at=None,
        registration_closes_at=None,
        checkin_opens_at=event.starts_at,
        checkin_closes_at=event.ends_at,
        registration_mode="import_only",
    )
    events.save_gate(host, session, event.id, name="Entrance")
    events.transition(host, session, event.id, configured.revision, "published")
    operations = EventOperationsService(pg.runtime, pg.auth)
    preview = operations.preview_import(
        host,
        session,
        event.id,
        "attendees.csv",
        b"email\nfirst@example.test\nsecond@example.test\n",
    )
    import_id = UUID(str(preview["import_id"]))
    mapping = {"email": "email"}
    assert (
        operations.validate_import(host, session, event.id, import_id, mapping)["valid_count"] == 2
    )
    operations.commit_import(host, session, event.id, import_id, True)
    with Session(pg.owner) as db:
        job = db.scalar(
            select(JobRecord).where(
                JobRecord.job_type == "registration.import",
                JobRecord.idempotency_key == import_id,
            )
        )
        assert job is not None
        db.expunge(job)
    with authorized_tenant_session(pg.runtime, tenant) as db:
        operations.process_import_job(db, job)
    tickets = TicketService(
        pg.runtime, pg.auth, TicketKeyring({1: b"i" * 32}, 1), MemoryTicketTransport()
    )
    assert tickets.bulk_status(host, session, event.id)["issued"] == 0
    assert tickets.issue_bulk(host, session, event.id)["eligible"] == 2
    assert tickets.issue_bulk(host, session, event.id)["eligible"] == 2
    with Session(pg.owner) as db:
        issue_jobs = list(
            db.scalars(
                select(JobRecord).where(
                    JobRecord.event_id == event.id,
                    JobRecord.job_type == "ticket.issue",
                )
            )
        )
        assert len(issue_jobs) == 2
        for issue in issue_jobs:
            db.expunge(issue)
    for issue in issue_jobs:
        with authorized_tenant_session(pg.runtime, tenant) as db:
            tickets.issue_job(db, issue)
    assert tickets.bulk_status(host, session, event.id)["issued"] == 2
    assert tickets.bulk_status(host, session, event.id)["queued"] == 0
    with ThreadPoolExecutor(max_workers=2) as pool:
        sent = list(pool.map(lambda _: tickets.send_bulk(host, session, event.id), range(2)))
    assert sum(item["newly_queued"] for item in sent) == 2
    assert tickets.send_bulk(host, session, event.id)["newly_queued"] == 0
    assert tickets.bulk_status(host, session, event.id)["queued"] == 2


def test_same_credential_at_five_gates_is_accepted_once(pg: Harness) -> None:
    tenant, host, session = owner(pg)
    now = datetime.now(UTC)
    events = EventService(pg.runtime, pg.auth)
    draft = events.create(
        host,
        session,
        slug="five-gate-rehearsal",
        name="Five gate rehearsal",
        starts_at=now + timedelta(hours=3, minutes=59),
        ends_at=now + timedelta(hours=6),
        timezone="Africa/Lagos",
    )
    configured = events.edit(
        host,
        session,
        draft.id,
        draft.revision,
        name=draft.name,
        location=None,
        starts_at=draft.starts_at,
        ends_at=draft.ends_at,
        timezone=draft.timezone,
        registration_opens_at=now - timedelta(hours=1),
        registration_closes_at=now + timedelta(hours=1),
        checkin_opens_at=draft.starts_at - timedelta(hours=4),
        checkin_closes_at=draft.ends_at,
    )
    gates = [
        events.save_gate(host, session, draft.id, name=f"Gate {index}") for index in range(1, 6)
    ]
    events.transition(host, session, draft.id, configured.revision, "published")
    seed_notice(pg, tenant)
    registrations = RegistrationService(pg.runtime, PermitLimiter(), issuance_ready=True)
    registrations.register(
        host,
        draft.slug,
        "rehearsal-peer",
        full_name="Synthetic Attendee",
        email="rehearsal@example.test",
        phone="+2348012345678",
        custom_answers={},
        form_version=draft.form_schema_version,
        notice_version=1,
        notice_acknowledged=True,
    )
    registrations.register(
        host,
        draft.slug,
        "rehearsal-peer",
        full_name="Revoked Synthetic Attendee",
        email="revoked-rehearsal@example.test",
        phone="+2348012345679",
        custom_answers={},
        form_version=draft.form_schema_version,
        notice_version=1,
        notice_acknowledged=True,
    )
    keys = TicketKeyring({1: b"z" * 32}, 1)
    tickets = TicketService(pg.runtime, pg.auth, keys, MemoryTicketTransport())
    with Session(pg.owner) as db:
        issue_jobs = list(
            db.scalars(
                select(JobRecord).where(
                    JobRecord.job_type == "ticket.issue", JobRecord.event_id == draft.id
                )
            )
        )
        assert len(issue_jobs) == 2
        for issue in issue_jobs:
            db.expunge(issue)
    for issue in issue_jobs:
        with authorized_tenant_session(pg.runtime, tenant) as db:
            tickets.issue_job(db, issue)
    with Session(pg.owner) as db:
        registration = db.scalar(
            select(Registration).where(Registration.email == "rehearsal@example.test")
        )
        revoked_registration = db.scalar(
            select(Registration).where(Registration.email == "revoked-rehearsal@example.test")
        )
        assert registration is not None and revoked_registration is not None
        ticket = db.scalar(select(Ticket).where(Ticket.registration_id == registration.id))
        revoked_ticket = db.scalar(
            select(Ticket).where(Ticket.registration_id == revoked_registration.id)
        )
        assert ticket is not None and revoked_ticket is not None
        credential = keys.decrypt(
            ticket.token_ciphertext,
            ticket.key_version,
            tenant,
            draft.id,
            registration.id,
            ticket.id,
        )
        revoked_credential = keys.decrypt(
            revoked_ticket.token_ciphertext,
            revoked_ticket.key_version,
            tenant,
            draft.id,
            revoked_registration.id,
            revoked_ticket.id,
        )
        revoked_ticket_id = revoked_ticket.id
    with pg.owner.begin() as db:
        db.execute(
            text("UPDATE tickets SET status='revoked' WHERE id=:ticket"),
            {"ticket": revoked_ticket_id},
        )
    operations = EventOperationsService(pg.runtime, pg.auth, keys)
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(
            pool.map(
                lambda gate: operations.redeem(host, session, draft.id, gate.id, credential),
                gates,
            )
        )
    outcomes = [result["outcome"] for result in results]
    assert outcomes.count("accepted") == 1
    assert outcomes.count("duplicate") == 4
    assert [result["reason_code"] for result in results].count("ACCEPTED") == 1
    assert [result["reason_code"] for result in results].count("DUPLICATE_ADMISSION") == 4
    revoked = operations.redeem(host, session, draft.id, gates[0].id, revoked_credential)
    assert (revoked["outcome"], revoked["reason_code"]) == ("revoked", "REVOKED_TICKET")
    invalid = operations.redeem(host, session, draft.id, gates[0].id, "not-a-ticket")
    assert (invalid["outcome"], invalid["reason_code"]) == ("invalid", "INVALID_TICKET")
    attendance = operations.attendance(host, session, draft.id)
    assert attendance["checked_in"] == 1
    assert attendance["duplicate_scans"] == 4
    assert sum(gate["checked_in"] for gate in attendance["gates"]) == 1
    assert "rehearsal@example.test" in operations.attendance_csv(host, session, draft.id)


def test_gate_context_rejections_have_stable_reason_codes(pg: Harness) -> None:
    _tenant, host, session = owner(pg)
    now = datetime.now(UTC)
    events = EventService(pg.runtime, pg.auth)
    operations = EventOperationsService(pg.runtime, pg.auth, TicketKeyring({1: b"r" * 32}, 1))

    def context_event(
        slug: str,
        opens: datetime | None,
        closes: datetime | None,
        *,
        force_publish: bool = False,
    ) -> tuple[object, object]:
        event = events.create(
            host,
            session,
            slug=slug,
            name=f"Reason code {slug}",
            starts_at=now - timedelta(hours=1),
            ends_at=now + timedelta(hours=1),
            timezone="Africa/Lagos",
        )
        configured = events.edit(
            host,
            session,
            event.id,
            event.revision,
            name=event.name,
            location=None,
            starts_at=event.starts_at,
            ends_at=event.ends_at,
            timezone=event.timezone,
            registration_opens_at=now - timedelta(hours=2),
            registration_closes_at=now + timedelta(minutes=30),
            checkin_opens_at=opens,
            checkin_closes_at=closes,
        )
        gate = events.save_gate(host, session, event.id, name="Context gate")
        if force_publish:
            # Construct an intentionally incomplete legacy record without weakening
            # the production transition or schedule-immutability guards.
            with pg.owner.begin() as db:
                db.execute(
                    text("UPDATE events SET status='published' WHERE id=:event"),
                    {"event": event.id},
                )
        else:
            events.transition(host, session, event.id, configured.revision, "published")
        return event, gate

    event, gate = context_event(
        "reason-code-availability",
        now - timedelta(minutes=30),
        now + timedelta(minutes=30),
    )
    with pg.owner.begin() as db:
        db.execute(text("UPDATE gates SET status='inactive' WHERE id=:gate"), {"gate": gate.id})
    assert operations.redeem(host, session, event.id, gate.id, "invalid")["reason_code"] == (
        "GATE_UNAVAILABLE"
    )
    events.transition(host, session, event.id, 3, "cancelled")
    assert operations.redeem(host, session, event.id, gate.id, "invalid")["reason_code"] == (
        "EVENT_UNAVAILABLE"
    )

    incomplete, incomplete_gate = context_event(
        "reason-code-window", None, None, force_publish=True
    )
    assert operations.redeem(host, session, incomplete.id, incomplete_gate.id, "invalid")[
        "reason_code"
    ] == ("CHECKIN_WINDOW_UNAVAILABLE")

    early, early_gate = context_event(
        "reason-code-early",
        now + timedelta(minutes=10),
        now + timedelta(minutes=20),
    )
    assert operations.redeem(host, session, early.id, early_gate.id, "invalid")["reason_code"] == (
        "CHECKIN_NOT_OPEN"
    )

    closed, closed_gate = context_event(
        "reason-code-closed",
        now - timedelta(minutes=20),
        now - timedelta(minutes=10),
    )
    assert operations.redeem(host, session, closed.id, closed_gate.id, "invalid")[
        "reason_code"
    ] == ("CHECKIN_CLOSED")

"""M2-01 control-plane and tenant boundaries against isolated real PostgreSQL."""

import base64
import hashlib
import os
import secrets
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import sql
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.orm import Session
from test_tenant_postgres import _migrate

from app.auth.corpus import CompromisedPasswordCorpus
from app.auth.email import DeliveryUnavailable
from app.auth.security import hash_password, token_digest, totp_code
from app.auth.service import AuthDenied, AuthService
from app.core.config import Settings
from app.db.models import TenantDomain
from app.db.session import authorized_tenant_session
from app.tenancy.domains import (
    DomainDenied,
    DomainService,
    now,
    schedule_due_reconciliations,
)
from app.tenancy.platform_auth import PlatformAuth

pytestmark = pytest.mark.postgres


@dataclass
class FakeProvider:
    proof: dict[str, str] = field(default_factory=dict)
    tls: set[str] = field(default_factory=set)
    edge: set[str] = field(default_factory=set)
    smoke: set[str] = field(default_factory=set)

    def txt_values(self, hostname: str) -> list[str]:
        return [self.proof[hostname]] if hostname in self.proof else []

    def certificate_valid_until(self, hostname: str) -> datetime | None:
        return now() + timedelta(hours=2) if hostname in self.tls else None

    def edge_mapping_ready(self, hostname: str, tenant_id: UUID) -> bool:
        return hostname in self.edge

    def smoke_check(self, hostname: str, tenant_id: UUID) -> bool:
        return hostname in self.smoke

    def ready(self, hostname: str, proof: str) -> None:
        self.proof[f"_eventcheckin-verify.{hostname}"] = proof
        self.tls.add(hostname)
        self.edge.add(hostname)
        self.smoke.add(hostname)


@dataclass
class CaptureEmail:
    links: list[str] = field(default_factory=list)

    def send_link(self, recipient: str, subject: str, link: str) -> None:
        self.links.append(link)


@dataclass
class Harness:
    owner: Engine
    runtime: Engine
    identity: Engine
    control: Engine
    bootstrap: Engine
    worker: Engine
    scheduler: Engine
    actor: UUID
    settings: Settings
    provider: FakeProvider
    domain: DomainService
    worker_domain: DomainService
    platform_auth: PlatformAuth
    auth: AuthService
    email: CaptureEmail

    def job_for(self, domain_id: UUID) -> tuple[UUID, UUID]:
        with self.owner.connect() as db:
            row = db.execute(
                text("""SELECT tenant_id, job_id FROM domain_reconcile_requests
                WHERE domain_id=:domain ORDER BY created_at DESC, job_id DESC LIMIT 1"""),
                {"domain": domain_id},
            ).one()
            return row.tenant_id, row.job_id


@pytest.fixture(scope="module")
def pg(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Harness]:
    raw_url = os.environ.get("TEST_MIGRATION_DATABASE_URL")
    if not raw_url:
        if os.environ.get("CI") == "true":
            pytest.fail("CI requires TEST_MIGRATION_DATABASE_URL for real PostgreSQL")
        pytest.skip("Set TEST_MIGRATION_DATABASE_URL for real PostgreSQL")
    parsed = make_url(raw_url)
    suffix = secrets.token_hex(5)
    database = f"eventcheckin_m201_{suffix}"
    baseline = f"eventcheckin_m201_baseline_{suffix}"
    maintenance = parsed.set(drivername="postgresql", database="postgres").render_as_string(
        hide_password=False
    )
    admin = psycopg.connect(maintenance, autocommit=True)
    roles: list[str] = []
    engines: list[Engine] = []
    try:
        for name in (database, baseline):
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        url = parsed.set(database=database).render_as_string(hide_password=False)
        baseline_url = parsed.set(database=baseline).render_as_string(hide_password=False)
        _migrate(baseline_url, "0005_reliable_jobs_storage")
        _migrate(baseline_url, "head")
        _migrate(baseline_url, "0005_reliable_jobs_storage", direction="downgrade")
        _migrate(baseline_url, "head")
        _migrate(url, "head")
        owner = create_engine(url)
        engines.append(owner)
        with owner.connect() as db:
            assert db.scalar(text("SELECT version_num FROM alembic_version")) == (
                "0013_privacy_notice_workflow"
            )
            for table in ("tenant_domains", "staff_invitations", "domain_reconcile_requests"):
                assert db.execute(
                    text("""SELECT relrowsecurity,relforcerowsecurity
                    FROM pg_class WHERE relname=:table"""),
                    {"table": table},
                ).one() == (True, True)
        role_urls: dict[str, str] = {}
        for label, group in (
            ("runtime", "eventcheckin_runtime"),
            ("identity", "eventcheckin_identity"),
            ("control", "eventcheckin_platform"),
            ("bootstrap", "eventcheckin_bootstrap"),
            ("worker", "eventcheckin_domain_worker"),
            ("scheduler", "eventcheckin_domain_scheduler"),
        ):
            role = f"eventcheckin_{label}_test_{suffix}"
            password = secrets.token_urlsafe(24)
            admin.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOBYPASSRLS").format(
                    sql.Identifier(role), sql.Literal(password)
                )
            )
            admin.execute(
                sql.SQL("GRANT {} TO {}").format(sql.Identifier(group), sql.Identifier(role))
            )
            admin.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(database), sql.Identifier(role)
                )
            )
            roles.append(role)
            role_urls[label] = parsed.set(
                database=database, username=role, password=password
            ).render_as_string(hide_password=False)
        runtime = create_engine(role_urls["runtime"], pool_size=2, max_overflow=2)
        identity = create_engine(role_urls["identity"], pool_size=2, max_overflow=2)
        control = create_engine(role_urls["control"], pool_size=2, max_overflow=2)
        bootstrap = create_engine(role_urls["bootstrap"])
        worker = create_engine(role_urls["worker"])
        scheduler = create_engine(role_urls["scheduler"])
        engines.extend((runtime, identity, control, bootstrap, worker, scheduler))
        actor = uuid4()
        with owner.begin() as db:
            db.execute(
                text("""INSERT INTO users (id,email,display_name,status)
                VALUES (:id,'platform@example.test','Platform Actor','active')"""),
                {"id": actor},
            )
            db.execute(
                text("""INSERT INTO password_credentials (user_id,password_hash)
                VALUES (:user,:hash)"""),
                {"user": actor, "hash": hash_password("approved-platform-password")},
            )
            db.execute(
                text("""INSERT INTO platform_grants
                (user_id,operation,valid_from,valid_until)
                VALUES (:user,'tenant.provision',now(),now()+interval '1 day')"""),
                {"user": actor},
            )
        corpus_file = tmp_path_factory.mktemp("m201") / "corpus.txt"
        corpus_file.write_text(
            hashlib.sha1(b"compromised-example-password").hexdigest().upper() + "\n"
        )
        corpus_sha = hashlib.sha256(corpus_file.read_bytes()).hexdigest()
        settings = Settings(
            app_env="test",
            database_url=role_urls["runtime"],
            identity_database_url=role_urls["identity"],
            platform_database_url=role_urls["control"],
            platform_host="platform.local.example.test",
            fallback_domain_suffix="local.example.test",
            auth_encryption_key=base64.b64encode(b"t" * 32).decode(),
            compromised_password_corpus=str(corpus_file),
            compromised_password_sha256=corpus_sha,
        )
        email = CaptureEmail()
        auth = AuthService(
            identity, settings, CompromisedPasswordCorpus(str(corpus_file), corpus_sha), email
        )
        provider = FakeProvider()
        domain = DomainService(control, runtime, auth, provider, "local.example.test")
        worker_domain = DomainService(worker, runtime, None, provider, "local.example.test")
        yield Harness(
            owner,
            runtime,
            identity,
            control,
            bootstrap,
            worker,
            scheduler,
            actor,
            settings,
            provider,
            domain,
            worker_domain,
            PlatformAuth(identity, settings),
            auth,
            email,
        )
    finally:
        for engine in reversed(engines):
            engine.dispose()
        for name in (database, baseline):
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
        for role in roles:
            admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        admin.close()


def test_platform_mfa_session_and_grant_revocation(pg: Harness) -> None:
    state, challenge = pg.platform_auth.login(
        "platform@example.test", "approved-platform-password", "192.0.2.1"
    )
    assert state == "enroll"
    secret = pg.platform_auth.enroll(challenge)
    with pytest.raises(AuthDenied):
        pg.platform_auth.verify(challenge, "00000000", False, "192.0.2.1")
    session, recovery_codes = pg.platform_auth.verify(
        challenge, totp_code(secret, int(now().timestamp() // 30)), False, "192.0.2.1"
    )
    assert len(recovery_codes) == 10
    assert pg.platform_auth.current(session).id == pg.actor
    with pg.owner.connect() as conn:
        row = conn.execute(
            text(
                "SELECT absolute_expires_at-created_at FROM platform_auth_sessions "
                "WHERE token_digest=:digest"
            ),
            {"digest": token_digest(session)},
        ).one()
        assert abs(row[0] - timedelta(hours=48)) < timedelta(seconds=2)

    with pytest.raises(AuthDenied):
        pg.platform_auth.current(challenge)
    with pytest.raises(AuthDenied):
        pg.platform_auth.verify(
            challenge, totp_code(secret, int(now().timestamp() // 30)), False, "192.0.2.1"
        )
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("""SELECT count(*) FROM security_audit_events
            WHERE action='platform.mfa.failed'""")
            )
            >= 1
        )
    with pg.owner.begin() as db:
        db.execute(
            text("UPDATE platform_grants SET revoked_at=now() WHERE user_id=:user"),
            {"user": pg.actor},
        )
    with pytest.raises(AuthDenied):
        pg.platform_auth.current(session)
    with pg.owner.begin() as db:
        db.execute(
            text("UPDATE platform_grants SET revoked_at=NULL WHERE user_id=:user"),
            {"user": pg.actor},
        )
    with pytest.raises(AuthDenied):
        pg.platform_auth.current(session)  # trigger revocation survives grant restoration


def test_one_time_bootstrap_role_is_narrow_and_usable(pg: Harness) -> None:
    def consume(label: str) -> bool:
        try:
            with pg.bootstrap.begin() as db:
                db.scalar(
                    text("""SELECT consume_platform_bootstrap(
                    CAST(:email AS citext), :hash, :operator_ref, :verification_ref,
                    now()+interval '1 hour')"""),
                    {
                        "email": f"bootstrap-{label}@example.test",
                        "hash": hash_password("safe-password-123"),
                        "operator_ref": "test-operator",
                        "verification_ref": "test-email",
                    },
                )
            return True
        except IntegrityError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(consume, ("a", "b"))) == [False, True]
    assert consume("later") is False
    with pg.owner.connect() as db:
        assert db.scalar(text("SELECT count(*) FROM platform_bootstrap")) == 1
        assert (
            db.scalar(
                text("""SELECT count(*) FROM security_audit_events
            WHERE action='platform.bootstrap.consumed'""")
            )
            == 1
        )
    with pg.bootstrap.connect() as db:
        with pytest.raises(ProgrammingError):
            db.execute(text("SELECT password_hash FROM password_credentials"))
    with pg.bootstrap.connect() as db:
        with pytest.raises(ProgrammingError):
            db.execute(
                text("""INSERT INTO platform_grants
                (user_id,operation,valid_from,valid_until)
                VALUES (:actor,'tenant.provision',now(),now()+interval '1 hour')"""),
                {"actor": pg.actor},
            )
    with pg.bootstrap.connect() as db:
        with pytest.raises(ProgrammingError):
            db.execute(
                text("""INSERT INTO users(email,display_name,status)
                VALUES ('unauthorized@example.test','Unauthorized','active')""")
            )


def test_provision_fallback_owner_mfa_and_domain_lifecycle(pg: Harness) -> None:
    tenant, fallback_id, fallback_host, proof = pg.domain.provision(pg.actor, "Àjọ Events", "ajo")
    with pg.owner.connect() as db:
        assert (
            db.scalar(text("SELECT resolve_active_tenant_domain(:host)"), {"host": fallback_host})
            is None
        )
    pg.provider.ready(fallback_host, proof)
    _, job_id = pg.job_for(fallback_id)
    pg.worker_domain.reconcile(job_id, tenant)
    pg.domain.activate(pg.actor, tenant, fallback_id)
    # The claim deadline limits initial activation, not the life of an active
    # domain whose DNS ownership proof still verifies on each reconciliation.
    with pg.owner.begin() as db:
        db.execute(
            text("UPDATE tenant_domains SET claim_expires_at=now()-interval '1 hour' WHERE id=:id"),
            {"id": fallback_id},
        )
    pg.worker_domain.reconcile(job_id, tenant)
    with pg.runtime.connect() as db:
        assert (
            db.scalar(text("SELECT resolve_active_tenant_domain(:host)"), {"host": fallback_host})
            == tenant
        )
    with pg.owner.begin() as db:
        db.execute(
            text("""UPDATE tenant_domains
            SET smoke_checked_at=now()-interval '16 minutes' WHERE id=:id"""),
            {"id": fallback_id},
        )
    with pg.runtime.connect() as db:
        assert (
            db.scalar(text("SELECT resolve_active_tenant_domain(:host)"), {"host": fallback_host})
            is None
        )
    pg.worker_domain.reconcile(job_id, tenant)
    with pg.runtime.connect() as db:
        assert (
            db.scalar(text("SELECT resolve_active_tenant_domain(:host)"), {"host": fallback_host})
            == tenant
        )
    with pytest.raises(DomainDenied, match="fallback"):
        pg.domain.deactivate(pg.actor, tenant, fallback_id)
    pg.domain.issue_first_owner(pg.actor, tenant, "owner@example.test", pg.email)
    token = parse_qs(urlsplit(pg.email.links[-1]).fragment)["token"][0]
    state, challenge = pg.auth.accept_invitation(fallback_host, token, "fresh-owner-password-123")
    assert state == "enroll"
    with pytest.raises(AuthDenied):
        pg.auth.accept_invitation(fallback_host, token, "fresh-owner-password-123")
    secret = pg.auth.enroll_totp(fallback_host, challenge)
    owner_session, _ = pg.auth.verify_mfa(
        fallback_host, challenge, totp_code(secret, int(now().timestamp() // 30))
    )
    assert pg.auth.authorize(fallback_host, owner_session, "tenant.domain.manage") == tenant
    custom_id, custom_host, custom_proof = pg.domain.request_claim(
        fallback_host, owner_session, "BÜCHER.Example.Test"
    )
    assert custom_host == "xn--bcher-kva.example.test"
    pg.provider.ready(custom_host, custom_proof)
    _, custom_job = pg.job_for(custom_id)
    pg.worker_domain.reconcile(custom_job, tenant)
    pg.domain.activate(pg.actor, tenant, custom_id)
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("""SELECT count(*) FROM tenant_domains
            WHERE tenant_id=:tenant AND is_primary AND routing_state='active'"""),
                {"tenant": tenant},
            )
            == 1
        )
    pg.domain.deactivate(pg.actor, tenant, custom_id)
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("SELECT is_primary FROM tenant_domains WHERE id=:id"), {"id": fallback_id}
            )
            is True
        )
        assert (
            db.scalar(text("SELECT resolve_active_tenant_domain(:host)"), {"host": custom_host})
            is None
        )
    # Reverification can recover a previously deactivated domain, but still
    # requires a fresh platform activation decision.
    pg.worker_domain.reconcile(custom_job, tenant)
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("SELECT routing_state FROM tenant_domains WHERE id=:id"), {"id": custom_id}
            )
            == "ready"
        )
    renewed = pg.domain.renew_claim(fallback_host, owner_session, custom_id)
    assert renewed != custom_proof
    _, renewed_job = pg.job_for(custom_id)
    pg.worker_domain.reconcile(renewed_job, tenant)
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("SELECT verification_state FROM tenant_domains WHERE id=:id"),
                {"id": custom_id},
            )
            == "failed"
        )
    pg.provider.ready(custom_host, renewed)
    pg.worker_domain.reconcile(renewed_job, tenant)
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("SELECT routing_state FROM tenant_domains WHERE id=:id"), {"id": custom_id}
            )
            == "ready"
        )


def test_tls_loss_and_suspended_owner_recovery(pg: Harness) -> None:
    tenant, fallback_id, fallback_host, proof = pg.domain.provision(pg.actor, "Recovery", "recover")
    pg.provider.ready(fallback_host, proof)
    _, job_id = pg.job_for(fallback_id)
    pg.worker_domain.reconcile(job_id, tenant)
    pg.domain.activate(pg.actor, tenant, fallback_id)
    pg.domain.issue_first_owner(pg.actor, tenant, "recover-owner@example.test", pg.email)
    token = parse_qs(urlsplit(pg.email.links[-1]).fragment)["token"][0]
    _, challenge = pg.auth.accept_invitation(fallback_host, token, "recover-owner-password-123")
    secret = pg.auth.enroll_totp(fallback_host, challenge)
    owner_session, _ = pg.auth.verify_mfa(
        fallback_host, challenge, totp_code(secret, int(now().timestamp() // 30))
    )
    custom_id, custom_host, custom_proof = pg.domain.request_claim(
        fallback_host, owner_session, "recovery.example.test"
    )
    pg.provider.ready(custom_host, custom_proof)
    _, job_id = pg.job_for(custom_id)
    pg.worker_domain.reconcile(job_id, tenant)
    pg.domain.activate(pg.actor, tenant, custom_id)
    pg.provider.tls.remove(custom_host)
    pg.worker_domain.reconcile(job_id, tenant)
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("SELECT routing_state FROM tenant_domains WHERE id=:id"), {"id": custom_id}
            )
            == "deactivated"
        )
    with pg.owner.begin() as db:
        db.execute(
            text("UPDATE tenants SET status='suspended' WHERE id=:tenant"), {"tenant": tenant}
        )
    with Session(pg.owner) as db:
        suspended_fallback = db.get(TenantDomain, fallback_id)
        assert suspended_fallback is not None
        assert pg.domain.public_route_serving(suspended_fallback) is False
    with pg.runtime.connect() as db:
        assert (
            db.scalar(text("SELECT resolve_active_tenant_domain(:host)"), {"host": fallback_host})
            is None
        )
        with pytest.raises(ProgrammingError):
            db.scalar(text("SELECT resolve_auth_tenant_domain(:host)"), {"host": fallback_host})
    with pg.identity.connect() as db:
        assert (
            db.scalar(text("SELECT resolve_auth_tenant_domain(:host)"), {"host": fallback_host})
            == tenant
        )
    _, challenge = pg.auth.login(
        fallback_host, "recover-owner@example.test", "recover-owner-password-123", "192.0.2.5"
    )
    owner_session, _ = pg.auth.verify_mfa(
        fallback_host, challenge, totp_code(secret, int(now().timestamp() // 30) + 1)
    )
    assert pg.auth.authorize(fallback_host, owner_session, "tenant.domain.recover") == tenant
    with pytest.raises(AuthDenied):
        pg.auth.authorize(fallback_host, owner_session, "tenant.domain.manage")


def test_role_separation_rls_and_concurrent_hostname_claim(pg: Harness) -> None:
    first, first_domain, _, _ = pg.domain.provision(pg.actor, "First Tenant", "first")
    second, second_domain, _, _ = pg.domain.provision(pg.actor, "Second Tenant", "second")
    with pg.control.connect() as db:
        assert (
            db.scalar(text("SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user")) is False
        )
        with pytest.raises(ProgrammingError):
            db.execute(text("SELECT * FROM registrations"))
    with pg.bootstrap.connect() as db:
        assert (
            db.scalar(
                text("""SELECT has_column_privilege(
            current_user,'password_credentials','password_hash','SELECT')""")
            )
            is False
        )
        assert (
            db.scalar(
                text("""SELECT has_column_privilege(
            current_user,'totp_credentials','encrypted_secret','SELECT')""")
            )
            is False
        )
        assert (
            db.scalar(
                text("""SELECT has_table_privilege(
            current_user,'password_credentials','INSERT')""")
            )
            is False
        )
        with pytest.raises(ProgrammingError):
            db.execute(text("SELECT * FROM registrations"))
    with authorized_tenant_session(pg.runtime, first) as db:
        assert db.scalar(select(TenantDomain).where(TenantDomain.tenant_id == second)) is None
    with pytest.raises(ProgrammingError), authorized_tenant_session(pg.runtime, first) as db:
        db.execute(
            text("""INSERT INTO tenant_domains
            (tenant_id,hostname,kind,verification_state,tls_state)
            VALUES (:tenant,'forged.example.test','custom','pending','pending')"""),
            {"tenant": first},
        )
    with pytest.raises(DBAPIError), authorized_tenant_session(pg.runtime, first) as db:
        db.add(
            TenantDomain(
                tenant_id=second,
                hostname="wrong.example.test",
                kind="custom",
                verification_state="pending",
                tls_state="pending",
            )
        )
        db.flush()
    with pg.worker.connect() as db:
        with pytest.raises(ProgrammingError):
            db.execute(text("SELECT * FROM registrations"))
    with pg.worker.connect() as db:
        with pytest.raises(ProgrammingError):
            db.execute(text("INSERT INTO tenants(name,slug,status) VALUES ('Bad','bad','active')"))
    with pg.owner.begin() as db:
        db.execute(
            text("""UPDATE tenant_domains SET verification_state='verified',
            tls_state='active', edge_ready=true, activated_at=now(),
            ownership_valid_until=now()+interval '1 day',
            tls_valid_until=now()+interval '1 day', smoke_checked_at=now()
            WHERE id=:id"""),
            {"id": first_domain},
        )
    with pytest.raises(ProgrammingError), authorized_tenant_session(pg.worker, first) as db:
        db.execute(
            text("UPDATE tenant_domains SET routing_state='active' WHERE id=:id"),
            {"id": first_domain},
        )
    with pg.owner.begin() as db:
        db.execute(
            text("""UPDATE tenant_domains SET next_reconcile_at=now()-interval '1 minute'
            WHERE id IN (:first, :second)"""),
            {"first": first_domain, "second": second_domain},
        )
    assert schedule_due_reconciliations(pg.scheduler, limit=2) == 2
    assert pg.job_for(first_domain)[0] == first
    assert pg.job_for(second_domain)[0] == second

    def claim(tenant_id: UUID) -> bool:
        try:
            with pg.control.begin() as db:
                db.execute(
                    text("SELECT set_config('app.tenant_id',:id,true)"), {"id": str(tenant_id)}
                )
                db.execute(
                    text("""INSERT INTO tenant_domains
                    (tenant_id,hostname,kind,verification_state,tls_state)
                    VALUES (:tenant,'collision.example.test','custom','pending','pending')"""),
                    {"tenant": tenant_id},
                )
            return True
        except IntegrityError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, (first, second)))
    assert sorted(results) == [False, True]


def test_concurrent_first_owner_invitation_is_single_use(pg: Harness) -> None:
    tenant, fallback_id, fallback_host, proof = pg.domain.provision(
        pg.actor, "Invitation Race", "invite-race"
    )
    pg.provider.ready(fallback_host, proof)
    _, job_id = pg.job_for(fallback_id)
    pg.worker_domain.reconcile(job_id, tenant)
    pg.domain.activate(pg.actor, tenant, fallback_id)

    def invite(address: str) -> bool:
        try:
            pg.domain.issue_first_owner(pg.actor, tenant, address, pg.email)
            return True
        except (DomainDenied, IntegrityError):
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(invite, ("owner-a@example.test", "owner-b@example.test")))
    assert sorted(results) == [False, True]
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("""SELECT count(*) FROM staff_invitations
            WHERE tenant_id=:tenant AND role='tenant_owner' AND revoked_at IS NULL"""),
                {"tenant": tenant},
            )
            == 1
        )


def test_failed_owner_delivery_revokes_token_and_reissue_blocks_replay(pg: Harness) -> None:
    tenant, fallback_id, fallback_host, proof = pg.domain.provision(
        pg.actor, "Invitation Recovery", "invite-recovery"
    )
    pg.provider.ready(fallback_host, proof)
    _, job_id = pg.job_for(fallback_id)
    pg.worker_domain.reconcile(job_id, tenant)
    pg.domain.activate(pg.actor, tenant, fallback_id)

    class AmbiguousDelivery:
        def send_link(self, recipient: str, subject: str, link: str) -> None:
            pg.email.links.append(link)
            raise DeliveryUnavailable("simulated send failure")

    with pytest.raises(DeliveryUnavailable):
        pg.domain.issue_first_owner(
            pg.actor, tenant, "recovery-owner@example.test", AmbiguousDelivery()
        )
    failed_token = parse_qs(urlsplit(pg.email.links[-1]).fragment)["token"][0]
    with pytest.raises(AuthDenied):
        pg.auth.accept_invitation(fallback_host, failed_token, "fresh-owner-password-123")

    pg.domain.issue_first_owner(pg.actor, tenant, "recovery-owner@example.test", pg.email)
    first_token = parse_qs(urlsplit(pg.email.links[-1]).fragment)["token"][0]
    pg.domain.reissue_first_owner(pg.actor, tenant, pg.email)
    second_token = parse_qs(urlsplit(pg.email.links[-1]).fragment)["token"][0]
    assert first_token != second_token
    with pytest.raises(AuthDenied):
        pg.auth.accept_invitation(fallback_host, first_token, "fresh-owner-password-123")
    with pg.owner.connect() as db:
        assert (
            db.scalar(
                text("""SELECT count(*) FROM staff_invitations
            WHERE tenant_id=:tenant AND role='tenant_owner' AND platform_actor_id IS NOT NULL
              AND accepted_at IS NULL AND revoked_at IS NULL"""),
                {"tenant": tenant},
            )
            == 1
        )
        assert (
            db.scalar(
                text("""SELECT count(*) FROM security_audit_events
            WHERE action='owner.invitation_delivery_failed'
              AND tenant_id=:tenant"""),
                {"tenant": tenant},
            )
            == 1
        )
        assert (
            db.scalar(
                text("""SELECT count(*) FROM security_audit_events
            WHERE action='owner.invitation_reissued'
              AND tenant_id=:tenant"""),
                {"tenant": tenant},
            )
            == 1
        )
    state, challenge = pg.auth.accept_invitation(
        fallback_host, second_token, "fresh-owner-password-123"
    )
    assert state == "enroll"
    with pytest.raises(AuthDenied):
        pg.auth.accept_invitation(fallback_host, second_token, "fresh-owner-password-123")
    with pytest.raises(DomainDenied):
        pg.domain.reissue_first_owner(pg.actor, tenant, pg.email)

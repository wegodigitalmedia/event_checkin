"""Restricted platform control plane and fail-closed web-domain routing.

Revision ID: 0006_tenant_provisioning
Revises: 0005_reliable_jobs_storage
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0006_tenant_provisioning"
down_revision: str | None = "0005_reliable_jobs_storage"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
TS = sa.DateTime(timezone=True)
NOW = sa.text("now()")
NEW_ID = sa.text("gen_random_uuid()")


def upgrade() -> None:
    op.execute("""DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='eventcheckin_platform') THEN
        CREATE ROLE eventcheckin_platform NOLOGIN NOBYPASSRLS;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='eventcheckin_bootstrap') THEN
        CREATE ROLE eventcheckin_bootstrap NOLOGIN NOBYPASSRLS;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='eventcheckin_bootstrap_executor') THEN
        CREATE ROLE eventcheckin_bootstrap_executor NOLOGIN NOBYPASSRLS;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='eventcheckin_domain_worker') THEN
        CREATE ROLE eventcheckin_domain_worker NOLOGIN NOBYPASSRLS;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='eventcheckin_domain_scheduler') THEN
        CREATE ROLE eventcheckin_domain_scheduler NOLOGIN NOBYPASSRLS;
      END IF;
    END $$""")
    op.add_column(
        "tenant_domains",
        sa.Column("routing_state", sa.String(24), nullable=False, server_default="reserved"),
    )
    op.add_column("tenant_domains", sa.Column("claim_digest", sa.LargeBinary()))
    op.add_column("tenant_domains", sa.Column("claim_expires_at", TS))
    op.add_column("tenant_domains", sa.Column("ownership_checked_at", TS))
    op.add_column("tenant_domains", sa.Column("ownership_valid_until", TS))
    op.add_column("tenant_domains", sa.Column("tls_checked_at", TS))
    op.add_column("tenant_domains", sa.Column("tls_valid_until", TS))
    op.add_column(
        "tenant_domains",
        sa.Column("edge_ready", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column("tenant_domains", sa.Column("smoke_checked_at", TS))
    op.add_column("tenant_domains", sa.Column("last_error_code", sa.String(64)))
    op.add_column("tenant_domains", sa.Column("updated_at", TS, nullable=False, server_default=NOW))
    op.add_column(
        "tenant_domains", sa.Column("next_reconcile_at", TS, nullable=False, server_default=NOW)
    )
    op.create_check_constraint("ck_domain_kind", "tenant_domains", "kind IN ('custom','fallback')")
    op.create_unique_constraint(
        "uq_tenant_domains_tenant_id", "tenant_domains", ["tenant_id", "id"]
    )
    op.create_check_constraint(
        "ck_domain_verification",
        "tenant_domains",
        "verification_state IN ('pending','checking','verified','failed')",
    )
    op.create_check_constraint(
        "ck_domain_tls", "tenant_domains", "tls_state IN ('pending','issuing','active','failed')"
    )
    op.create_check_constraint(
        "ck_domain_routing",
        "tenant_domains",
        "routing_state IN ('reserved','ready','active','deactivated')",
    )
    op.create_check_constraint(
        "ck_domain_active_gates",
        "tenant_domains",
        "routing_state <> 'active' OR (verification_state='verified' "
        "AND tls_state='active' AND edge_ready AND activated_at IS NOT NULL "
        "AND ownership_valid_until IS NOT NULL AND tls_valid_until IS NOT NULL "
        "AND smoke_checked_at IS NOT NULL)",
    )
    op.execute("""CREATE FUNCTION guard_domain_activation()
      RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
      BEGIN
        IF NEW.routing_state='active' AND OLD.routing_state IS DISTINCT FROM 'active' AND
          NOT pg_has_role(current_user, 'eventcheckin_platform', 'MEMBER') AND
          NOT pg_has_role(current_user::regrole,
            (SELECT relowner FROM pg_class WHERE oid=TG_RELID), 'MEMBER') THEN
          RAISE EXCEPTION 'Platform domain activation required'
            USING ERRCODE='42501';
        END IF;
        RETURN NEW;
      END $$""")
    op.execute("REVOKE ALL ON FUNCTION guard_domain_activation() FROM PUBLIC")
    op.execute("""CREATE TRIGGER guard_domain_activation
      BEFORE UPDATE OF routing_state ON tenant_domains
      FOR EACH ROW EXECUTE FUNCTION guard_domain_activation()""")
    # Existing rows remain reserved until reverified. This deliberately does not
    # grandfather an unproved hostname into the new fail-closed routing rule.
    op.drop_index("uq_tenant_domains_primary", table_name="tenant_domains")
    op.create_index(
        "uq_tenant_domains_primary",
        "tenant_domains",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text("is_primary AND routing_state='active'"),
    )
    op.create_index(
        "uq_tenant_domains_fallback",
        "tenant_domains",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text("kind='fallback'"),
    )

    op.alter_column("staff_invitations", "invited_by", nullable=True)
    op.add_column(
        "staff_invitations", sa.Column("platform_actor_id", UUID, sa.ForeignKey("users.id"))
    )
    op.create_check_constraint(
        "ck_invitation_inviter_source",
        "staff_invitations",
        "(invited_by IS NOT NULL) <> (platform_actor_id IS NOT NULL)",
    )
    op.create_index(
        "uq_initial_owner_pending",
        "staff_invitations",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text(
            "role='tenant_owner' AND platform_actor_id IS NOT NULL "
            "AND accepted_at IS NULL AND revoked_at IS NULL"
        ),
    )
    op.create_table(
        "platform_bootstrap",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_user_id", UUID, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("operator_ref", sa.String(160), nullable=False),
        sa.Column("email_verification_ref", sa.String(160), nullable=False),
        sa.Column("consumed_at", TS, nullable=False, server_default=NOW),
        sa.CheckConstraint("id=1", name="ck_platform_bootstrap_singleton"),
    )
    for name in ("platform_auth_challenges", "platform_auth_sessions"):
        columns: list[sa.Column[object]] = [
            sa.Column("id", UUID, primary_key=True, server_default=NEW_ID),
            sa.Column("user_id", UUID, sa.ForeignKey("users.id"), nullable=False),
            sa.Column("token_digest", sa.LargeBinary(), nullable=False),
            sa.Column("created_at", TS, nullable=False, server_default=NOW),
        ]
        if name == "platform_auth_challenges":
            columns += [
                sa.Column("purpose", sa.String(16), nullable=False),
                sa.Column("expires_at", TS, nullable=False),
                sa.Column("consumed_at", TS),
                sa.CheckConstraint(
                    "purpose IN ('mfa','enroll')", name="ck_platform_challenge_purpose"
                ),
            ]
        else:
            columns += [
                sa.Column("last_seen_at", TS, nullable=False),
                sa.Column("idle_expires_at", TS, nullable=False),
                sa.Column("absolute_expires_at", TS, nullable=False),
                sa.Column("revoked_at", TS),
                sa.Column("mfa_verified_at", TS, nullable=False),
                sa.CheckConstraint(
                    "idle_expires_at <= absolute_expires_at", name="ck_platform_session_idle"
                ),
            ]
        op.create_table(
            name, *columns, sa.UniqueConstraint("token_digest", name=f"uq_{name}_token")
        )
    op.create_index(
        "ix_platform_auth_sessions_user", "platform_auth_sessions", ["user_id", "revoked_at"]
    )
    op.create_table(
        "domain_reconcile_requests",
        sa.Column("tenant_id", UUID, nullable=False),
        sa.Column("job_id", UUID, primary_key=True),
        sa.Column("domain_id", UUID, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=NOW),
        sa.ForeignKeyConstraint(
            ["tenant_id", "job_id"],
            ["job_records.tenant_id", "job_records.id"],
            name="fk_domain_reconcile_job",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "domain_id"],
            ["tenant_domains.tenant_id", "tenant_domains.id"],
            name="fk_domain_reconcile_domain",
        ),
    )
    op.create_index(
        "ix_domain_reconcile_tenant", "domain_reconcile_requests", ["tenant_id", "domain_id"]
    )
    op.execute("ALTER TABLE domain_reconcile_requests ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE domain_reconcile_requests FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY domain_reconcile_tenant ON domain_reconcile_requests
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)""")

    op.execute("""GRANT USAGE ON SCHEMA public TO eventcheckin_platform,
      eventcheckin_bootstrap, eventcheckin_bootstrap_executor,
      eventcheckin_domain_worker, eventcheckin_domain_scheduler""")
    op.execute("GRANT SELECT, INSERT, UPDATE ON tenants TO eventcheckin_platform")
    op.execute("GRANT SELECT, INSERT, UPDATE ON tenant_domains TO eventcheckin_platform")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE (revoked_at) ON staff_invitations TO eventcheckin_platform"
    )
    op.execute("GRANT SELECT ON users, platform_grants TO eventcheckin_platform")
    op.execute("GRANT SELECT ON tenant_memberships TO eventcheckin_platform")
    op.execute("GRANT SELECT, INSERT ON security_audit_events TO eventcheckin_platform")
    op.execute("GRANT SELECT, INSERT ON job_records, outbox_events TO eventcheckin_platform")
    op.execute(
        "GRANT SELECT, INSERT ON domain_reconcile_requests TO eventcheckin_platform, "
        "eventcheckin_runtime, eventcheckin_domain_scheduler"
    )
    op.execute("GRANT SELECT ON domain_reconcile_requests TO eventcheckin_jobs")
    op.execute("""CREATE POLICY platform_domain_control ON tenant_domains
      TO eventcheckin_platform USING (true) WITH CHECK (true)""")
    op.execute("""CREATE POLICY platform_invitation_control ON staff_invitations
      TO eventcheckin_platform USING (true) WITH CHECK (true)""")
    for table in ("job_records", "outbox_events"):
        op.execute(f"""CREATE POLICY platform_job_control ON {table}
          TO eventcheckin_platform
          USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
          WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)""")
    op.execute("GRANT SELECT ON tenant_domains TO eventcheckin_domain_worker")
    op.execute("""GRANT UPDATE (verification_state, ownership_checked_at,
      ownership_valid_until, tls_state, tls_checked_at, tls_valid_until, edge_ready,
      smoke_checked_at, updated_at, next_reconcile_at, routing_state, is_primary,
      last_error_code) ON tenant_domains TO eventcheckin_domain_worker""")
    op.execute("""CREATE POLICY domain_worker_scope ON tenant_domains
      TO eventcheckin_domain_worker
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)""")
    op.execute("""GRANT SELECT, UPDATE (next_reconcile_at) ON tenant_domains
      TO eventcheckin_domain_scheduler""")
    op.execute("""CREATE POLICY domain_scheduler_metadata ON tenant_domains
      TO eventcheckin_domain_scheduler USING (true) WITH CHECK (true)""")
    op.execute("""GRANT SELECT, INSERT ON job_records, outbox_events
      TO eventcheckin_domain_scheduler""")
    for table in ("job_records", "outbox_events"):
        op.execute(f"""CREATE POLICY domain_scheduler_job_scope ON {table}
          TO eventcheckin_domain_scheduler
          USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
          WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)""")
    op.execute("GRANT INSERT ON security_audit_events TO eventcheckin_domain_worker")
    op.execute("""GRANT SELECT (id, occurred_at, metadata) ON security_audit_events
      TO eventcheckin_domain_worker""")
    op.execute("""GRANT INSERT ON users, password_credentials, platform_grants,
      platform_bootstrap, security_audit_events TO eventcheckin_bootstrap_executor""")
    op.execute("GRANT CREATE ON SCHEMA public TO eventcheckin_bootstrap_executor")
    op.execute("""CREATE FUNCTION consume_platform_bootstrap(
      p_email citext, p_password_hash text, p_operator_ref text,
      p_email_verification_ref text, p_grant_until timestamptz)
      RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
      DECLARE v_user uuid := gen_random_uuid();
      BEGIN
        IF p_grant_until <= clock_timestamp()
          OR length(p_operator_ref) NOT BETWEEN 1 AND 160
          OR length(p_email_verification_ref) NOT BETWEEN 1 AND 160
          OR p_password_hash NOT LIKE '$argon2id$%'
          OR length(p_email::text) > 320 THEN
          RAISE EXCEPTION 'Invalid bootstrap contract';
        END IF;
        INSERT INTO public.users(id,email,display_name,status)
          VALUES (v_user,p_email,p_email::text,'active');
        INSERT INTO public.password_credentials(user_id,password_hash)
          VALUES (v_user,p_password_hash);
        INSERT INTO public.platform_grants
          (user_id,operation,tenant_id,valid_from,valid_until)
          VALUES (v_user,'tenant.provision',NULL,clock_timestamp(),p_grant_until);
        INSERT INTO public.platform_bootstrap
          (id,actor_user_id,operator_ref,email_verification_ref)
          VALUES (1,v_user,p_operator_ref,p_email_verification_ref);
        INSERT INTO public.security_audit_events(actor_user_id,action,metadata)
          VALUES (v_user,'platform.bootstrap.consumed',
            jsonb_build_object('operator_ref',p_operator_ref,
              'email_verification_ref',p_email_verification_ref));
        RETURN v_user;
      END $$""")
    op.execute("""ALTER FUNCTION consume_platform_bootstrap(citext,text,text,text,timestamptz)
      OWNER TO eventcheckin_bootstrap_executor""")
    op.execute("REVOKE CREATE ON SCHEMA public FROM eventcheckin_bootstrap_executor")
    op.execute("""REVOKE ALL ON FUNCTION
      consume_platform_bootstrap(citext,text,text,text,timestamptz) FROM PUBLIC""")
    op.execute("""GRANT EXECUTE ON FUNCTION
      consume_platform_bootstrap(citext,text,text,text,timestamptz)
      TO eventcheckin_bootstrap""")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON platform_auth_challenges, "
        "platform_auth_sessions TO eventcheckin_identity"
    )
    op.execute("GRANT SELECT ON platform_bootstrap TO eventcheckin_identity")
    op.execute("""CREATE OR REPLACE FUNCTION revoke_sessions_on_user_status_change()
      RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
      BEGIN
        IF OLD.status IS DISTINCT FROM NEW.status THEN
          UPDATE public.auth_sessions SET revoked_at=clock_timestamp()
            WHERE user_id=NEW.id AND revoked_at IS NULL;
          UPDATE public.auth_challenges SET consumed_at=clock_timestamp()
            WHERE user_id=NEW.id AND consumed_at IS NULL;
          UPDATE public.platform_auth_sessions SET revoked_at=clock_timestamp()
            WHERE user_id=NEW.id AND revoked_at IS NULL;
          UPDATE public.platform_auth_challenges SET consumed_at=clock_timestamp()
            WHERE user_id=NEW.id AND consumed_at IS NULL;
          UPDATE public.password_reset_tokens SET consumed_at=clock_timestamp()
            WHERE user_id=NEW.id AND consumed_at IS NULL;
          INSERT INTO public.security_audit_events (actor_user_id, action, metadata)
          VALUES (NULL, 'user.status_changed',
            jsonb_build_object('target_user_id', NEW.id::text,
              'old_status', OLD.status, 'new_status', NEW.status,
              'database_login', session_user));
        END IF;
        RETURN NEW;
      END $$""")
    op.execute("""CREATE FUNCTION revoke_platform_grant_sessions()
      RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
      BEGIN
        UPDATE public.platform_auth_sessions SET revoked_at=clock_timestamp()
          WHERE user_id=OLD.user_id AND revoked_at IS NULL;
        UPDATE public.platform_auth_challenges SET consumed_at=clock_timestamp()
          WHERE user_id=OLD.user_id AND consumed_at IS NULL;
        INSERT INTO public.security_audit_events (actor_user_id, action, metadata)
          VALUES (NULL, 'platform.grant_changed',
            jsonb_build_object('target_user_id', OLD.user_id::text,
              'grant_id', OLD.id::text, 'database_login', session_user));
        RETURN COALESCE(NEW, OLD);
      END $$""")
    op.execute("REVOKE ALL ON FUNCTION revoke_platform_grant_sessions() FROM PUBLIC")
    op.execute("""CREATE TRIGGER revoke_platform_grant_sessions
      AFTER UPDATE OR DELETE ON platform_grants FOR EACH ROW
      EXECUTE FUNCTION revoke_platform_grant_sessions()""")
    op.execute("GRANT CREATE ON SCHEMA public TO eventcheckin_domain_resolver")
    op.execute("""CREATE OR REPLACE FUNCTION resolve_active_tenant_domain(p_hostname citext)
      RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
      SET search_path = public, pg_temp AS $$
      SELECT d.tenant_id FROM public.tenant_domains d
      JOIN public.tenants t ON t.id=d.tenant_id
      WHERE d.hostname=p_hostname AND t.status='active'
        AND d.routing_state='active' AND d.verification_state='verified'
        AND d.tls_state='active' AND d.edge_ready
        AND d.ownership_valid_until>now() AND d.tls_valid_until>now()
        AND d.smoke_checked_at>now()-interval '15 minutes'
        AND d.activated_at IS NOT NULL
      LIMIT 1 $$""")
    op.execute(
        "ALTER FUNCTION resolve_active_tenant_domain(citext) OWNER TO eventcheckin_domain_resolver"
    )
    op.execute("GRANT SELECT ON tenants TO eventcheckin_domain_resolver")
    op.execute("""CREATE FUNCTION resolve_auth_tenant_domain(p_hostname citext)
      RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
      SET search_path = public, pg_temp AS $$
      SELECT d.tenant_id FROM public.tenant_domains d
      JOIN public.tenants t ON t.id=d.tenant_id
      WHERE d.hostname=p_hostname
        AND (t.status='active' OR (t.status='suspended' AND d.kind='fallback'))
        AND d.routing_state='active' AND d.verification_state='verified'
        AND d.tls_state='active' AND d.edge_ready
        AND d.ownership_valid_until>now() AND d.tls_valid_until>now()
        AND d.smoke_checked_at>now()-interval '15 minutes'
        AND d.activated_at IS NOT NULL
      LIMIT 1 $$""")
    op.execute(
        "ALTER FUNCTION resolve_auth_tenant_domain(citext) OWNER TO eventcheckin_domain_resolver"
    )
    op.execute("REVOKE CREATE ON SCHEMA public FROM eventcheckin_domain_resolver")
    op.execute("REVOKE ALL ON FUNCTION resolve_auth_tenant_domain(citext) FROM PUBLIC")
    op.execute(
        "GRANT EXECUTE ON FUNCTION resolve_auth_tenant_domain(citext) TO eventcheckin_identity"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER guard_domain_activation ON tenant_domains")
    op.execute("DROP FUNCTION guard_domain_activation()")
    op.execute("""REVOKE EXECUTE ON FUNCTION
      consume_platform_bootstrap(citext,text,text,text,timestamptz)
      FROM eventcheckin_bootstrap""")
    op.execute("DROP FUNCTION consume_platform_bootstrap(citext,text,text,text,timestamptz)")
    op.execute("""REVOKE INSERT ON users, password_credentials, platform_grants,
      platform_bootstrap, security_audit_events FROM eventcheckin_bootstrap_executor""")
    op.execute("""REVOKE SELECT (id, occurred_at, metadata) ON security_audit_events
      FROM eventcheckin_domain_worker""")
    op.execute("REVOKE INSERT ON security_audit_events FROM eventcheckin_domain_worker")
    for table in ("job_records", "outbox_events"):
        op.execute(f"DROP POLICY domain_scheduler_job_scope ON {table}")
    op.execute("""REVOKE SELECT, INSERT ON job_records, outbox_events
      FROM eventcheckin_domain_scheduler""")
    op.execute("DROP POLICY domain_scheduler_metadata ON tenant_domains")
    op.execute("""REVOKE SELECT, UPDATE (next_reconcile_at) ON tenant_domains
      FROM eventcheckin_domain_scheduler""")
    op.execute("DROP POLICY domain_worker_scope ON tenant_domains")
    op.execute("""REVOKE UPDATE (verification_state, ownership_checked_at,
      ownership_valid_until, tls_state, tls_checked_at, tls_valid_until, edge_ready,
      smoke_checked_at, updated_at, next_reconcile_at, routing_state, is_primary,
      last_error_code) ON tenant_domains FROM eventcheckin_domain_worker""")
    op.execute("REVOKE SELECT ON tenant_domains FROM eventcheckin_domain_worker")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION resolve_auth_tenant_domain(citext) FROM eventcheckin_identity"
    )
    op.execute("DROP FUNCTION resolve_auth_tenant_domain(citext)")
    op.execute("DROP TRIGGER revoke_platform_grant_sessions ON platform_grants")
    op.execute("DROP FUNCTION revoke_platform_grant_sessions()")
    op.execute("""CREATE OR REPLACE FUNCTION revoke_sessions_on_user_status_change()
      RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
      BEGIN
        IF OLD.status IS DISTINCT FROM NEW.status THEN
          UPDATE public.auth_sessions SET revoked_at=clock_timestamp()
            WHERE user_id=NEW.id AND revoked_at IS NULL;
          UPDATE public.auth_challenges SET consumed_at=clock_timestamp()
            WHERE user_id=NEW.id AND consumed_at IS NULL;
          UPDATE public.password_reset_tokens SET consumed_at=clock_timestamp()
            WHERE user_id=NEW.id AND consumed_at IS NULL;
          INSERT INTO public.security_audit_events (actor_user_id, action, metadata)
          VALUES (NULL, 'user.status_changed',
            jsonb_build_object('target_user_id', NEW.id::text,
              'old_status', OLD.status, 'new_status', NEW.status,
              'database_login', session_user));
        END IF;
        RETURN NEW;
      END $$""")
    op.execute("""CREATE OR REPLACE FUNCTION resolve_active_tenant_domain(p_hostname citext)
      RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
      SET search_path = public, pg_temp AS $$
      SELECT tenant_id FROM public.tenant_domains
      WHERE hostname=p_hostname AND verification_state='verified'
        AND tls_state='active' AND activated_at IS NOT NULL LIMIT 1 $$""")
    op.execute(
        "ALTER FUNCTION resolve_active_tenant_domain(citext) OWNER TO eventcheckin_domain_resolver"
    )
    op.execute("REVOKE SELECT ON tenants FROM eventcheckin_domain_resolver")
    op.execute("REVOKE SELECT ON platform_bootstrap FROM eventcheckin_identity")
    op.execute(
        "REVOKE SELECT, INSERT, UPDATE ON platform_auth_challenges, "
        "platform_auth_sessions FROM eventcheckin_identity"
    )
    for table in ("job_records", "outbox_events"):
        op.execute(f"DROP POLICY platform_job_control ON {table}")
    op.execute("DROP POLICY platform_invitation_control ON staff_invitations")
    op.execute("DROP POLICY platform_domain_control ON tenant_domains")
    op.execute("REVOKE SELECT, INSERT ON job_records, outbox_events FROM eventcheckin_platform")
    op.execute("REVOKE SELECT ON domain_reconcile_requests FROM eventcheckin_jobs")
    op.execute(
        "REVOKE SELECT, INSERT ON domain_reconcile_requests FROM eventcheckin_platform, "
        "eventcheckin_runtime, eventcheckin_domain_scheduler"
    )
    op.execute("REVOKE SELECT, INSERT ON security_audit_events FROM eventcheckin_platform")
    op.execute(
        "REVOKE SELECT, INSERT, UPDATE (revoked_at) ON staff_invitations FROM eventcheckin_platform"
    )
    op.execute("REVOKE SELECT ON users, platform_grants FROM eventcheckin_platform")
    op.execute("REVOKE SELECT ON tenant_memberships FROM eventcheckin_platform")
    op.execute("REVOKE SELECT, INSERT, UPDATE ON tenant_domains FROM eventcheckin_platform")
    op.execute("REVOKE SELECT, INSERT, UPDATE ON tenants FROM eventcheckin_platform")
    op.drop_index("ix_platform_auth_sessions_user", table_name="platform_auth_sessions")
    op.drop_table("platform_auth_sessions")
    op.drop_table("platform_auth_challenges")
    op.drop_index("ix_domain_reconcile_tenant", table_name="domain_reconcile_requests")
    op.drop_table("domain_reconcile_requests")
    op.drop_table("platform_bootstrap")
    op.drop_index("uq_initial_owner_pending", table_name="staff_invitations")
    op.drop_constraint("ck_invitation_inviter_source", "staff_invitations", type_="check")
    op.drop_column("staff_invitations", "platform_actor_id")
    op.alter_column("staff_invitations", "invited_by", nullable=False)
    op.drop_index("uq_tenant_domains_fallback", table_name="tenant_domains")
    op.drop_constraint("uq_tenant_domains_tenant_id", "tenant_domains", type_="unique")
    op.drop_index("uq_tenant_domains_primary", table_name="tenant_domains")
    op.create_index(
        "uq_tenant_domains_primary",
        "tenant_domains",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text(
            "is_primary AND verification_state='verified' AND tls_state='active'"
        ),
    )
    for constraint in (
        "ck_domain_active_gates",
        "ck_domain_routing",
        "ck_domain_tls",
        "ck_domain_verification",
        "ck_domain_kind",
    ):
        op.drop_constraint(constraint, "tenant_domains", type_="check")
    for column in (
        "next_reconcile_at",
        "updated_at",
        "last_error_code",
        "smoke_checked_at",
        "edge_ready",
        "tls_valid_until",
        "tls_checked_at",
        "ownership_valid_until",
        "ownership_checked_at",
        "claim_expires_at",
        "claim_digest",
        "routing_state",
    ):
        op.drop_column("tenant_domains", column)

"""Versioned tenant branding with draft and attributable publication history.

Revision ID: 0008_tenant_branding
Revises: 0007_event_configuration
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0008_tenant_branding"
down_revision: str | None = "0007_event_configuration"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
TS = sa.DateTime(timezone=True)
NOW = sa.text("now()")


def upgrade() -> None:
    op.add_column("tenant_branding", sa.Column("display_name", sa.Text()))
    op.add_column("tenant_branding", sa.Column("published_version", sa.Integer()))
    op.create_check_constraint(
        "ck_tenant_branding_published_version",
        "tenant_branding",
        "published_version IS NULL OR published_version > 0",
    )
    op.create_table(
        "tenant_branding_drafts",
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("display_name", sa.Text()),
        sa.Column("logo_object_key", sa.Text()),
        sa.Column("primary_color", sa.String(7)),
        sa.Column("accent_color", sa.String(7)),
        sa.Column("sender_name", sa.Text()),
        sa.Column("updated_by", UUID, nullable=False),
        sa.Column("updated_at", TS, nullable=False, server_default=NOW),
        sa.ForeignKeyConstraint(
            ["tenant_id", "updated_by"],
            ["tenant_memberships.tenant_id", "tenant_memberships.user_id"],
            name="fk_branding_draft_actor_member",
        ),
        sa.CheckConstraint("revision >= 0", name="ck_branding_draft_revision"),
    )
    op.create_table(
        "tenant_branding_versions",
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("display_name", sa.Text()),
        sa.Column("logo_object_key", sa.Text()),
        sa.Column("primary_color", sa.String(7)),
        sa.Column("accent_color", sa.String(7)),
        sa.Column("sender_name", sa.Text()),
        sa.Column("published_by", UUID, nullable=False),
        sa.Column("published_at", TS, nullable=False, server_default=NOW),
        sa.Column("restored_from_version", sa.Integer()),
        sa.ForeignKeyConstraint(
            ["tenant_id", "published_by"],
            ["tenant_memberships.tenant_id", "tenant_memberships.user_id"],
            name="fk_branding_version_actor_member",
        ),
        sa.CheckConstraint("version > 0", name="ck_branding_version_positive"),
    )
    op.create_foreign_key(
        "fk_tenant_branding_published_version",
        "tenant_branding",
        "tenant_branding_versions",
        ["tenant_id", "published_version"],
        ["tenant_id", "version"],
        deferrable=True,
        initially="DEFERRED",
    )
    op.create_table(
        "tenant_branding_audit",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("actor_user_id", UUID, nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("version", sa.Integer()),
        sa.Column("occurred_at", TS, nullable=False, server_default=NOW),
        sa.Column(
            "metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "actor_user_id"],
            ["tenant_memberships.tenant_id", "tenant_memberships.user_id"],
            name="fk_branding_audit_actor_member",
        ),
    )
    op.create_index(
        "ix_tenant_branding_audit_scope", "tenant_branding_audit", ["tenant_id", "occurred_at"]
    )
    for table in ("tenant_branding_drafts", "tenant_branding_versions", "tenant_branding_audit"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_isolation ON {table}
          USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
          WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)""")
    op.execute("GRANT SELECT, INSERT, UPDATE ON tenant_branding_drafts TO eventcheckin_runtime")
    op.execute("GRANT SELECT, INSERT ON tenant_branding_versions TO eventcheckin_runtime")
    op.execute("GRANT SELECT, INSERT ON tenant_branding_audit TO eventcheckin_runtime")
    op.execute("GRANT CREATE ON SCHEMA public TO eventcheckin_domain_resolver")
    op.execute("""CREATE FUNCTION current_active_tenant_profile()
      RETURNS TABLE(id uuid, name text) LANGUAGE sql STABLE SECURITY DEFINER
      SET search_path = public, pg_temp AS $$
      SELECT t.id,t.name FROM public.tenants t
      WHERE t.id=nullif(current_setting('app.tenant_id', true), '')::uuid
        AND t.status='active' $$""")
    op.execute(
        "ALTER FUNCTION current_active_tenant_profile() OWNER TO eventcheckin_domain_resolver"
    )
    op.execute("REVOKE CREATE ON SCHEMA public FROM eventcheckin_domain_resolver")
    op.execute("REVOKE ALL ON FUNCTION current_active_tenant_profile() FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION current_active_tenant_profile() TO eventcheckin_runtime")
    op.execute("""CREATE FUNCTION reject_branding_history_mutation() RETURNS trigger
      LANGUAGE plpgsql SET search_path=pg_catalog AS $$
      BEGIN RAISE EXCEPTION 'Branding history is append-only' USING ERRCODE='42501'; END $$""")
    op.execute("REVOKE ALL ON FUNCTION reject_branding_history_mutation() FROM PUBLIC")
    for table in ("tenant_branding_versions", "tenant_branding_audit"):
        op.execute(f"""CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table}
          FOR EACH ROW EXECUTE FUNCTION reject_branding_history_mutation()""")


def downgrade() -> None:
    op.execute("""DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM tenant_branding_versions)
         OR EXISTS (SELECT 1 FROM tenant_branding_audit)
         OR EXISTS (SELECT 1 FROM tenant_branding_drafts) THEN
        RAISE EXCEPTION 'Branding downgrade requires reviewed data migration';
      END IF;
    END $$""")
    for table in ("tenant_branding_versions", "tenant_branding_audit"):
        op.execute(f"DROP TRIGGER {table}_immutable ON {table}")
    op.execute("DROP FUNCTION reject_branding_history_mutation()")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION current_active_tenant_profile() FROM eventcheckin_runtime"
    )
    op.execute("DROP FUNCTION current_active_tenant_profile()")
    op.execute("REVOKE SELECT, INSERT ON tenant_branding_audit FROM eventcheckin_runtime")
    op.execute("REVOKE SELECT, INSERT ON tenant_branding_versions FROM eventcheckin_runtime")
    op.execute("REVOKE SELECT, INSERT, UPDATE ON tenant_branding_drafts FROM eventcheckin_runtime")
    op.drop_index("ix_tenant_branding_audit_scope", table_name="tenant_branding_audit")
    op.drop_table("tenant_branding_audit")
    op.drop_constraint(
        "fk_tenant_branding_published_version", "tenant_branding", type_="foreignkey"
    )
    op.drop_table("tenant_branding_versions")
    op.drop_table("tenant_branding_drafts")
    op.drop_constraint("ck_tenant_branding_published_version", "tenant_branding", type_="check")
    op.drop_column("tenant_branding", "published_version")
    op.drop_column("tenant_branding", "display_name")

"""Exercise ownership transfers as a non-superuser with no RLS bypass."""

import os
import secrets

import psycopg
import pytest
from psycopg import sql
from sqlalchemy.engine import make_url
from test_tenant_postgres import _migrate

pytestmark = pytest.mark.postgres

OWNERS = (
    "eventcheckin_domain_resolver",
    "eventcheckin_bootstrap_executor",
    "eventcheckin_shared_resolver",
)


@pytest.mark.parametrize("baseline", [None, "0005_reliable_jobs_storage"])
def test_restricted_owner_migrates_with_temporary_schema_create(baseline: str | None) -> None:
    raw_url = os.environ.get("TEST_MIGRATION_DATABASE_URL")
    if not raw_url:
        if os.environ.get("CI") == "true":
            pytest.fail("CI must provide TEST_MIGRATION_DATABASE_URL")
        pytest.skip("Set TEST_MIGRATION_DATABASE_URL to an isolated PostgreSQL admin login")
    parsed = make_url(raw_url)
    suffix = secrets.token_hex(5)
    database = f"eventcheckin_migration_permissions_{suffix}"
    login = f"eventcheckin_migration_owner_{suffix}"
    password = secrets.token_urlsafe(24)
    admin_url = parsed.set(drivername="postgresql", database="postgres")
    admin = psycopg.connect(admin_url.render_as_string(hide_password=False), autocommit=True)
    if admin.info.server_version < 160000:
        admin.close()
        pytest.skip("Requires PostgreSQL 16+ membership options")
    owner_url = parsed.set(database=database, username=login, password=password)
    try:
        admin.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} CREATEROLE NOBYPASSRLS NOSUPERUSER").format(
                sql.Identifier(login), sql.Literal(password)
            )
        )
        admin.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(database), sql.Identifier(login)
            )
        )
        for role in OWNERS:
            if not admin.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone():
                admin.execute(
                    sql.SQL("CREATE ROLE {} NOLOGIN NOBYPASSRLS").format(sql.Identifier(role))
                )
            admin.execute(
                sql.SQL("GRANT {} TO {} WITH INHERIT TRUE, SET TRUE").format(
                    sql.Identifier(role), sql.Identifier(login)
                )
            )
        url = owner_url.render_as_string(hide_password=False)
        if baseline is not None:
            _migrate(url, baseline)
        with psycopg.connect(owner_url.set(drivername="postgresql").render_as_string(
            hide_password=False
        )) as conn:
            # A preflight grant before a fresh upgrade is revoked by 0002.
            conn.execute("GRANT CREATE ON SCHEMA public TO eventcheckin_domain_resolver")
            assert conn.execute(
                "SELECT has_schema_privilege('eventcheckin_domain_resolver','public','CREATE')"
            ).fetchone() == (True,)
        _migrate(url, "head")
        with psycopg.connect(owner_url.set(drivername="postgresql").render_as_string(
            hide_password=False
        )) as conn:
            assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "0013_privacy_notice_workflow",
            )
            assert conn.execute(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user"
            ).fetchone() == (False, False)
            for role in OWNERS:
                assert conn.execute(
                    "SELECT has_schema_privilege(%s,'public','CREATE')", (role,)
                ).fetchone() == (False,)
                assert conn.execute(
                    "SELECT rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname=%s",
                    (role,),
                ).fetchone() == (False, False, False)
            for function, role in (
                ("resolve_active_tenant_domain", OWNERS[0]),
                ("resolve_auth_tenant_domain", OWNERS[0]),
                ("current_active_tenant_profile", OWNERS[0]),
                ("consume_platform_bootstrap", OWNERS[1]),
                ("shared_login_contexts", OWNERS[2]),
            ):
                assert conn.execute(
                    "SELECT pg_get_userbyid(proowner) FROM pg_proc "
                    "WHERE pronamespace='public'::regnamespace AND proname=%s", (function,)
                ).fetchone() == (role,)
            for table in ("events", "tenant_domains", "registration_notice_versions",
                          "participant_imports", "tenant_branding_versions"):
                assert conn.execute(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid=%s::regclass",
                    (f"public.{table}",),
                ).fetchone() == (True, True)
    finally:
        admin.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(database))
        )
        admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(login)))
        admin.close()

"""Routing hints are signed, short-lived, and never accepted when altered."""

import base64
from uuid import uuid4

from app.core.config import Settings
from app.tenancy.shared_host import sign_context, verify_context


def test_shared_tenant_context_signature_rejects_tampering() -> None:
    settings = Settings(
        app_env="test",
        database_url="postgresql+psycopg://runtime:local@localhost/test",
        platform_host="platform.local.example.test",
        auth_encryption_key=base64.b64encode(b"a" * 32).decode(),
    )
    tenant_id = uuid4()
    signed = sign_context(settings, tenant_id)
    assert verify_context(settings, signed) == tenant_id
    changed = "A" if signed[20] != "A" else "B"
    assert verify_context(settings, signed[:20] + changed + signed[21:]) is None
    assert verify_context(settings, "not-a-context") is None


def test_shared_context_covers_full_session_and_expires(monkeypatch) -> None:
    settings = Settings(
        app_env="test",
        database_url="postgresql+psycopg://runtime:local@localhost/test",
        auth_encryption_key=base64.b64encode(b"a" * 32).decode(),
    )
    clock = 1_800_000_000
    monkeypatch.setattr("app.tenancy.shared_host.time.time", lambda: clock)
    tenant = uuid4()
    token = sign_context(settings, tenant)
    clock += 47 * 60 * 60
    assert verify_context(settings, token) == tenant
    clock += 60 * 60
    assert verify_context(settings, token) is None

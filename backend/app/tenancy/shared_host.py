"""Signed tenant routing hint for authenticated access on the platform host.

The hint is never an authorization grant. AuthService still verifies the
tenant-bound session, membership, MFA state, and event assignment.
"""

import base64
import hashlib
import hmac
import time
from uuid import UUID

from app.auth.policy import SESSION_MAX_AGE
from app.core.config import Settings

CONTEXT_COOKIE = "__Host-ecs_tenant_context"
CONTEXT_LIFETIME = SESSION_MAX_AGE


def shared_host_tenant(tenant_id: UUID) -> str:
    return f"shared-tenant-{tenant_id}"


def _key(settings: Settings) -> bytes:
    if settings.auth_encryption_key is None:
        raise ValueError("Shared tenant routing requires the authentication key")
    key = base64.b64decode(settings.auth_encryption_key.get_secret_value(), validate=True)
    if len(key) != 32:
        raise ValueError("Invalid authentication key")
    return key


def sign_context(settings: Settings, tenant_id: UUID) -> str:
    payload = f"1:{tenant_id}:{int(time.time()) + CONTEXT_LIFETIME}".encode("ascii")
    digest = hmac.new(_key(settings), payload, hashlib.sha256).digest()
    return (base64.urlsafe_b64encode(payload + b":" + digest).rstrip(b"=")).decode("ascii")


def verify_context(settings: Settings, value: str) -> UUID | None:
    try:
        encoded = value.encode("ascii")
        decoded = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
        if len(decoded) < 34 or decoded[-33:-32] != b":":
            return None
        payload, digest = decoded[:-33], decoded[-32:]
        expected = hmac.new(_key(settings), payload, hashlib.sha256).digest()
        version, raw_tenant, raw_expiry = payload.decode("ascii").split(":")
        if not hmac.compare_digest(digest, expected) or version != "1":
            return None
        if not int(time.time()) < int(raw_expiry) <= int(time.time()) + CONTEXT_LIFETIME:
            return None
        return UUID(raw_tenant)
    except (UnicodeError, ValueError, OverflowError):
        return None

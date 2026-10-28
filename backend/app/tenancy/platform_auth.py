"""Dedicated-host platform identity; no tenant runtime connection is used here."""

import base64
from datetime import timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.auth.policy import SESSION_DURATION
from app.auth.security import (
    accepted_totp_step,
    decrypt_totp,
    encrypt_totp,
    new_token,
    new_totp_secret,
    recovery_codes,
    token_digest,
    verify_password,
)
from app.auth.service import AuthDenied, AuthService, utcnow
from app.core.config import Settings
from app.db.models import (
    MfaRecoveryCode,
    PasswordCredential,
    PlatformAuthChallenge,
    PlatformAuthSession,
    PlatformGrant,
    SecurityAuditEvent,
    TotpCredential,
    User,
)


class PlatformAuth:
    def __init__(self, engine: Engine, settings: Settings) -> None:
        self.engine, self.settings = engine, settings

    def _encryption_key(self) -> bytes:
        value = self.settings.auth_encryption_key
        if value is None:
            raise AuthDenied("MFA encryption key is unavailable")
        try:
            key = base64.b64decode(value.get_secret_value(), validate=True)
        except ValueError as exc:
            raise AuthDenied("MFA encryption key is invalid") from exc
        if len(key) != 32:
            raise AuthDenied("MFA encryption key is invalid")
        return key

    @staticmethod
    def _granted(db: Session, user_id: UUID, operation: str = "tenant.provision") -> bool:
        now = utcnow()
        return (
            db.scalar(
                select(PlatformGrant.id)
                .where(
                    PlatformGrant.user_id == user_id,
                    PlatformGrant.operation == operation,
                    PlatformGrant.tenant_id.is_(None),
                    PlatformGrant.valid_from <= now,
                    PlatformGrant.valid_until > now,
                    PlatformGrant.revoked_at.is_(None),
                )
                .limit(1)
            )
            is not None
        )

    @staticmethod
    def _audit(db: Session, action: str, user: UUID | None = None) -> None:
        db.add(SecurityAuditEvent(actor_user_id=user, tenant_id=None, action=action))

    def login(self, email: str, password: str, ip: str) -> tuple[str, str]:
        # Rate-limit both the account and peer before password work. A failure is
        # committed in a separate transaction rather than rolled back with denial.
        key = f"platform:login:{email.casefold()}"
        peer = f"platform:login:ip:{ip}"
        with Session(self.engine) as db, db.begin():
            AuthService._check_limit(db, key, utcnow())
            AuthService._check_limit(db, peer, utcnow())
        try:
            with Session(self.engine) as db, db.begin():
                user = db.scalar(select(User).where(User.email == email))
                credential = db.get(PasswordCredential, user.id) if user else None
                if (
                    not verify_password(credential.password_hash if credential else None, password)
                    or user is None
                    or user.status != "active"
                    or not self._granted(db, user.id)
                ):
                    raise AuthDenied("Invalid credentials")
                totp = db.get(TotpCredential, user.id)
                purpose = "mfa" if totp and totp.confirmed_at else "enroll"
                raw = new_token()
                db.add(
                    PlatformAuthChallenge(
                        user_id=user.id,
                        token_digest=token_digest(raw),
                        purpose=purpose,
                        expires_at=utcnow() + timedelta(minutes=5),
                    )
                )
                self._audit(db, "platform.authentication.password_verified", user.id)
                return purpose, raw
        except AuthDenied:
            with Session(self.engine) as db, db.begin():
                AuthService._limit(db, key, utcnow())
                AuthService._limit(db, peer, utcnow(), 20)
                self._audit(db, "platform.authentication.failed")
            raise

    def _challenge(self, db: Session, raw: str) -> PlatformAuthChallenge:
        row = db.scalar(
            select(PlatformAuthChallenge)
            .where(PlatformAuthChallenge.token_digest == token_digest(raw))
            .with_for_update()
        )
        if (
            row is None
            or row.consumed_at is not None
            or row.expires_at <= utcnow()
            or not self._granted(db, row.user_id)
        ):
            raise AuthDenied("Authentication challenge expired")
        return row

    def enroll(self, raw: str) -> str:
        with Session(self.engine) as db, db.begin():
            challenge = self._challenge(db, raw)
            if challenge.purpose != "enroll":
                raise AuthDenied("Invalid enrollment state")
            totp = db.get(TotpCredential, challenge.user_id, with_for_update=True)
            if totp and totp.confirmed_at:
                raise AuthDenied("MFA already enrolled")
            secret = new_totp_secret()
            key = self._encryption_key()  # same G-02 application key
            if totp:
                totp.encrypted_secret = encrypt_totp(secret, key, str(challenge.user_id))
                totp.key_id = self.settings.auth_key_id
            else:
                db.add(
                    TotpCredential(
                        user_id=challenge.user_id,
                        encrypted_secret=encrypt_totp(secret, key, str(challenge.user_id)),
                        key_id=self.settings.auth_key_id,
                    )
                )
            self._audit(db, "platform.mfa.enrollment_started", challenge.user_id)
            return secret

    def verify(self, raw: str, code: str, recovery: bool, ip: str) -> tuple[str, list[str]]:
        try:
            return self._verify_inner(raw, code, recovery, ip)
        except AuthDenied:
            with Session(self.engine) as db, db.begin():
                self._audit(db, "platform.mfa.failed")
            raise

    def _verify_inner(self, raw: str, code: str, recovery: bool, ip: str) -> tuple[str, list[str]]:
        with Session(self.engine) as limiter, limiter.begin():
            challenge = self._challenge(limiter, raw)
            AuthService._limit(limiter, f"platform:mfa:{challenge.user_id}", utcnow())
            AuthService._limit(limiter, f"platform:mfa:ip:{ip}", utcnow(), 20)
        with Session(self.engine) as db, db.begin():
            challenge = self._challenge(db, raw)
            totp = db.get(TotpCredential, challenge.user_id, with_for_update=True)
            if totp is None or totp.key_id != self.settings.auth_key_id:
                raise AuthDenied("MFA unavailable")
            if recovery:
                if challenge.purpose != "mfa":
                    raise AuthDenied("Invalid MFA method")
                row = db.scalar(
                    select(MfaRecoveryCode)
                    .where(
                        MfaRecoveryCode.user_id == challenge.user_id,
                        MfaRecoveryCode.code_digest == token_digest(code),
                        MfaRecoveryCode.used_at.is_(None),
                    )
                    .with_for_update()
                )
                if row is None:
                    raise AuthDenied("Invalid MFA code")
                row.used_at = utcnow()
                self._audit(db, "platform.mfa.recovery_used", challenge.user_id)
            else:
                secret = decrypt_totp(
                    totp.encrypted_secret, self._encryption_key(), str(challenge.user_id)
                )
                step = accepted_totp_step(secret, code, totp.last_accepted_step)
                if step is None:
                    raise AuthDenied("Invalid MFA code")
                totp.last_accepted_step = step
            issued: list[str] = []
            if challenge.purpose == "enroll":
                if recovery or totp.confirmed_at is not None:
                    raise AuthDenied("Invalid enrollment state")
                totp.confirmed_at = utcnow()
                for value in recovery_codes():
                    issued.append(value)
                    db.add(
                        MfaRecoveryCode(user_id=challenge.user_id, code_digest=token_digest(value))
                    )
                self._audit(db, "platform.mfa.enrolled", challenge.user_id)
            elif totp.confirmed_at is None:
                raise AuthDenied("MFA enrollment incomplete")
            challenge.consumed_at = utcnow()
            # Session fixation protection: previous platform sessions are revoked
            # on a fresh MFA completion; only a new opaque token becomes valid.
            for session in db.scalars(
                select(PlatformAuthSession)
                .where(
                    PlatformAuthSession.user_id == challenge.user_id,
                    PlatformAuthSession.revoked_at.is_(None),
                )
                .with_for_update()
            ):
                session.revoked_at = utcnow()
            token = new_token()
            now = utcnow()
            db.add(
                PlatformAuthSession(
                    user_id=challenge.user_id,
                    token_digest=token_digest(token),
                    last_seen_at=now,
                    idle_expires_at=now + SESSION_DURATION,
                    absolute_expires_at=now + SESSION_DURATION,
                    mfa_verified_at=now,
                )
            )
            AuthService._clear_limit(db, f"platform:mfa:{challenge.user_id}")
            AuthService._clear_limit(db, f"platform:mfa:ip:{ip}")
            self._audit(db, "platform.authentication.succeeded", challenge.user_id)
            return token, issued

    def current(self, raw: str, operation: str = "tenant.provision") -> User:
        with Session(self.engine) as db, db.begin():
            row = db.scalar(
                select(PlatformAuthSession)
                .where(PlatformAuthSession.token_digest == token_digest(raw))
                .with_for_update()
            )
            now = utcnow()
            if (
                row is None
                or row.revoked_at is not None
                or row.idle_expires_at <= now
                or row.absolute_expires_at <= now
                or row.mfa_verified_at is None
            ):
                raise AuthDenied("Session expired")
            user = db.get(User, row.user_id)
            if user is None or user.status != "active" or not self._granted(db, user.id, operation):
                raise AuthDenied("Unauthorized")
            row.last_seen_at = now
            row.idle_expires_at = min(now + SESSION_DURATION, row.absolute_expires_at)
            db.expunge(user)
            return user

    def revoke(self, raw: str) -> None:
        with Session(self.engine) as db, db.begin():
            row = db.scalar(
                select(PlatformAuthSession)
                .where(PlatformAuthSession.token_digest == token_digest(raw))
                .with_for_update()
            )
            if row and row.revoked_at is None:
                row.revoked_at = utcnow()
                self._audit(db, "platform.session.revoked", row.user_id)

    def cancel_challenge(self, raw: str) -> None:
        with Session(self.engine) as db, db.begin():
            row = db.scalar(
                select(PlatformAuthChallenge)
                .where(PlatformAuthChallenge.token_digest == token_digest(raw))
                .with_for_update()
            )
            if row and row.consumed_at is None:
                row.consumed_at = utcnow()

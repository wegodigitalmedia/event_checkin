import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import create_engine

from app.api.auth import valid_email
from app.auth.address import single_email_address
from app.auth.corpus import CompromisedPasswordCorpus, CorpusUnavailable
from app.auth.email import DeliveryUnavailable, DisabledEmailDelivery, SmtpEmailDelivery
from app.auth.policy import Assignment, permits, requires_mfa, session_lifetime
from app.auth.security import (
    accepted_totp_step,
    decrypt_totp,
    encrypt_totp,
    hash_password,
    new_token,
    token_digest,
    totp_code,
    verify_password,
)
from app.auth.service import AuthService
from app.core.config import Settings


def test_password_hash_and_verification() -> None:
    password = "correct horse battery staple"
    first, second = hash_password(password), hash_password(password)
    assert first != second
    assert verify_password(first, password)
    assert not verify_password(first, "not the password")
    assert not verify_password(None, password)
    with pytest.raises(ValueError):
        hash_password("short")


def test_secret_links_require_one_email_recipient() -> None:
    assert single_email_address("  ada.okafor@example.test  ") == "ada.okafor@example.test"
    for address in (
        "victim@example.test, attacker@evil.test",
        "victim@example.test; attacker@evil.test",
        "Display Name <victim@example.test>",
        "victim@example.test\nBcc:attacker@evil.test",
    ):
        with pytest.raises(ValueError):
            valid_email(address)
        with pytest.raises(ValueError):
            SmtpEmailDelivery("localhost", 1025, "staff@example.test").send_link(
                address, "Invitation", "https://example.test/invite#token=test"
            )


def test_token_digest_and_totp_replay() -> None:
    token = new_token()
    assert token.encode() not in token_digest(token)
    secret = "JBSWY3DPEHPK3PXP"
    now = 1_700_000_000.0
    step = int(now // 30)
    code = totp_code(secret, step)
    assert accepted_totp_step(secret, code, None, now) == step
    assert accepted_totp_step(secret, code, step, now) is None


def test_totp_ciphertext_binds_user() -> None:
    key = base64.b64encode(bytes(range(32)))
    raw_key = base64.b64decode(key)
    ciphertext = encrypt_totp("JBSWY3DPEHPK3PXP", raw_key, "user-a")
    assert decrypt_totp(ciphertext, raw_key, "user-a") == "JBSWY3DPEHPK3PXP"
    with pytest.raises(InvalidTag):
        decrypt_totp(ciphertext, raw_key, "user-b")


def test_corpus_fails_closed_and_detects_compromise(tmp_path: Path) -> None:
    with pytest.raises(CorpusUnavailable):
        CompromisedPasswordCorpus(None, None).require_acceptable("password")
    contents = (hashlib.sha1(b"compromised secret").hexdigest().upper() + "\n").encode()
    path = tmp_path / "corpus-v1.sha1"
    path.write_bytes(contents)
    corpus = CompromisedPasswordCorpus(str(path), hashlib.sha256(contents).hexdigest())
    with pytest.raises(ValueError):
        corpus.require_acceptable("compromised secret")
    corpus.require_acceptable("unlisted long password")
    with pytest.raises(CorpusUnavailable):
        CompromisedPasswordCorpus(str(path), "0" * 64).require_acceptable("anything")


def test_role_matrix_and_assignment_scope() -> None:
    now, event, gate = datetime.now(UTC), uuid4(), uuid4()
    assignment = Assignment(event, gate, now - timedelta(minutes=1), None, None)
    assert requires_mfa("tenant_admin") and not requires_mfa("gate_scanner")
    assert permits("gate_scanner", "checkin.perform", [assignment], now, event, gate)
    assert not permits("gate_scanner", "checkin.perform", [assignment], now, event, uuid4())
    assert not permits("gate_scanner", "attendee.export", [assignment], now, event, gate)
    assert not permits("organizer", "billing.manage", [assignment], now, event)
    assert not permits("gate_supervisor", "report.view", [assignment], now, event, gate)
    assert session_lifetime("tenant_admin") == (timedelta(minutes=15), timedelta(hours=8))
    assert session_lifetime("gate_scanner") == (timedelta(minutes=30), timedelta(hours=12))


def test_unconfigured_delivery_fails_before_account_lookup() -> None:
    settings = Settings(
        app_env="test", database_url="postgresql+psycopg://runtime:local@localhost:5432/test"
    )
    service = AuthService(
        create_engine("sqlite+pysqlite:///:memory:"),
        settings,
        CompromisedPasswordCorpus(None, None),
        DisabledEmailDelivery(),
    )
    for address in ("known@example.test", "unknown@example.test"):
        with pytest.raises(DeliveryUnavailable):
            service.request_reset("tenant.example.test", address, "127.0.0.1")


def test_password_screening_mode_explicit_and_fail_closed(monkeypatch) -> None:
    from unittest.mock import MagicMock

    from pydantic import ValidationError

    settings = Settings(
        app_env="test", database_url="postgresql+psycopg://runtime:local@localhost/test"
    )
    offline = MagicMock(spec=CompromisedPasswordCorpus)
    online = MagicMock(side_effect=CorpusUnavailable("Unavailable"))
    monkeypatch.setattr("app.auth.service.require_hibp_acceptable", online)
    service = AuthService(create_engine("sqlite://"), settings, offline, DisabledEmailDelivery())
    service._screen_new_password("synthetic-password")
    offline.require_acceptable.assert_called_once_with("synthetic-password")
    online.assert_not_called()
    settings.password_screening_mode = "hibp"
    with pytest.raises(CorpusUnavailable):
        service._screen_new_password("synthetic-password")
    assert offline.require_acceptable.call_count == 1
    with pytest.raises(ValidationError):
        Settings(
            app_env="test",
            database_url="postgresql+psycopg://runtime:local@localhost/test",
            password_screening_mode="disabled",
        )

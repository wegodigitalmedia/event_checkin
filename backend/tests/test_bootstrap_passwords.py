import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.auth import password_screening as bootstrap_passwords
from app.auth.corpus import CorpusUnavailable
from app.tenancy import bootstrap


@pytest.mark.parametrize(
    "mode",
    [
        "safe",
        "compromised",
        "padding",
        "malformed",
        "http",
        "timeout",
        "empty",
        "oversized",
        "nonascii",
        "redirect",
    ],
)
def test_online_screening(monkeypatch, mode):
    password = "synthetic test password only"
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    connection = MagicMock()
    response = connection.getresponse.return_value
    response.status = 503 if mode == "http" else 302 if mode == "redirect" else 200
    suffix = digest[5:] if mode in ("compromised", "padding") else "0" * 35
    count = 0 if mode == "padding" else 1
    response.read.return_value = (
        b"invalid" if mode == "malformed" else f"{suffix}:{count}\r\n".encode()
    )
    if mode == "empty":
        response.read.return_value = b""
    elif mode == "oversized":
        response.read.return_value = b"A" * 2_000_001
    elif mode == "nonascii":
        response.read.return_value = bytes([255])
    if mode == "timeout":
        connection.request.side_effect = TimeoutError()
    factory = MagicMock(return_value=connection)
    monkeypatch.setattr(bootstrap_passwords.http.client, "HTTPSConnection", factory)
    error = ValueError if mode == "compromised" else CorpusUnavailable
    if mode in ("safe", "padding"):
        bootstrap_passwords.require_hibp_acceptable(password)
    else:
        with pytest.raises(error):
            bootstrap_passwords.require_hibp_acceptable(password)
    assert factory.call_args.args == ("api.pwnedpasswords.com",)
    assert connection.request.call_args.args == ("GET", "/range/" + digest[:5])
    assert password not in str(connection.mock_calls)
    assert digest not in str(connection.mock_calls)
    connection.close.assert_called_once()


def test_bootstrap_records_explicit_waiver(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "bootstrap",
            "--email",
            "admin@example.test",
            "--operator-ref",
            "CHANGE-1",
            "--waive-mailbox-verification",
            "--password-check",
            "hibp",
            "--grant-until",
            "2099-11-30T23:59:59Z",
        ],
    )
    terminal = MagicMock()
    terminal.isatty.return_value = True
    monkeypatch.setattr("sys.stdin", terminal)
    monkeypatch.setattr(bootstrap.getpass, "getpass", lambda _: "synthetic password")
    screen = MagicMock()
    monkeypatch.setattr(bootstrap, "require_hibp_acceptable", screen)
    monkeypatch.setattr(bootstrap, "hash_password", lambda _: "$argon2id$synthetic")
    monkeypatch.setattr(
        bootstrap,
        "get_settings",
        lambda: SimpleNamespace(
            bootstrap_database_url=SimpleNamespace(get_secret_value=lambda: "synthetic-url")
        ),
    )
    engine = MagicMock()
    monkeypatch.setattr(bootstrap, "create_engine", MagicMock(return_value=engine))
    session = MagicMock()
    monkeypatch.setattr(bootstrap, "Session", MagicMock(return_value=session))
    bootstrap.main()
    params = session.__enter__.return_value.execute.call_args.args[1]
    assert params["email_verification_ref"] == "WAIVED_BY_OPERATOR:CHANGE-1"
    screen.assert_called_once_with("synthetic password")
    engine.dispose.assert_called_once()


@pytest.mark.parametrize(
    "args", [[], ["--email-verification-ref", "RECORD", "--waive-mailbox-verification"]]
)
def test_verification_choice_required(monkeypatch, args):
    monkeypatch.setattr(
        "sys.argv",
        [
            "bootstrap",
            "--email",
            "admin@example.test",
            "--operator-ref",
            "CHANGE-1",
            "--grant-until",
            "2099-11-30T23:59:59Z",
            *args,
        ],
    )
    engine = MagicMock()
    monkeypatch.setattr(bootstrap, "create_engine", engine)
    with pytest.raises(SystemExit):
        bootstrap.main()
    engine.assert_not_called()


def test_failed_screening_never_opens_database(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "bootstrap",
            "--email",
            "admin@example.test",
            "--operator-ref",
            "CHANGE-1",
            "--waive-mailbox-verification",
            "--password-check",
            "hibp",
            "--grant-until",
            "2099-11-30T23:59:59Z",
        ],
    )
    terminal = MagicMock()
    terminal.isatty.return_value = True
    monkeypatch.setattr("sys.stdin", terminal)
    monkeypatch.setattr(bootstrap.getpass, "getpass", lambda _: "synthetic password")
    monkeypatch.setattr(
        bootstrap, "get_settings", lambda: SimpleNamespace(bootstrap_database_url=object())
    )
    monkeypatch.setattr(
        bootstrap,
        "require_hibp_acceptable",
        MagicMock(side_effect=CorpusUnavailable("Screening unavailable")),
    )
    engine = MagicMock()
    monkeypatch.setattr(bootstrap, "create_engine", engine)
    with pytest.raises(SystemExit):
        bootstrap.main()
    engine.assert_not_called()

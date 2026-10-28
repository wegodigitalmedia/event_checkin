"""One-time operator bootstrap. Never installed as an HTTP route."""

import argparse
import getpass
import sys
from datetime import UTC, datetime

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.address import single_email_address
from app.auth.corpus import CompromisedPasswordCorpus, CorpusUnavailable
from app.auth.password_screening import require_hibp_acceptable
from app.auth.security import hash_password
from app.core.config import get_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="One-time platform actor bootstrap")
    parser.add_argument("--email", required=True)
    parser.add_argument(
        "--operator-ref",
        required=True,
        help="Approved operator access record, not a password or token",
    )
    verification = parser.add_mutually_exclusive_group(required=True)
    verification.add_argument(
        "--email-verification-ref",
        help="Record showing the platform actor controls this mailbox",
    )
    verification.add_argument(
        "--waive-mailbox-verification",
        action="store_true",
        help="Record an operator-approved waiver; does not claim mailbox verification",
    )
    parser.add_argument("--password-check", choices=("offline", "hibp"), default="offline")
    parser.add_argument(
        "--grant-until",
        required=True,
        help="Reviewed UTC ISO-8601 expiry; no implicit grant duration",
    )
    args = parser.parse_args()
    if not sys.stdin.isatty():
        parser.error("An interactive terminal is required")
    verification_ref = (
        "WAIVED_BY_OPERATOR:" + args.operator_ref
        if args.waive_mailbox_verification
        else args.email_verification_ref
    )
    if not 1 <= len(args.operator_ref) <= 160 or not 1 <= len(verification_ref) <= 160:
        parser.error("Operator and email verification references are required")
    try:
        expiry = datetime.fromisoformat(args.grant_until.replace("Z", "+00:00"))
    except ValueError:
        parser.error("--grant-until must be an ISO-8601 UTC timestamp")
    if expiry.tzinfo is None or expiry.utcoffset() != datetime.now(UTC).utcoffset():
        parser.error("--grant-until must be UTC")
    instant = datetime.now(UTC)
    if expiry <= instant:
        parser.error("Grant expiry must be in the future")
    email = single_email_address(args.email)
    password = getpass.getpass("New platform password: ")
    if password != getpass.getpass("Confirm platform password: "):
        parser.error("Passwords do not match")
    settings = get_settings()
    if settings.bootstrap_database_url is None:
        parser.error("BOOTSTRAP_DATABASE_URL is required")
    try:
        if args.password_check == "hibp":
            require_hibp_acceptable(password)
        else:
            CompromisedPasswordCorpus(
                settings.compromised_password_corpus, settings.compromised_password_sha256
            ).require_acceptable(password)
    except (CorpusUnavailable, ValueError) as exc:
        parser.error(str(exc))
    hashed = hash_password(password)
    engine = create_engine(
        settings.bootstrap_database_url.get_secret_value(),
        pool_pre_ping=True,
        hide_parameters=True,
    )
    try:
        with Session(engine) as db, db.begin():
            db.execute(
                text("""SELECT consume_platform_bootstrap(
                    CAST(:email AS citext), :password_hash, :operator_ref,
                    :email_verification_ref, :grant_until)"""),
                {
                    "email": email,
                    "password_hash": hashed,
                    "operator_ref": args.operator_ref,
                    "email_verification_ref": verification_ref,
                    "grant_until": expiry,
                },
            )
    except IntegrityError:
        raise SystemExit("Bootstrap is unavailable or already consumed") from None
    finally:
        engine.dispose()
    print("Bootstrap recorded. Sign in on the platform host and enroll TOTP before provisioning.")


if __name__ == "__main__":
    main()

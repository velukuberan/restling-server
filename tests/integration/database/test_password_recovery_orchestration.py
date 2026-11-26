"""Integration tests for public password-recovery orchestration."""

import smtplib
import ssl
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from hashlib import sha256
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.users.models import (
    AuditLog,
    LoginSession,
    OneTimeToken,
    PasswordResetAttempt,
    User,
)
from restling_server.users.password_recovery import (
    PasswordRecoveryUnavailableError,
    request_password_recovery,
)
from restling_server.users.passwords import hash_password
from restling_server.users.service import (
    InvalidPasswordResetTokenError,
    issue_password_reset_token,
    login_user,
    reset_user_password,
)
from restling_server.users.tokens import generate_token, hash_token

EMAIL = "recovery@example.com"
PASSWORD = "A secure password recovery test passphrase #8472"
SOURCE_IP = "192.0.2.10"


def make_settings(**overrides: object) -> Settings:
    """Build deterministic password-recovery settings."""
    return Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": "https://restling.example.com",
            "RESTLING_SMTP_HOST": "localhost",
            "RESTLING_SMTP_PORT": 1025,
            "RESTLING_SMTP_SECURITY": "none",
            "RESTLING_SMTP_USERNAME": None,
            "RESTLING_SMTP_PASSWORD": None,
            "RESTLING_SMTP_FROM_EMAIL": "noreply@example.com",
            "RESTLING_PASSWORD_RESET_EXPIRY_MINUTES": 30,
            "RESTLING_PASSWORD_RESET_COOLDOWN_SECONDS": 60,
            "RESTLING_PASSWORD_RESET_EMAIL_HOURLY_LIMIT": 5,
            "RESTLING_PASSWORD_RESET_IP_HOURLY_LIMIT": 20,
            **overrides,
        }
    )


def create_account(
    session: Session,
    *,
    email: str = EMAIL,
    status: str = "active",
    system_role: str = "user",
    password_reset_required: bool = False,
) -> UUID:
    """Persist an account for recovery testing."""
    with session.begin():
        user = User(
            email=email,
            normalized_email=email.casefold(),
            display_name="Recovery Test User",
            status=status,
            system_role=system_role,
            password_hash=(None if status == "pending" else hash_password(PASSWORD)),
            password_reset_required=password_reset_required,
        )

        session.add(user)
        session.flush()

        user_id = user.id

    return user_id


def seed_reset_token(
    session: Session,
    *,
    user_id: UUID,
    raw_token: str,
) -> UUID:
    """Persist an existing password-reset credential."""
    now = datetime.now(UTC)

    with session.begin():
        token = OneTimeToken(
            user_id=user_id,
            purpose="password_reset",
            token_hash=hash_token(raw_token),
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        session.add(token)
        session.flush()

        token_id = token.id

    return token_id


class SMTPRecorder:
    """Record delivery attempts at the external SMTP boundary."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.messages: list[EmailMessage] = []
        self.connection_count = 0
        self.fail_delivery = False
        self.on_send: Callable[[], None] | None = None

    def connect(
        self,
        host: str,
        port: int,
        *,
        timeout: int,
        context: ssl.SSLContext | None = None,
    ) -> "SMTPRecorder":
        # SMTP must not hold an application database transaction.
        assert not self.session.in_transaction()

        self.connection_count += 1

        return self

    def __enter__(self) -> "SMTPRecorder":
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def send_message(self, message: EmailMessage) -> None:
        assert not self.session.in_transaction()

        self.messages.append(message)

        if self.on_send is not None:
            self.on_send()

        assert not self.session.in_transaction()

        if self.fail_delivery:
            raise smtplib.SMTPException("Simulated SMTP delivery failure")


@pytest.fixture
def smtp(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> SMTPRecorder:
    """Replace only the external SMTP connection."""
    recorder = SMTPRecorder(db_session)

    monkeypatch.setattr(
        smtplib,
        "SMTP",
        recorder.connect,
    )

    monkeypatch.setattr(
        smtplib,
        "SMTP_SSL",
        recorder.connect,
    )

    return recorder


def request_recovery(
    session: Session,
    *,
    settings: Settings | None = None,
    email: str = EMAIL,
    source_ip: str = SOURCE_IP,
) -> None:
    """Request recovery using the real orchestration service."""
    request_password_recovery(
        session,
        settings=settings if settings is not None else make_settings(),
        email=email,
        source_ip=source_ip,
    )


def extract_reset_token(message: EmailMessage) -> str:
    """Extract the credential from the actual delivered email."""
    content = message.get_content()

    assert isinstance(content, str)

    links = [
        line.strip() for line in content.splitlines() if line.startswith("https://")
    ]

    assert len(links) == 1

    parsed_url = urlsplit(links[0])

    assert parsed_url.scheme == "https"
    assert parsed_url.netloc == "restling.example.com"
    assert parsed_url.path == "/reset-password"

    query = parse_qs(parsed_url.query)

    assert "token" in query
    assert len(query["token"]) == 1

    token = query["token"][0]

    assert token

    return token


@pytest.mark.parametrize(
    ("status", "password_reset_required"),
    [
        ("active", False),
        ("active", True),
        ("suspended", False),
    ],
)
def test_recovery_delivers_and_persists_reset_token(
    db_session: Session,
    smtp: SMTPRecorder,
    status: str,
    password_reset_required: bool,
) -> None:
    """Eligible accounts receive a usable password-reset credential."""
    user_id = create_account(
        db_session,
        email="Recovery@Example.com",
        status=status,
        password_reset_required=password_reset_required,
    )

    request_recovery(
        db_session,
        email="RECOVERY@EXAMPLE.COM",
    )

    assert smtp.connection_count == 1
    assert len(smtp.messages) == 1

    message = smtp.messages[0]

    assert message["To"] == "Recovery@Example.com"
    assert message["Subject"] == "Reset your Restling password"

    raw_token = extract_reset_token(message)

    with db_session.begin():
        tokens = db_session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1

        token = tokens[0]

        assert token.token_hash == hash_token(raw_token)
        assert token.token_hash != raw_token
        assert token.revoked_at is None
        assert token.consumed_at is None

        assert token.expires_at == (token.created_at + timedelta(minutes=30))

        attempts = db_session.scalars(select(PasswordResetAttempt)).all()

        assert len(attempts) == 1
        assert attempts[0].email_key == sha256(EMAIL.encode()).hexdigest()
        assert attempts[0].source_ip == SOURCE_IP

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id is None


@pytest.mark.parametrize("account_exists", [False, True])
def test_recovery_ineligible_account_does_not_send_email(
    db_session: Session,
    smtp: SMTPRecorder,
    account_exists: bool,
) -> None:
    """Unknown and pending accounts still consume an attempt."""
    if account_exists:
        create_account(
            db_session,
            status="pending",
        )

    request_recovery(db_session)

    assert smtp.connection_count == 0
    assert smtp.messages == []

    with db_session.begin():
        attempts = db_session.scalars(select(PasswordResetAttempt)).all()

        assert len(attempts) == 1
        assert attempts[0].email_key == sha256(EMAIL.encode()).hexdigest()

        assert db_session.scalars(select(OneTimeToken)).all() == []

        assert (
            db_session.scalars(
                select(AuditLog).where(AuditLog.action == "user.password_reset_issued")
            ).all()
            == []
        )


def test_recovery_rate_limited_request_does_not_send_email(
    db_session: Session,
    smtp: SMTPRecorder,
) -> None:
    """Immediate recovery retries must have no delivery side effects."""
    create_account(db_session)

    request_recovery(db_session)
    request_recovery(db_session)

    assert smtp.connection_count == 1
    assert len(smtp.messages) == 1

    with db_session.begin():
        assert len(db_session.scalars(select(PasswordResetAttempt)).all()) == 1

        assert len(db_session.scalars(select(OneTimeToken)).all()) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "RESTLING_SMTP_HOST": None,
            "RESTLING_SMTP_FROM_EMAIL": None,
        },
        {
            "RESTLING_PUBLIC_URL": None,
        },
    ],
)
def test_recovery_unavailable_configuration_has_no_side_effects(
    db_session: Session,
    smtp: SMTPRecorder,
    overrides: dict[str, object],
) -> None:
    """Reject unavailable recovery before reserving an attempt."""
    create_account(db_session)

    settings = make_settings(**overrides)

    with pytest.raises(PasswordRecoveryUnavailableError):
        request_recovery(
            db_session,
            settings=settings,
        )

    assert smtp.connection_count == 0

    with db_session.begin():
        assert db_session.scalars(select(PasswordResetAttempt)).all() == []

        assert db_session.scalars(select(OneTimeToken)).all() == []


def test_recovery_delivery_failure_preserves_previous_token(
    db_session: Session,
    smtp: SMTPRecorder,
) -> None:
    """A failed email must not invalidate an existing credential."""
    user_id = create_account(db_session)

    previous_token = generate_token()

    previous_token_id = seed_reset_token(
        db_session,
        user_id=user_id,
        raw_token=previous_token,
    )

    smtp.fail_delivery = True

    request_recovery(db_session)

    assert smtp.connection_count == 1

    failed_token = extract_reset_token(smtp.messages[0])

    with db_session.begin():
        tokens = db_session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].id == previous_token_id
        assert tokens[0].token_hash == hash_token(previous_token)
        assert tokens[0].revoked_at is None

        assert len(db_session.scalars(select(PasswordResetAttempt)).all()) == 1

        assert (
            db_session.scalars(
                select(AuditLog).where(
                    AuditLog.target_user_id == user_id,
                    AuditLog.action == "user.password_reset_issued",
                )
            ).all()
            == []
        )

    with pytest.raises(InvalidPasswordResetTokenError):
        reset_user_password(
            db_session,
            token=failed_token,
            new_password="Another secure recovery passphrase #9274",
        )


def test_recovery_failed_delivery_consumes_rate_limit(
    db_session: Session,
    smtp: SMTPRecorder,
) -> None:
    """SMTP failures cannot bypass the hourly recovery quota."""
    create_account(db_session)

    smtp.fail_delivery = True

    settings = make_settings(
        RESTLING_PASSWORD_RESET_EMAIL_HOURLY_LIMIT=1,
    )

    request_recovery(
        db_session,
        settings=settings,
    )

    # Move the reservation outside the cooldown but keep it
    # within the rolling hourly window.
    with db_session.begin():
        attempt = db_session.scalar(select(PasswordResetAttempt))

        assert attempt is not None

        attempt.created_at = datetime.now(UTC) - timedelta(minutes=2)

    request_recovery(
        db_session,
        settings=settings,
    )

    assert smtp.connection_count == 1
    assert len(smtp.messages) == 1

    with db_session.begin():
        assert len(db_session.scalars(select(PasswordResetAttempt)).all()) == 1

        assert db_session.scalars(select(OneTimeToken)).all() == []


def test_recovery_rejects_token_when_email_changes_during_delivery(
    db_session: Session,
    smtp: SMTPRecorder,
) -> None:
    """An email delivered to an old address must remain unusable."""
    user_id = create_account(db_session)

    def change_account_email() -> None:
        with db_session.begin():
            user = db_session.get(User, user_id)

            assert user is not None

            user.email = "changed@example.com"
            user.normalized_email = "changed@example.com"

    smtp.on_send = change_account_email

    request_recovery(db_session)

    assert len(smtp.messages) == 1
    assert smtp.messages[0]["To"] == EMAIL

    delivered_token = extract_reset_token(smtp.messages[0])

    with db_session.begin():
        assert (
            db_session.scalars(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                )
            ).all()
            == []
        )

        assert (
            db_session.scalars(
                select(AuditLog).where(
                    AuditLog.target_user_id == user_id,
                    AuditLog.action == "user.password_reset_issued",
                )
            ).all()
            == []
        )

    with pytest.raises(InvalidPasswordResetTokenError):
        reset_user_password(
            db_session,
            token=delivered_token,
            new_password="Another secure recovery passphrase #9274",
        )


def test_recovery_preserves_administrator_token_issued_during_delivery(
    db_session: Session,
    smtp: SMTPRecorder,
) -> None:
    """Delayed public recovery cannot replace a newer admin token."""
    administrator_id = create_account(
        db_session,
        email="administrator@example.com",
        system_role="administrator",
    )

    user_id = create_account(db_session)

    administrator_tokens: list[str] = []

    def issue_administrator_token() -> None:
        raw_token, _ = issue_password_reset_token(
            db_session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

        administrator_tokens.append(raw_token)

    smtp.on_send = issue_administrator_token

    request_recovery(db_session)

    assert len(smtp.messages) == 1
    assert len(administrator_tokens) == 1

    delivered_token = extract_reset_token(smtp.messages[0])

    with db_session.begin():
        tokens = db_session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].token_hash == hash_token(administrator_tokens[0])
        assert tokens[0].revoked_at is None

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == administrator_id

    with pytest.raises(InvalidPasswordResetTokenError):
        reset_user_password(
            db_session,
            token=delivered_token,
            new_password="Another secure recovery passphrase #9274",
        )


def test_recovery_does_not_persist_token_before_smtp_delivery(
    db_session: Session,
    smtp: SMTPRecorder,
) -> None:
    """SMTP must complete before the reset credential is persisted."""
    user_id = create_account(db_session)

    def inspect_database_during_delivery() -> None:
        with db_session.begin():
            assert (
                db_session.scalars(
                    select(OneTimeToken).where(
                        OneTimeToken.user_id == user_id,
                    )
                ).all()
                == []
            )

            # Rate-limit reservation must already exist.
            assert len(db_session.scalars(select(PasswordResetAttempt)).all()) == 1

    smtp.on_send = inspect_database_during_delivery

    request_recovery(db_session)

    assert len(smtp.messages) == 1

    with db_session.begin():
        assert (
            len(
                db_session.scalars(
                    select(OneTimeToken).where(
                        OneTimeToken.user_id == user_id,
                    )
                ).all()
            )
            == 1
        )


def test_recovery_preserves_sessions_until_password_reset(
    db_session: Session,
    smtp: SMTPRecorder,
) -> None:
    """Issuance preserves sessions; successful reset revokes them."""
    create_account(db_session)

    login = login_user(
        db_session,
        email=EMAIL,
        password=PASSWORD,
        access_token_expiry_minutes=15,
        refresh_session_expiry_days=7,
        max_active_sessions=2,
    )

    request_recovery(db_session)

    raw_token = extract_reset_token(smtp.messages[0])

    with db_session.begin():
        login_session = db_session.get(
            LoginSession,
            login.session_id,
        )

        assert login_session is not None
        assert login_session.revoked_at is None
        assert login_session.refresh_token_hash is not None

    reset_user_password(
        db_session,
        token=raw_token,
        new_password="Another secure recovery passphrase #9274",
    )

    with db_session.begin():
        login_session = db_session.get(
            LoginSession,
            login.session_id,
        )

        assert login_session is not None
        assert login_session.revoked_at is not None
        assert login_session.refresh_token_hash is None
        assert login_session.revocation_reason == "password_reset"


def test_recovery_delivery_failure_logs_no_sensitive_information(
    db_session: Session,
    smtp: SMTPRecorder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Operational logs must not contain recovery credentials."""
    create_account(db_session)

    smtp.fail_delivery = True

    with caplog.at_level("WARNING"):
        request_recovery(db_session)

    raw_token = extract_reset_token(smtp.messages[0])

    assert "Password-recovery email delivery failed." in caplog.text
    assert raw_token not in caplog.text
    assert EMAIL not in caplog.text
    assert "https://restling.example.com" not in caplog.text
    assert "Simulated SMTP delivery failure" not in caplog.text


def test_recovery_stale_delivery_logs_no_sensitive_information(
    db_session: Session,
    smtp: SMTPRecorder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Discarded credentials must not be exposed through logging."""
    user_id = create_account(db_session)

    def change_account_state() -> None:
        with db_session.begin():
            user = db_session.get(User, user_id)

            assert user is not None

            user.password_reset_required = True

    smtp.on_send = change_account_state

    with caplog.at_level("INFO"):
        request_recovery(db_session)

    raw_token = extract_reset_token(smtp.messages[0])

    assert "Delivered password-reset credential discarded" in caplog.text
    assert raw_token not in caplog.text
    assert EMAIL not in caplog.text
    assert "https://restling.example.com" not in caplog.text

"""Integration tests for public password-recovery orchestration."""

import smtplib
import ssl
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from hashlib import sha256
from threading import Event
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from sqlalchemy import Engine, event, select
from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.core.database import create_session_factory
from restling_server.users.email_change import (
    confirm_email_change,
    request_email_change_verification,
)
from restling_server.users.models import (
    AuditLog,
    LoginSession,
    OneTimeToken,
    PasswordResetAttempt,
    User,
)
from restling_server.users.password_recovery import (
    PasswordRecoveryUnavailableError,
    process_password_recovery_task,
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


def test_background_recovery_uses_independent_session(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Background recovery must own an independent database session."""
    session_factory = create_session_factory(test_engine)

    delivered_messages: list[EmailMessage] = []
    task_sessions: list[Session] = []

    with session_factory() as request_session:
        user_id = create_account(request_session)

        def record_transaction(
            session: Session,
            _transaction: object,
            _connection: object,
        ) -> None:
            task_sessions.append(session)

        def record_delivery(message: EmailMessage) -> None:
            assert task_sessions

            task_session = task_sessions[-1]

            assert task_session is not request_session
            assert not task_session.in_transaction()

            delivered_messages.append(message)

        recorder = SMTPRecorder(request_session)

        monkeypatch.setattr(
            smtplib,
            "SMTP",
            recorder.connect,
        )

        monkeypatch.setattr(
            recorder,
            "send_message",
            record_delivery,
        )

        event.listen(
            session_factory,
            "after_begin",
            record_transaction,
        )

        try:
            process_password_recovery_task(
                session_factory,
                settings=make_settings(),
                email=EMAIL,
                source_ip=SOURCE_IP,
            )

        finally:
            event.remove(
                session_factory,
                "after_begin",
                record_transaction,
            )

        assert task_sessions
        assert all(session is not request_session for session in task_sessions)

        assert len({id(session) for session in task_sessions}) == 1

        assert len(delivered_messages) == 1

        raw_token = extract_reset_token(delivered_messages[0])

        # The caller's session remains independently usable.
        with request_session.begin():
            token = request_session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                    OneTimeToken.token_hash == hash_token(raw_token),
                )
            )

            assert token is not None


def test_background_recovery_releases_database_connections(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Completed background tasks must release checked-out connections."""
    session_factory = create_session_factory(test_engine)

    with session_factory() as session:
        create_account(session)

    checked_out: set[int] = set()

    def record_checkout(
        _dbapi_connection: object,
        connection_record: object,
        _connection_proxy: object,
    ) -> None:
        checked_out.add(id(connection_record))

    def record_checkin(
        _dbapi_connection: object,
        connection_record: object,
    ) -> None:
        checked_out.discard(id(connection_record))

    event.listen(
        test_engine,
        "checkout",
        record_checkout,
    )

    event.listen(
        test_engine,
        "checkin",
        record_checkin,
    )

    try:
        with session_factory() as observer_session:
            recorder = SMTPRecorder(observer_session)

            monkeypatch.setattr(
                smtplib,
                "SMTP",
                recorder.connect,
            )

            def inspect_delivery() -> None:
                # The background task must release its database
                # connection before performing SMTP communication.
                assert checked_out == set()

            recorder.on_send = inspect_delivery

            process_password_recovery_task(
                session_factory,
                settings=make_settings(),
                email=EMAIL,
                source_ip=SOURCE_IP,
            )

            assert len(recorder.messages) == 1
            assert checked_out == set()

    finally:
        event.remove(
            test_engine,
            "checkout",
            record_checkout,
        )

        event.remove(
            test_engine,
            "checkin",
            record_checkin,
        )


def test_background_recovery_rolls_back_failed_persistence(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unexpected task failure must preserve existing credentials."""
    session_factory = create_session_factory(test_engine)

    with session_factory() as session:
        user_id = create_account(session)

        previous_token = generate_token()

        previous_token_id = seed_reset_token(
            session,
            user_id=user_id,
            raw_token=previous_token,
        )

    checked_out: set[int] = set()
    delivered_tokens: list[str] = []

    def record_checkout(
        _dbapi_connection: object,
        connection_record: object,
        _connection_proxy: object,
    ) -> None:
        checked_out.add(id(connection_record))

    def record_checkin(
        _dbapi_connection: object,
        connection_record: object,
    ) -> None:
        checked_out.discard(id(connection_record))

    def fail_persistence(
        _session: Session,
        _flush_context: object,
    ) -> None:
        if delivered_tokens:
            raise RuntimeError(f"Simulated database failure: {delivered_tokens[0]}")

    event.listen(
        test_engine,
        "checkout",
        record_checkout,
    )

    event.listen(
        test_engine,
        "checkin",
        record_checkin,
    )

    event.listen(
        session_factory,
        "after_flush_postexec",
        fail_persistence,
    )

    try:
        with session_factory() as observer_session:
            recorder = SMTPRecorder(observer_session)

            monkeypatch.setattr(
                smtplib,
                "SMTP",
                recorder.connect,
            )

            def capture_delivered_token() -> None:
                delivered_tokens.append(extract_reset_token(recorder.messages[0]))

            recorder.on_send = capture_delivered_token

            with caplog.at_level(
                "ERROR",
                logger="restling_server.users.password_recovery",
            ):
                process_password_recovery_task(
                    session_factory,
                    settings=make_settings(),
                    email=EMAIL,
                    source_ip=SOURCE_IP,
                )

            assert len(recorder.messages) == 1
            assert len(delivered_tokens) == 1
            assert checked_out == set()

    finally:
        event.remove(
            session_factory,
            "after_flush_postexec",
            fail_persistence,
        )

        event.remove(
            test_engine,
            "checkout",
            record_checkout,
        )

        event.remove(
            test_engine,
            "checkin",
            record_checkin,
        )

    with session_factory.begin() as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].id == previous_token_id
        assert tokens[0].token_hash == hash_token(previous_token)
        assert tokens[0].revoked_at is None
        assert tokens[0].consumed_at is None

        # Earlier committed rate-limit reservation survives.
        assert len(session.scalars(select(PasswordResetAttempt)).all()) == 1

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert audit_events == []

    assert "Background password-recovery processing failed." in caplog.text

    assert delivered_tokens[0] not in caplog.text
    assert previous_token not in caplog.text
    assert EMAIL not in caplog.text
    assert "Simulated database failure" not in caplog.text

    assert all(
        record.exc_info is None
        for record in caplog.records
        if record.name == ("restling_server.users.password_recovery")
    )


def test_concurrent_recovery_preserves_administrator_reset_token(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent public recovery cannot replace a newer admin token."""
    session_factory = create_session_factory(test_engine)

    with session_factory() as session:
        administrator_id = create_account(
            session,
            email="administrator@example.com",
            system_role="administrator",
        )

        user_id = create_account(session)

    delivery_started = Event()
    allow_delivery_to_finish = Event()

    delivered_tokens: list[str] = []

    def execute_public_recovery() -> None:
        with session_factory() as session:
            recorder = SMTPRecorder(session)

            def pause_delivery() -> None:
                delivered_tokens.append(extract_reset_token(recorder.messages[0]))

                delivery_started.set()

                assert allow_delivery_to_finish.wait(timeout=10), (
                    "Timed out waiting for administrator issuance."
                )

            recorder.on_send = pause_delivery

            monkeypatch.setattr(
                smtplib,
                "SMTP",
                recorder.connect,
            )

            request_recovery(session)

            assert recorder.connection_count == 1
            assert len(recorder.messages) == 1

    with ThreadPoolExecutor(max_workers=1) as executor:
        recovery_future = executor.submit(execute_public_recovery)

        try:
            assert delivery_started.wait(timeout=10), (
                "Public recovery did not reach SMTP delivery."
            )

            assert len(delivered_tokens) == 1

            with session_factory() as administrator_session:
                administrator_token, _ = issue_password_reset_token(
                    administrator_session,
                    actor_id=administrator_id,
                    user_id=user_id,
                    expiry_minutes=30,
                )

                assert not administrator_session.in_transaction()

            # Confirm administrator issuance was committed while
            # public recovery was still waiting for SMTP delivery.
            with session_factory.begin() as session:
                tokens = session.scalars(
                    select(OneTimeToken).where(
                        OneTimeToken.user_id == user_id,
                        OneTimeToken.purpose == "password_reset",
                    )
                ).all()

                assert len(tokens) == 1

                assert tokens[0].token_hash == hash_token(administrator_token)

                assert tokens[0].revoked_at is None
                assert tokens[0].consumed_at is None

        finally:
            allow_delivery_to_finish.set()

        recovery_future.result(timeout=10)

    delivered_token = delivered_tokens[0]

    assert delivered_token != administrator_token

    with session_factory.begin() as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1

        token = tokens[0]

        assert token.token_hash == hash_token(administrator_token)
        assert token.revoked_at is None
        assert token.consumed_at is None

        attempts = session.scalars(select(PasswordResetAttempt)).all()

        assert len(attempts) == 1

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == administrator_id

    # The credential delivered by public recovery must be unusable.
    with session_factory() as session:
        with pytest.raises(InvalidPasswordResetTokenError):
            reset_user_password(
                session,
                token=delivered_token,
                new_password="Another secure recovery passphrase #9274",
            )

    # The administrator-issued credential must remain usable.
    with session_factory() as session:
        reset_user_password(
            session,
            token=administrator_token,
            new_password="Another secure recovery passphrase #9274",
        )

    with session_factory.begin() as session:
        token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(administrator_token)
            )
        )

        assert token is not None
        assert token.consumed_at is not None


def test_concurrent_recovery_requests_enforce_cooldown(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent recovery requests must respect the email cooldown."""
    session_factory = create_session_factory(test_engine)

    with session_factory() as session:
        user_id = create_account(session)

    delivery_started = Event()
    allow_delivery_to_finish = Event()

    recorders: list[SMTPRecorder] = []

    def execute_first_recovery() -> None:
        with session_factory() as session:
            recorder = SMTPRecorder(session)
            recorders.append(recorder)

            def pause_delivery() -> None:
                delivery_started.set()

                assert allow_delivery_to_finish.wait(timeout=10), (
                    "Timed out waiting for concurrent recovery."
                )

            recorder.on_send = pause_delivery

            monkeypatch.setattr(
                smtplib,
                "SMTP",
                recorder.connect,
            )

            request_recovery(session)

    with ThreadPoolExecutor(max_workers=1) as executor:
        recovery_future = executor.submit(execute_first_recovery)

        try:
            assert delivery_started.wait(timeout=10), (
                "First recovery did not reach SMTP delivery."
            )

            # Use an independent session and source IP.
            # The email cooldown must still apply.
            with session_factory() as session:
                second_recorder = SMTPRecorder(session)

                with monkeypatch.context() as patch:
                    patch.setattr(
                        smtplib,
                        "SMTP",
                        second_recorder.connect,
                    )

                    request_recovery(
                        session,
                        source_ip="192.0.2.20",
                    )

                assert second_recorder.connection_count == 0
                assert second_recorder.messages == []

            with session_factory.begin() as session:
                attempts = session.scalars(select(PasswordResetAttempt)).all()

                assert len(attempts) == 1
                assert attempts[0].source_ip == SOURCE_IP

                # First delivery is still incomplete.
                assert (
                    session.scalars(
                        select(OneTimeToken).where(
                            OneTimeToken.user_id == user_id,
                            OneTimeToken.purpose == "password_reset",
                        )
                    ).all()
                    == []
                )

        finally:
            allow_delivery_to_finish.set()

        recovery_future.result(timeout=10)

    assert len(recorders) == 1

    recorder = recorders[0]

    assert recorder.connection_count == 1
    assert len(recorder.messages) == 1

    delivered_token = extract_reset_token(recorder.messages[0])

    with session_factory.begin() as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].token_hash == hash_token(delivered_token)
        assert tokens[0].revoked_at is None
        assert tokens[0].consumed_at is None

        assert len(session.scalars(select(PasswordResetAttempt)).all()) == 1

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id is None


def test_concurrent_admitted_recoveries_persist_only_one_token(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Overlapping admitted recoveries must not replace newer credentials."""
    session_factory = create_session_factory(test_engine)

    with session_factory() as session:
        user_id = create_account(session)

    delivery_started = Event()
    allow_delivery_to_finish = Event()

    first_delivered_tokens: list[str] = []

    def execute_first_recovery() -> None:
        with session_factory() as session:
            recorder = SMTPRecorder(session)

            def pause_delivery() -> None:
                first_delivered_tokens.append(extract_reset_token(recorder.messages[0]))

                delivery_started.set()

                assert allow_delivery_to_finish.wait(timeout=10), (
                    "Timed out waiting for second recovery."
                )

            recorder.on_send = pause_delivery

            monkeypatch.setattr(
                smtplib,
                "SMTP",
                recorder.connect,
            )

            request_recovery(session)

            assert recorder.connection_count == 1
            assert len(recorder.messages) == 1

    with ThreadPoolExecutor(max_workers=1) as executor:
        recovery_future = executor.submit(execute_first_recovery)

        try:
            assert delivery_started.wait(timeout=10), (
                "First recovery did not reach SMTP delivery."
            )

            # Simulate expiration of the email cooldown while
            # retaining the attempt inside the hourly window.
            with session_factory.begin() as session:
                attempt = session.scalar(select(PasswordResetAttempt))

                assert attempt is not None

                attempt.created_at = datetime.now(UTC) - timedelta(minutes=2)

                assert session.scalars(select(OneTimeToken)).all() == []

            with session_factory() as session:
                second_recorder = SMTPRecorder(session)

                with monkeypatch.context() as patch:
                    patch.setattr(
                        smtplib,
                        "SMTP",
                        second_recorder.connect,
                    )

                    request_recovery(
                        session,
                        source_ip="192.0.2.20",
                    )

                assert second_recorder.connection_count == 1
                assert len(second_recorder.messages) == 1

                second_token = extract_reset_token(second_recorder.messages[0])

            # Confirm that the second recovery has committed
            # before releasing the first SMTP operation.
            with session_factory.begin() as session:
                tokens = session.scalars(
                    select(OneTimeToken).where(
                        OneTimeToken.user_id == user_id,
                        OneTimeToken.purpose == "password_reset",
                    )
                ).all()

                assert len(tokens) == 1
                assert tokens[0].token_hash == hash_token(second_token)
                assert tokens[0].revoked_at is None
                assert tokens[0].consumed_at is None

        finally:
            allow_delivery_to_finish.set()

        recovery_future.result(timeout=10)

    assert len(first_delivered_tokens) == 1

    first_token = first_delivered_tokens[0]

    assert first_token != second_token

    with session_factory.begin() as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1

        assert tokens[0].token_hash == hash_token(second_token)
        assert tokens[0].revoked_at is None
        assert tokens[0].consumed_at is None

        attempts = session.scalars(select(PasswordResetAttempt)).all()

        assert len(attempts) == 2

        assert {attempt.source_ip for attempt in attempts} == {
            SOURCE_IP,
            "192.0.2.20",
        }

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id is None

    # The first delivered credential must remain unusable.
    with session_factory() as session:
        with pytest.raises(InvalidPasswordResetTokenError):
            reset_user_password(
                session,
                token=first_token,
                new_password="Another secure recovery passphrase #9274",
            )

    # The successfully persisted credential must remain usable.
    with session_factory() as session:
        reset_user_password(
            session,
            token=second_token,
            new_password="Another secure recovery passphrase #9274",
        )


def test_concurrent_recovery_rejects_token_after_verified_email_change(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recovery credentials delivered to a previous email must be unusable."""
    session_factory = create_session_factory(test_engine)
    settings = make_settings()
    new_email = "changed@example.com"

    # Prepare a genuine email-change verification request.
    with session_factory() as session:
        user_id = create_account(session)

        login = login_user(
            session,
            email=EMAIL,
            password=PASSWORD,
            access_token_expiry_minutes=15,
            refresh_session_expiry_days=7,
            max_active_sessions=2,
        )

        verification_recorder = SMTPRecorder(session)

        with monkeypatch.context() as patch:
            patch.setattr(
                smtplib,
                "SMTP",
                verification_recorder.connect,
            )

            assert request_email_change_verification(
                session,
                settings=settings,
                access_token=login.access_token,
                current_password=PASSWORD,
                email=new_email,
            )

        assert verification_recorder.connection_count == 1
        assert len(verification_recorder.messages) == 1

        verification_message = verification_recorder.messages[0]

        assert verification_message["To"] == new_email

        content = verification_message.get_content()

        assert isinstance(content, str)

        links = [
            line.strip() for line in content.splitlines() if line.startswith("https://")
        ]

        assert len(links) == 1

        parsed_url = urlsplit(links[0])

        assert parsed_url.scheme == "https"
        assert parsed_url.netloc == "restling.example.com"
        assert parsed_url.path == "/verify-email-change"

        query = parse_qs(parsed_url.query)

        assert "token" in query
        assert len(query["token"]) == 1

        verification_token = query["token"][0]

    delivery_started = Event()
    allow_delivery_to_finish = Event()

    delivered_tokens: list[str] = []

    def execute_public_recovery() -> None:
        with session_factory() as session:
            recorder = SMTPRecorder(session)

            def pause_delivery() -> None:
                message = recorder.messages[0]

                assert message["To"] == EMAIL

                delivered_tokens.append(extract_reset_token(message))

                delivery_started.set()

                assert allow_delivery_to_finish.wait(timeout=10), (
                    "Timed out waiting for email-change verification."
                )

            recorder.on_send = pause_delivery

            monkeypatch.setattr(
                smtplib,
                "SMTP",
                recorder.connect,
            )

            request_recovery(
                session,
                settings=settings,
                email=EMAIL,
            )

            assert recorder.connection_count == 1
            assert len(recorder.messages) == 1

    with ThreadPoolExecutor(max_workers=1) as executor:
        recovery_future = executor.submit(execute_public_recovery)

        try:
            assert delivery_started.wait(timeout=10), (
                "Public recovery did not reach SMTP delivery."
            )

            # Complete the actual email-change workflow through
            # an independently owned database session.
            with session_factory() as session:
                notification_recorder = SMTPRecorder(session)

                with monkeypatch.context() as patch:
                    patch.setattr(
                        smtplib,
                        "SMTP",
                        notification_recorder.connect,
                    )

                    confirm_email_change(
                        session,
                        settings=settings,
                        token=verification_token,
                    )

                assert notification_recorder.connection_count == 1
                assert len(notification_recorder.messages) == 1

                notification = notification_recorder.messages[0]

                assert notification["To"] == EMAIL
                assert notification["Subject"] == (
                    "Your Restling account email was changed"
                )

                assert not session.in_transaction()

            # Confirm that the email change has committed
            # before allowing recovery delivery to complete.
            with session_factory.begin() as session:
                user = session.get(User, user_id)

                assert user is not None
                assert user.email == new_email
                assert user.normalized_email == new_email

                reset_tokens = session.scalars(
                    select(OneTimeToken).where(
                        OneTimeToken.user_id == user_id,
                        OneTimeToken.purpose == "password_reset",
                    )
                ).all()

                assert reset_tokens == []

        finally:
            allow_delivery_to_finish.set()

        recovery_future.result(timeout=10)

    assert len(delivered_tokens) == 1

    delivered_token = delivered_tokens[0]

    with session_factory.begin() as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == new_email
        assert user.normalized_email == new_email

        reset_tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert reset_tokens == []

        stored_verification_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(verification_token),
                OneTimeToken.purpose == "email_change",
            )
        )

        assert stored_verification_token is not None
        assert stored_verification_token.consumed_at is not None

        login_session = session.get(
            LoginSession,
            login.session_id,
        )

        assert login_session is not None
        assert login_session.revoked_at is not None
        assert login_session.refresh_token_hash is None
        assert login_session.revocation_reason == "email_change"

        attempts = session.scalars(select(PasswordResetAttempt)).all()

        assert len(attempts) == 1

        reset_audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert reset_audit_events == []

        email_change_audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.email_change.verified",
            )
        ).all()

        assert len(email_change_audit_events) == 1

    # The credential delivered to the previous email address
    # must never become usable.
    with session_factory() as session:
        with pytest.raises(InvalidPasswordResetTokenError):
            reset_user_password(
                session,
                token=delivered_token,
                new_password="Another secure recovery passphrase #9274",
            )


def test_concurrent_recovery_rejects_token_after_completed_password_reset(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An intervening password reset must invalidate in-flight recovery."""
    session_factory = create_session_factory(test_engine)

    new_password = "Another secure recovery passphrase #9274"

    with session_factory() as session:
        user_id = create_account(session)

        previous_token = generate_token()

        previous_token_id = seed_reset_token(
            session,
            user_id=user_id,
            raw_token=previous_token,
        )

        login = login_user(
            session,
            email=EMAIL,
            password=PASSWORD,
            access_token_expiry_minutes=15,
            refresh_session_expiry_days=7,
            max_active_sessions=2,
        )

    delivery_started = Event()
    allow_delivery_to_finish = Event()

    delivered_tokens: list[str] = []

    def execute_public_recovery() -> None:
        with session_factory() as session:
            recorder = SMTPRecorder(session)

            def pause_delivery() -> None:
                delivered_tokens.append(extract_reset_token(recorder.messages[0]))

                delivery_started.set()

                assert allow_delivery_to_finish.wait(timeout=10), (
                    "Timed out waiting for password-reset completion."
                )

            recorder.on_send = pause_delivery

            monkeypatch.setattr(
                smtplib,
                "SMTP",
                recorder.connect,
            )

            request_recovery(session)

            assert recorder.connection_count == 1
            assert len(recorder.messages) == 1

    with ThreadPoolExecutor(max_workers=1) as executor:
        recovery_future = executor.submit(execute_public_recovery)

        try:
            assert delivery_started.wait(timeout=10), (
                "Public recovery did not reach SMTP delivery."
            )

            # Complete the previous password reset while
            # the new recovery operation remains in flight.
            with session_factory() as session:
                reset_user_password(
                    session,
                    token=previous_token,
                    new_password=new_password,
                )

                assert not session.in_transaction()

            # Confirm the reset committed before SMTP resumes.
            with session_factory.begin() as session:
                token = session.get(
                    OneTimeToken,
                    previous_token_id,
                )

                assert token is not None
                assert token.consumed_at is not None

                login_session = session.get(
                    LoginSession,
                    login.session_id,
                )

                assert login_session is not None
                assert login_session.revoked_at is not None
                assert login_session.refresh_token_hash is None
                assert login_session.revocation_reason == "password_reset"

        finally:
            allow_delivery_to_finish.set()

        recovery_future.result(timeout=10)

    assert len(delivered_tokens) == 1

    delivered_token = delivered_tokens[0]

    assert delivered_token != previous_token

    with session_factory.begin() as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1

        assert tokens[0].id == previous_token_id
        assert tokens[0].token_hash == hash_token(previous_token)
        assert tokens[0].consumed_at is not None

        attempts = session.scalars(select(PasswordResetAttempt)).all()

        assert len(attempts) == 1

        issuance_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert issuance_events == []

        completion_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_completed",
            )
        ).all()

        assert len(completion_events) == 1

    # The newly delivered credential must remain unusable.
    with session_factory() as session:
        with pytest.raises(InvalidPasswordResetTokenError):
            reset_user_password(
                session,
                token=delivered_token,
                new_password="A different secure passphrase #6382",
            )

    # Confirm that the password established by the completed
    # reset remains valid.
    with session_factory() as session:
        login_user(
            session,
            email=EMAIL,
            password=new_password,
            access_token_expiry_minutes=15,
            refresh_session_expiry_days=7,
            max_active_sessions=2,
        )

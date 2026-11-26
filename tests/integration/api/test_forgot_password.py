"""HTTP integration tests for public password recovery."""

import asyncio
import json
import smtplib
import ssl
from collections.abc import Iterator
from datetime import timedelta
from email.message import EmailMessage
from hashlib import sha256
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, event, select
from starlette.types import Message, Scope

from restling_server.core.config import Settings
from restling_server.core.database import create_session_factory
from restling_server.main import app
from restling_server.users.models import (
    AuditLog,
    OneTimeToken,
    PasswordResetAttempt,
    User,
)
from restling_server.users.passwords import hash_password
from restling_server.users.tokens import hash_token

ENDPOINT = "/api/v1/auth/forgot-password"

EMAIL = "recovery@example.com"
PASSWORD = "A secure password recovery test passphrase #8472"
SOURCE_IP = "192.0.2.10"

ACCEPTED_RESPONSE = {
    "message": (
        "If the account is eligible, password reset instructions will be sent."
    ),
}

UNAVAILABLE_RESPONSE = {
    "error": {
        "code": "PASSWORD_RECOVERY_UNAVAILABLE",
        "message": (
            "Email-based password recovery is unavailable. Contact your administrator."
        ),
    },
}


def make_settings(**overrides: object) -> Settings:
    """Create deterministic password-recovery settings."""
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
    engine: Engine,
    *,
    email: str = EMAIL,
    status: str = "active",
    password_reset_required: bool = False,
) -> UUID:
    """Persist a recovery account in the isolated test database."""
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        user = User(
            email=email,
            normalized_email=email.casefold(),
            display_name="Password Recovery Test User",
            status=status,
            system_role="user",
            password_hash=(None if status == "pending" else hash_password(PASSWORD)),
            password_reset_required=password_reset_required,
        )

        session.add(user)
        session.flush()

        user_id = user.id

    return user_id


class SMTPRecorder:
    """Capture messages at the external SMTP boundary."""

    def __init__(self) -> None:
        self.messages: list[EmailMessage] = []
        self.connection_count = 0
        self.fail_delivery = False

    def connect(
        self,
        host: str,
        port: int,
        *,
        timeout: int,
        context: ssl.SSLContext | None = None,
    ) -> "SMTPRecorder":
        self.connection_count += 1

        return self

    def __enter__(self) -> "SMTPRecorder":
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def send_message(self, message: EmailMessage) -> None:
        self.messages.append(message)

        if self.fail_delivery:
            raise smtplib.SMTPException("Simulated SMTP delivery failure")


@pytest.fixture
def smtp(
    monkeypatch: pytest.MonkeyPatch,
) -> SMTPRecorder:
    """Replace only the external SMTP connection."""
    recorder = SMTPRecorder()

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


@pytest.fixture
def recovery_client(
    test_engine: Engine,
    smtp: SMTPRecorder,
) -> Iterator[TestClient]:
    """Connect background recovery to the isolated test database."""
    session_factory = create_session_factory(test_engine)

    with TestClient(
        app,
        client=(SOURCE_IP, 12345),
    ) as client:
        original_session_factory = app.state.session_factory
        original_settings = app.state.settings

        app.state.session_factory = session_factory
        app.state.settings = make_settings()

        try:
            yield client
        finally:
            app.state.session_factory = original_session_factory
            app.state.settings = original_settings


def extract_reset_token(message: EmailMessage) -> str:
    """Extract the actual credential from a delivered recovery email."""
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

    raw_token = query["token"][0]

    assert raw_token

    return raw_token


@pytest.mark.parametrize(
    ("status", "password_reset_required"),
    [
        ("active", False),
        ("active", True),
        ("suspended", False),
        ("suspended", True),
    ],
)
def test_forgot_password_accepts_eligible_accounts(
    recovery_client: TestClient,
    test_engine: Engine,
    smtp: SMTPRecorder,
    status: str,
    password_reset_required: bool,
) -> None:
    """Eligible accounts receive a reset email and generic response."""
    user_id = create_account(
        test_engine,
        email="Recovery@Example.com",
        status=status,
        password_reset_required=password_reset_required,
    )

    response = recovery_client.post(
        ENDPOINT,
        json={"email": "RECOVERY@EXAMPLE.COM"},
    )

    assert response.status_code == 202
    assert response.json() == ACCEPTED_RESPONSE
    assert response.headers["cache-control"] == "no-store"

    assert smtp.connection_count == 1
    assert len(smtp.messages) == 1

    message = smtp.messages[0]

    assert message["To"] == "Recovery@Example.com"

    raw_token = extract_reset_token(message)

    assert raw_token not in response.text
    assert EMAIL not in response.text

    session_factory = create_session_factory(test_engine)

    with session_factory.begin() as session:
        tokens = session.scalars(
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

        attempts = session.scalars(select(PasswordResetAttempt)).all()

        assert len(attempts) == 1
        assert attempts[0].source_ip == SOURCE_IP
        assert attempts[0].email_key == sha256(EMAIL.encode()).hexdigest()

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id is None


@pytest.mark.parametrize("account_exists", [False, True])
def test_forgot_password_accepts_ineligible_accounts_generically(
    recovery_client: TestClient,
    test_engine: Engine,
    smtp: SMTPRecorder,
    account_exists: bool,
) -> None:
    """Unknown and pending accounts receive the same HTTP response."""
    if account_exists:
        create_account(
            test_engine,
            status="pending",
        )

    response = recovery_client.post(
        ENDPOINT,
        json={"email": EMAIL},
    )

    assert response.status_code == 202
    assert response.json() == ACCEPTED_RESPONSE
    assert response.headers["cache-control"] == "no-store"

    assert smtp.connection_count == 0

    session_factory = create_session_factory(test_engine)

    with session_factory.begin() as session:
        attempts = session.scalars(select(PasswordResetAttempt)).all()

        assert len(attempts) == 1

        assert session.scalars(select(OneTimeToken)).all() == []


def test_forgot_password_rate_limiting_preserves_generic_response(
    recovery_client: TestClient,
    test_engine: Engine,
    smtp: SMTPRecorder,
) -> None:
    """Rate-limited requests must not disclose their rejection."""
    create_account(test_engine)

    first = recovery_client.post(
        ENDPOINT,
        json={"email": EMAIL},
    )

    second = recovery_client.post(
        ENDPOINT,
        json={"email": EMAIL},
    )

    assert first.status_code == 202
    assert second.status_code == 202

    assert first.json() == ACCEPTED_RESPONSE
    assert second.json() == ACCEPTED_RESPONSE

    assert first.headers["cache-control"] == "no-store"
    assert second.headers["cache-control"] == "no-store"

    assert smtp.connection_count == 1
    assert len(smtp.messages) == 1

    session_factory = create_session_factory(test_engine)

    with session_factory.begin() as session:
        assert len(session.scalars(select(PasswordResetAttempt)).all()) == 1

        assert len(session.scalars(select(OneTimeToken)).all()) == 1


def test_forgot_password_smtp_failure_preserves_generic_response(
    recovery_client: TestClient,
    test_engine: Engine,
    smtp: SMTPRecorder,
) -> None:
    """SMTP failure must not reveal account existence."""
    create_account(test_engine)

    smtp.fail_delivery = True

    response = recovery_client.post(
        ENDPOINT,
        json={"email": EMAIL},
    )

    assert response.status_code == 202
    assert response.json() == ACCEPTED_RESPONSE
    assert response.headers["cache-control"] == "no-store"

    assert smtp.connection_count == 1

    session_factory = create_session_factory(test_engine)

    with session_factory.begin() as session:
        assert len(session.scalars(select(PasswordResetAttempt)).all()) == 1

        assert session.scalars(select(OneTimeToken)).all() == []


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
def test_forgot_password_rejects_unavailable_configuration(
    recovery_client: TestClient,
    test_engine: Engine,
    smtp: SMTPRecorder,
    overrides: dict[str, object],
) -> None:
    """Unavailable recovery must not schedule processing."""

    original_settings = app.state.settings
    app.state.settings = make_settings(**overrides)

    try:
        response = recovery_client.post(
            ENDPOINT,
            json={"email": EMAIL},
        )
    finally:
        app.state.settings = original_settings

    assert response.status_code == 503
    assert response.json() == UNAVAILABLE_RESPONSE
    assert response.headers["cache-control"] == "no-store"

    assert smtp.connection_count == 0

    session_factory = create_session_factory(test_engine)

    with session_factory.begin() as session:
        assert session.scalars(select(PasswordResetAttempt)).all() == []

        assert session.scalars(select(OneTimeToken)).all() == []


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"email": None},
        {"email": ""},
        {"email": "invalid-email"},
        {"email": "user@"},
        {"email": 123},
        {"email": ["user@example.com"]},
        {"email": EMAIL, "user_id": "unexpected"},
        {"email": EMAIL, "source_ip": "198.51.100.50"},
    ],
)
def test_forgot_password_rejects_invalid_request_body(
    recovery_client: TestClient,
    test_engine: Engine,
    smtp: SMTPRecorder,
    payload: dict[str, object],
) -> None:
    """Invalid input must be rejected before scheduling recovery."""
    response = recovery_client.post(
        ENDPOINT,
        json=payload,
    )

    assert response.status_code == 422
    assert response.headers["cache-control"] == "no-store"

    assert response.json() == {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Invalid request data.",
        }
    }

    assert smtp.connection_count == 0

    session_factory = create_session_factory(test_engine)

    with session_factory.begin() as session:
        assert session.scalars(select(PasswordResetAttempt)).all() == []


def test_forgot_password_ignores_untrusted_forwarding_headers(
    recovery_client: TestClient,
    test_engine: Engine,
) -> None:
    """Raw forwarding headers must not override the ASGI client IP."""
    response = recovery_client.post(
        ENDPOINT,
        json={"email": EMAIL},
        headers={
            "X-Forwarded-For": "198.51.100.50",
            "X-Real-IP": "198.51.100.51",
            "Forwarded": "for=198.51.100.52",
        },
    )

    assert response.status_code == 202

    session_factory = create_session_factory(test_engine)

    with session_factory.begin() as session:
        attempts = session.scalars(select(PasswordResetAttempt)).all()

        assert len(attempts) == 1
        assert attempts[0].source_ip == SOURCE_IP


def test_forgot_password_rejects_invalid_client_address(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    smtp: SMTPRecorder,
) -> None:
    """An invalid ASGI client address must not schedule recovery."""
    session_factory = create_session_factory(test_engine)

    with TestClient(
        app,
        client=("invalid-client-address", 12345),
    ) as client:
        with monkeypatch.context() as patch:
            patch.setattr(
                app.state,
                "session_factory",
                session_factory,
            )

            patch.setattr(
                app.state,
                "settings",
                make_settings(),
            )

            response = client.post(
                ENDPOINT,
                json={"email": EMAIL},
            )

    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"

    assert response.json() == {
        "error": {
            "code": "CLIENT_IP_UNAVAILABLE",
            "message": "Unable to determine client IP address.",
        }
    }

    assert smtp.connection_count == 0

    with session_factory.begin() as session:
        assert session.scalars(select(PasswordResetAttempt)).all() == []


def test_forgot_password_sends_response_before_background_processing(
    recovery_client: TestClient,
    test_engine: Engine,
    smtp: SMTPRecorder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recovery processing must begin only after the complete response."""
    create_account(test_engine)

    execution_order: list[str] = []
    response_statuses: list[int] = []
    response_chunks: list[bytes] = []
    response_completed = False
    request_received = False

    request_body = json.dumps({"email": EMAIL}).encode()

    scope: Scope = {
        "type": "http",
        "asgi": {
            "version": "3.0",
            "spec_version": "2.4",
        },
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": ENDPOINT,
        "raw_path": ENDPOINT.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"testserver"),
            (b"content-type", b"application/json"),
            (
                b"content-length",
                str(len(request_body)).encode(),
            ),
        ],
        "client": (SOURCE_IP, 12345),
        "server": ("testserver", 80),
    }

    async def receive() -> Message:
        nonlocal request_received

        if not request_received:
            request_received = True

            return {
                "type": "http.request",
                "body": request_body,
                "more_body": False,
            }

        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        nonlocal response_completed

        if message["type"] == "http.response.start":
            response_statuses.append(message["status"])
            execution_order.append("response_started")

        elif message["type"] == "http.response.body":
            response_chunks.append(message.get("body", b""))

            if not message.get("more_body", False):
                response_completed = True
                execution_order.append("response_completed")

    def record_database_checkout(
        _dbapi_connection: object,
        _connection_record: object,
        _connection_proxy: object,
    ) -> None:
        execution_order.append("database_checkout")

        assert response_completed, (
            "Database access began before the HTTP response completed."
        )

    original_connect = smtp.connect

    def record_smtp_connection(
        host: str,
        port: int,
        *,
        timeout: int,
        context: ssl.SSLContext | None = None,
    ) -> SMTPRecorder:
        execution_order.append("smtp_connection")

        assert response_completed, (
            "SMTP delivery began before the HTTP response completed."
        )

        return original_connect(
            host,
            port,
            timeout=timeout,
            context=context,
        )

    monkeypatch.setattr(
        smtplib,
        "SMTP",
        record_smtp_connection,
    )

    event.listen(
        test_engine,
        "checkout",
        record_database_checkout,
    )

    try:
        asyncio.run(app(scope, receive, send))

    finally:
        event.remove(
            test_engine,
            "checkout",
            record_database_checkout,
        )

    assert response_statuses == [202]
    assert response_completed

    assert json.loads(b"".join(response_chunks)) == ACCEPTED_RESPONSE

    assert execution_order[:2] == [
        "response_started",
        "response_completed",
    ]

    assert "database_checkout" in execution_order
    assert "smtp_connection" in execution_order

    assert execution_order.index("response_completed") < execution_order.index(
        "database_checkout"
    )

    assert execution_order.index("response_completed") < execution_order.index(
        "smtp_connection"
    )

    assert smtp.connection_count == 1
    assert len(smtp.messages) == 1

    raw_token = extract_reset_token(smtp.messages[0])

    session_factory = create_session_factory(test_engine)

    with session_factory.begin() as session:
        token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
                OneTimeToken.purpose == "password_reset",
            )
        )

        assert token is not None
        assert token.revoked_at is None
        assert token.consumed_at is None

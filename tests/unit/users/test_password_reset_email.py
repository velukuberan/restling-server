"""Unit tests for SMTP password-reset delivery."""

import smtplib
import ssl
from email.message import EmailMessage

import pytest

from restling_server.core.config import Settings
from restling_server.users.password_reset_email import (
    PasswordResetDeliveryError,
    send_password_reset_email,
)

RESET_URL = "https://restling.example.com/reset-password?token=test-reset-token"


def make_settings(**overrides: object) -> Settings:
    """Create settings independent of local SMTP configuration."""
    return Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_SMTP_HOST": None,
            "RESTLING_SMTP_PORT": 587,
            "RESTLING_SMTP_SECURITY": "starttls",
            "RESTLING_SMTP_USERNAME": None,
            "RESTLING_SMTP_PASSWORD": None,
            "RESTLING_SMTP_FROM_EMAIL": None,
            **overrides,
        }
    )


class FakeSMTP:
    """Record SMTP operations without establishing a network connection."""

    instances: list["FakeSMTP"] = []

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: int,
        context: ssl.SSLContext | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.starttls_context: ssl.SSLContext | None = None
        self.username: str | None = None
        self.password: str | None = None
        self.message: EmailMessage | None = None
        self.operations: list[str] = []

        self.instances.append(self)

    def __enter__(self) -> "FakeSMTP":
        return self

    def __exit__(self, *args: object) -> None:
        self.operations.append("close")

    def starttls(self, *, context: ssl.SSLContext) -> None:
        self.starttls_context = context
        self.operations.append("starttls")

    def login(self, user: str, password: str) -> None:
        self.username = user
        self.password = password
        self.operations.append("login")

    def send_message(self, message: EmailMessage) -> None:
        self.message = message
        self.operations.append("send_message")


@pytest.fixture(autouse=True)
def reset_fake_smtp() -> None:
    """Reset recorded SMTP interactions before every test."""
    FakeSMTP.instances.clear()


@pytest.mark.parametrize(
    ("security", "expected_starttls", "expected_ssl"),
    [
        ("starttls", True, False),
        ("ssl", False, True),
        ("none", False, False),
    ],
)
def test_password_reset_uses_configured_transport(
    monkeypatch: pytest.MonkeyPatch,
    security: str,
    expected_starttls: bool,
    expected_ssl: bool,
) -> None:
    """Use the configured transport and compose a plain-text email."""
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)

    host = "localhost" if security == "none" else "smtp.example.com"

    settings = make_settings(
        RESTLING_SMTP_HOST=host,
        RESTLING_SMTP_SECURITY=security,
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
    )

    send_password_reset_email(
        settings,
        recipient="user@example.com",
        reset_url=RESET_URL,
    )

    assert len(FakeSMTP.instances) == 1

    smtp = FakeSMTP.instances[0]

    assert smtp.host == host
    assert smtp.port == 587
    assert smtp.timeout == 10

    assert (smtp.starttls_context is not None) is expected_starttls
    assert (smtp.context is not None) is expected_ssl

    if smtp.starttls_context is not None:
        assert smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert smtp.starttls_context.check_hostname is True

    if smtp.context is not None:
        assert smtp.context.verify_mode == ssl.CERT_REQUIRED
        assert smtp.context.check_hostname is True

    assert smtp.username is None
    assert smtp.password is None
    assert "login" not in smtp.operations

    assert smtp.message is not None
    assert smtp.message["Subject"] == "Reset your Restling password"
    assert smtp.message["From"] == "noreply@example.com"
    assert smtp.message["To"] == "user@example.com"
    assert smtp.message.get_content_type() == "text/plain"

    content = smtp.message.get_content()

    assert isinstance(content, str)
    assert RESET_URL in content
    assert "This link can only be used once." in content
    assert "you can ignore this email." in content
    assert "Your current password will remain unchanged." in content

    assert smtp.operations[-1] == "close"


def test_password_reset_authenticates_after_starttls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Establish TLS before sending SMTP authentication credentials."""
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    settings = make_settings(
        RESTLING_SMTP_HOST="smtp.example.com",
        RESTLING_SMTP_SECURITY="starttls",
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
        RESTLING_SMTP_USERNAME="restling",
        RESTLING_SMTP_PASSWORD="test-password",
    )

    send_password_reset_email(
        settings,
        recipient="user@example.com",
        reset_url=RESET_URL,
    )

    smtp = FakeSMTP.instances[0]

    assert smtp.starttls_context is not None
    assert smtp.username == "restling"
    assert smtp.password == "test-password"

    assert smtp.operations == [
        "starttls",
        "login",
        "send_message",
        "close",
    ]


def test_password_reset_authenticates_using_ssl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authenticate over an encrypted SMTP connection."""
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)

    settings = make_settings(
        RESTLING_SMTP_HOST="smtp.example.com",
        RESTLING_SMTP_PORT=465,
        RESTLING_SMTP_SECURITY="ssl",
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
        RESTLING_SMTP_USERNAME="restling",
        RESTLING_SMTP_PASSWORD="test-password",
    )

    send_password_reset_email(
        settings,
        recipient="user@example.com",
        reset_url=RESET_URL,
    )

    smtp = FakeSMTP.instances[0]

    assert smtp.port == 465
    assert smtp.context is not None
    assert smtp.starttls_context is None
    assert smtp.username == "restling"
    assert smtp.password == "test-password"

    assert smtp.operations == [
        "login",
        "send_message",
        "close",
    ]


def test_password_reset_requires_smtp_configuration() -> None:
    """Reject delivery when SMTP is disabled."""
    settings = make_settings()

    with pytest.raises(
        PasswordResetDeliveryError,
        match="SMTP delivery is not configured",
    ):
        send_password_reset_email(
            settings,
            recipient="user@example.com",
            reset_url=RESET_URL,
        )

    assert FakeSMTP.instances == []


@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("Connection timed out: test-reset-token"),
        smtplib.SMTPException("Transport failed: test-reset-token"),
        ssl.SSLError("Certificate verification failed"),
    ],
)
def test_password_reset_translates_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    """Transport errors must not expose reset credentials."""

    def failing_smtp(
        *args: object,
        **kwargs: object,
    ) -> FakeSMTP:
        raise failure

    monkeypatch.setattr(smtplib, "SMTP", failing_smtp)

    settings = make_settings(
        RESTLING_SMTP_HOST="smtp.example.com",
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
    )

    with pytest.raises(PasswordResetDeliveryError) as exc_info:
        send_password_reset_email(
            settings,
            recipient="user@example.com",
            reset_url=RESET_URL,
        )

    assert str(exc_info.value) == ("Unable to deliver password-reset email.")
    assert "test-reset-token" not in str(exc_info.value)
    assert exc_info.value.__suppress_context__ is True


@pytest.mark.parametrize(
    ("failed_operation", "expected_operations"),
    [
        ("starttls", ["close"]),
        ("login", ["starttls", "close"]),
        ("send_message", ["starttls", "login", "close"]),
    ],
)
def test_password_reset_handles_smtp_operation_failures(
    monkeypatch: pytest.MonkeyPatch,
    failed_operation: str,
    expected_operations: list[str],
) -> None:
    """Stop delivery safely when an SMTP operation fails."""

    def fail_operation(
        *args: object,
        **kwargs: object,
    ) -> None:
        raise smtplib.SMTPException("SMTP operation failed: test-reset-token")

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(
        FakeSMTP,
        failed_operation,
        fail_operation,
    )

    settings = make_settings(
        RESTLING_SMTP_HOST="smtp.example.com",
        RESTLING_SMTP_SECURITY="starttls",
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
        RESTLING_SMTP_USERNAME="restling",
        RESTLING_SMTP_PASSWORD="test-password",
    )

    with pytest.raises(PasswordResetDeliveryError) as exc_info:
        send_password_reset_email(
            settings,
            recipient="user@example.com",
            reset_url=RESET_URL,
        )

    assert str(exc_info.value) == ("Unable to deliver password-reset email.")

    smtp = FakeSMTP.instances[0]

    assert smtp.operations == expected_operations
    assert smtp.message is None

"""Unit tests for SMTP invitation delivery."""

import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import pytest

from restling_server.core.config import Settings
from restling_server.users.invitation_email import (
    InvitationDeliveryError,
    send_invitation_email,
)


def make_settings(**overrides: object) -> Settings:
    """Create SMTP settings independent of local SMTP configuration."""
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
    """Record SMTP interactions without a network connection."""

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

        self.instances.append(self)

    def __enter__(self) -> "FakeSMTP":
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def starttls(self, *, context: ssl.SSLContext) -> None:
        self.starttls_context = context

    def login(self, user: str, password: str) -> None:
        self.username = user
        self.password = password

    def send_message(self, message: EmailMessage) -> None:
        self.message = message


@pytest.fixture(autouse=True)
def reset_fake_smtp() -> None:
    """Reset SMTP test state before each test."""
    FakeSMTP.instances.clear()


@pytest.mark.parametrize(
    ("security", "expected_starttls", "expected_ssl"),
    [
        ("starttls", True, False),
        ("ssl", False, True),
        ("none", False, False),
    ],
)
def test_invitation_uses_configured_transport(
    monkeypatch: pytest.MonkeyPatch,
    security: str,
    expected_starttls: bool,
    expected_ssl: bool,
) -> None:
    """Select the configured transport and verify message content."""
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)

    host = "localhost" if security == "none" else "smtp.example.com"

    settings = make_settings(
        RESTLING_SMTP_HOST=host,
        RESTLING_SMTP_SECURITY=security,
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
    )

    send_invitation_email(
        settings,
        recipient="user@example.com",
        activation_url="https://restling.example.com/activate?token=test-token",
    )

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

    assert smtp.message is not None
    assert smtp.message["Subject"] == "Activate your Restling account"
    assert smtp.message["From"] == "noreply@example.com"
    assert smtp.message["To"] == "user@example.com"
    assert "test-token" in smtp.message.get_content()


def test_invitation_authenticates_after_starttls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use SMTP credentials with STARTTLS enabled."""
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    settings = make_settings(
        RESTLING_SMTP_HOST="smtp.example.com",
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
        RESTLING_SMTP_USERNAME="restling",
        RESTLING_SMTP_PASSWORD="test-password",
    )

    send_invitation_email(
        settings,
        recipient="user@example.com",
        activation_url="https://restling.example.com/activate?token=abc",
    )

    smtp = FakeSMTP.instances[0]

    assert smtp.starttls_context is not None
    assert smtp.username == "restling"
    assert smtp.password == "test-password"


@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("SMTP connection timed out"),
        smtplib.SMTPException("SMTP transport failure"),
        ssl.SSLError("Certificate verification failed"),
    ],
)
def test_invitation_translates_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    """Never expose transport failure details through application errors."""

    def failing_smtp(*args: Any, **kwargs: Any) -> FakeSMTP:
        raise failure

    monkeypatch.setattr(smtplib, "SMTP", failing_smtp)

    settings = make_settings(
        RESTLING_SMTP_HOST="smtp.example.com",
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
    )

    with pytest.raises(InvitationDeliveryError) as exc_info:
        send_invitation_email(
            settings,
            recipient="user@example.com",
            activation_url="https://restling.example.com/activate?token=secret",
        )

    assert str(exc_info.value) == "Unable to deliver account invitation."
    assert "secret" not in str(exc_info.value)


def test_invitation_requires_smtp_configuration() -> None:
    """Reject email delivery when SMTP is disabled."""
    settings = make_settings()

    with pytest.raises(
        InvitationDeliveryError,
        match="SMTP delivery is not configured",
    ):
        send_invitation_email(
            settings,
            recipient="user@example.com",
            activation_url="https://restling.example.com/activate?token=abc",
        )


@pytest.mark.parametrize(
    "failed_operation",
    ["starttls", "send_message"],
)
def test_invitation_handles_smtp_operation_failures(
    monkeypatch: pytest.MonkeyPatch,
    failed_operation: str,
) -> None:
    """Safely handle failures after establishing an SMTP connection."""

    def fail_operation(*args: object, **kwargs: object) -> None:
        raise smtplib.SMTPException("SMTP operation failed")

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(FakeSMTP, failed_operation, fail_operation)

    settings = make_settings(
        RESTLING_SMTP_HOST="smtp.example.com",
        RESTLING_SMTP_SECURITY="starttls",
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
    )

    with pytest.raises(
        InvitationDeliveryError,
        match="Unable to deliver account invitation",
    ):
        send_invitation_email(
            settings,
            recipient="user@example.com",
            activation_url=("https://restling.example.com/activate?token=secret-token"),
        )

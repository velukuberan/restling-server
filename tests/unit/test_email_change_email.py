"""Tests for email-change verification delivery."""

from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from restling_server.core.config import Settings
from restling_server.users.email_change_email import (
    EmailChangeDeliveryError,
    send_email_change_verification,
)


def test_smtp_connection_failure_raises_delivery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An SMTP connection failure produces a safe delivery error."""
    monkeypatch.setenv("RESTLING_SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("RESTLING_SMTP_PORT", "1025")
    monkeypatch.setenv("RESTLING_SMTP_SECURITY", "none")
    monkeypatch.setenv("RESTLING_SMTP_FROM_EMAIL", "no-reply@example.com")
    monkeypatch.delenv("RESTLING_SMTP_USERNAME", raising=False)
    monkeypatch.delenv("RESTLING_SMTP_PASSWORD", raising=False)

    settings = Settings(
        postgres_user="test",
        postgres_password=SecretStr("test"),
        postgres_db="test",
    )

    with patch(
        "smtplib.SMTP",
        side_effect=OSError("Connection refused"),
    ):
        with pytest.raises(
            EmailChangeDeliveryError,
            match="Unable to deliver email-change verification",
        ):
            send_email_change_verification(
                settings,
                recipient="new@example.com",
                verification_url=(
                    "https://restling.example.com/"
                    "verify-email-change?token=sample-token"
                ),
            )


def test_email_change_verification_sent_to_new_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deliver the verification link to the proposed new email."""
    monkeypatch.setenv("RESTLING_SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("RESTLING_SMTP_PORT", "1025")
    monkeypatch.setenv("RESTLING_SMTP_SECURITY", "none")
    monkeypatch.setenv("RESTLING_SMTP_FROM_EMAIL", "no-reply@example.com")
    monkeypatch.delenv("RESTLING_SMTP_USERNAME", raising=False)
    monkeypatch.delenv("RESTLING_SMTP_PASSWORD", raising=False)

    settings = Settings(
        postgres_user="test",
        postgres_password=SecretStr("test"),
        postgres_db="test",
    )

    verification_url = (
        "https://restling.example.com/verify-email-change?token=sample-token"
    )

    smtp_connection = MagicMock()

    with patch("smtplib.SMTP") as mock_smtp:
        mock_smtp.return_value.__enter__.return_value = smtp_connection

        send_email_change_verification(
            settings,
            recipient="new@example.com",
            verification_url=verification_url,
        )

    smtp_connection.send_message.assert_called_once()

    message = smtp_connection.send_message.call_args.args[0]

    assert message["To"] == "new@example.com"
    assert message["From"] == "no-reply@example.com"
    assert message["Subject"] == "Verify your Restling email change"
    assert verification_url in message.get_content()

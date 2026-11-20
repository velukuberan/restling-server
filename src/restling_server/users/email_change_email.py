"""SMTP delivery of email-change verification links."""

import smtplib
import ssl
from email.message import EmailMessage

from restling_server.core.config import Settings


class EmailChangeDeliveryError(Exception):
    """An email-change verification message could not be delivered."""


def send_email_change_verification(
    settings: Settings,
    *,
    recipient: str,
    verification_url: str,
) -> None:
    """Deliver an email-change verification link through SMTP."""
    if settings.smtp_host is None or settings.smtp_from_email is None:
        raise EmailChangeDeliveryError("SMTP delivery is not configured.")

    message = EmailMessage()
    message["Subject"] = "Verify your Restling email change"
    message["From"] = str(settings.smtp_from_email)
    message["To"] = recipient

    message.set_content(
        "A change to your Restling account email was requested.\n\n"
        "Open the following link to verify your new email address:\n"
        f"{verification_url}\n\n"
        "This link can only be used once.\n"
        "If you did not request this change, ignore this email."
    )

    ssl_context = ssl.create_default_context()

    try:
        if settings.smtp_security == "ssl":
            with smtplib.SMTP_SSL(
                settings.smtp_host,
                settings.smtp_port,
                timeout=10,
                context=ssl_context,
            ) as smtp:
                _send_message(smtp, settings, message)
        else:
            with smtplib.SMTP(
                settings.smtp_host,
                settings.smtp_port,
                timeout=10,
            ) as smtp:
                if settings.smtp_security == "starttls":
                    smtp.starttls(context=ssl_context)

                _send_message(smtp, settings, message)

    except (OSError, smtplib.SMTPException):
        raise EmailChangeDeliveryError(
            "Unable to deliver email-change verification."
        ) from None


def _send_message(
    smtp: smtplib.SMTP,
    settings: Settings,
    message: EmailMessage,
) -> None:
    """Authenticate when configured and deliver the message."""
    if settings.smtp_username is not None:
        if settings.smtp_password is None:
            raise EmailChangeDeliveryError(
                "SMTP authentication is not configured correctly."
            )

        smtp.login(
            settings.smtp_username,
            settings.smtp_password.get_secret_value(),
        )

    smtp.send_message(message)

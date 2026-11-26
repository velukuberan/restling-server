"""SMTP delivery of Restling password-reset links."""

import smtplib
import ssl
from email.message import EmailMessage

from restling_server.core.config import Settings


class PasswordResetDeliveryError(Exception):
    """A password-reset message could not be delivered."""


def send_password_reset_email(
    settings: Settings,
    *,
    recipient: str,
    reset_url: str,
) -> None:
    """Deliver a password-reset link through configured SMTP."""
    if settings.smtp_host is None or settings.smtp_from_email is None:
        raise PasswordResetDeliveryError("SMTP delivery is not configured.")

    message = EmailMessage()
    message["Subject"] = "Reset your Restling password"
    message["From"] = str(settings.smtp_from_email)
    message["To"] = recipient

    message.set_content(
        "A password reset was requested for your Restling account.\n\n"
        "Open the following link to set a new password:\n"
        f"{reset_url}\n\n"
        "This link can only be used once.\n\n"
        "If you did not request a password reset, "
        "you can ignore this email. "
        "Your current password will remain unchanged.\n\n"
        "Restling"
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
                _authenticate_and_send(
                    smtp,
                    settings,
                    message,
                )

        else:
            with smtplib.SMTP(
                settings.smtp_host,
                settings.smtp_port,
                timeout=10,
            ) as smtp:
                if settings.smtp_security == "starttls":
                    smtp.starttls(context=ssl_context)

                _authenticate_and_send(
                    smtp,
                    settings,
                    message,
                )

    except (OSError, smtplib.SMTPException):
        raise PasswordResetDeliveryError(
            "Unable to deliver password-reset email."
        ) from None


def _authenticate_and_send(
    smtp: smtplib.SMTP,
    settings: Settings,
    message: EmailMessage,
) -> None:
    """Authenticate when configured, then deliver the message."""
    if settings.smtp_username is not None:
        if settings.smtp_password is None:
            raise PasswordResetDeliveryError(
                "SMTP authentication is not configured correctly."
            )

        smtp.login(
            settings.smtp_username,
            settings.smtp_password.get_secret_value(),
        )

    smtp.send_message(message)

"""SMTP delivery for Restling account invitations."""

import smtplib
import ssl
from email.message import EmailMessage

from restling_server.core.config import Settings


class InvitationDeliveryError(Exception):
    """An account invitation could not be delivered."""


def send_invitation_email(
    settings: Settings,
    *,
    recipient: str,
    activation_url: str,
) -> None:
    """Send an activation invitation using configured SMTP."""
    if settings.smtp_host is None or settings.smtp_from_email is None:
        raise InvitationDeliveryError("SMTP delivery is not configured.")

    message = EmailMessage()
    message["Subject"] = "Activate your Restling account"
    message["From"] = str(settings.smtp_from_email)
    message["To"] = recipient

    message.set_content(
        "Your Restling account is ready for activation.\n\n"
        "Open the following link to set your password:\n"
        f"{activation_url}\n\n"
        "This invitation can only be used once.\n"
        "If you were not expecting this invitation, "
        "you can ignore this email."
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
                _authenticate_and_send(smtp, settings, message)

        else:
            with smtplib.SMTP(
                settings.smtp_host,
                settings.smtp_port,
                timeout=10,
            ) as smtp:
                if settings.smtp_security == "starttls":
                    smtp.starttls(context=ssl_context)

                _authenticate_and_send(smtp, settings, message)

    except (OSError, smtplib.SMTPException):
        raise InvitationDeliveryError("Unable to deliver account invitation.") from None


def _authenticate_and_send(
    smtp: smtplib.SMTP,
    settings: Settings,
    message: EmailMessage,
) -> None:
    """Authenticate when configured, then send the message."""
    if settings.smtp_username is not None:
        if settings.smtp_password is None:
            raise InvitationDeliveryError(
                "SMTP authentication is not configured correctly."
            )

        smtp.login(
            settings.smtp_username,
            settings.smtp_password.get_secret_value(),
        )

    smtp.send_message(message)

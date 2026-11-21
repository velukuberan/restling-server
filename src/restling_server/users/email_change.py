"""Coordinate self-service email-change verification requests."""

from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.users.email_change_email import (
    EmailChangeDeliveryError,
    send_email_change_notification,
    send_email_change_verification,
)
from restling_server.users.email_change_links import build_email_change_url
from restling_server.users.service import (
    commit_email_change_token_after_delivery,
    reserve_email_change_delivery_attempt,
    validate_email_change_request,
    verify_email_change,
)
from restling_server.users.tokens import generate_token


def request_email_change_verification(
    session: Session,
    *,
    settings: Settings,
    access_token: str,
    current_password: str,
    email: str,
) -> bool:
    """Validate, deliver, and persist an email-change verification token."""
    email_change_required = validate_email_change_request(
        session,
        access_token=access_token,
        current_password=current_password,
        email=email,
        cooldown_seconds=settings.email_change_cooldown_seconds,
        hourly_limit=settings.email_change_hourly_limit,
    )

    # Same-email requests have no side effects.
    if not email_change_required:
        return False

    if settings.smtp_host is None or settings.smtp_from_email is None:
        raise EmailChangeDeliveryError("SMTP delivery is not configured.")

    raw_token = generate_token()

    verification_url = build_email_change_url(
        settings,
        token=raw_token,
    )

    attempt_reserved = reserve_email_change_delivery_attempt(
        session,
        access_token=access_token,
        current_password=current_password,
        email=email,
        cooldown_seconds=settings.email_change_cooldown_seconds,
        hourly_limit=settings.email_change_hourly_limit,
        smtp_attempt_hourly_limit=settings.email_change_smtp_attempt_hourly_limit,
    )

    if not attempt_reserved:
        return False

    # SMTP happens outside the database transaction.
    send_email_change_verification(
        settings,
        recipient=email.strip(),
        verification_url=verification_url,
    )

    # Revalidate the account after SMTP delivery and atomically
    # replace previously issued verification tokens.
    return commit_email_change_token_after_delivery(
        session,
        access_token=access_token,
        current_password=current_password,
        email=email,
        raw_token=raw_token,
        expiry_minutes=settings.email_change_expiry_minutes,
        cooldown_seconds=settings.email_change_cooldown_seconds,
        hourly_limit=settings.email_change_hourly_limit,
    )


def confirm_email_change(
    session: Session,
    *,
    settings: Settings,
    token: str,
) -> None:
    """Verify an email change and notify the previous address."""
    old_email, new_email = verify_email_change(
        session,
        token=token,
    )

    # The database transaction has already committed.
    # Notification failure must not undo the completed change.
    try:
        send_email_change_notification(
            settings,
            recipient=old_email,
            new_email=new_email,
        )
    except EmailChangeDeliveryError:
        # Best-effort security notification.
        pass

"""Coordinate public password-recovery requests."""

import logging

from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.users.password_reset_email import (
    PasswordResetDeliveryError,
    send_password_reset_email,
)
from restling_server.users.password_reset_links import (
    build_password_reset_url,
)
from restling_server.users.service import (
    commit_password_reset_token_after_delivery,
    prepare_password_recovery,
    reserve_password_reset_attempt,
)
from restling_server.users.tokens import generate_token

logger = logging.getLogger(__name__)


class PasswordRecoveryUnavailableError(Exception):
    """Email-based password recovery is unavailable."""


def request_password_recovery(
    session: Session,
    *,
    settings: Settings,
    email: str,
    source_ip: str,
) -> None:
    """Deliver and persist a password-reset credential when permitted."""
    if (
        settings.smtp_host is None
        or settings.smtp_from_email is None
        or settings.public_url is None
    ):
        raise PasswordRecoveryUnavailableError(
            "Email-based password recovery is unavailable."
        )

    attempt_reserved = reserve_password_reset_attempt(
        session,
        email=email,
        source_ip=source_ip,
        cooldown_seconds=settings.password_reset_cooldown_seconds,
        email_hourly_limit=settings.password_reset_email_hourly_limit,
        ip_hourly_limit=settings.password_reset_ip_hourly_limit,
    )

    if not attempt_reserved:
        return

    recovery_state = prepare_password_recovery(
        session,
        email=email,
    )

    if recovery_state is None:
        return

    raw_token = generate_token()

    reset_url = build_password_reset_url(
        settings,
        token=raw_token,
    )

    # SMTP delivery must occur outside a database transaction.
    try:
        send_password_reset_email(
            settings,
            recipient=recovery_state.recipient,
            reset_url=reset_url,
        )

    except PasswordResetDeliveryError:
        # Never log the recipient, reset URL or raw credential.
        logger.warning("Password-recovery email delivery failed.")
        return

    credential_persisted = commit_password_reset_token_after_delivery(
        session,
        expected_state=recovery_state,
        raw_token=raw_token,
        expiry_minutes=settings.password_reset_expiry_minutes,
    )

    if not credential_persisted:
        logger.info(
            "Delivered password-reset credential discarded "
            "because account state changed."
        )

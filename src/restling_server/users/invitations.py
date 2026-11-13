"""Coordinate account activation invitations."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.users.activation_links import (
    ActivationURLNotConfiguredError,
    build_activation_url,
)
from restling_server.users.invitation_email import (
    InvitationDeliveryError,
    send_invitation_email,
)
from restling_server.users.models import User
from restling_server.users.service import issue_activation_token


def prepare_activation_invitation(
    session: Session,
    *,
    settings: Settings,
    actor_id: UUID,
    user_id: UUID,
) -> tuple[str, datetime]:
    """Issue an activation credential and prepare its trusted URL."""
    if settings.public_url is None:
        raise ActivationURLNotConfiguredError("RESTLING_PUBLIC_URL must be configured.")

    raw_token, expires_at = issue_activation_token(
        session,
        actor_id=actor_id,
        user_id=user_id,
        expiry_hours=settings.invitation_expiry_hours,
    )

    activation_url = build_activation_url(
        settings,
        token=raw_token,
    )

    return activation_url, expires_at


def deliver_activation_invitation(
    session: Session,
    *,
    settings: Settings,
    actor_id: UUID,
    user_id: UUID,
) -> datetime:
    """Issue an invitation and deliver it through SMTP."""
    # Reject unavailable SMTP before issuing or replacing a token.
    if settings.smtp_host is None or settings.smtp_from_email is None:
        raise InvitationDeliveryError("SMTP delivery is not configured.")

    # This operation owns and commits its database transaction.
    activation_url, expires_at = prepare_activation_invitation(
        session,
        settings=settings,
        actor_id=actor_id,
        user_id=user_id,
    )

    # Obtain the recipient in a separate, short transaction.
    with session.begin():
        recipient = session.scalar(
            select(User.email).where(
                User.id == user_id,
                User.status == "pending",
            )
        )

    if recipient is None:
        raise InvitationDeliveryError("Unable to deliver account invitation.")

    # No database transaction is active during SMTP communication.
    send_invitation_email(
        settings,
        recipient=recipient,
        activation_url=activation_url,
    )

    return expires_at

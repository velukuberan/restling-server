"""Application operations for user management."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from email_validator import EmailNotValidError, validate_email
from psycopg.errors import UniqueViolation
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from restling_server.users.models import OneTimeToken, User
from restling_server.users.passwords import hash_password, validate_password
from restling_server.users.tokens import generate_token, hash_token

# PostgreSQL advisory-lock identifiers reserved for administrator bootstrap.
_BOOTSTRAP_LOCK_NAMESPACE = 723941
_BOOTSTRAP_LOCK_ID = 1


class AdministratorAlreadyInitializedError(Exception):
    """Initial administrator bootstrap is no longer permitted."""


class UserCreationNotAllowedError(Exception):
    """The actor cannot create user accounts."""


class UserAlreadyExistsError(Exception):
    """A user account with this email already exists."""


class InvitationNotAllowedError(Exception):
    """The invitation cannot be issued for this actor or account."""


class InvalidActivationTokenError(Exception):
    """The activation credential is invalid or no longer usable."""


def bootstrap_administrator(
    session: Session,
    *,
    email: str,
    display_name: str,
    password: str,
) -> User:
    """Create the initial administrator in a single transaction."""
    original_email = email.strip()

    try:
        validated_email = validate_email(
            original_email,
            check_deliverability=False,
        )
    except EmailNotValidError as exc:
        raise ValueError("Invalid administrator email address.") from exc

    normalized_email = validated_email.normalized.casefold()

    normalized_display_name = display_name.strip()

    if not normalized_display_name:
        raise ValueError("Administrator display name is required.")

    if len(normalized_display_name) > 150:
        raise ValueError("Administrator display name must not exceed 150 characters.")

    validate_password(password)
    password_hash = hash_password(password)

    with session.begin():
        # Serialize bootstrap attempts across PostgreSQL connections.
        session.execute(
            text("SELECT pg_advisory_xact_lock(:namespace, :lock_id)"),
            {
                "namespace": _BOOTSTRAP_LOCK_NAMESPACE,
                "lock_id": _BOOTSTRAP_LOCK_ID,
            },
        )

        existing_user = session.scalar(select(User.id).limit(1))

        if existing_user is not None:
            raise AdministratorAlreadyInitializedError(
                "Initial administrator bootstrap is unavailable."
            )

        administrator = User(
            email=original_email,
            normalized_email=normalized_email,
            display_name=normalized_display_name,
            password_hash=password_hash,
            password_reset_required=False,
            status="active",
            system_role="administrator",
            activated_at=datetime.now(UTC),
        )

        session.add(administrator)
        session.flush()

    return administrator


def create_user(
    session: Session,
    *,
    actor_id: UUID,
    email: str,
    display_name: str,
    job_title: str | None = None,
) -> User:
    """Create a pending user account as an administrator."""
    original_email = email.strip()

    try:
        validated_email = validate_email(
            original_email,
            check_deliverability=False,
        )
    except EmailNotValidError as exc:
        raise ValueError("Invalid user email address.") from exc

    normalized_email = validated_email.normalized.casefold()

    normalized_display_name = display_name.strip()

    if not normalized_display_name:
        raise ValueError("User display name is required.")

    if len(normalized_display_name) > 150:
        raise ValueError("User display name must not exceed 150 characters.")

    normalized_job_title = None

    if job_title is not None:
        normalized_job_title = job_title.strip()

        if len(normalized_job_title) > 100:
            raise ValueError("Job title must not exceed 100 characters.")

        if not normalized_job_title:
            normalized_job_title = None

    try:
        with session.begin():
            actor = session.get(User, actor_id)

            if (
                actor is None
                or actor.system_role != "administrator"
                or actor.status != "active"
            ):
                raise UserCreationNotAllowedError(
                    "Administrator privileges are required."
                )

            user = User(
                email=original_email,
                normalized_email=normalized_email,
                display_name=normalized_display_name,
                job_title=normalized_job_title,
                status="pending",
                system_role="user",
                password_hash=None,
                password_reset_required=False,
            )

            session.add(user)
            session.flush()

    except IntegrityError as exc:
        if (
            isinstance(exc.orig, UniqueViolation)
            and exc.orig.diag.constraint_name == "users_normalized_email_key"
        ):
            raise UserAlreadyExistsError(
                "A user with this email address already exists."
            ) from exc

        raise

    return user


def issue_activation_token(
    session: Session,
    *,
    actor_id: UUID,
    user_id: UUID,
    expiry_hours: int,
) -> tuple[str, datetime]:
    """Issue or replace an activation token for a pending user."""
    if expiry_hours < 1:
        raise ValueError("Invitation expiry must be at least one hour.")

    with session.begin():
        actor = session.get(User, actor_id)

        if (
            actor is None
            or actor.system_role != "administrator"
            or actor.status != "active"
        ):
            raise InvitationNotAllowedError("Administrator privileges are required.")

        # Serialize issuance and replacement for this user.
        user = session.scalar(select(User).where(User.id == user_id).with_for_update())

        if user is None or user.status != "pending":
            raise InvitationNotAllowedError("Account is not eligible for activation.")

        now = datetime.now(UTC)

        # Invalidate previous usable activation invitations.
        existing_tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
                OneTimeToken.consumed_at.is_(None),
                OneTimeToken.revoked_at.is_(None),
            )
        ).all()

        for existing_token in existing_tokens:
            existing_token.revoked_at = now

        raw_token = generate_token()
        expires_at = now + timedelta(hours=expiry_hours)

        token = OneTimeToken(
            user_id=user.id,
            purpose="account_activation",
            token_hash=hash_token(raw_token),
            pending_email=None,
            created_at=now,
            expires_at=expires_at,
        )

        session.add(token)
        session.flush()

    return raw_token, expires_at


def activate_user(
    session: Session,
    *,
    token: str,
    password: str,
) -> None:
    """Activate a pending user with a valid one-time credential."""

    token_digest = hash_token(token)

    with session.begin():
        # Look up the credential without locking the token row yet.
        token_user_id = session.scalar(
            select(OneTimeToken.user_id).where(
                OneTimeToken.token_hash == token_digest,
                OneTimeToken.purpose == "account_activation",
            )
        )

        if token_user_id is None:
            raise InvalidActivationTokenError(
                "Invalid or expired activation credential."
            )

        # Lock the user first, matching invitation issuance lock order.
        user = session.scalar(
            select(User).where(User.id == token_user_id).with_for_update()
        )

        if user is None or user.status != "pending":
            raise InvalidActivationTokenError(
                "Invalid or expired activation credential."
            )

        # Re-read and lock the token after acquiring the user lock.
        # It may have been revoked by another transaction meanwhile.
        stored_token = session.scalar(
            select(OneTimeToken)
            .where(
                OneTimeToken.token_hash == token_digest,
                OneTimeToken.user_id == user.id,
                OneTimeToken.purpose == "account_activation",
            )
            .with_for_update()
        )

        now = datetime.now(UTC)

        if (
            stored_token is None
            or stored_token.expires_at <= now
            or stored_token.consumed_at is not None
            or stored_token.revoked_at is not None
        ):
            raise InvalidActivationTokenError(
                "Invalid or expired activation credential."
            )

        # Validate the password only after confirming the token is usable.
        validate_password(password)

        user.password_hash = hash_password(password)
        user.password_reset_required = False
        user.status = "active"
        user.activated_at = now

        stored_token.consumed_at = now

        session.flush()

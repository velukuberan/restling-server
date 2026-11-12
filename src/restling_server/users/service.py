"""Application operations for user management."""

from datetime import UTC, datetime
from uuid import UUID

from email_validator import EmailNotValidError, validate_email
from psycopg.errors import UniqueViolation
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from restling_server.users.models import User
from restling_server.users.passwords import hash_password, validate_password

# PostgreSQL advisory-lock identifiers reserved for administrator bootstrap.
_BOOTSTRAP_LOCK_NAMESPACE = 723941
_BOOTSTRAP_LOCK_ID = 1


class AdministratorAlreadyInitializedError(Exception):
    """Initial administrator bootstrap is no longer permitted."""


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


class UserCreationNotAllowedError(Exception):
    """The actor cannot create user accounts."""


class UserAlreadyExistsError(Exception):
    """A user account with this email already exists."""


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

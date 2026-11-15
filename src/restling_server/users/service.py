"""Application operations for user management."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from email_validator import EmailNotValidError, validate_email
from psycopg.errors import UniqueViolation
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from restling_server.users.models import (
    AccessToken,
    LoginSession,
    OneTimeToken,
    RefreshTokenHistory,
    User,
)
from restling_server.users.passwords import (
    hash_password,
    validate_password,
    verify_password,
)
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


class InvalidCredentialsError(Exception):
    """The supplied login credentials are invalid."""


class SessionLimitReachedError(Exception):
    """The account has reached its active-session limit."""


@dataclass(frozen=True)
class LoginResult:
    """Credentials and session details returned by successful login."""

    session_id: UUID
    access_token: str
    refresh_token: str
    access_token_expires_at: datetime
    session_expires_at: datetime


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
                or actor.password_reset_required
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
            or actor.password_reset_required
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


def login_user(
    session: Session,
    *,
    email: str,
    password: str,
    access_token_expiry_minutes: int,
    refresh_session_expiry_days: int,
    max_active_sessions: int,
) -> LoginResult:
    """Authenticate a user and create an opaque-token login session."""
    if (
        access_token_expiry_minutes < 1
        or refresh_session_expiry_days < 1
        or max_active_sessions < 1
    ):
        raise ValueError("Authentication settings must be positive.")

    try:
        validated_email = validate_email(
            email.strip(),
            check_deliverability=False,
        )
    except EmailNotValidError as exc:
        raise InvalidCredentialsError("Invalid email address or password.") from exc

    normalized_email = validated_email.normalized.casefold()

    with session.begin():
        user = session.scalar(
            select(User)
            .where(User.normalized_email == normalized_email)
            .with_for_update()
        )

        if user is None:
            raise InvalidCredentialsError("Invalid email address or password.")

        if user.password_hash is None or not verify_password(
            password, user.password_hash
        ):
            raise InvalidCredentialsError("Invalid email address or password.")

        if user.status != "active" or user.password_reset_required:
            raise InvalidCredentialsError("Invalid email address or password.")

        now = datetime.now(UTC)

        active_session_count = session.scalar(
            select(func.count(LoginSession.id)).where(
                LoginSession.user_id == user.id,
                LoginSession.revoked_at.is_(None),
                LoginSession.expires_at > now,
            )
        )

        if active_session_count is None:
            active_session_count = 0

        if active_session_count >= max_active_sessions:
            raise SessionLimitReachedError("Maximum active sessions reached.")

        raw_access_token = generate_token()
        raw_refresh_token = generate_token()

        session_expires_at = now + timedelta(days=refresh_session_expiry_days)

        access_token_expires_at = min(
            now + timedelta(minutes=access_token_expiry_minutes),
            session_expires_at,
        )

        login_session = LoginSession(
            user_id=user.id,
            refresh_token_hash=hash_token(raw_refresh_token),
            created_at=now,
            expires_at=session_expires_at,
        )

        session.add(login_session)
        session.flush()

        access_token = AccessToken(
            session_id=login_session.id,
            token_hash=hash_token(raw_access_token),
            created_at=now,
            expires_at=access_token_expires_at,
        )

        session.add(access_token)
        session.flush()

        result = LoginResult(
            session_id=login_session.id,
            access_token=raw_access_token,
            refresh_token=raw_refresh_token,
            access_token_expires_at=access_token_expires_at,
            session_expires_at=session_expires_at,
        )

    return result


def refresh_session(
    session: Session,
    *,
    refresh_token: str,
    access_token_expiry_minutes: int,
) -> LoginResult:
    """Rotate refresh credentials and revoke sessions on replay."""
    if access_token_expiry_minutes < 1:
        raise ValueError("Access-token expiry must be positive.")

    token_digest = hash_token(refresh_token)
    replay_detected = False
    result: LoginResult | None = None

    with session.begin():
        # A credential may be current or already consumed.
        session_user_id = session.scalar(
            select(LoginSession.user_id).where(
                LoginSession.refresh_token_hash == token_digest
            )
        )

        if session_user_id is None:
            session_user_id = session.scalar(
                select(LoginSession.user_id)
                .join(
                    RefreshTokenHistory,
                    RefreshTokenHistory.session_id == LoginSession.id,
                )
                .where(RefreshTokenHistory.token_hash == token_digest)
            )

        if session_user_id is None:
            raise InvalidCredentialsError("Invalid refresh credential.")

        # Lock the user first, consistent with login and other operations.
        user = session.scalar(
            select(User).where(User.id == session_user_id).with_for_update()
        )

        if user is None:
            raise InvalidCredentialsError("Invalid refresh credential.")

        # Re-read history after acquiring the user lock.
        # A concurrent refresh may have consumed this token meanwhile.
        consumed_token = session.scalar(
            select(RefreshTokenHistory).where(
                RefreshTokenHistory.token_hash == token_digest
            )
        )

        if consumed_token is not None:
            login_session = session.scalar(
                select(LoginSession)
                .where(LoginSession.id == consumed_token.session_id)
                .with_for_update()
            )

            if login_session is not None:
                if login_session.revoked_at is None:
                    login_session.refresh_token_hash = None
                    login_session.revoked_at = datetime.now(UTC)
                    login_session.revocation_reason = "refresh_token_replay"

                replay_detected = True

        else:
            login_session = session.scalar(
                select(LoginSession)
                .where(
                    LoginSession.user_id == user.id,
                    LoginSession.refresh_token_hash == token_digest,
                )
                .with_for_update()
            )

            now = datetime.now(UTC)

            if (
                login_session is None
                or login_session.revoked_at is not None
                or login_session.expires_at <= now
                or user.status != "active"
                or user.password_reset_required
            ):
                raise InvalidCredentialsError("Invalid refresh credential.")

            raw_access_token = generate_token()
            raw_refresh_token = generate_token()

            access_token_expires_at = min(
                now + timedelta(minutes=access_token_expiry_minutes),
                login_session.expires_at,
            )

            previous_token = RefreshTokenHistory(
                session_id=login_session.id,
                token_hash=token_digest,
                used_at=now,
            )

            login_session.refresh_token_hash = hash_token(raw_refresh_token)
            login_session.last_used_at = now

            access_token = AccessToken(
                session_id=login_session.id,
                token_hash=hash_token(raw_access_token),
                created_at=now,
                expires_at=access_token_expires_at,
            )

            session.add(previous_token)
            session.add(access_token)

            result = LoginResult(
                session_id=login_session.id,
                access_token=raw_access_token,
                refresh_token=raw_refresh_token,
                access_token_expires_at=access_token_expires_at,
                session_expires_at=login_session.expires_at,
            )

        session.flush()

    # The transaction has committed before reporting a replay.
    if replay_detected:
        raise InvalidCredentialsError("Invalid refresh credential.")

    if result is None:
        raise InvalidCredentialsError("Invalid refresh credential.")

    return result


def authenticate_access_token(
    session: Session,
    *,
    access_token: str,
) -> User:
    """Resolve an eligible user from a valid opaque access token."""
    token_digest = hash_token(access_token)
    now = datetime.now(UTC)

    user = session.scalar(
        select(User)
        .join(LoginSession, LoginSession.user_id == User.id)
        .join(AccessToken, AccessToken.session_id == LoginSession.id)
        .where(
            AccessToken.token_hash == token_digest,
            AccessToken.expires_at > now,
            LoginSession.expires_at > now,
            LoginSession.revoked_at.is_(None),
            User.status == "active",
            User.password_reset_required.is_(False),
        )
    )

    if user is None:
        raise InvalidCredentialsError("Invalid access credential.")

    return user

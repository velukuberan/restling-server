"""Application operations for user management."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from email_validator import EmailNotValidError, validate_email
from psycopg.errors import UniqueViolation
from sqlalchemy import (
    and_,
    case,
    func,
    or_,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from restling_server.users.models import (
    AccessToken,
    AuditLog,
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

# Serialize operations that change active administrator membership.
_ACCOUNT_LIFECYCLE_LOCK_ID = 2


class AdministratorAlreadyInitializedError(Exception):
    """Initial administrator bootstrap is no longer permitted."""


class UserCreationNotAllowedError(Exception):
    """The actor cannot create user accounts."""


class UserAlreadyExistsError(Exception):
    """A user account with this email already exists."""


class UserListingNotAllowedError(Exception):
    """The actor cannot list server accounts."""


class InvitationNotAllowedError(Exception):
    """The invitation cannot be issued for this actor or account."""


class InvalidActivationTokenError(Exception):
    """The activation credential is invalid or no longer usable."""


class InvalidCredentialsError(Exception):
    """The supplied login credentials are invalid."""


class SessionNotFoundError(InvalidCredentialsError):
    """The requested session does not belong to the user or does not exist."""


class SessionLimitReachedError(Exception):
    """The account has reached its active-session limit."""


class PasswordResetNotAllowedError(Exception):
    """The actor cannot issue a password-reset credential."""


class InvalidPasswordResetTokenError(Exception):
    """The password-reset credential is invalid or no longer usable."""


class UserSuspensionNotAllowedError(Exception):
    """The actor or target account is not eligible for suspension."""


class UserDetailNotAllowedError(Exception):
    """The actor cannot view another user's account details."""


class UserNotFoundError(Exception):
    """The requested account does not exist."""


class LastAdministratorError(Exception):
    """The operation would leave no active system administrator."""


class UserRestorationNotAllowedError(Exception):
    """The actor or target account is not eligible for restoration."""


@dataclass(frozen=True)
class LoginResult:
    """Credentials and session details returned by successful login."""

    session_id: UUID
    access_token: str
    refresh_token: str
    access_token_expires_at: datetime
    session_expires_at: datetime


@dataclass(frozen=True)
class SessionSummary:
    """Safe metadata describing an active login session."""

    session_id: UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    login_ip: str | None
    last_seen_ip: str | None
    machine_name: str | None
    is_current: bool


SessionStatus = Literal["active", "revoked", "expired"]


@dataclass(frozen=True)
class SessionHistoryItem:
    """Safe metadata for a current or historical session."""

    session_id: UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    login_ip: str | None
    last_seen_ip: str | None
    machine_name: str | None
    status: SessionStatus
    is_current: bool


@dataclass(frozen=True)
class SessionHistoryPage:
    """Paginated sessions with an unpaginated total."""

    items: list[SessionHistoryItem]
    total: int


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


def issue_password_reset_token(
    session: Session,
    *,
    actor_id: UUID,
    user_id: UUID,
    expiry_minutes: int,
) -> tuple[str, datetime]:
    """Issue or replace a password-reset token for an existing user."""
    if expiry_minutes < 1:
        raise ValueError("Password-reset expiry must be positive.")

    with session.begin():
        actor = session.get(User, actor_id)

        if (
            actor is None
            or actor.system_role != "administrator"
            or actor.status != "active"
            or actor.password_reset_required
        ):
            raise PasswordResetNotAllowedError("Administrator privileges are required.")

        # Lock the user to serialize concurrent reset-token issuance.
        user = session.scalar(select(User).where(User.id == user_id).with_for_update())

        if user is None or user.status not in ("active", "suspended"):
            raise PasswordResetNotAllowedError(
                "Account is not eligible for password recovery."
            )

        now = datetime.now(UTC)

        # Invalidate all previously usable reset credentials.
        existing_tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user.id,
                OneTimeToken.purpose == "password_reset",
                OneTimeToken.consumed_at.is_(None),
                OneTimeToken.revoked_at.is_(None),
            )
        ).all()

        for existing_token in existing_tokens:
            existing_token.revoked_at = now

        raw_token = generate_token()
        expires_at = now + timedelta(minutes=expiry_minutes)

        reset_token = OneTimeToken(
            user_id=user.id,
            purpose="password_reset",
            token_hash=hash_token(raw_token),
            pending_email=None,
            created_at=now,
            expires_at=expires_at,
        )

        session.add(reset_token)
        session.add(
            AuditLog(
                actor_user_id=actor_id,
                target_user_id=user_id,
                action="user.password_reset_issued",
            )
        )
        session.flush()

    return raw_token, expires_at


def reset_user_password(
    session: Session,
    *,
    token: str,
    new_password: str,
) -> None:
    """Reset a user's password and revoke all existing sessions."""
    token_digest = hash_token(token)

    with session.begin():
        # Identify the account associated with the reset token.
        token_user_id = session.scalar(
            select(OneTimeToken.user_id).where(
                OneTimeToken.token_hash == token_digest,
                OneTimeToken.purpose == "password_reset",
            )
        )

        if token_user_id is None:
            raise InvalidPasswordResetTokenError(
                "Invalid or expired password-reset credential."
            )

        # Lock the user before locking the token or sessions.
        # This follows the account-level locking convention.
        user = session.scalar(
            select(User).where(User.id == token_user_id).with_for_update()
        )

        if user is None or user.status not in ("active", "suspended"):
            raise InvalidPasswordResetTokenError(
                "Invalid or expired password-reset credential."
            )

        # Re-read after acquiring the user lock so a concurrent
        # token replacement cannot leave a stale token usable.
        stored_token = session.scalar(
            select(OneTimeToken)
            .where(
                OneTimeToken.token_hash == token_digest,
                OneTimeToken.user_id == user.id,
                OneTimeToken.purpose == "password_reset",
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
            raise InvalidPasswordResetTokenError(
                "Invalid or expired password-reset credential."
            )

        # An invalid new password must not consume the token.
        validate_password(new_password)
        new_password_hash = hash_password(new_password)

        # Lock and revoke all non-revoked login sessions.
        login_sessions = session.scalars(
            select(LoginSession)
            .where(
                LoginSession.user_id == user.id,
                LoginSession.revoked_at.is_(None),
            )
            .order_by(LoginSession.id)
            .with_for_update()
        ).all()

        for login_session in login_sessions:
            login_session.refresh_token_hash = None
            login_session.revoked_at = now
            login_session.revocation_reason = "password_reset"

        # Persist the new credential and clear forced-reset state.
        user.password_hash = new_password_hash
        user.password_reset_required = False

        # The reset credential is single-use.
        stored_token.consumed_at = now
        session.add(
            AuditLog(
                actor_user_id=None,
                target_user_id=user.id,
                action="user.password_reset_completed",
            )
        )
        session.flush()


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


def logout_session(
    session: Session,
    *,
    access_token: str,
) -> None:
    """Revoke the login session associated with an access token."""
    token_digest = hash_token(access_token)

    with session.begin():
        now = datetime.now(UTC)

        login_session = session.scalar(
            select(LoginSession)
            .join(
                AccessToken,
                AccessToken.session_id == LoginSession.id,
            )
            .join(
                User,
                User.id == LoginSession.user_id,
            )
            .where(
                AccessToken.token_hash == token_digest,
                AccessToken.expires_at > now,
                LoginSession.expires_at > now,
                LoginSession.revoked_at.is_(None),
                User.status == "active",
                User.password_reset_required.is_(False),
            )
            .with_for_update(of=LoginSession)
        )

        if login_session is None:
            raise InvalidCredentialsError("Invalid access credential.")

        login_session.refresh_token_hash = None
        login_session.revoked_at = now
        login_session.revocation_reason = "logout"

        session.flush()


def list_user_sessions(
    session: Session,
    *,
    access_token: str,
) -> list[SessionSummary]:
    """List active sessions owned by the authenticated user."""
    token_digest = hash_token(access_token)
    now = datetime.now(UTC)

    current = session.execute(
        select(LoginSession.id, LoginSession.user_id)
        .join(
            AccessToken,
            AccessToken.session_id == LoginSession.id,
        )
        .join(
            User,
            User.id == LoginSession.user_id,
        )
        .where(
            AccessToken.token_hash == token_digest,
            AccessToken.expires_at > now,
            LoginSession.expires_at > now,
            LoginSession.revoked_at.is_(None),
            User.status == "active",
            User.password_reset_required.is_(False),
        )
    ).one_or_none()

    if current is None:
        raise InvalidCredentialsError("Invalid access credential.")

    current_session_id, user_id = current

    active_sessions = session.scalars(
        select(LoginSession)
        .where(
            LoginSession.user_id == user_id,
            LoginSession.revoked_at.is_(None),
            LoginSession.expires_at > now,
        )
        .order_by(LoginSession.created_at.desc(), LoginSession.id)
    ).all()

    return [
        SessionSummary(
            session_id=item.id,
            created_at=item.created_at,
            expires_at=item.expires_at,
            last_used_at=item.last_used_at,
            login_ip=item.login_ip,
            last_seen_ip=item.last_seen_ip,
            machine_name=item.machine_name,
            is_current=item.id == current_session_id,
        )
        for item in active_sessions
    ]


def list_user_session_history(
    session: Session,
    *,
    access_token: str,
    status: SessionStatus | None = None,
    limit: int = 25,
    offset: int = 0,
    retention_days: int = 30,
) -> SessionHistoryPage:
    """List retained sessions owned by the authenticated user."""
    if not 1 <= limit <= 100:
        raise ValueError("Session page limit must be between 1 and 100.")

    if offset < 0:
        raise ValueError("Session page offset cannot be negative.")

    if retention_days < 1:
        raise ValueError("Session history retention must be positive.")

    if status not in (None, "active", "revoked", "expired"):
        raise ValueError("Invalid session status.")

    user = authenticate_access_token(
        session,
        access_token=access_token,
    )

    current_session_id = session.scalar(
        select(LoginSession.id)
        .join(AccessToken, AccessToken.session_id == LoginSession.id)
        .where(
            AccessToken.token_hash == hash_token(access_token),
            LoginSession.user_id == user.id,
        )
    )

    if current_session_id is None:
        raise InvalidCredentialsError("Invalid access credential.")

    now = datetime.now(UTC)
    cutoff = now - timedelta(days=retention_days)

    active = and_(
        LoginSession.revoked_at.is_(None),
        LoginSession.expires_at > now,
    )

    revoked = and_(
        LoginSession.revoked_at.is_not(None),
        LoginSession.revoked_at >= cutoff,
    )

    expired = and_(
        LoginSession.revoked_at.is_(None),
        LoginSession.expires_at <= now,
        LoginSession.expires_at >= cutoff,
    )

    if status == "active":
        visibility = active
    elif status == "revoked":
        visibility = revoked
    elif status == "expired":
        visibility = expired
    else:
        visibility = or_(active, revoked, expired)

    criteria = and_(
        LoginSession.user_id == user.id,
        visibility,
    )

    total = session.scalar(select(func.count(LoginSession.id)).where(criteria))

    active_first = case(
        (active, 0),
        else_=1,
    )

    records = session.scalars(
        select(LoginSession)
        .where(criteria)
        .order_by(
            active_first,
            LoginSession.created_at.desc(),
            LoginSession.id.desc(),
        )
        .limit(limit)
        .offset(offset)
    ).all()

    items: list[SessionHistoryItem] = []

    for record in records:
        if record.revoked_at is not None:
            record_status: SessionStatus = "revoked"
        elif record.expires_at <= now:
            record_status = "expired"
        else:
            record_status = "active"

        items.append(
            SessionHistoryItem(
                session_id=record.id,
                created_at=record.created_at,
                expires_at=record.expires_at,
                last_used_at=record.last_used_at,
                revoked_at=record.revoked_at,
                login_ip=record.login_ip,
                last_seen_ip=record.last_seen_ip,
                machine_name=record.machine_name,
                status=record_status,
                is_current=record.id == current_session_id,
            )
        )

    return SessionHistoryPage(
        items=items,
        total=total if total is not None else 0,
    )


def revoke_user_session(
    session: Session,
    *,
    access_token: str,
    target_session_id: UUID,
) -> None:
    """Revoke a session owned by the authenticated user."""
    token_digest = hash_token(access_token)

    with session.begin():
        # Identify the account associated with the access credential.
        user_id = session.scalar(
            select(LoginSession.user_id)
            .join(
                AccessToken,
                AccessToken.session_id == LoginSession.id,
            )
            .where(AccessToken.token_hash == token_digest)
        )

        if user_id is None:
            raise InvalidCredentialsError("Invalid access credential.")

        # Serialize account-level session operations.
        user = session.scalar(select(User).where(User.id == user_id).with_for_update())

        if user is None:
            raise InvalidCredentialsError("Invalid access credential.")

        now = datetime.now(UTC)

        # Revalidate the credential after acquiring the user lock.
        current_session_id = session.scalar(
            select(LoginSession.id)
            .join(
                AccessToken,
                AccessToken.session_id == LoginSession.id,
            )
            .where(
                LoginSession.user_id == user.id,
                AccessToken.token_hash == token_digest,
                AccessToken.expires_at > now,
                LoginSession.expires_at > now,
                LoginSession.revoked_at.is_(None),
            )
        )

        if (
            current_session_id is None
            or user.status != "active"
            or user.password_reset_required
        ):
            raise InvalidCredentialsError("Invalid access credential.")

        # Ownership is enforced as part of the database query.
        target = session.scalar(
            select(LoginSession)
            .where(
                LoginSession.id == target_session_id,
                LoginSession.user_id == user.id,
            )
            .with_for_update()
        )

        if target is None:
            raise SessionNotFoundError("Session not found.")

        # Revocation is idempotent for owned historical sessions.
        # Preserve their original status and revocation reason.
        if target.revoked_at is not None or target.expires_at <= now:
            return

        target.refresh_token_hash = None
        target.revoked_at = now
        target.revocation_reason = "user_revoked"

        session.flush()


def revoke_other_sessions(
    session: Session,
    *,
    access_token: str,
) -> int:
    """Revoke all other active sessions owned by the authenticated user."""
    token_digest = hash_token(access_token)

    with session.begin():
        # Identify the owner of the supplied access credential.
        user_id = session.scalar(
            select(LoginSession.user_id)
            .join(
                AccessToken,
                AccessToken.session_id == LoginSession.id,
            )
            .where(AccessToken.token_hash == token_digest)
        )

        if user_id is None:
            raise InvalidCredentialsError("Invalid access credential.")

        # Serialize operations affecting this user's sessions.
        user = session.scalar(select(User).where(User.id == user_id).with_for_update())

        if user is None:
            raise InvalidCredentialsError("Invalid access credential.")

        now = datetime.now(UTC)

        # Revalidate authentication after acquiring the user lock.
        current_session_id = session.scalar(
            select(LoginSession.id)
            .join(
                AccessToken,
                AccessToken.session_id == LoginSession.id,
            )
            .where(
                LoginSession.user_id == user.id,
                AccessToken.token_hash == token_digest,
                AccessToken.expires_at > now,
                LoginSession.expires_at > now,
                LoginSession.revoked_at.is_(None),
            )
        )

        if (
            current_session_id is None
            or user.status != "active"
            or user.password_reset_required
        ):
            raise InvalidCredentialsError("Invalid access credential.")

        # Select only active sessions owned by this user,
        # explicitly excluding the current session.
        other_sessions = session.scalars(
            select(LoginSession)
            .where(
                LoginSession.user_id == user.id,
                LoginSession.id != current_session_id,
                LoginSession.revoked_at.is_(None),
                LoginSession.expires_at > now,
            )
            .order_by(LoginSession.id)
            .with_for_update()
        ).all()

        for other in other_sessions:
            other.refresh_token_hash = None
            other.revoked_at = now
            other.revocation_reason = "user_revoked"

        session.flush()

        return len(other_sessions)


def revoke_all_user_sessions(
    session: Session,
    *,
    access_token: str,
) -> None:
    """Revoke every active session belonging to the authenticated user."""
    token_digest = hash_token(access_token)

    with session.begin():
        user_id = session.scalar(
            select(LoginSession.user_id)
            .join(
                AccessToken,
                AccessToken.session_id == LoginSession.id,
            )
            .where(AccessToken.token_hash == token_digest)
        )

        if user_id is None:
            raise InvalidCredentialsError("Invalid access credential.")

        # Serialize session changes at the account level.
        user = session.scalar(select(User).where(User.id == user_id).with_for_update())

        if user is None:
            raise InvalidCredentialsError("Invalid access credential.")

        now = datetime.now(UTC)

        # Revalidate the credential after acquiring the account lock.
        current_session_id = session.scalar(
            select(LoginSession.id)
            .join(
                AccessToken,
                AccessToken.session_id == LoginSession.id,
            )
            .where(
                LoginSession.user_id == user.id,
                AccessToken.token_hash == token_digest,
                AccessToken.expires_at > now,
                LoginSession.expires_at > now,
                LoginSession.revoked_at.is_(None),
            )
        )

        if (
            current_session_id is None
            or user.status != "active"
            or user.password_reset_required
        ):
            raise InvalidCredentialsError("Invalid access credential.")

        active_sessions = session.scalars(
            select(LoginSession)
            .where(
                LoginSession.user_id == user.id,
                LoginSession.revoked_at.is_(None),
                LoginSession.expires_at > now,
            )
            .order_by(LoginSession.id)
            .with_for_update()
        ).all()

        for active_session in active_sessions:
            active_session.refresh_token_hash = None
            active_session.revoked_at = now
            active_session.revocation_reason = "user_revoked"

        session.flush()


def suspend_user(
    session: Session,
    *,
    actor_id: UUID,
    user_id: UUID,
) -> None:
    """Suspend an account and immediately revoke its login sessions."""
    with session.begin():
        # Serialize administrator lifecycle changes across workers.
        # Future demotion/deletion operations must use this same lock.
        session.execute(
            text("SELECT pg_advisory_xact_lock(:namespace, :lock_id)"),
            {
                "namespace": _BOOTSTRAP_LOCK_NAMESPACE,
                "lock_id": _ACCOUNT_LIFECYCLE_LOCK_ID,
            },
        )

        actor = session.get(User, actor_id)

        if (
            actor is None
            or actor.system_role != "administrator"
            or actor.status != "active"
            or actor.password_reset_required
        ):
            raise UserSuspensionNotAllowedError(
                "Administrator privileges are required."
            )

        # Lock the target account before changing its state.
        user = session.scalar(select(User).where(User.id == user_id).with_for_update())

        if user is None or user.status != "active":
            raise UserSuspensionNotAllowedError(
                "Account is not eligible for suspension."
            )

        if user.system_role == "administrator":
            active_administrator_count = session.scalar(
                select(func.count(User.id)).where(
                    User.system_role == "administrator",
                    User.status == "active",
                )
            )

            if active_administrator_count is None or active_administrator_count <= 1:
                raise LastAdministratorError(
                    "The last active administrator cannot be suspended."
                )

        now = datetime.now(UTC)

        # Lock sessions in a deterministic order.
        login_sessions = session.scalars(
            select(LoginSession)
            .where(
                LoginSession.user_id == user.id,
                LoginSession.revoked_at.is_(None),
            )
            .order_by(LoginSession.id)
            .with_for_update()
        ).all()

        for login_session in login_sessions:
            login_session.refresh_token_hash = None
            login_session.revoked_at = now
            login_session.revocation_reason = "account_suspended"

        user.status = "suspended"

        session.add(
            AuditLog(
                actor_user_id=actor_id,
                target_user_id=user_id,
                action="user.suspended",
            )
        )

        session.flush()


def restore_user(
    session: Session,
    *,
    actor_id: UUID,
    user_id: UUID,
    require_password_reset: bool = False,
) -> None:
    """Restore a suspended account without reviving revoked sessions."""
    with session.begin():
        # Use the same lifecycle lock as suspension.
        session.execute(
            text("SELECT pg_advisory_xact_lock(:namespace, :lock_id)"),
            {
                "namespace": _BOOTSTRAP_LOCK_NAMESPACE,
                "lock_id": _ACCOUNT_LIFECYCLE_LOCK_ID,
            },
        )

        actor = session.get(User, actor_id)

        if (
            actor is None
            or actor.system_role != "administrator"
            or actor.status != "active"
            or actor.password_reset_required
        ):
            raise UserRestorationNotAllowedError(
                "Administrator privileges are required."
            )

        user = session.scalar(select(User).where(User.id == user_id).with_for_update())

        if user is None or user.status != "suspended":
            raise UserRestorationNotAllowedError(
                "Account is not eligible for restoration."
            )

        user.status = "active"

        # Never silently clear an existing forced-reset restriction.
        if require_password_reset:
            user.password_reset_required = True

        session.add(
            AuditLog(
                actor_user_id=actor_id,
                target_user_id=user_id,
                action="user.restored",
                event_metadata={
                    "password_reset_required": user.password_reset_required,
                },
            )
        )

        session.flush()


def list_users(
    session: Session,
    *,
    actor: User,
    limit: int,
    offset: int,
    status: str | None = None,
    system_role: str | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> tuple[list[User], int]:
    """List accounts visible to a system administrator."""
    if (
        actor.system_role != "administrator"
        or actor.status != "active"
        or actor.password_reset_required
    ):
        raise UserListingNotAllowedError("Administrator privileges are required.")

    filters: list[ColumnElement[bool]] = []

    if status is not None:
        filters.append(User.status == status)

    if system_role is not None:
        filters.append(User.system_role == system_role)

    if search is not None and search.strip():
        pattern = (
            "%"
            + search.strip()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
            + "%"
        )
        filters.append(
            or_(
                User.email.ilike(pattern, escape="\\"),
                User.display_name.ilike(pattern, escape="\\"),
            )
        )

    sort_columns = {
        "created_at": User.created_at,
        "email": User.email,
        "display_name": User.display_name,
        "status": User.status,
    }

    column = sort_columns[sort_by]

    if sort_order == "asc":
        ordering = (column.asc(), User.id.asc())
    else:
        ordering = (column.desc(), User.id.desc())

    total = session.scalar(select(func.count()).select_from(User).where(*filters))

    users = session.scalars(
        select(User).where(*filters).order_by(*ordering).limit(limit).offset(offset)
    ).all()

    return list(users), total or 0


def get_user_detail(
    session: Session,
    *,
    actor: User,
    user_id: UUID,
) -> User:
    """Retrieve a user account as a system administrator."""
    if (
        actor.system_role != "administrator"
        or actor.status != "active"
        or actor.password_reset_required
    ):
        raise UserDetailNotAllowedError("Administrator privileges are required.")

    user = session.get(User, user_id)

    if user is None:
        raise UserNotFoundError("User account not found.")

    return user

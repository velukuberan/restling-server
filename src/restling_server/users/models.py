"""SQLAlchemy persistence models for user identity."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from uuid6 import uuid7

from restling_server.core.database import Base


class User(Base):
    """Persisted server user account."""

    __tablename__ = "users"

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'active', 'suspended')",
            name="ck_users_status",
        ),
        CheckConstraint(
            "system_role IN ('administrator', 'user')",
            name="ck_users_system_role",
        ),
        CheckConstraint(
            """
            (status = 'pending' AND password_hash IS NULL)
            OR
            (
                status IN ('active', 'suspended')
                AND password_hash IS NOT NULL
                AND LENGTH(TRIM(password_hash)) > 0
            )
            """,
            name="ck_users_password_state",
        ),
        UniqueConstraint(
            "normalized_email",
            name="users_normalized_email_key",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        primary_key=True,
        default=uuid7,
    )

    email: Mapped[str] = mapped_column(Text, nullable=False)

    normalized_email: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    display_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    job_title: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    password_hash: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    password_reset_required: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
    )

    system_role: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="user",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class OneTimeToken(Base):
    """One-time credentials for account-related operations."""

    __tablename__ = "one_time_tokens"

    __table_args__ = (
        CheckConstraint(
            "purpose IN ('account_activation', 'password_reset', 'email_change')",
            name="ck_one_time_tokens_purpose",
        ),
        CheckConstraint(
            "LENGTH(TRIM(token_hash)) > 0",
            name="ck_one_time_tokens_hash_not_empty",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_one_time_tokens_expiry",
        ),
        CheckConstraint(
            """
            (purpose = 'email_change'
                AND pending_email IS NOT NULL
                AND LENGTH(TRIM(pending_email)) > 0)
            OR
            (purpose != 'email_change' AND pending_email IS NULL)
            """,
            name="ck_one_time_tokens_pending_email",
        ),
        CheckConstraint(
            "consumed_at IS NULL OR revoked_at IS NULL",
            name="ck_one_time_tokens_terminal_state",
        ),
        UniqueConstraint(
            "token_hash",
            name="one_time_tokens_token_hash_key",
        ),
        Index("ix_one_time_tokens_user_id", "user_id"),
        Index("ix_one_time_tokens_expires_at", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        primary_key=True,
        default=uuid7,
    )

    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )

    purpose: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    token_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    pending_email: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class LoginSession(Base):
    """A login session with one current refresh credential."""

    __tablename__ = "sessions"

    __table_args__ = (
        CheckConstraint(
            "expires_at > created_at",
            name="ck_sessions_expiry",
        ),
        CheckConstraint(
            """
            revoked_at IS NULL
            OR (
                refresh_token_hash IS NULL
                AND revocation_reason IS NOT NULL
                AND LENGTH(TRIM(revocation_reason)) > 0
            )
            """,
            name="ck_sessions_revocation",
        ),
        CheckConstraint(
            """
            refresh_token_hash IS NULL
            OR LENGTH(TRIM(refresh_token_hash)) > 0
            """,
            name="ck_sessions_refresh_hash_not_empty",
        ),
        UniqueConstraint(
            "refresh_token_hash",
            name="sessions_refresh_token_hash_key",
        ),
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_expires_at", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        primary_key=True,
        default=uuid7,
    )

    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )

    refresh_token_hash: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revocation_reason: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    login_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    last_seen_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    machine_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )


class AccessToken(Base):
    """An opaque access credential associated with a login session."""

    __tablename__ = "access_tokens"

    __table_args__ = (
        CheckConstraint(
            "expires_at > created_at",
            name="ck_access_tokens_expiry",
        ),
        CheckConstraint(
            "LENGTH(TRIM(token_hash)) > 0",
            name="ck_access_tokens_hash_not_empty",
        ),
        UniqueConstraint(
            "token_hash",
            name="access_tokens_token_hash_key",
        ),
        Index("ix_access_tokens_expires_at", "expires_at"),
        Index("ix_access_tokens_session_id", "session_id"),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        primary_key=True,
        default=uuid7,
    )

    session_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )

    token_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    issued_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )


class RefreshTokenHistory(Base):
    """A consumed refresh credential retained for replay detection."""

    __tablename__ = "refresh_token_history"

    __table_args__ = (
        CheckConstraint(
            "LENGTH(TRIM(token_hash)) > 0",
            name="ck_refresh_token_history_hash_not_empty",
        ),
        UniqueConstraint(
            "token_hash",
            name="refresh_token_history_token_hash_key",
        ),
        Index(
            "ix_refresh_token_history_session_id",
            "session_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        primary_key=True,
        default=uuid7,
    )

    session_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )

    token_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )


class AuditLog(Base):
    """Historical record of a security-relevant event."""

    __tablename__ = "audit_logs"

    __table_args__ = (
        CheckConstraint(
            "LENGTH(TRIM(action)) > 0",
            name="ck_audit_logs_action_not_empty",
        ),
        Index(
            "ix_audit_logs_created_at_id",
            "created_at",
            "id",
        ),
        Index(
            "ix_audit_logs_actor_created_at",
            "actor_user_id",
            "created_at",
        ),
        Index(
            "ix_audit_logs_target_created_at",
            "target_user_id",
            "created_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        primary_key=True,
        default=uuid7,
    )

    actor_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        nullable=True,
    )

    target_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True, native_uuid=True),
        nullable=True,
    )

    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
    )

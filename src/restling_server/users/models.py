"""SQLAlchemy persistence models for user identity."""

from datetime import UTC, datetime
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

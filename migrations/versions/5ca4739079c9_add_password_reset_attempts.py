"""add password reset attempts

Revision ID: 5ca4739079c9
Revises: 775afb7c626a
Create Date: 2026-11-26 14:51:10.462222

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "5ca4739079c9"
down_revision: str | Sequence[str] | None = "775afb7c626a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "password_reset_attempts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email_key", sa.String(length=64), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "LENGTH(TRIM(source_ip)) > 0",
            name="ck_password_reset_attempts_source_ip_not_empty",
        ),
        sa.CheckConstraint(
            "LENGTH(email_key) = 64",
            name="ck_password_reset_attempts_email_key_length",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_password_reset_attempts_created_at",
        "password_reset_attempts",
        ["created_at"],
        unique=False,
    )

    op.create_index(
        "ix_password_reset_attempts_email_created_at",
        "password_reset_attempts",
        ["email_key", "created_at"],
        unique=False,
    )

    op.create_index(
        "ix_password_reset_attempts_ip_created_at",
        "password_reset_attempts",
        ["source_ip", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        "ix_password_reset_attempts_ip_created_at",
        table_name="password_reset_attempts",
    )

    op.drop_index(
        "ix_password_reset_attempts_email_created_at",
        table_name="password_reset_attempts",
    )

    op.drop_index(
        "ix_password_reset_attempts_created_at",
        table_name="password_reset_attempts",
    )

    op.drop_table("password_reset_attempts")

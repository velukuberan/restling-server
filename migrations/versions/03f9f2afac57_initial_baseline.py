"""initial baseline

Revision ID: 03f9f2afac57
Revises:
Create Date: 2026-11-11 21:30:43.287495

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "03f9f2afac57"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass

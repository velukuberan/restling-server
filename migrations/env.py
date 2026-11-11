"""Alembic migration environment."""

from alembic import context

from restling_server.core.config import Settings
from restling_server.core.database import create_database_engine

# ORM metadata will be registered when models are introduced.
target_metadata = None


def run_migrations_online() -> None:
    """Run migrations using the configured PostgreSQL engine."""
    engine = create_database_engine(Settings())

    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
            )

            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("Offline migrations are not configured.")
else:
    run_migrations_online()

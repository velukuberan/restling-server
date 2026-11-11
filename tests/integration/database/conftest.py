"""Fixtures for PostgreSQL integration tests."""

from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.core.database import (
    create_database_engine,
)


@pytest.fixture
def db_session() -> Iterator[Session]:
    """Provide an isolated PostgreSQL test session."""
    settings = Settings()  # pyright: ignore[reportCallIssue]

    test_database = "restling_test"

    if settings.postgres_db == test_database:
        raise RuntimeError("Application database must differ from test database.")

    test_settings = settings.model_copy(update={"postgres_db": test_database})

    engine = create_database_engine(test_settings)

    try:
        with engine.connect() as connection:
            connected_database = connection.execute(
                text("SELECT current_database()")
            ).scalar_one()

            if connected_database != test_database:
                raise RuntimeError("Unsafe test database connection.")

            # End the implicit read transaction.
            connection.rollback()

            transaction = connection.begin()

            try:
                with Session(
                    bind=connection,
                    join_transaction_mode="create_savepoint",
                ) as session:
                    yield session
            finally:
                transaction.rollback()
    finally:
        engine.dispose()

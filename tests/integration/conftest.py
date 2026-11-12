"""Fixtures for PostgreSQL integration tests."""

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.core.database import create_database_engine


@pytest.fixture
def test_engine() -> Iterator[Engine]:
    """Create a verified PostgreSQL test database engine."""
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

        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_session(test_engine: Engine) -> Iterator[Session]:
    """Provide a rollback-isolated PostgreSQL test session."""
    with test_engine.connect() as connection:
        transaction = connection.begin()

        try:
            with Session(
                bind=connection,
                join_transaction_mode="create_savepoint",
            ) as session:
                yield session
        finally:
            transaction.rollback()

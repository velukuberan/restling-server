"""Fixtures for isolated PostgreSQL integration tests."""

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.core.database import create_database_engine


@pytest.fixture(scope="session")
def migrated_test_template() -> Iterator[tuple[Settings, Engine, str]]:
    """Prepare one migrated PostgreSQL template for the test session."""
    settings = Settings()  # pyright: ignore[reportCallIssue]

    if (
        settings.postgres_host not in {"127.0.0.1", "localhost", "::1"}
        or settings.postgres_db != "restling_dev"
    ):
        raise RuntimeError(
            "Integration tests require a local restling_dev configuration."
        )

    template_name = f"restling_test_template_{uuid4().hex}"

    maintenance_settings = settings.model_copy(update={"postgres_db": "postgres"})
    template_settings = settings.model_copy(update={"postgres_db": template_name})

    maintenance_engine = create_database_engine(maintenance_settings)
    template_created = False

    try:
        with maintenance_engine.connect() as connection:
            connection = connection.execution_options(isolation_level="AUTOCOMMIT")
            connection.exec_driver_sql(f'CREATE DATABASE "{template_name}"')
            template_created = True

        # Apply Alembic migrations once per pytest session.
        migration_environment = os.environ.copy()
        migration_environment["POSTGRES_DB"] = template_name

        project_root = Path(__file__).resolve().parents[2]

        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=project_root,
            env=migration_environment,
            check=True,
        )

        # Check the migrated template before cloning it.
        template_engine = create_database_engine(template_settings)

        try:
            with template_engine.connect() as connection:
                connected_database = connection.scalar(
                    text("SELECT current_database()")
                )

                if connected_database != template_name:
                    raise RuntimeError("Unsafe test template connection.")
        finally:
            template_engine.dispose()

        yield settings, maintenance_engine, template_name

    finally:
        try:
            if template_created:
                with maintenance_engine.connect() as connection:
                    connection = connection.execution_options(
                        isolation_level="AUTOCOMMIT"
                    )
                    connection.exec_driver_sql(
                        f'DROP DATABASE "{template_name}" WITH (FORCE)'
                    )
        finally:
            maintenance_engine.dispose()


@pytest.fixture
def test_engine(
    migrated_test_template: tuple[Settings, Engine, str],
) -> Iterator[Engine]:
    """Provide a fresh PostgreSQL database cloned from the template."""
    settings, maintenance_engine, template_name = migrated_test_template

    test_database = f"restling_test_{uuid4().hex}"
    test_settings = settings.model_copy(update={"postgres_db": test_database})

    engine: Engine | None = None
    database_created = False

    try:
        with maintenance_engine.connect() as connection:
            connection = connection.execution_options(isolation_level="AUTOCOMMIT")
            connection.exec_driver_sql(
                f'CREATE DATABASE "{test_database}" TEMPLATE "{template_name}"'
            )
            database_created = True

        engine = create_database_engine(test_settings)

        with engine.connect() as connection:
            connected_database = connection.scalar(text("SELECT current_database()"))

            if connected_database != test_database:
                raise RuntimeError("Unsafe test database connection.")

        yield engine

    finally:
        if engine is not None:
            engine.dispose()

        if database_created:
            with maintenance_engine.connect() as connection:
                connection = connection.execution_options(isolation_level="AUTOCOMMIT")
                connection.exec_driver_sql(
                    f'DROP DATABASE "{test_database}" WITH (FORCE)'
                )


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

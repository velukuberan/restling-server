"""Shared PostgreSQL connection and session infrastructure."""

from sqlalchemy import URL, Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from restling_server.core.config import Settings


def create_database_engine(settings: Settings) -> Engine:
    """Create a PostgreSQL engine using validated configuration."""
    database_url = URL.create(
        drivername="postgresql+psycopg",
        username=settings.postgres_user,
        password=settings.postgres_password.get_secret_value(),
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
    )

    return create_engine(database_url, pool_pre_ping=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a factory for independent synchronous DB sessions."""
    return sessionmaker(bind=engine, expire_on_commit=False)

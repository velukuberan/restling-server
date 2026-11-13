"""FastAPI dependencies for shared infrastructure."""

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session, sessionmaker


def get_db_session(request: Request) -> Iterator[Session]:
    """Provide an independent database session per request."""
    session_factory: sessionmaker[Session] = request.app.state.session_factory

    with session_factory() as session:
        yield session

"""Shared fixtures for HTTP integration tests."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from restling_server.core.dependencies import get_db_session
from restling_server.main import app


@pytest.fixture
def api_client(test_engine: Engine) -> Iterator[TestClient]:
    """Provide an HTTP client connected to the verified test database."""

    def override_db_session() -> Iterator[Session]:
        with Session(test_engine) as session:
            yield session

    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)

"""HTTP integration tests for authenticated user profiles."""

from collections.abc import Iterator

from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.core.dependencies import get_db_session
from restling_server.main import app
from restling_server.users.models import User
from restling_server.users.passwords import hash_password
from restling_server.users.service import login_user, logout_session


def test_get_my_profile_requires_valid_access_token(
    test_engine: Engine,
) -> None:
    """Only a valid active session may access the user profile."""
    password = "A secure test passphrase #8472"
    email = f"profile-{uuid7().hex}@example.com"

    def override_db_session() -> Iterator[Session]:
        with Session(test_engine) as session:
            yield session

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Profile User",
            job_title="Backend Engineer",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add(user)
        session.commit()
        user_id = user.id

    with Session(test_engine) as session:
        login = login_user(
            session,
            email=email,
            password=password,
            access_token_expiry_minutes=15,
            refresh_session_expiry_days=7,
            max_active_sessions=2,
        )

    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app) as client:
            # Missing bearer credential.
            missing = client.get("/api/v1/users/me")

            assert missing.status_code == 401
            assert missing.json()["error"]["code"] == "UNAUTHORIZED"
            assert missing.headers["www-authenticate"] == "Bearer"

            # Invalid access credential.
            invalid = client.get(
                "/api/v1/users/me",
                headers={"Authorization": "Bearer invalid-token"},
            )

            assert invalid.status_code == 401

            # A refresh token is not an access token.
            wrong_token_type = client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {login.refresh_token}"},
            )

            assert wrong_token_type.status_code == 401

            # Valid access credential.
            valid = client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {login.access_token}"},
            )

            assert valid.status_code == 200

            data = valid.json()["data"]

            assert data["id"] == str(user_id)
            assert data["email"] == email
            assert data["display_name"] == "Profile User"
            assert data["job_title"] == "Backend Engineer"
            assert data["status"] == "active"
            assert data["system_role"] == "user"
            assert data["password_reset_required"] is False

            assert "password_hash" not in data
            assert "access_token" not in data
            assert "refresh_token" not in data

            # Revoking the session immediately invalidates access.
            with Session(test_engine) as session:
                logout_session(
                    session,
                    access_token=login.access_token,
                )

            revoked = client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {login.access_token}"},
            )

            assert revoked.status_code == 401

    finally:
        app.dependency_overrides.pop(get_db_session, None)

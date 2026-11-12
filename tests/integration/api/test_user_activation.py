"""HTTP integration tests for account activation."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.core.dependencies import get_db_session
from restling_server.main import app
from restling_server.users.models import OneTimeToken, User
from restling_server.users.passwords import verify_password
from restling_server.users.service import issue_activation_token


def test_activation_endpoint_activates_user_and_rejects_replay(
    test_engine: Engine,
) -> None:
    """HTTP activation succeeds once and rejects token reuse."""
    test_id = uuid7().hex
    admin_email = f"http-admin-{test_id}@example.com"
    user_email = f"http-user-{test_id}@example.com"
    password = "A secure activation passphrase #8472"

    def override_db_session() -> Iterator[Session]:
        with Session(test_engine) as session:
            yield session

    try:
        # Prepare the account in the verified test database.
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        with Session(test_engine) as session:
            raw_token, _ = issue_activation_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_hours=24,
            )

        # Route database operations to restling_test.
        app.dependency_overrides[get_db_session] = override_db_session

        with TestClient(app) as client:
            response = client.post(
                "/api/v1/auth/activate",
                json={
                    "token": raw_token,
                    "password": password,
                },
            )

            assert response.status_code == 200
            assert response.json() == {"message": "Account activated successfully."}
            assert response.headers["cache-control"] == "no-store"

            # The same activation credential cannot be reused.
            replay_response = client.post(
                "/api/v1/auth/activate",
                json={
                    "token": raw_token,
                    "password": password,
                },
            )

            assert replay_response.status_code == 400
            assert replay_response.json() == {
                "error": {
                    "code": "INVALID_ACTIVATION_TOKEN",
                    "message": "Invalid or expired activation credential.",
                }
            }
            assert replay_response.headers["cache-control"] == "no-store"

        # Verify the committed database state.
        with Session(test_engine) as session:
            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "active"
            assert user.password_hash is not None
            assert verify_password(password, user.password_hash)
            assert user.activated_at is not None

            tokens = session.scalars(
                select(OneTimeToken).where(OneTimeToken.user_id == user_id)
            ).all()

            assert len(tokens) == 1
            assert tokens[0].consumed_at is not None

    finally:
        app.dependency_overrides.pop(get_db_session, None)

        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([admin_email, user_email])
            )

            connection.execute(
                delete(OneTimeToken).where(OneTimeToken.user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


@pytest.mark.parametrize(
    "token",
    ["", "invalid-token", "A" * 43],
)
def test_activation_endpoint_rejects_invalid_tokens(
    test_engine: Engine,
    token: str,
) -> None:
    """Invalid activation credentials return the agreed HTTP error."""

    def override_db_session() -> Iterator[Session]:
        with Session(test_engine) as session:
            yield session

    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/auth/activate",
                json={
                    "token": token,
                    "password": "A secure activation passphrase #8472",
                },
            )

        expected_code = (
            "VALIDATION_ERROR" if token == "" else "INVALID_ACTIVATION_TOKEN"
        )

        assert response.status_code == (422 if token == "" else 400)
        assert response.json()["error"]["code"] == expected_code
        assert response.headers["cache-control"] == "no-store"

    finally:
        app.dependency_overrides.pop(get_db_session, None)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"token": "some-token"},
        {"password": "some-password"},
        {"token": 123, "password": "some-password"},
        {"token": "some-token", "password": None},
    ],
)
def test_activation_endpoint_rejects_malformed_requests(
    payload: dict[str, object],
) -> None:
    """Malformed activation requests use the standard error envelope."""

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/activate",
            json=payload,
        )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Invalid request data.",
        }
    }
    assert response.headers["cache-control"] == "no-store"


def test_activation_endpoint_rejects_weak_password_without_consuming_token(
    test_engine: Engine,
) -> None:
    """A password-policy error leaves the activation credential usable."""
    test_id = uuid7().hex
    admin_email = f"http-password-admin-{test_id}@example.com"
    user_email = f"http-password-user-{test_id}@example.com"

    valid_password = "A secure activation passphrase #8472"

    def override_db_session() -> Iterator[Session]:
        with Session(test_engine) as session:
            yield session

    try:
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        with Session(test_engine) as session:
            raw_token, _ = issue_activation_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_hours=24,
            )

        app.dependency_overrides[get_db_session] = override_db_session

        with TestClient(app) as client:
            response = client.post(
                "/api/v1/auth/activate",
                json={
                    "token": raw_token,
                    "password": "short",
                },
            )

            assert response.status_code == 422
            assert response.json() == {
                "error": {
                    "code": "PASSWORD_POLICY_VIOLATION",
                    "message": "Password does not meet the required policy.",
                }
            }
            assert response.headers["cache-control"] == "no-store"

            # The same token must remain usable.
            retry_response = client.post(
                "/api/v1/auth/activate",
                json={
                    "token": raw_token,
                    "password": valid_password,
                },
            )

            assert retry_response.status_code == 200

        with Session(test_engine) as session:
            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "active"
            assert user.password_hash is not None
            assert verify_password(valid_password, user.password_hash)

            tokens = session.scalars(
                select(OneTimeToken).where(OneTimeToken.user_id == user_id)
            ).all()

            assert len(tokens) == 1
            assert tokens[0].consumed_at is not None

    finally:
        app.dependency_overrides.pop(get_db_session, None)

        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([admin_email, user_email])
            )

            connection.execute(
                delete(OneTimeToken).where(OneTimeToken.user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )

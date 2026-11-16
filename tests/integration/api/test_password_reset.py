"""HTTP integration tests for password recovery."""

from collections.abc import Iterator

from fastapi.testclient import TestClient
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.core.dependencies import get_db_session
from restling_server.main import app
from restling_server.users.models import OneTimeToken, User
from restling_server.users.passwords import verify_password
from restling_server.users.service import issue_password_reset_token
from restling_server.users.tokens import hash_token


def test_reset_password_endpoint_succeeds_and_rejects_replay(
    test_engine: Engine,
) -> None:
    """HTTP password recovery succeeds once and rejects reuse."""
    test_id = uuid7().hex
    admin_email = f"http-reset-admin-{test_id}@example.com"
    user_email = f"http-reset-user-{test_id}@example.com"
    new_password = "A secure replacement passphrase #8472"

    def override_db_session() -> Iterator[Session]:
        with Session(test_engine) as session:
            yield session

    try:
        # Prepare two independent accounts in PostgreSQL.
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Reset User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
                password_reset_required=True,
            )

            session.add_all([administrator, user])
            session.commit()

            administrator_id = administrator.id
            user_id = user.id

        with Session(test_engine) as session:
            raw_token, _ = issue_password_reset_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_minutes=30,
            )

        app.dependency_overrides[get_db_session] = override_db_session

        with TestClient(app) as client:
            response = client.post(
                "/api/v1/auth/reset-password",
                json={
                    "token": raw_token,
                    "new_password": new_password,
                },
            )

            assert response.status_code == 200
            assert response.json() == {"message": "Password reset successfully."}
            assert response.headers["cache-control"] == "no-store"

            # A consumed credential cannot be used a second time.
            replay_response = client.post(
                "/api/v1/auth/reset-password",
                json={
                    "token": raw_token,
                    "new_password": "Another secure passphrase #9382",
                },
            )

            assert replay_response.status_code == 400
            assert replay_response.json() == {
                "error": {
                    "code": "INVALID_PASSWORD_RESET_TOKEN",
                    "message": "Invalid or expired password-reset credential.",
                }
            }
            assert replay_response.headers["cache-control"] == "no-store"

        # Verify the actual committed database state.
        with Session(test_engine) as session:
            stored_user = session.get(User, user_id)

            assert stored_user is not None
            assert stored_user.password_hash is not None
            assert verify_password(new_password, stored_user.password_hash)
            assert stored_user.password_reset_required is False
            assert stored_user.status == "active"

            stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.token_hash == hash_token(raw_token)
                )
            )

            assert stored_token is not None
            assert stored_token.consumed_at is not None
            assert stored_token.revoked_at is None

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

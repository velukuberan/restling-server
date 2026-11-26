"""HTTP integration tests for administrator-assisted password recovery."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from time import monotonic, sleep
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import AnyHttpUrl
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.main import app
from restling_server.users.models import (
    AccessToken,
    AuditLog,
    LoginSession,
    OneTimeToken,
    User,
)
from restling_server.users.passwords import hash_password
from restling_server.users.tokens import hash_token


@pytest.fixture
def accounts(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, str]:
    """Create administrator and ordinary-user accounts."""
    key = uuid7().hex
    password = "A secure password recovery test passphrase #8472"

    administrator_email = f"reset-admin-{key}@example.com"
    user_email = f"reset-user-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=administrator_email,
            normalized_email=administrator_email,
            display_name="Recovery Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )

        user = User(
            email=user_email,
            normalized_email=user_email,
            display_name="Recovery User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, user])
        session.flush()

        administrator_id = administrator.id
        user_id = user.id

        session.commit()

    monkeypatch.setattr(
        app.state.settings,
        "public_url",
        AnyHttpUrl("http://127.0.0.1:8000"),
    )
    monkeypatch.setattr(
        app.state.settings,
        "password_reset_expiry_minutes",
        30,
    )
    monkeypatch.setattr(app.state.settings, "smtp_host", None)
    monkeypatch.setattr(app.state.settings, "smtp_from_email", None)

    def login(email: str) -> str:
        response = api_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )

        assert response.status_code == 200

        return str(response.json()["data"]["access_token"])

    return {
        "administrator_id": str(administrator_id),
        "user_id": str(user_id),
        "administrator_token": login(administrator_email),
        "user_token": login(user_email),
    }


def auth(token: str) -> dict[str, str]:
    """Build the Authorization header."""
    return {"Authorization": f"Bearer {token}"}


def test_administrator_can_issue_password_reset_link(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """An administrator receives a manually deliverable reset link."""
    user_id = UUID(accounts["user_id"])

    response = api_client.post(
        f"/api/v1/users/{user_id}/reset-password",
        headers=auth(accounts["administrator_token"]),
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    data = response.json()["data"]

    assert data["delivery"] == "manual"
    assert data["expires_at"]

    reset_url_value: str = data["reset_url"]
    assert isinstance(reset_url_value, str)

    reset_url = urlsplit(reset_url_value)

    assert reset_url.scheme == "http"
    assert reset_url.netloc == "127.0.0.1:8000"
    assert reset_url.path == "/reset-password"

    raw_token = parse_qs(reset_url.query)["token"][0]

    with Session(test_engine) as session:
        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        )

        assert stored_token is not None
        assert stored_token.token_hash == hash_token(raw_token)
        assert stored_token.token_hash != raw_token
        assert stored_token.consumed_at is None
        assert stored_token.revoked_at is None
        assert stored_token.pending_email is None

        assert stored_token.expires_at - stored_token.created_at == timedelta(
            minutes=30
        )

        assert stored_token.expires_at == datetime.fromisoformat(data["expires_at"])

        audit_event = session.scalar(
            select(AuditLog).where(
                AuditLog.actor_user_id == UUID(accounts["administrator_id"]),
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        )

        assert audit_event is not None


@pytest.mark.parametrize("token", [None, "invalid-token"])
def test_password_reset_requires_authentication(
    api_client: TestClient,
    accounts: dict[str, str],
    token: str | None,
) -> None:
    """Missing or invalid access credentials are rejected."""
    headers = auth(token) if token is not None else {}

    response = api_client.post(
        f"/api/v1/users/{accounts['user_id']}/reset-password",
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_regular_user_cannot_issue_password_reset_link(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Ordinary users cannot issue administrator reset links."""
    response = api_client.post(
        f"/api/v1/users/{accounts['administrator_id']}/reset-password",
        headers=auth(accounts["user_token"]),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_password_reset_rejects_unknown_user(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An administrator cannot issue a reset link for an unknown user."""
    response = api_client.post(
        f"/api/v1/users/{uuid7()}/reset-password",
        headers=auth(accounts["administrator_token"]),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "USER_NOT_FOUND"


def test_password_reset_rejects_pending_user(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Pending accounts require activation rather than password recovery."""
    email = f"pending-reset-{uuid7().hex}@example.com"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Pending Recovery User",
            status="pending",
            system_role="user",
        )

        session.add(user)
        session.flush()

        user_id = user.id

        session.commit()

    response = api_client.post(
        f"/api/v1/users/{user_id}/reset-password",
        headers=auth(accounts["administrator_token"]),
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PASSWORD_RESET_NOT_ALLOWED"


def test_administrator_can_issue_reset_link_for_suspended_user(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Suspended accounts remain eligible for password recovery."""
    headers = auth(accounts["administrator_token"])
    user_id = accounts["user_id"]

    suspension = api_client.post(
        f"/api/v1/users/{user_id}/suspend",
        headers=headers,
    )

    assert suspension.status_code == 204

    response = api_client.post(
        f"/api/v1/users/{user_id}/reset-password",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["data"]["delivery"] == "manual"


def test_reissuing_password_reset_revokes_previous_token(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Only the latest issued password-reset credential remains usable."""
    user_id = UUID(accounts["user_id"])
    headers = auth(accounts["administrator_token"])
    endpoint = f"/api/v1/users/{user_id}/reset-password"

    first_response = api_client.post(endpoint, headers=headers)
    assert first_response.status_code == 200

    second_response = api_client.post(endpoint, headers=headers)
    assert second_response.status_code == 200

    first_url_value: str = first_response.json()["data"]["reset_url"]
    second_url_value: str = second_response.json()["data"]["reset_url"]

    assert isinstance(first_url_value, str)
    assert isinstance(second_url_value, str)

    first_url = urlsplit(first_url_value)
    second_url = urlsplit(second_url_value)

    first_token = parse_qs(first_url.query)["token"][0]
    second_token = parse_qs(second_url.query)["token"][0]

    assert first_token != second_token

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 2

        previous = next(
            token for token in tokens if token.token_hash == hash_token(first_token)
        )

        replacement = next(
            token for token in tokens if token.token_hash == hash_token(second_token)
        )

        assert previous.revoked_at is not None
        assert previous.consumed_at is None

        assert replacement.revoked_at is None
        assert replacement.consumed_at is None


def test_issuing_password_reset_preserves_existing_session(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Issuing a reset link alone does not invalidate existing sessions."""
    response = api_client.post(
        f"/api/v1/users/{accounts['user_id']}/reset-password",
        headers=auth(accounts["administrator_token"]),
    )

    assert response.status_code == 200

    profile = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["user_token"]),
    )

    assert profile.status_code == 200
    assert profile.json()["data"]["password_reset_required"] is False


def test_password_reset_requires_configured_public_url(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing URL configuration must not create a reset credential."""
    monkeypatch.setattr(app.state.settings, "public_url", None)

    response = api_client.post(
        f"/api/v1/users/{accounts['user_id']}/reset-password",
        headers=auth(accounts["administrator_token"]),
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PASSWORD_RESET_UNAVAILABLE"

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == UUID(accounts["user_id"]),
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert tokens == []


def test_concurrent_password_reset_requests_leave_one_usable_token(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Concurrent reset requests must leave only one usable credential."""
    user_id = UUID(accounts["user_id"])
    administrator_id = UUID(accounts["administrator_id"])
    headers = auth(accounts["administrator_token"])

    barrier = Barrier(2)

    def issue_reset() -> str:
        barrier.wait(timeout=10)

        response = api_client.post(
            f"/api/v1/users/{user_id}/reset-password",
            headers=headers,
        )

        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"

        reset_url: str = response.json()["data"]["reset_url"]
        assert isinstance(reset_url, str)

        return parse_qs(urlsplit(reset_url).query)["token"][0]

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(issue_reset)
        second_future = executor.submit(issue_reset)

        first_token = first_future.result(timeout=20)
        second_token = second_future.result(timeout=20)

    assert first_token != second_token

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 2

        usable_tokens = [
            token
            for token in tokens
            if token.revoked_at is None
            and token.consumed_at is None
            and token.expires_at > datetime.now(UTC)
        ]

        assert len(usable_tokens) == 1

        revoked_tokens = [token for token in tokens if token.revoked_at is not None]

        assert len(revoked_tokens) == 1

        assert {token.token_hash for token in tokens} == {
            hash_token(first_token),
            hash_token(second_token),
        }

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == administrator_id,
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 2


def test_revoked_administrator_session_cannot_issue_password_reset(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """A revoked administrator session cannot issue reset credentials."""
    headers = auth(accounts["administrator_token"])
    user_id = UUID(accounts["user_id"])

    logout = api_client.post(
        "/api/v1/auth/logout",
        headers=headers,
    )

    assert logout.status_code == 204

    response = api_client.post(
        f"/api/v1/users/{user_id}/reset-password",
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert tokens == []


def test_expired_administrator_token_cannot_issue_password_reset(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """An expired administrator access token cannot authorize recovery."""
    administrator_token = accounts["administrator_token"]
    user_id = UUID(accounts["user_id"])

    with Session(test_engine) as session:
        with session.begin():
            access_token = session.scalar(
                select(AccessToken).where(
                    AccessToken.token_hash == hash_token(administrator_token)
                )
            )

            assert access_token is not None

            now = datetime.now(UTC)

            access_token.created_at = now - timedelta(minutes=20)
            access_token.expires_at = now - timedelta(minutes=5)

    response = api_client.post(
        f"/api/v1/users/{user_id}/reset-password",
        headers=auth(administrator_token),
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert tokens == []


def test_password_reset_authorization_precedes_configuration(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unauthorized users cannot discover reset-link configuration."""
    monkeypatch.setattr(app.state.settings, "public_url", None)

    administrator_id = UUID(accounts["administrator_id"])

    response = api_client.post(
        f"/api/v1/users/{administrator_id}/reset-password",
        headers=auth(accounts["user_token"]),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == administrator_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert tokens == []


def test_failed_password_reset_reissue_preserves_previous_token(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed replacement must preserve the previous reset credential."""
    user_id = UUID(accounts["user_id"])
    administrator_id = UUID(accounts["administrator_id"])

    headers = auth(accounts["administrator_token"])
    endpoint = f"/api/v1/users/{user_id}/reset-password"

    first_response = api_client.post(
        endpoint,
        headers=headers,
    )

    assert first_response.status_code == 200

    reset_url: str = first_response.json()["data"]["reset_url"]
    assert isinstance(reset_url, str)

    first_token = parse_qs(urlsplit(reset_url).query)["token"][0]

    monkeypatch.setattr(app.state.settings, "public_url", None)

    second_response = api_client.post(
        endpoint,
        headers=headers,
    )

    assert second_response.status_code == 503
    assert second_response.json()["error"]["code"] == ("PASSWORD_RESET_UNAVAILABLE")
    assert second_response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1

        original_token = tokens[0]

        assert original_token.token_hash == hash_token(first_token)
        assert original_token.revoked_at is None
        assert original_token.consumed_at is None
        assert original_token.expires_at > datetime.now(UTC)

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == administrator_id,
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 1


def test_administrator_assisted_password_recovery_completes_successfully(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """An administrator-issued token completes recovery only once."""
    user_id = UUID(accounts["user_id"])
    old_password = "A secure password recovery test passphrase #8472"
    new_password = "A new secure password recovery passphrase #9284"

    issue_response = api_client.post(
        f"/api/v1/users/{user_id}/reset-password",
        headers=auth(accounts["administrator_token"]),
    )

    assert issue_response.status_code == 200

    reset_url: str = issue_response.json()["data"]["reset_url"]
    assert isinstance(reset_url, str)

    raw_token = parse_qs(urlsplit(reset_url).query)["token"][0]

    reset_response = api_client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": raw_token,
            "new_password": new_password,
        },
    )

    assert reset_response.status_code == 200
    assert reset_response.headers["cache-control"] == "no-store"

    # Password recovery must not automatically issue login credentials.
    assert "access_token" not in reset_response.text
    assert "refresh_token" not in reset_response.text

    old_profile = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["user_token"]),
    )

    assert old_profile.status_code == 401

    # Reusing the same reset credential must fail.
    repeated_reset = api_client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": raw_token,
            "new_password": new_password,
        },
    )

    assert repeated_reset.status_code == 400
    assert repeated_reset.json()["error"]["code"] == ("INVALID_PASSWORD_RESET_TOKEN")

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_reset_required is False

        email = user.email

        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.consumed_at is not None
        assert stored_token.revoked_at is None

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_completed",
            )
        ).all()

        assert len(audit_events) == 1

    old_login = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": old_password,
        },
    )

    assert old_login.status_code == 401

    new_login = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": new_password,
        },
    )

    assert new_login.status_code == 200

    # Recovery must not invalidate the issuing administrator's session.
    administrator_profile = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["administrator_token"]),
    )

    assert administrator_profile.status_code == 200


@pytest.mark.parametrize(
    "invalidation",
    [
        "session_revoked",
        "password_reset_required",
    ],
)
def test_password_reset_revalidates_administrator_after_account_lock(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    invalidation: str,
) -> None:
    """Authorization must remain valid after acquiring account locks."""
    administrator_id = UUID(accounts["administrator_id"])
    user_id = UUID(accounts["user_id"])
    administrator_token = accounts["administrator_token"]

    def issue_reset() -> int:
        response = api_client.post(
            f"/api/v1/users/{user_id}/reset-password",
            headers=auth(administrator_token),
        )

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"
        assert response.headers["cache-control"] == "no-store"

        return response.status_code

    with ThreadPoolExecutor(max_workers=1) as executor:
        with Session(test_engine) as blocking_session:
            with blocking_session.begin():
                administrator = blocking_session.scalar(
                    select(User).where(User.id == administrator_id).with_for_update()
                )

                assert administrator is not None

                blocker_pid = blocking_session.scalar(text("SELECT pg_backend_pid()"))

                assert isinstance(blocker_pid, int)

                # The reset request must wait for the administrator
                # account lock held by this transaction.
                future = executor.submit(issue_reset)

                deadline = monotonic() + 10
                lock_wait_observed = False

                while monotonic() < deadline:
                    with test_engine.connect() as observer:
                        blocked = observer.scalar(
                            text(
                                "SELECT EXISTS ("
                                "SELECT 1 "
                                "FROM pg_stat_activity "
                                "WHERE datname = current_database() "
                                "AND :blocker_pid = ANY("
                                "pg_blocking_pids(pid)"
                                ")"
                                ")"
                            ),
                            {"blocker_pid": blocker_pid},
                        )

                    if blocked is True:
                        lock_wait_observed = True
                        break

                    if future.done():
                        # Surface an unexpected early response.
                        future.result(timeout=1)
                        break

                    sleep(0.02)

                assert lock_wait_observed, (
                    "Password-reset issuance did not wait "
                    "for the administrator account lock."
                )

                if invalidation == "session_revoked":
                    login_session = blocking_session.scalar(
                        select(LoginSession)
                        .join(
                            AccessToken,
                            AccessToken.session_id == LoginSession.id,
                        )
                        .where(
                            AccessToken.token_hash == hash_token(administrator_token)
                        )
                        .with_for_update(of=LoginSession)
                    )

                    assert login_session is not None

                    login_session.refresh_token_hash = None
                    login_session.revoked_at = datetime.now(UTC)
                    login_session.revocation_reason = "logout"

                else:
                    administrator.password_reset_required = True

                blocking_session.flush()

            # Committing releases the account lock and makes the
            # authorization change visible to the reset operation.

        assert future.result(timeout=10) == 401

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert tokens == []

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == administrator_id,
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert audit_events == []

    # The rejected operation must not affect the target user's session.
    profile = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["user_token"]),
    )

    assert profile.status_code == 200

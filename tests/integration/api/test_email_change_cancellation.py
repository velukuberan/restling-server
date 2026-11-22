"""Integration tests for email-change cancellation."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AuditLog, OneTimeToken, User
from restling_server.users.passwords import hash_password
from restling_server.users.service import cancel_email_change
from restling_server.users.tokens import hash_token


def test_user_can_cancel_pending_email_change(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Cancellation revokes pending tokens without changing the account."""
    key = uuid7().hex
    email = f"cancel-{key}@example.com"
    password = "A secure email cancellation test passphrase"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Email Cancellation Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()
        user_id = user.id

        for index in range(2):
            session.add(
                OneTimeToken(
                    user_id=user_id,
                    purpose="email_change",
                    token_hash=hash_token(f"cancel-token-{index}-{key}"),
                    pending_email=f"pending-{index}-{key}@example.com",
                    created_at=now,
                    expires_at=now + timedelta(minutes=30),
                )
            )

        session.commit()

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    response = api_client.delete(
        "/api/v1/users/me/email-change",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 204
    assert response.content == b""

    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)

        assert stored_user is not None
        assert stored_user.email == email
        assert stored_user.normalized_email == email

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        ).all()

        assert len(tokens) == 2
        assert all(token.revoked_at is not None for token in tokens)
        assert all(token.consumed_at is None for token in tokens)

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.email_change.cancelled",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == user_id

    # Cancellation must not revoke the user's login session.
    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert profile_response.status_code == 200

    # Repeated cancellation must be safe and idempotent.
    second_response = api_client.delete(
        "/api/v1/users/me/email-change",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert second_response.status_code == 204
    assert second_response.content == b""

    with Session(test_engine) as session:
        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.email_change.cancelled",
            )
        ).all()

        assert len(audit_events) == 1


def test_email_change_cancellation_requires_authentication(
    api_client: TestClient,
) -> None:
    """Missing or invalid credentials cannot cancel email changes."""
    for headers in (
        {},
        {"Authorization": "Bearer invalid-token"},
    ):
        response = api_client.delete(
            "/api/v1/users/me/email-change",
            headers=headers,
        )

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"
        assert response.headers["cache-control"] == "no-store"


def test_email_change_cancellation_preserves_other_users_tokens(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Cancelling an email change affects only the authenticated user."""
    key = uuid7().hex
    password = "A secure cross-user cancellation test passphrase"
    now = datetime.now(UTC)

    users: list[tuple[str, str]] = []

    with Session(test_engine) as session:
        for index in range(2):
            email = f"isolation-{index}-{key}@example.com"
            raw_token = f"isolation-token-{index}-{key}"

            user = User(
                email=email,
                normalized_email=email,
                display_name=f"Isolation Test User {index}",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.flush()

            session.add(
                OneTimeToken(
                    user_id=user.id,
                    purpose="email_change",
                    token_hash=hash_token(raw_token),
                    pending_email=f"isolation-new-{index}-{key}@example.com",
                    created_at=now,
                    expires_at=now + timedelta(minutes=30),
                )
            )

            users.append((email, raw_token))

        session.commit()

    # Authenticate User A.
    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": users[0][0], "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    # Cancel User A's email change.
    response = api_client.delete(
        "/api/v1/users/me/email-change",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 204

    with Session(test_engine) as session:
        first_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(users[0][1]),
            )
        )
        second_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(users[1][1]),
            )
        )

        assert first_token is not None
        assert first_token.revoked_at is not None
        assert first_token.consumed_at is None

        assert second_token is not None
        assert second_token.revoked_at is None
        assert second_token.consumed_at is None

        for email, _ in users:
            stored_user = session.scalar(
                select(User).where(User.normalized_email == email)
            )

            assert stored_user is not None
            assert stored_user.email == email


def test_concurrent_email_change_cancellation_is_idempotent(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Concurrent cancellation must revoke tokens only once."""
    key = uuid7().hex
    email = f"concurrent-cancel-{key}@example.com"
    password = "A secure concurrent cancellation test passphrase"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Concurrent Cancellation Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()
        user_id = user.id

        for index in range(2):
            session.add(
                OneTimeToken(
                    user_id=user_id,
                    purpose="email_change",
                    token_hash=hash_token(f"concurrent-cancel-{index}-{key}"),
                    pending_email=f"new-{index}-{key}@example.com",
                    created_at=now,
                    expires_at=now + timedelta(minutes=30),
                )
            )

        session.commit()

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    barrier = Barrier(2)

    def cancel() -> int:
        barrier.wait()

        response = api_client.delete(
            "/api/v1/users/me/email-change",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(cancel)
        second = executor.submit(cancel)

        results = [first.result(), second.result()]

    assert results == [204, 204]

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        ).all()

        assert len(tokens) == 2
        assert all(token.revoked_at is not None for token in tokens)
        assert all(token.consumed_at is None for token in tokens)

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.email_change.cancelled",
            )
        ).all()

        assert len(audit_events) == 1

        stored_user = session.get(User, user_id)

        assert stored_user is not None
        assert stored_user.email == email


def test_email_change_cancellation_rolls_back_on_failure(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A transaction failure must preserve pending verification tokens."""
    key = uuid7().hex
    email = f"rollback-cancel-{key}@example.com"
    password = "A secure cancellation rollback test passphrase"
    raw_token = f"rollback-token-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Cancellation Rollback Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()
        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=f"new-{key}@example.com",
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    def fail_after_flush(
        _session: Session,
        _flush_context: object,
    ) -> None:
        raise RuntimeError("Simulated cancellation failure")

    with Session(test_engine) as session:
        event.listen(session, "after_flush_postexec", fail_after_flush)

        with pytest.raises(
            RuntimeError,
            match="Simulated cancellation failure",
        ):
            cancel_email_change(
                session,
                access_token=access_token,
            )

    # Inspect committed state using a fresh database session.
    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)

        assert stored_user is not None
        assert stored_user.email == email

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert stored_token is not None
        assert stored_token.revoked_at is None
        assert stored_token.consumed_at is None

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.email_change.cancelled",
            )
        ).all()

        assert audit_events == []

    # A failed cancellation must not invalidate authentication.
    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert profile_response.status_code == 200


def test_cancelled_email_change_token_cannot_be_verified(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Cancellation prevents later verification of the same token."""
    key = uuid7().hex
    email = f"cancel-verify-{key}@example.com"
    new_email = f"cancel-verify-new-{key}@example.com"
    password = "A secure cancellation verification test passphrase"
    raw_token = f"cancel-verify-token-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Cancellation Verification Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()
        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    cancellation_response = api_client.delete(
        "/api/v1/users/me/email-change",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert cancellation_response.status_code == 204

    verification_response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": raw_token},
    )

    assert verification_response.status_code == 400
    assert verification_response.json()["error"]["code"] == "INVALID_EMAIL_CHANGE_TOKEN"

    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)

        assert stored_user is not None
        assert stored_user.email == email
        assert stored_user.normalized_email == email

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert stored_token is not None
        assert stored_token.revoked_at is not None
        assert stored_token.consumed_at is None


def test_concurrent_cancellation_and_verification_are_consistent(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Cancellation and verification cannot both consume the same token."""
    key = uuid7().hex
    old_email = f"race-old-{key}@example.com"
    new_email = f"race-new-{key}@example.com"
    password = "A secure concurrent cancellation verification passphrase"
    raw_token = f"race-verification-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Cancellation Verification Race User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()
        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": old_email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    barrier = Barrier(2)

    def cancel() -> int:
        barrier.wait()
        response = api_client.delete(
            "/api/v1/users/me/email-change",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        return response.status_code

    def verify() -> int:
        barrier.wait()
        response = api_client.post(
            "/api/v1/auth/verify-email-change",
            json={"token": raw_token},
        )
        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        cancellation_future = executor.submit(cancel)
        verification_future = executor.submit(verify)

        cancellation_status = cancellation_future.result()
        verification_status = verification_future.result()

    assert (cancellation_status, verification_status) in {
        (204, 400),
        (401, 200),
    }

    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)
        assert stored_user is not None

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )
        assert stored_token is not None

        if verification_status == 200:
            assert stored_user.email == new_email
            assert stored_token.consumed_at is not None
            assert stored_token.revoked_at is None
        else:
            assert stored_user.email == old_email
            assert stored_token.consumed_at is None
            assert stored_token.revoked_at is not None

        assert not (
            stored_token.consumed_at is not None and stored_token.revoked_at is not None
        )

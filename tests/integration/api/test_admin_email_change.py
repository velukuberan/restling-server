"""Integration tests for administrator email changes."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AuditLog, LoginSession, OneTimeToken, User
from restling_server.users.passwords import hash_password
from restling_server.users.service import change_user_email_as_administrator
from restling_server.users.tokens import hash_token


def test_administrator_can_change_active_users_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Admin change revokes target credentials and pending email links."""
    key = uuid7().hex
    password = "A secure administrator email change passphrase"
    admin_email = f"admin-email-{key}@example.com"
    old_email = f"old-email-{key}@example.com"
    new_email = f"new-email-{key}@example.com"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Target User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.flush()

        admin_id = administrator.id
        target_id = target.id

        session.add(
            OneTimeToken(
                user_id=target_id,
                purpose="email_change",
                token_hash=hash_token(f"pending-admin-change-{key}"),
                pending_email=f"other-{key}@example.com",
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    # Establish independent administrator and target-user sessions.
    admin_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    target_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": old_email, "password": password},
    )

    assert admin_login.status_code == 200
    assert target_login.status_code == 200

    admin_access_token = admin_login.json()["data"]["access_token"]
    target_access_token = target_login.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {admin_access_token}"},
        json={
            "email": new_email,
            "current_password": password,
        },
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["data"]["email"] == new_email

    with Session(test_engine) as session:
        stored_user = session.get(User, target_id)

        assert stored_user is not None
        assert stored_user.email == new_email
        assert stored_user.normalized_email == new_email
        assert stored_user.password_reset_required is False

        pending_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.user_id == target_id,
                OneTimeToken.purpose == "email_change",
            )
        )

        assert pending_token is not None
        assert pending_token.revoked_at is not None
        assert pending_token.consumed_at is None

        active_sessions = session.scalars(
            select(LoginSession).where(
                LoginSession.user_id == target_id,
                LoginSession.revoked_at.is_(None),
            )
        ).all()

        assert active_sessions == []

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert len(audit_events) == 1

    # The target's previous session must be invalidated.
    target_profile = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {target_access_token}"},
    )
    assert target_profile.status_code == 401

    # The administrator's session remains valid.
    admin_profile = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {admin_access_token}"},
    )
    assert admin_profile.status_code == 200

    # The target can sign in using the new address and unchanged password.
    new_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": new_email, "password": password},
    )
    assert new_login.status_code == 200


def test_admin_email_change_requires_authentication(
    api_client: TestClient,
) -> None:
    """Missing or invalid credentials cannot change another user's email."""
    for headers in (
        {},
        {"Authorization": "Bearer invalid-token"},
    ):
        response = api_client.patch(
            f"/api/v1/users/{uuid7()}/email",
            headers=headers,
            json={
                "email": "new@example.com",
                "current_password": "A secure test passphrase",
            },
        )

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"
        assert response.headers["cache-control"] == "no-store"


def test_regular_user_cannot_change_another_users_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Administrator email changes require administrator privileges."""
    key = uuid7().hex
    password = "A secure email authorization test passphrase"
    regular_email = f"regular-email-{key}@example.com"
    target_email = f"target-email-{key}@example.com"
    new_email = f"unauthorized-email-{key}@example.com"

    with Session(test_engine) as session:
        regular_user = User(
            email=regular_email,
            normalized_email=regular_email,
            display_name="Regular User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Target User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([regular_user, target])
        session.commit()

        target_id = target.id

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": regular_email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": new_email,
            "current_password": password,
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == target_email
        assert stored_target.normalized_email == target_email

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert audit_events == []


def test_admin_email_change_rejects_incorrect_password(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Incorrect administrator password must not modify the target."""
    key = uuid7().hex
    password = "A secure administrator password verification passphrase"
    admin_email = f"password-admin-{key}@example.com"
    target_email = f"password-target-{key}@example.com"
    new_email = f"password-new-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Target User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.commit()

        target_id = target.id

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": new_email,
            "current_password": "An intentionally incorrect password",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == target_email
        assert stored_target.normalized_email == target_email

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert audit_events == []


def test_admin_email_change_rejects_unknown_user(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Administrator email changes reject nonexistent user accounts."""
    key = uuid7().hex
    password = "A secure unknown user email change passphrase"
    admin_email = f"unknown-admin-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        session.add(administrator)
        session.commit()

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{uuid7()}/email",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": f"unknown-new-{key}@example.com",
            "current_password": password,
        },
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "USER_NOT_FOUND"
    assert response.headers["cache-control"] == "no-store"


def test_admin_email_change_rejects_existing_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An administrator cannot assign another user's email address."""
    key = uuid7().hex
    password = "A secure duplicate email change test passphrase"

    admin_email = f"duplicate-admin-{key}@example.com"
    target_email = f"duplicate-target-{key}@example.com"
    existing_email = f"duplicate-existing-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Target User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        existing_user = User(
            email=existing_email,
            normalized_email=existing_email,
            display_name="Existing User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target, existing_user])
        session.commit()
        target_id = target.id

    admin_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    target_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": target_email, "password": password},
    )

    assert admin_login.status_code == 200
    assert target_login.status_code == 200

    admin_access_token = admin_login.json()["data"]["access_token"]
    target_access_token = target_login.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {admin_access_token}"},
        json={
            "email": existing_email,
            "current_password": password,
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_ALREADY_EXISTS"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == target_email
        assert stored_target.normalized_email == target_email

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert events == []

    # A rejected email change must preserve the target's session.
    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {target_access_token}"},
    )

    assert profile_response.status_code == 200


def test_admin_email_change_is_no_op_for_unchanged_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Submitting the same email must not modify account state."""
    key = uuid7().hex
    password = "A secure email idempotency test passphrase"
    admin_email = f"idempotent-admin-{key}@example.com"
    target_email = f"idempotent-target-{key}@example.com"
    raw_token = f"idempotent-token-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Target User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.flush()
        target_id = target.id

        session.add(
            OneTimeToken(
                user_id=target_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=f"pending-{key}@example.com",
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    admin_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    target_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": target_email, "password": password},
    )

    assert admin_login.status_code == 200
    assert target_login.status_code == 200

    admin_access_token = admin_login.json()["data"]["access_token"]
    target_access_token = target_login.json()["data"]["access_token"]

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)
        assert stored_target is not None
        original_updated_at = stored_target.updated_at

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {admin_access_token}"},
        json={
            "email": target_email,
            "current_password": password,
        },
    )

    assert response.status_code == 200
    assert response.json()["data"]["email"] == target_email
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == target_email
        assert stored_target.normalized_email == target_email
        assert stored_target.updated_at == original_updated_at

        pending_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert pending_token is not None
        assert pending_token.revoked_at is None
        assert pending_token.consumed_at is None

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert events == []

    # The target remains authenticated after a no-op.
    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {target_access_token}"},
    )

    assert profile_response.status_code == 200


@pytest.mark.parametrize(
    "invalid_email",
    [
        "not-an-email",
        "user@",
        "@example.com",
        "   ",
    ],
)
def test_admin_email_change_rejects_invalid_email(
    api_client: TestClient,
    test_engine: Engine,
    invalid_email: str,
) -> None:
    """Malformed email addresses must not modify the target account."""
    key = uuid7().hex
    password = "A secure invalid email change test passphrase"
    admin_email = f"invalid-admin-{key}@example.com"
    target_email = f"invalid-target-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Target User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.commit()
        target_id = target.id

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": invalid_email,
            "current_password": password,
        },
    )

    assert response.status_code == 422
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == target_email
        assert stored_target.normalized_email == target_email

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert events == []


def test_concurrent_admin_email_changes_allow_one_owner(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Two accounts cannot claim the same email concurrently."""
    key = uuid7().hex
    password = "A secure concurrent administrator email passphrase"
    shared_email = f"shared-admin-{key}@example.com"

    administrators: list[str] = []
    targets: list[tuple[str, object]] = []

    with Session(test_engine) as session:
        for index in range(2):
            admin_email = f"race-admin-{index}-{key}@example.com"
            target_email = f"race-target-{index}-{key}@example.com"

            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name=f"Administrator {index}",
                status="active",
                system_role="administrator",
                password_hash=hash_password(password),
            )
            target = User(
                email=target_email,
                normalized_email=target_email,
                display_name=f"Target User {index}",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )

            session.add_all([administrator, target])
            session.flush()

            administrators.append(admin_email)
            targets.append((target_email, target.id))

            session.add(
                OneTimeToken(
                    user_id=target.id,
                    purpose="email_change",
                    token_hash=hash_token(f"race-pending-{index}-{key}"),
                    pending_email=f"pending-{index}-{key}@example.com",
                    created_at=datetime.now(UTC),
                    expires_at=datetime.now(UTC) + timedelta(minutes=30),
                )
            )

        session.commit()

    access_tokens: list[str] = []

    for admin_email in administrators:
        login = api_client.post(
            "/api/v1/auth/login",
            json={"email": admin_email, "password": password},
        )

        assert login.status_code == 200
        access_tokens.append(login.json()["data"]["access_token"])

    target_access_tokens: list[str] = []

    for target_email, _ in targets:
        login = api_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": password},
        )

        assert login.status_code == 200
        target_access_tokens.append(login.json()["data"]["access_token"])

    barrier = Barrier(2)

    def change_email(index: int) -> int:
        barrier.wait()

        response = api_client.patch(
            f"/api/v1/users/{targets[index][1]}/email",
            headers={"Authorization": f"Bearer {access_tokens[index]}"},
            json={
                "email": shared_email,
                "current_password": password,
            },
        )

        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(change_email, 0)
        second = executor.submit(change_email, 1)

        results = [first.result(), second.result()]

    assert sorted(results) == [200, 409]

    with Session(test_engine) as session:
        stored_targets = [session.get(User, target_id) for _, target_id in targets]

        assert all(user is not None for user in stored_targets)

        emails = [user.email for user in stored_targets if user is not None]

        assert emails.count(shared_email) == 1

        # The losing account retains its previous email.
        for original_email, target_id in targets:
            stored_user = session.get(User, target_id)
            assert stored_user is not None
            assert stored_user.email in (original_email, shared_email)

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.action == "user.email_change.admin",
                AuditLog.target_user_id.in_([target_id for _, target_id in targets]),
            )
        ).all()

        assert len(audit_events) == 1

    winner_index = results.index(200)
    loser_index = results.index(409)

    with Session(test_engine) as session:
        for index in range(2):
            original_email, target_id = targets[index]

            stored_user = session.get(User, target_id)
            assert stored_user is not None

            pending_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.token_hash
                    == hash_token(f"race-pending-{index}-{key}"),
                )
            )
            assert pending_token is not None

            if index == winner_index:
                assert stored_user.email == shared_email
                assert pending_token.revoked_at is not None
            else:
                assert index == loser_index
                assert stored_user.email == original_email
                assert pending_token.revoked_at is None

            assert pending_token.consumed_at is None

    # Winning operation revokes the target's old session.
    winner_profile = api_client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {target_access_tokens[winner_index]}",
        },
    )
    assert winner_profile.status_code == 401

    # Losing operation must preserve the target's session.
    loser_profile = api_client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {target_access_tokens[loser_index]}",
        },
    )
    assert loser_profile.status_code == 200


def test_admin_email_change_rolls_back_on_transaction_failure(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A failed transaction preserves email, tokens, sessions and audit."""
    key = uuid7().hex
    password = "A secure administrator rollback test passphrase"
    admin_email = f"rollback-admin-{key}@example.com"
    old_email = f"rollback-target-{key}@example.com"
    new_email = f"rollback-new-{key}@example.com"
    raw_pending_token = f"rollback-pending-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Rollback Target",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.flush()
        target_id = target.id

        session.add(
            OneTimeToken(
                user_id=target_id,
                purpose="email_change",
                token_hash=hash_token(raw_pending_token),
                pending_email=f"pending-{key}@example.com",
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    admin_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    target_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": old_email, "password": password},
    )

    assert admin_login.status_code == 200
    assert target_login.status_code == 200

    admin_access_token = admin_login.json()["data"]["access_token"]
    target_access_token = target_login.json()["data"]["access_token"]

    def fail_after_flush(
        _session: Session,
        _flush_context: object,
    ) -> None:
        raise RuntimeError("Simulated administrator email-change failure")

    with Session(test_engine) as session:
        event.listen(session, "after_flush_postexec", fail_after_flush)

        with pytest.raises(
            RuntimeError,
            match="Simulated administrator email-change failure",
        ):
            change_user_email_as_administrator(
                session,
                access_token=admin_access_token,
                user_id=target_id,
                email=new_email,
                current_password=password,
            )

    # A fresh database session sees only committed changes.
    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == old_email
        assert stored_target.normalized_email == old_email

        pending_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_pending_token),
            )
        )

        assert pending_token is not None
        assert pending_token.revoked_at is None
        assert pending_token.consumed_at is None

        active_sessions = session.scalars(
            select(LoginSession).where(
                LoginSession.user_id == target_id,
                LoginSession.revoked_at.is_(None),
            )
        ).all()

        assert len(active_sessions) == 1

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert audit_events == []

    # The target's original access token must remain usable.
    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {target_access_token}"},
    )

    assert profile_response.status_code == 200


def test_administrator_can_change_own_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Administrator self-change updates the email and revokes their session."""
    key = uuid7().hex
    password = "A secure administrator self-change passphrase"
    old_email = f"self-admin-old-{key}@example.com"
    new_email = f"self-admin-new-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        session.add(administrator)
        session.commit()
        admin_id = administrator.id

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": old_email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{admin_id}/email",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": new_email,
            "current_password": password,
        },
    )

    assert response.status_code == 200
    assert response.json()["data"]["email"] == new_email

    with Session(test_engine) as session:
        stored_user = session.get(User, admin_id)

        assert stored_user is not None
        assert stored_user.normalized_email == new_email
        assert stored_user.system_role == "administrator"

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == admin_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert len(events) == 1

    # Successful email change invalidates the previous session.
    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert profile_response.status_code == 401

    # The administrator can log in again using the new email.
    new_login = api_client.post(
        "/api/v1/auth/login",
        json={"email": new_email, "password": password},
    )

    assert new_login.status_code == 200


def test_administrator_can_change_suspended_users_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Administrator email changes preserve a target's suspended status."""
    key = uuid7().hex
    password = "A secure suspended account email change passphrase"
    admin_email = f"suspended-admin-{key}@example.com"
    old_email = f"suspended-old-{key}@example.com"
    new_email = f"suspended-new-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Suspended User",
            status="suspended",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.flush()

        admin_id = administrator.id
        target_id = target.id
        session.commit()

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )

    assert login.status_code == 200
    access_token = login.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": new_email,
            "current_password": password,
        },
    )

    assert response.status_code == 200
    assert response.json()["data"]["email"] == new_email
    assert response.json()["data"]["status"] == "suspended"

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == new_email
        assert stored_target.normalized_email == new_email
        assert stored_target.status == "suspended"

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert len(events) == 1

    # Changing the email does not restore a suspended account.
    login_as_target = api_client.post(
        "/api/v1/auth/login",
        json={"email": new_email, "password": password},
    )

    assert login_as_target.status_code == 401


def test_admin_email_change_rejects_pending_account(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Pending accounts must use the invitation-correction workflow."""
    key = uuid7().hex
    password = "A secure pending account email change passphrase"
    admin_email = f"pending-admin-{key}@example.com"
    pending_email = f"pending-target-{key}@example.com"
    new_email = f"pending-new-{key}@example.com"
    raw_invitation = f"pending-invitation-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=pending_email,
            normalized_email=pending_email,
            display_name="Pending User",
            status="pending",
            system_role="user",
            password_hash=None,
        )

        session.add_all([administrator, target])
        session.flush()
        target_id = target.id

        session.add(
            OneTimeToken(
                user_id=target_id,
                purpose="account_activation",
                token_hash=hash_token(raw_invitation),
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        session.commit()

    login_response = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )

    assert login_response.status_code == 200
    access_token = login_response.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": new_email,
            "current_password": password,
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_CHANGE_NOT_ALLOWED"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == pending_email
        assert stored_target.normalized_email == pending_email
        assert stored_target.status == "pending"
        assert stored_target.password_hash is None

        invitation = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_invitation),
            )
        )

        assert invitation is not None
        assert invitation.revoked_at is None
        assert invitation.consumed_at is None

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert events == []


def test_suspended_administrator_cannot_change_user_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Suspended administrators cannot use existing credentials."""
    key = uuid7().hex
    password = "A secure suspended administrator test passphrase"
    admin_email = f"suspended-actor-{key}@example.com"
    target_email = f"suspended-actor-target-{key}@example.com"
    new_email = f"suspended-actor-new-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Target User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.commit()
        admin_id = administrator.id
        target_id = target.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )

    assert login.status_code == 200
    access_token = login.json()["data"]["access_token"]

    # Simulate the administrator account becoming suspended while
    # an access credential issued earlier still exists.
    with Session(test_engine) as session:
        administrator = session.get(User, admin_id)

        assert administrator is not None
        administrator.status = "suspended"
        session.commit()

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": new_email,
            "current_password": password,
        },
    )

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == target_email
        assert stored_target.normalized_email == target_email

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert events == []


def test_password_reset_required_administrator_cannot_change_user_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Administrators requiring a password reset cannot change emails."""
    key = uuid7().hex
    password = "A secure administrator password reset test passphrase"
    admin_email = f"reset-required-admin-{key}@example.com"
    target_email = f"reset-required-target-{key}@example.com"
    new_email = f"reset-required-new-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
            password_reset_required=False,
        )
        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Target User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.commit()
        admin_id = administrator.id
        target_id = target.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )

    assert login.status_code == 200
    access_token = login.json()["data"]["access_token"]

    # Simulate a password-reset requirement being applied after login.
    with Session(test_engine) as session:
        administrator = session.get(User, admin_id)

        assert administrator is not None
        administrator.password_reset_required = True
        session.commit()

    response = api_client.patch(
        f"/api/v1/users/{target_id}/email",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": new_email,
            "current_password": password,
        },
    )

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        stored_target = session.get(User, target_id)

        assert stored_target is not None
        assert stored_target.email == target_email
        assert stored_target.normalized_email == target_email

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.email_change.admin",
            )
        ).all()

        assert events == []

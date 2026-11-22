"""Integration tests for inactive login-session cleanup."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import (
    AccessToken,
    LoginSession,
    RefreshTokenHistory,
    User,
)
from restling_server.users.service import cleanup_inactive_sessions
from restling_server.users.tokens import generate_token, hash_token


def test_cleanup_deletes_expired_session_and_cascades_children(
    test_engine: Engine,
) -> None:
    """Delete an expired session beyond retention with its token history."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

    with Session(test_engine) as session:
        with session.begin():
            email = f"session-cleanup-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Session Cleanup User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )
            session.add(user)
            session.flush()

            old_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=hash_token(generate_token()),
                created_at=now - timedelta(days=50),
                expires_at=now - timedelta(days=45),
            )
            session.add(old_session)
            session.flush()

            old_session_id = old_session.id

            old_access_token = AccessToken(
                session_id=old_session_id,
                token_hash=hash_token(generate_token()),
                created_at=now - timedelta(days=50),
                expires_at=now - timedelta(days=49),
            )

            refresh_history = RefreshTokenHistory(
                session_id=old_session_id,
                token_hash=hash_token(generate_token()),
                used_at=now - timedelta(days=48),
            )

            session.add_all([old_access_token, refresh_history])
            session.flush()

            old_access_token_id = old_access_token.id
            refresh_history_id = refresh_history.id

    with Session(test_engine) as session:
        deleted_count = cleanup_inactive_sessions(
            session,
            now=now,
            retention_days=30,
            batch_size=100,
        )

    assert deleted_count == 1

    with Session(test_engine) as session:
        assert session.get(LoginSession, old_session_id) is None
        assert session.get(AccessToken, old_access_token_id) is None
        assert session.get(RefreshTokenHistory, refresh_history_id) is None


def test_cleanup_respects_revocation_time_and_preserves_active_sessions(
    test_engine: Engine,
) -> None:
    """Use revocation time for retention and preserve active sessions."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

    with Session(test_engine) as session:
        with session.begin():
            email = f"session-retention-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Session Retention User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )
            session.add(user)
            session.flush()

            old_revoked_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=None,
                created_at=now - timedelta(days=60),
                expires_at=now + timedelta(days=10),
                revoked_at=now - timedelta(days=45),
                revocation_reason="user_logout",
            )

            recently_revoked_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=None,
                created_at=now - timedelta(days=90),
                expires_at=now - timedelta(days=60),
                revoked_at=now - timedelta(days=5),
                revocation_reason="user_logout",
            )

            active_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=hash_token(generate_token()),
                created_at=now - timedelta(days=1),
                expires_at=now + timedelta(days=6),
            )

            session.add_all(
                [
                    old_revoked_session,
                    recently_revoked_session,
                    active_session,
                ]
            )
            session.flush()

            old_revoked_id = old_revoked_session.id
            recently_revoked_id = recently_revoked_session.id
            active_id = active_session.id

    with Session(test_engine) as session:
        deleted_count = cleanup_inactive_sessions(
            session,
            now=now,
            retention_days=30,
            batch_size=100,
        )

    assert deleted_count == 1

    with Session(test_engine) as session:
        assert session.get(LoginSession, old_revoked_id) is None
        assert session.get(LoginSession, recently_revoked_id) is not None
        assert session.get(LoginSession, active_id) is not None


@pytest.mark.parametrize(
    ("retention_days", "batch_size"),
    [
        (0, 100),
        (-1, 100),
        (30, 0),
        (30, -1),
    ],
)
def test_session_cleanup_rejects_invalid_limits(
    test_engine: Engine,
    retention_days: int,
    batch_size: int,
) -> None:
    """Session cleanup requires positive retention and batch limits."""
    with Session(test_engine) as session:
        with pytest.raises(ValueError):
            cleanup_inactive_sessions(
                session,
                now=datetime(2026, 11, 22, 12, 0, tzinfo=UTC),
                retention_days=retention_days,
                batch_size=batch_size,
            )


def test_cleanup_deletes_sessions_in_bounded_batches(
    test_engine: Engine,
) -> None:
    """Cleanup deletes at most batch_size sessions per invocation."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    session_ids: list[UUID] = []

    with Session(test_engine) as session:
        with session.begin():
            email = f"session-cleanup-batch-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Session Cleanup Batch User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )
            session.add(user)
            session.flush()

            user_id = user.id

            for _ in range(5):
                login_session = LoginSession(
                    user_id=user_id,
                    refresh_token_hash=hash_token(generate_token()),
                    created_at=now - timedelta(days=50),
                    expires_at=now - timedelta(days=45),
                )

                session.add(login_session)
                session.flush()
                session_ids.append(login_session.id)

    deleted_counts: list[int] = []

    for _ in range(4):
        with Session(test_engine) as session:
            deleted_counts.append(
                cleanup_inactive_sessions(
                    session,
                    now=now,
                    retention_days=30,
                    batch_size=2,
                )
            )

    assert deleted_counts == [2, 2, 1, 0]

    with Session(test_engine) as session:
        remaining_sessions = session.scalars(
            select(LoginSession).where(
                LoginSession.id.in_(session_ids),
            )
        ).all()

        retained_user = session.get(User, user_id)

        assert remaining_sessions == []
        assert retained_user is not None


def test_concurrent_session_cleanup_does_not_delete_twice(
    test_engine: Engine,
) -> None:
    """Concurrent cleanup workers must not delete sessions twice."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    session_ids: list[UUID] = []

    with Session(test_engine) as session:
        with session.begin():
            email = f"session-cleanup-concurrent-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Concurrent Session Cleanup User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )
            session.add(user)
            session.flush()

            user_id = user.id

            for _ in range(5):
                login_session = LoginSession(
                    user_id=user_id,
                    refresh_token_hash=hash_token(generate_token()),
                    created_at=now - timedelta(days=50),
                    expires_at=now - timedelta(days=45),
                )

                session.add(login_session)
                session.flush()
                session_ids.append(login_session.id)

    barrier = Barrier(2, timeout=10)

    def run_cleanup() -> int:
        with Session(test_engine) as session:
            barrier.wait()

            return cleanup_inactive_sessions(
                session,
                now=now,
                retention_days=30,
                batch_size=3,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(run_cleanup)
        second = executor.submit(run_cleanup)

        results = [
            first.result(timeout=20),
            second.result(timeout=20),
        ]

    assert sum(results) == 5
    assert all(0 <= count <= 3 for count in results)

    with Session(test_engine) as session:
        remaining_sessions = session.scalars(
            select(LoginSession).where(
                LoginSession.id.in_(session_ids),
            )
        ).all()

        retained_user = session.get(User, user_id)

        assert remaining_sessions == []
        assert retained_user is not None

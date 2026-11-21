"""Integration tests for expired access-token cleanup."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AccessToken, LoginSession, User
from restling_server.users.service import cleanup_expired_access_tokens
from restling_server.users.tokens import generate_token, hash_token


def test_cleanup_deletes_old_access_tokens_but_preserves_recent_tokens(
    test_engine: Engine,
) -> None:
    """Delete tokens beyond retention without removing their session."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

    old_hash = hash_token(generate_token())
    recent_hash = hash_token(generate_token())

    with Session(test_engine) as session:
        with session.begin():
            email = f"access-cleanup-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Access Cleanup User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )
            session.add(user)
            session.flush()

            login_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=hash_token(generate_token()),
                created_at=now - timedelta(days=2),
                expires_at=now + timedelta(days=5),
            )
            session.add(login_session)
            session.flush()

            login_session_id = login_session.id

            session.add_all(
                [
                    AccessToken(
                        session_id=login_session_id,
                        token_hash=old_hash,
                        created_at=now - timedelta(hours=3),
                        expires_at=now - timedelta(hours=2),
                    ),
                    AccessToken(
                        session_id=login_session_id,
                        token_hash=recent_hash,
                        created_at=now - timedelta(hours=1),
                        expires_at=now - timedelta(minutes=30),
                    ),
                ]
            )

    with Session(test_engine) as session:
        deleted_count = cleanup_expired_access_tokens(
            session,
            now=now,
            retention_hours=1,
            batch_size=100,
        )

    assert deleted_count == 1

    with Session(test_engine) as session:
        old_token = session.scalar(
            select(AccessToken).where(
                AccessToken.token_hash == old_hash,
            )
        )
        recent_token = session.scalar(
            select(AccessToken).where(
                AccessToken.token_hash == recent_hash,
            )
        )
        retained_session = session.get(LoginSession, login_session_id)

        assert old_token is None
        assert recent_token is not None
        assert retained_session is not None


@pytest.mark.parametrize(
    ("retention_hours", "batch_size"),
    [
        (0, 100),
        (-1, 100),
        (1, 0),
        (1, -1),
    ],
)
def test_cleanup_rejects_invalid_limits(
    test_engine: Engine,
    retention_hours: int,
    batch_size: int,
) -> None:
    """Cleanup requires positive retention and batch limits."""
    with Session(test_engine) as session:
        with pytest.raises(ValueError):
            cleanup_expired_access_tokens(
                session,
                now=datetime(2026, 11, 22, 12, 0, tzinfo=UTC),
                retention_hours=retention_hours,
                batch_size=batch_size,
            )


def test_cleanup_deletes_access_tokens_in_bounded_batches(
    test_engine: Engine,
) -> None:
    """Cleanup deletes at most batch_size tokens per invocation."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    token_hashes: list[str] = []

    with Session(test_engine) as session:
        with session.begin():
            email = f"access-cleanup-batch-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Access Cleanup Batch User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )
            session.add(user)
            session.flush()

            login_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=hash_token(generate_token()),
                created_at=now - timedelta(days=2),
                expires_at=now + timedelta(days=5),
            )
            session.add(login_session)
            session.flush()

            login_session_id = login_session.id

            for _ in range(5):
                token_digest = hash_token(generate_token())
                token_hashes.append(token_digest)

                session.add(
                    AccessToken(
                        session_id=login_session_id,
                        token_hash=token_digest,
                        created_at=now - timedelta(hours=4),
                        expires_at=now - timedelta(hours=3),
                    )
                )

    deleted_counts: list[int] = []

    for _ in range(4):
        with Session(test_engine) as session:
            deleted_counts.append(
                cleanup_expired_access_tokens(
                    session,
                    now=now,
                    retention_hours=1,
                    batch_size=2,
                )
            )

    assert deleted_counts == [2, 2, 1, 0]

    with Session(test_engine) as session:
        remaining_tokens = session.scalars(
            select(AccessToken).where(
                AccessToken.token_hash.in_(token_hashes),
            )
        ).all()

        retained_session = session.get(LoginSession, login_session_id)

        assert remaining_tokens == []
        assert retained_session is not None


def test_concurrent_access_token_cleanup_does_not_delete_twice(
    test_engine: Engine,
) -> None:
    """Concurrent cleanup workers must not delete the same tokens twice."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    token_hashes: list[str] = []

    with Session(test_engine) as session:
        with session.begin():
            email = f"access-cleanup-concurrent-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Concurrent Access Cleanup User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )
            session.add(user)
            session.flush()

            login_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=hash_token(generate_token()),
                created_at=now - timedelta(days=2),
                expires_at=now + timedelta(days=5),
            )
            session.add(login_session)
            session.flush()

            login_session_id = login_session.id

            for _ in range(5):
                token_digest = hash_token(generate_token())
                token_hashes.append(token_digest)

                session.add(
                    AccessToken(
                        session_id=login_session_id,
                        token_hash=token_digest,
                        created_at=now - timedelta(hours=4),
                        expires_at=now - timedelta(hours=3),
                    )
                )

    barrier = Barrier(2, timeout=10)

    def run_cleanup() -> int:
        with Session(test_engine) as session:
            barrier.wait()

            return cleanup_expired_access_tokens(
                session,
                now=now,
                retention_hours=1,
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
        remaining_tokens = session.scalars(
            select(AccessToken).where(
                AccessToken.token_hash.in_(token_hashes),
            )
        ).all()

        retained_session = session.get(LoginSession, login_session_id)

        assert remaining_tokens == []
        assert retained_session is not None

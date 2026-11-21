"""PostgreSQL integration tests for one-time-token retention."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import OneTimeToken, User
from restling_server.users.service import cleanup_one_time_tokens
from restling_server.users.tokens import generate_token, hash_token


def test_cleanup_deletes_only_tokens_past_retention(
    test_engine: Engine,
) -> None:
    """Retain recent history and usable tokens across all purposes."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

    old = now - timedelta(days=31)
    recent = now - timedelta(days=29)
    long_ago = now - timedelta(days=100)
    expired_earlier = now - timedelta(days=60)

    cases = [
        # name, purpose, expires_at, consumed_at, revoked_at, delete
        ("consumed_old", "account_activation", expired_earlier, old, None, True),
        ("revoked_old", "password_reset", expired_earlier, None, old, True),
        ("expired_old", "email_change", old, None, None, True),
        ("consumed_recent", "account_activation", expired_earlier, recent, None, False),
        ("revoked_recent", "password_reset", expired_earlier, None, recent, False),
        ("expired_recent", "email_change", recent, None, None, False),
        (
            "still_valid",
            "email_change",
            now + timedelta(days=1),
            None,
            None,
            False,
        ),
    ]

    token_hashes: dict[str, str] = {}

    with Session(test_engine) as session:
        with session.begin():
            email = f"cleanup-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Cleanup Test User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )

            session.add(user)
            session.flush()

            for name, purpose, expires_at, consumed_at, revoked_at, _ in cases:
                token_digest = hash_token(generate_token())
                token_hashes[name] = token_digest

                session.add(
                    OneTimeToken(
                        user_id=user.id,
                        purpose=purpose,
                        token_hash=token_digest,
                        pending_email=(
                            "new@example.com" if purpose == "email_change" else None
                        ),
                        created_at=long_ago,
                        expires_at=expires_at,
                        consumed_at=consumed_at,
                        revoked_at=revoked_at,
                    )
                )

    with Session(test_engine) as session:
        deleted_count = cleanup_one_time_tokens(
            session,
            now=now,
            retention_days=30,
            batch_size=100,
        )

    assert deleted_count == 3

    with Session(test_engine) as session:
        remaining_hashes = set(
            session.scalars(
                select(OneTimeToken.token_hash).where(
                    OneTimeToken.token_hash.in_(token_hashes.values()),
                )
            ).all()
        )

    for name, _, _, _, _, should_delete in cases:
        if should_delete:
            assert token_hashes[name] not in remaining_hashes
        else:
            assert token_hashes[name] in remaining_hashes


def test_cleanup_respects_batch_size(
    test_engine: Engine,
) -> None:
    """Cleanup deletes no more than the configured batch size."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    expired_at = now - timedelta(days=45)

    token_hashes: list[str] = []

    with Session(test_engine) as session:
        with session.begin():
            email = f"cleanup-batch-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Cleanup Batch User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )

            session.add(user)
            session.flush()

            for _ in range(5):
                token_digest = hash_token(generate_token())
                token_hashes.append(token_digest)

                session.add(
                    OneTimeToken(
                        user_id=user.id,
                        purpose="password_reset",
                        token_hash=token_digest,
                        created_at=expired_at - timedelta(days=1),
                        expires_at=expired_at,
                    )
                )

    expected_deletions = [2, 2, 1, 0]

    for expected_count in expected_deletions:
        with Session(test_engine) as session:
            deleted_count = cleanup_one_time_tokens(
                session,
                now=now,
                retention_days=30,
                batch_size=2,
            )

        assert deleted_count == expected_count

    with Session(test_engine) as session:
        remaining_tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.token_hash.in_(token_hashes),
            )
        ).all()

        assert remaining_tokens == []


@pytest.mark.parametrize(
    ("retention_days", "batch_size"),
    [
        (0, 100),
        (-1, 100),
        (30, 0),
        (30, -1),
    ],
)
def test_cleanup_rejects_invalid_limits(
    test_engine: Engine,
    retention_days: int,
    batch_size: int,
) -> None:
    """Cleanup must reject nonpositive retention and batch limits."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

    with Session(test_engine) as session:
        with pytest.raises(ValueError):
            cleanup_one_time_tokens(
                session,
                now=now,
                retention_days=retention_days,
                batch_size=batch_size,
            )


def test_concurrent_cleanup_does_not_delete_tokens_twice(
    test_engine: Engine,
) -> None:
    """Concurrent workers must not claim the same token records."""
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    expired_at = now - timedelta(days=45)
    token_hashes: list[str] = []

    with Session(test_engine) as session:
        with session.begin():
            email = f"cleanup-concurrent-{uuid7().hex}@example.com"

            user = User(
                email=email,
                normalized_email=email,
                display_name="Concurrent Cleanup User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )

            session.add(user)
            session.flush()

            for _ in range(5):
                token_digest = hash_token(generate_token())
                token_hashes.append(token_digest)

                session.add(
                    OneTimeToken(
                        user_id=user.id,
                        purpose="password_reset",
                        token_hash=token_digest,
                        created_at=expired_at - timedelta(days=1),
                        expires_at=expired_at,
                    )
                )

    barrier = Barrier(2, timeout=10)

    def run_cleanup() -> int:
        with Session(test_engine) as session:
            barrier.wait()

            return cleanup_one_time_tokens(
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
        remaining_tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.token_hash.in_(token_hashes),
            )
        ).all()

        assert remaining_tokens == []

"""PostgreSQL concurrency tests for email-change token replacement."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import OneTimeToken, User
from restling_server.users.passwords import hash_password
from restling_server.users.service import (
    EmailChangeRateLimitedError,
    commit_email_change_token_after_delivery,
)
from restling_server.users.tokens import generate_token


def test_concurrent_email_change_requests_leave_one_usable_token(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Concurrent replacements must leave only one usable token."""
    key = uuid7().hex
    email = f"concurrent-{key}@example.com"
    password = "A secure concurrent email change test passphrase"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Concurrency Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()
        user_id = user.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200
    access_token = login.json()["data"]["access_token"]

    barrier = Barrier(2)

    def replace_token(new_email: str) -> bool:
        raw_token = generate_token()

        barrier.wait(timeout=10)

        with Session(test_engine) as session:
            try:
                return commit_email_change_token_after_delivery(
                    session,
                    access_token=access_token,
                    current_password=password,
                    email=new_email,
                    raw_token=raw_token,
                    expiry_minutes=30,
                    cooldown_seconds=60,
                    hourly_limit=5,
                )
            except EmailChangeRateLimitedError:
                return False

    first_email = f"first-{key}@example.com"
    second_email = f"second-{key}@example.com"

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(replace_token, first_email)
        second_future = executor.submit(replace_token, second_email)

        results = [
            first_future.result(timeout=20),
            second_future.result(timeout=20),
        ]

        assert results.count(True) == 1
        assert results.count(False) == 1

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        ).all()

        assert len(tokens) == 1

        usable_tokens = [
            token
            for token in tokens
            if token.revoked_at is None and token.consumed_at is None
        ]

        assert len(usable_tokens) == 1
        assert usable_tokens[0].pending_email in {
            first_email,
            second_email,
        }

        user = session.get(User, user_id)

        assert user is not None
        assert user.email == email

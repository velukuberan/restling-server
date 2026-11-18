"""HTTP integration tests for administrator user listing."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import User
from restling_server.users.passwords import hash_password


@pytest.fixture
def accounts(
    api_client: TestClient,
    test_engine: Engine,
) -> tuple[str, str, str, list[UUID]]:
    """Create an administrator and three accounts for listing."""
    key = uuid7().hex
    prefix = f"listing-{key}"
    password = "A secure listing test passphrase #8472"
    password_hash = hash_password(password)

    administrator = User(
        email=f"admin-{key}@example.com",
        normalized_email=f"admin-{key}@example.com",
        display_name="Listing Administrator",
        status="active",
        system_role="administrator",
        password_hash=password_hash,
    )

    users = [
        User(
            email=f"{prefix}-alpha@example.com",
            normalized_email=f"{prefix}-alpha@example.com",
            display_name="Alpha",
            status="active",
            system_role="user",
            password_hash=password_hash,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        User(
            email=f"{prefix}-beta@example.com",
            normalized_email=f"{prefix}-beta@example.com",
            display_name="Beta",
            status="pending",
            system_role="user",
            password_hash=None,
            created_at=datetime(2026, 1, 2, tzinfo=UTC),
        ),
        User(
            email=f"{prefix}-zeta@example.com",
            normalized_email=f"{prefix}-zeta@example.com",
            display_name="Zeta",
            status="suspended",
            system_role="user",
            password_hash=password_hash,
            created_at=datetime(2026, 1, 3, tzinfo=UTC),
        ),
    ]

    with Session(test_engine) as session:
        session.add_all([administrator, *users])
        session.commit()

        administrator_email = administrator.email
        user_ids = [user.id for user in users]

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": administrator_email, "password": password},
    )

    assert login.status_code == 200
    admin_token = login.json()["data"]["access_token"]

    return admin_token, prefix, password, user_ids


def auth(token: str) -> dict[str, str]:
    """Build the bearer authorization header."""
    return {"Authorization": f"Bearer {token}"}


def test_listing_requires_authentication(
    api_client: TestClient,
) -> None:
    """Anonymous and invalid-token requests are rejected."""
    for headers in ({}, auth("invalid-token")):
        response = api_client.get(
            "/api/v1/users",
            headers=headers,
        )

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_regular_user_cannot_list_accounts(
    api_client: TestClient,
    test_engine: Engine,
    accounts: tuple[str, str, str, list[UUID]],
) -> None:
    """An ordinary user cannot enumerate server accounts."""
    _, prefix, password, _ = accounts
    email = f"{prefix}-alpha@example.com"

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200

    token = login.json()["data"]["access_token"]

    response = api_client.get(
        "/api/v1/users",
        headers=auth(token),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_administrator_can_filter_accounts(
    api_client: TestClient,
    accounts: tuple[str, str, str, list[UUID]],
) -> None:
    """Filtering is scoped to matching account records."""
    admin_token, prefix, _, _ = accounts

    response = api_client.get(
        "/api/v1/users",
        headers=auth(admin_token),
        params={
            "search": prefix.upper(),
            "system_role": "user",
            "status": "active",
        },
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    payload = response.json()

    assert payload["pagination"]["total"] == 1
    assert len(payload["data"]) == 1
    assert payload["data"][0]["display_name"] == "Alpha"

    for field in (
        "password_hash",
        "normalized_email",
        "refresh_token",
        "access_token",
    ):
        assert field not in payload["data"][0]


def test_listing_sorting_and_pagination(
    api_client: TestClient,
    accounts: tuple[str, str, str, list[UUID]],
) -> None:
    """Sorting and pagination produce predictable results."""
    admin_token, prefix, _, _ = accounts

    response = api_client.get(
        "/api/v1/users",
        headers=auth(admin_token),
        params={
            "search": prefix,
            "sort_by": "display_name",
            "sort_order": "asc",
            "limit": 2,
            "offset": 1,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["pagination"] == {
        "limit": 2,
        "offset": 1,
        "total": 3,
    }

    assert [user["display_name"] for user in payload["data"]] == [
        "Beta",
        "Zeta",
    ]


def test_listing_rejects_invalid_query_parameters(
    api_client: TestClient,
    accounts: tuple[str, str, str, list[UUID]],
) -> None:
    """Invalid pagination and sorting values are rejected."""
    admin_token, _, _, _ = accounts

    for params in (
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"status": "deleted"},
        {"system_role": "owner"},
        {"sort_by": "password_hash"},
        {"sort_order": "random"},
    ):
        response = api_client.get(
            "/api/v1/users",
            headers=auth(admin_token),
            params=params,
        )

        assert response.status_code == 422

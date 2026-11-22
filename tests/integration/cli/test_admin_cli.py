"""Integration tests for the administrator CLI."""

import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import ValidationError
from sqlalchemy import URL, Engine, create_engine, delete, event, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from uuid6 import uuid7

import restling_server.users.invitations as invitations
from restling_server.core.config import Settings
from restling_server.users import cli
from restling_server.users.invitation_email import InvitationDeliveryError
from restling_server.users.models import (
    AccessToken,
    LoginSession,
    OneTimeToken,
    RefreshTokenHistory,
    User,
)
from restling_server.users.service import bootstrap_administrator
from restling_server.users.tokens import hash_token


def test_admin_cli_displays_help() -> None:
    """Administrator CLI exposes the bootstrap command."""
    result = subprocess.run(
        ["uv", "run", "restling-admin", "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    assert result.returncode == 0
    assert "bootstrap" in result.stdout


def test_admin_cli_displays_cleanup_auth_help() -> None:
    """Administrator CLI exposes the auth cleanup command."""
    result = subprocess.run(
        ["uv", "run", "restling-admin", "cleanup-auth", "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    assert result.returncode == 0
    assert "cleanup-auth" in result.stdout


def test_admin_cli_rejects_password_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Mismatched passwords must stop administrator bootstrap."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "bootstrap"],
    )

    answers = iter(
        [
            "admin@example.com",
            "Initial Administrator",
        ]
    )

    def fake_input(prompt: str) -> str:
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)

    passwords = iter(
        [
            "First secure administrator passphrase #8472",
            "Different secure administrator passphrase #8472",
        ]
    )

    def fake_getpass(prompt: str) -> str:
        return next(passwords)

    monkeypatch.setattr(cli, "getpass", fake_getpass)

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code != 0

    captured = capsys.readouterr()
    assert "Passwords do not match" in captured.err


def test_admin_cli_creates_initial_administrator(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    test_engine: Engine,
) -> None:
    """CLI creates the initial administrator in PostgreSQL."""
    email = "cli-bootstrap@example.com"

    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "bootstrap"],
    )

    answers = iter(
        [
            email,
            "CLI Administrator",
        ]
    )

    def fake_input(prompt: str) -> str:
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)

    passwords = iter(
        [
            "A secure CLI administrator passphrase #8472",
            "A secure CLI administrator passphrase #8472",
        ]
    )

    def fake_getpass(prompt: str) -> str:
        return next(passwords)

    monkeypatch.setattr(cli, "getpass", fake_getpass)

    # Redirect only the CLI's database infrastructure to the
    # verified PostgreSQL test engine.
    def use_test_engine(settings: object) -> Engine:
        return test_engine

    monkeypatch.setattr(
        cli,
        "create_database_engine",
        use_test_engine,
        raising=False,
    )

    try:
        cli.main()

        with Session(test_engine) as session:
            administrator = session.scalar(
                select(User).where(User.normalized_email == email)
            )

            assert administrator is not None
            assert administrator.status == "active"
            assert administrator.system_role == "administrator"

        captured = capsys.readouterr()
        assert "created successfully" in captured.out.lower()

    finally:
        with test_engine.begin() as connection:
            connection.execute(delete(User).where(User.normalized_email == email))


def test_admin_cli_rejects_already_initialized_server(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    test_engine: Engine,
) -> None:
    """CLI refuses to bootstrap an already initialized server."""
    existing_email = "existing-admin@example.com"
    new_email = "second-cli-admin@example.com"

    # Initialize the test database using the real application service.
    try:
        with Session(test_engine) as session:
            bootstrap_administrator(
                session,
                email=existing_email,
                display_name="Existing Administrator",
                password="Existing administrator passphrase #8472",
            )

        monkeypatch.setattr(
            sys,
            "argv",
            ["restling-admin", "bootstrap"],
        )

        answers = iter([new_email, "Second Administrator"])

        def fake_input(prompt: str) -> str:
            return next(answers)

        monkeypatch.setattr("builtins.input", fake_input)

        def fake_getpass(prompt: str) -> str:
            return "Another administrator passphrase #8472"

        monkeypatch.setattr(cli, "getpass", fake_getpass)

        def use_test_engine(settings: object) -> Engine:
            return test_engine

        monkeypatch.setattr(
            cli,
            "create_database_engine",
            use_test_engine,
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.main()

        assert exc_info.value.code != 0

        captured = capsys.readouterr()

        assert "already initialized" in captured.err.lower()
        assert "created successfully" not in captured.out.lower()

        with Session(test_engine) as session:
            users = session.scalars(select(User)).all()

            assert len(users) == 1
            assert users[0].normalized_email == existing_email

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(
                    User.normalized_email.in_([existing_email, new_email])
                )
            )


@pytest.mark.parametrize(
    ("email", "display_name", "password"),
    [
        (
            "not-an-email",
            "Administrator",
            "A secure administrator passphrase #8472",
        ),
        (
            "admin@example.com",
            "",
            "A secure administrator passphrase #8472",
        ),
        (
            "admin@example.com",
            "Administrator",
            "short",
        ),
    ],
)
def test_admin_cli_rejects_invalid_input(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    test_engine: Engine,
    email: str,
    display_name: str,
    password: str,
) -> None:
    """CLI rejects invalid input without creating an administrator."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "bootstrap"],
    )

    answers = iter([email, display_name])

    def fake_input(prompt: str) -> str:
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)

    def fake_getpass(prompt: str) -> str:
        return password

    monkeypatch.setattr(cli, "getpass", fake_getpass)

    def use_test_engine(settings: object) -> Engine:
        return test_engine

    monkeypatch.setattr(cli, "create_database_engine", use_test_engine)

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code != 0

    captured = capsys.readouterr()
    assert "error:" in captured.err.lower()
    assert password not in captured.err
    assert "traceback" not in captured.err.lower()

    with Session(test_engine) as session:
        users = session.scalars(select(User)).all()
        assert users == []


def test_admin_cli_handles_database_engine_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI reports database setup failures without leaking details."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "bootstrap"],
    )

    answers = iter(["admin@example.com", "Administrator"])

    def fake_input(prompt: str) -> str:
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)

    def fake_getpass(prompt: str) -> str:
        return "A secure administrator passphrase #8472"

    monkeypatch.setattr(cli, "getpass", fake_getpass)

    def failing_engine(settings: object) -> Engine:
        raise SQLAlchemyError("Sensitive database connection details")

    # Database infrastructure is an appropriate test boundary.
    monkeypatch.setattr(
        cli,
        "create_database_engine",
        failing_engine,
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code != 0

    captured = capsys.readouterr()

    assert "Database operation failed" in captured.err
    assert "Sensitive database connection details" not in captured.err
    assert "Traceback" not in captured.err


def test_admin_cli_handles_invalid_configuration(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI reports invalid configuration without a traceback."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "bootstrap"],
    )

    answers = iter(["admin@example.com", "Administrator"])

    def fake_input(prompt: str) -> str:
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)

    def fake_getpass(prompt: str) -> str:
        return "A secure administrator passphrase #8472"

    monkeypatch.setattr(cli, "getpass", fake_getpass)

    def invalid_settings() -> None:
        raise ValidationError.from_exception_data(
            "Settings",
            [
                {
                    "type": "missing",
                    "loc": ("postgres_user",),
                    "input": {},
                }
            ],
        )

    monkeypatch.setattr(cli, "Settings", invalid_settings)

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code != 0

    captured = capsys.readouterr()

    assert "Invalid or incomplete database configuration" in captured.err
    assert "Traceback" not in captured.err


def test_admin_cli_handles_database_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI reports PostgreSQL connection failures safely."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "bootstrap"],
    )

    answers = iter(["admin@example.com", "Administrator"])

    def fake_input(prompt: str) -> str:
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)

    def fake_getpass(prompt: str) -> str:
        return "A secure administrator passphrase #8472"

    monkeypatch.setattr(cli, "getpass", fake_getpass)

    def create_unreachable_engine(settings: object) -> Engine:
        database_url = URL.create(
            drivername="postgresql+psycopg",
            username="restling",
            password="unused-test-password",
            host="127.0.0.1",
            port=1,
            database="restling_test",
        )

        return create_engine(
            database_url,
            connect_args={"connect_timeout": 2},
        )

    monkeypatch.setattr(
        cli,
        "create_database_engine",
        create_unreachable_engine,
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code != 0

    captured = capsys.readouterr()

    assert "Database operation failed" in captured.err
    assert "Traceback" not in captured.err
    assert "unused-test-password" not in captured.err
    assert "created successfully" not in captured.out.lower()


def test_admin_cli_invite_displays_help() -> None:
    """Invitation command documents the supported options."""
    result = subprocess.run(
        ["uv", "run", "restling-admin", "invite", "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    assert result.returncode == 0
    assert "--user" in result.stdout
    assert "--manual" in result.stdout


def test_admin_cli_invite_requires_user_email(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An invitation must identify its target account."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "invite"],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 2

    captured = capsys.readouterr()

    assert "--user" in captured.err
    assert "required" in captured.err.lower()


def test_cli_authenticates_active_administrator(
    test_engine: Engine,
) -> None:
    """A valid administrator password authenticates the CLI operator."""
    email = "cli-auth-admin@example.com"
    password = "A secure administrator passphrase #8472"

    try:
        with Session(test_engine) as session:
            administrator = bootstrap_administrator(
                session,
                email=email,
                display_name="CLI Administrator",
                password=password,
            )
            administrator_id = administrator.id

        with Session(test_engine) as session:
            authenticated_id = cli.authenticate_cli_administrator(
                session,
                email=email,
                password=password,
            )

        assert authenticated_id == administrator_id

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(
                    User.normalized_email == email,
                )
            )


@pytest.mark.parametrize(
    "scenario",
    [
        "incorrect_password",
        "ordinary_user",
        "suspended_administrator",
        "password_reset_required",
        "unknown_email",
    ],
)
def test_cli_rejects_invalid_administrator_credentials(
    test_engine: Engine,
    scenario: str,
) -> None:
    """Reject credentials without revealing administrator account state."""
    email = f"cli-auth-{scenario}@example.com"
    password = "A secure administrator passphrase #8472"

    try:
        with Session(test_engine) as session:
            administrator = bootstrap_administrator(
                session,
                email=email,
                display_name="CLI Administrator",
                password=password,
            )
            administrator_id = administrator.id

        if scenario in {
            "ordinary_user",
            "suspended_administrator",
            "password_reset_required",
        }:
            with Session(test_engine) as session:
                with session.begin():
                    administrator = session.get(User, administrator_id)
                    assert administrator is not None

                    if scenario == "ordinary_user":
                        administrator.system_role = "user"
                    elif scenario == "suspended_administrator":
                        administrator.status = "suspended"
                    else:
                        administrator.password_reset_required = True

        attempted_email = email
        attempted_password = password

        if scenario == "incorrect_password":
            attempted_password = "An incorrect administrator passphrase"

        if scenario == "unknown_email":
            attempted_email = "nonexistent-cli-admin@example.com"

        with Session(test_engine) as session:
            with pytest.raises(
                ValueError,
                match="^Invalid administrator credentials\\.$",
            ):
                cli.authenticate_cli_administrator(
                    session,
                    email=attempted_email,
                    password=attempted_password,
                )

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(
                    User.normalized_email == email,
                )
            )


def test_cli_finds_pending_user_by_email(
    test_engine: Engine,
) -> None:
    """Find a pending user using normalized email matching."""
    email = "cli-pending-user@example.com"

    try:
        with Session(test_engine) as session:
            pending_user = User(
                email="CLI-Pending-User@example.com",
                normalized_email=email,
                display_name="Pending CLI User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add(pending_user)
            session.commit()

            user_id = pending_user.id

        with Session(test_engine) as session:
            resolved_id = cli.find_pending_user_id(
                session,
                email="  CLI-PENDING-USER@EXAMPLE.COM  ",
            )

        assert resolved_id == user_id

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(
                    User.normalized_email == email,
                )
            )


@pytest.mark.parametrize(
    "scenario",
    [
        "active",
        "suspended",
        "unknown",
        "invalid_email",
    ],
)
def test_cli_rejects_ineligible_invitation_target(
    test_engine: Engine,
    scenario: str,
) -> None:
    """Only existing pending accounts qualify for invitation."""
    email = f"cli-lookup-{scenario}@example.com"

    try:
        if scenario in {"active", "suspended"}:
            with Session(test_engine) as session:
                user = User(
                    email=email,
                    normalized_email=email,
                    display_name="CLI Lookup User",
                    status=scenario,
                    system_role="user",
                    password_hash="test-password-hash",
                )

                session.add(user)
                session.commit()

        requested_email = email

        if scenario == "invalid_email":
            requested_email = "not-an-email"

        with Session(test_engine) as session:
            with pytest.raises(
                ValueError,
                match=r"^Pending user account not found\.$",
            ):
                cli.find_pending_user_id(
                    session,
                    email=requested_email,
                )

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(
                    User.normalized_email == email,
                )
            )


def test_admin_cli_sends_authenticated_smtp_invitation(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The authenticated CLI sends a committed invitation through SMTP."""
    test_id = uuid7().hex
    admin_email = f"cli-invite-admin-{test_id}@example.com"
    user_email = f"cli-invite-user-{test_id}@example.com"
    password = "A secure administrator passphrase #8472"

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": "https://restling.example.com",
            "RESTLING_SMTP_HOST": "localhost",
            "RESTLING_SMTP_PORT": 1025,
            "RESTLING_SMTP_SECURITY": "none",
            "RESTLING_SMTP_FROM_EMAIL": "restling@example.com",
        }
    )

    try:
        with Session(test_engine) as session:
            bootstrap_administrator(
                session,
                email=admin_email,
                display_name="CLI Administrator",
                password=password,
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending CLI User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add(pending_user)
            session.commit()
            user_id = pending_user.id

        monkeypatch.setattr(
            sys,
            "argv",
            ["restling-admin", "invite", "--user", user_email],
        )

        def fake_input(prompt: str) -> str:
            return admin_email

        def fake_getpass(prompt: str) -> str:
            return password

        def use_test_engine(configuration: Settings) -> Engine:
            return test_engine

        monkeypatch.setattr("builtins.input", fake_input)
        monkeypatch.setattr(cli, "getpass", fake_getpass)

        monkeypatch.setattr(cli, "Settings", lambda: settings)
        monkeypatch.setattr(
            cli,
            "create_database_engine",
            use_test_engine,
        )

        deliveries: list[str] = []

        def fake_sender(
            smtp_settings: Settings,
            *,
            recipient: str,
            activation_url: str,
        ) -> None:
            assert recipient == user_email

            token = parse_qs(urlsplit(activation_url).query)["token"][0]

            with Session(test_engine) as verification_session:
                stored_token = verification_session.scalar(
                    select(OneTimeToken).where(
                        OneTimeToken.user_id == user_id,
                        OneTimeToken.token_hash == hash_token(token),
                    )
                )

                assert stored_token is not None
                assert stored_token.revoked_at is None
                assert stored_token.consumed_at is None

            deliveries.append(activation_url)

        monkeypatch.setattr(
            invitations,
            "send_invitation_email",
            fake_sender,
        )

        cli.main()

        assert len(deliveries) == 1

        captured = capsys.readouterr()

        assert "Activation invitation submitted through SMTP." in captured.out
        assert "Invitation expires at:" in captured.out
        assert deliveries[0] not in captured.out
        assert "token=" not in captured.out

    finally:
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
    ("smtp_enabled", "manual_flag"),
    [
        (True, True),
        (False, False),
    ],
)
def test_admin_cli_generates_manual_invitation(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    smtp_enabled: bool,
    manual_flag: bool,
) -> None:
    """Manual delivery prints a valid link without using SMTP."""
    test_id = uuid7().hex
    admin_email = f"cli-manual-admin-{test_id}@example.com"
    user_email = f"cli-manual-user-{test_id}@example.com"
    password = "A secure administrator passphrase #8472"

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": "https://restling.example.com",
            "RESTLING_SMTP_HOST": "localhost" if smtp_enabled else None,
            "RESTLING_SMTP_PORT": 1025,
            "RESTLING_SMTP_SECURITY": "none",
            "RESTLING_SMTP_USERNAME": None,
            "RESTLING_SMTP_PASSWORD": None,
            "RESTLING_SMTP_FROM_EMAIL": (
                "restling@example.com" if smtp_enabled else None
            ),
        }
    )

    try:
        with Session(test_engine) as session:
            bootstrap_administrator(
                session,
                email=admin_email,
                display_name="CLI Administrator",
                password=password,
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending CLI User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add(pending_user)
            session.commit()
            user_id = pending_user.id

        arguments = [
            "restling-admin",
            "invite",
            "--user",
            user_email,
        ]

        if manual_flag:
            arguments.append("--manual")

        monkeypatch.setattr(sys, "argv", arguments)

        def fake_input(prompt: str) -> str:
            return admin_email

        def fake_getpass(prompt: str) -> str:
            return password

        def use_test_engine(configuration: Settings) -> Engine:
            return test_engine

        def unexpected_smtp(
            smtp_settings: Settings,
            *,
            recipient: str,
            activation_url: str,
        ) -> None:
            pytest.fail("SMTP must not be called in manual mode.")

        monkeypatch.setattr("builtins.input", fake_input)
        monkeypatch.setattr(cli, "getpass", fake_getpass)
        monkeypatch.setattr(cli, "Settings", lambda: settings)
        monkeypatch.setattr(
            cli,
            "create_database_engine",
            use_test_engine,
        )
        monkeypatch.setattr(
            invitations,
            "send_invitation_email",
            unexpected_smtp,
        )

        cli.main()

        captured = capsys.readouterr()

        assert "WARNING:" in captured.out
        assert "Activation link:" in captured.out
        assert "Invitation expires at:" in captured.out
        assert "submitted through SMTP" not in captured.out

        activation_url = captured.out.split("Activation link: ", 1)[1]
        activation_url = activation_url.splitlines()[0]

        assert activation_url.startswith("https://restling.example.com/activate?token=")

        raw_token = parse_qs(urlsplit(activation_url).query)["token"][0]

        with Session(test_engine) as session:
            stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                    OneTimeToken.token_hash == hash_token(raw_token),
                )
            )

            assert stored_token is not None
            assert stored_token.purpose == "account_activation"
            assert stored_token.revoked_at is None
            assert stored_token.consumed_at is None

    finally:
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


def test_admin_cli_rejects_invalid_password_without_issuing_token(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Invalid administrator credentials must not create invitations."""
    test_id = uuid7().hex
    admin_email = f"cli-denied-admin-{test_id}@example.com"
    user_email = f"cli-denied-user-{test_id}@example.com"
    password = "A secure administrator passphrase #8472"

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": "https://restling.example.com",
            "RESTLING_SMTP_HOST": None,
            "RESTLING_SMTP_FROM_EMAIL": None,
        }
    )

    try:
        with Session(test_engine) as session:
            bootstrap_administrator(
                session,
                email=admin_email,
                display_name="CLI Administrator",
                password=password,
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending CLI User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add(pending_user)
            session.commit()
            user_id = pending_user.id

        monkeypatch.setattr(
            sys,
            "argv",
            ["restling-admin", "invite", "--user", user_email],
        )

        def fake_input(prompt: str) -> str:
            return admin_email

        def fake_getpass(prompt: str) -> str:
            return "Incorrect administrator password"

        def use_test_engine(configuration: Settings) -> Engine:
            return test_engine

        monkeypatch.setattr("builtins.input", fake_input)
        monkeypatch.setattr(cli, "getpass", fake_getpass)
        monkeypatch.setattr(cli, "Settings", lambda: settings)
        monkeypatch.setattr(
            cli,
            "create_database_engine",
            use_test_engine,
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.main()

        assert exc_info.value.code == 2

        captured = capsys.readouterr()

        assert "Invalid administrator credentials." in captured.err
        assert "Activation link:" not in captured.out
        assert "token=" not in captured.out

        with Session(test_engine) as session:
            tokens = session.scalars(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                )
            ).all()

            assert tokens == []

            user = session.get(User, user_id)
            assert user is not None
            assert user.status == "pending"

    finally:
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


def test_admin_cli_handles_smtp_delivery_failure(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """SMTP failure must not disclose invitation credentials."""
    test_id = uuid7().hex
    admin_email = f"cli-smtp-failure-admin-{test_id}@example.com"
    user_email = f"cli-smtp-failure-user-{test_id}@example.com"
    password = "A secure administrator passphrase #8472"

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": "https://restling.example.com",
            "RESTLING_SMTP_HOST": "localhost",
            "RESTLING_SMTP_PORT": 1025,
            "RESTLING_SMTP_SECURITY": "none",
            "RESTLING_SMTP_FROM_EMAIL": "restling@example.com",
        }
    )

    try:
        with Session(test_engine) as session:
            bootstrap_administrator(
                session,
                email=admin_email,
                display_name="CLI Administrator",
                password=password,
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending CLI User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add(pending_user)
            session.commit()
            user_id = pending_user.id

        monkeypatch.setattr(
            sys,
            "argv",
            ["restling-admin", "invite", "--user", user_email],
        )

        def fake_input(prompt: str) -> str:
            return admin_email

        def fake_getpass(prompt: str) -> str:
            return password

        def use_test_engine(configuration: Settings) -> Engine:
            return test_engine

        failed_url: str | None = None

        def failing_sender(
            smtp_settings: Settings,
            *,
            recipient: str,
            activation_url: str,
        ) -> None:
            nonlocal failed_url

            assert recipient == user_email
            failed_url = activation_url

            raise InvitationDeliveryError("Unable to deliver account invitation.")

        monkeypatch.setattr("builtins.input", fake_input)
        monkeypatch.setattr(cli, "getpass", fake_getpass)
        monkeypatch.setattr(cli, "Settings", lambda: settings)
        monkeypatch.setattr(
            cli,
            "create_database_engine",
            use_test_engine,
        )
        monkeypatch.setattr(
            invitations,
            "send_invitation_email",
            failing_sender,
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.main()

        assert exc_info.value.code == 2
        assert failed_url is not None

        captured = capsys.readouterr()

        assert "Invitation delivery failed" in captured.err
        assert "Activation link:" not in captured.out
        assert "token=" not in captured.out
        assert failed_url not in captured.out
        assert failed_url not in captured.err
        assert "Traceback" not in captured.err

        raw_token = parse_qs(urlsplit(failed_url).query)["token"][0]

        with Session(test_engine) as session:
            stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                    OneTimeToken.token_hash == hash_token(raw_token),
                )
            )

            assert stored_token is not None
            assert stored_token.revoked_at is None
            assert stored_token.consumed_at is None

            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "pending"

    finally:
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


def test_cleanup_auth_cli_deletes_eligible_tokens(
    monkeypatch: pytest.MonkeyPatch,
    test_engine: Engine,
) -> None:
    """CLI deletes old tokens using the configured retention period."""
    now = datetime.now(UTC)
    email = f"cli-cleanup-{uuid7().hex}@example.com"

    old_token_hash = hash_token(uuid7().hex)
    recent_token_hash = hash_token(uuid7().hex)

    with Session(test_engine) as session:
        with session.begin():
            user = User(
                email=email,
                normalized_email=email,
                display_name="Cleanup CLI User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )

            session.add(user)
            session.flush()

            session.add_all(
                [
                    OneTimeToken(
                        user_id=user.id,
                        purpose="password_reset",
                        token_hash=old_token_hash,
                        created_at=now - timedelta(days=46),
                        expires_at=now - timedelta(days=45),
                    ),
                    OneTimeToken(
                        user_id=user.id,
                        purpose="password_reset",
                        token_hash=recent_token_hash,
                        created_at=now - timedelta(days=21),
                        expires_at=now - timedelta(days=20),
                    ),
                ]
            )

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_ONE_TIME_TOKEN_RETENTION_DAYS": 30,
        }
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "cleanup-auth"],
    )

    monkeypatch.setattr(cli, "Settings", lambda: settings)

    def use_test_engine(_settings: object) -> Engine:
        return test_engine

    monkeypatch.setattr(
        cli,
        "create_database_engine",
        use_test_engine,
    )

    cli.main()

    with Session(test_engine) as session:
        old_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == old_token_hash,
            )
        )

        recent_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == recent_token_hash,
            )
        )

        assert old_token is None
        assert recent_token is not None


def test_cleanup_auth_cli_rejects_overlapping_run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    test_engine: Engine,
) -> None:
    """A second cleanup invocation must not run while one holds the lock."""
    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
        }
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "cleanup-auth"],
    )
    monkeypatch.setattr(cli, "Settings", lambda: settings)

    def use_test_engine(_settings: object) -> Engine:
        return test_engine

    monkeypatch.setattr(
        cli,
        "create_database_engine",
        use_test_engine,
    )

    # Simulate another cleanup process holding the maintenance lock.
    # This is a session-level PostgreSQL advisory lock.
    with test_engine.connect() as lock_connection:
        acquired = lock_connection.scalar(
            text("SELECT pg_try_advisory_lock(723941, 3)")
        )
        assert acquired is True

        try:
            with pytest.raises(SystemExit) as exc_info:
                cli.main()

            assert exc_info.value.code != 0

            captured = capsys.readouterr()
            assert "already running" in captured.err.lower()

        finally:
            released = lock_connection.scalar(
                text("SELECT pg_advisory_unlock(723941, 3)")
            )
            assert released is True


def test_cleanup_auth_cli_releases_lock_after_database_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    test_engine: Engine,
) -> None:
    """A database failure must not leave the cleanup lock held."""
    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
        }
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "cleanup-auth"],
    )
    monkeypatch.setattr(cli, "Settings", lambda: settings)

    def use_test_engine(_settings: object) -> Engine:
        return test_engine

    monkeypatch.setattr(
        cli,
        "create_database_engine",
        use_test_engine,
    )

    def simulate_database_failure(
        connection: Connection,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if "FROM one_time_tokens" in statement:
            raise SQLAlchemyError("Simulated database failure")

    event.listen(
        test_engine,
        "before_cursor_execute",
        simulate_database_failure,
    )

    try:
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

        assert exc_info.value.code != 0

        captured = capsys.readouterr()
        assert "Database operation failed" in captured.err
        assert "Traceback" not in captured.err

    finally:
        event.remove(
            test_engine,
            "before_cursor_execute",
            simulate_database_failure,
        )

    # A new connection must be able to acquire the maintenance lock.
    with test_engine.connect() as connection:
        acquired = connection.scalar(text("SELECT pg_try_advisory_lock(723941, 3)"))

        assert acquired is True

        released = connection.scalar(text("SELECT pg_advisory_unlock(723941, 3)"))
        assert released is True


def test_cleanup_auth_cli_deletes_expired_access_tokens(
    monkeypatch: pytest.MonkeyPatch,
    test_engine: Engine,
) -> None:
    """CLI removes old access tokens without deleting their login session."""
    now = datetime.now(UTC)
    email = f"cli-access-cleanup-{uuid7().hex}@example.com"

    old_token_hash = hash_token(uuid7().hex)
    recent_token_hash = hash_token(uuid7().hex)

    with Session(test_engine) as session:
        with session.begin():
            user = User(
                email=email,
                normalized_email=email,
                display_name="CLI Access Cleanup User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )
            session.add(user)
            session.flush()

            login_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=hash_token(uuid7().hex),
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
                        token_hash=old_token_hash,
                        created_at=now - timedelta(hours=3),
                        expires_at=now - timedelta(hours=2),
                    ),
                    AccessToken(
                        session_id=login_session_id,
                        token_hash=recent_token_hash,
                        created_at=now - timedelta(hours=1),
                        expires_at=now - timedelta(minutes=30),
                    ),
                ]
            )

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_EXPIRED_ACCESS_TOKEN_RETENTION_HOURS": 1,
        }
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "cleanup-auth"],
    )
    monkeypatch.setattr(cli, "Settings", lambda: settings)

    def use_test_engine(_settings: object) -> Engine:
        return test_engine

    monkeypatch.setattr(
        cli,
        "create_database_engine",
        use_test_engine,
    )

    cli.main()

    with Session(test_engine) as session:
        old_token = session.scalar(
            select(AccessToken).where(
                AccessToken.token_hash == old_token_hash,
            )
        )
        recent_token = session.scalar(
            select(AccessToken).where(
                AccessToken.token_hash == recent_token_hash,
            )
        )
        retained_session = session.get(
            LoginSession,
            login_session_id,
        )

        assert old_token is None
        assert recent_token is not None
        assert retained_session is not None


def test_cleanup_auth_cli_deletes_inactive_sessions(
    monkeypatch: pytest.MonkeyPatch,
    test_engine: Engine,
) -> None:
    """CLI removes old sessions and their history, preserving active sessions."""
    now = datetime.now(UTC)
    email = f"cli-session-cleanup-{uuid7().hex}@example.com"

    with Session(test_engine) as session:
        with session.begin():
            user = User(
                email=email,
                normalized_email=email,
                display_name="CLI Session Cleanup User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )
            session.add(user)
            session.flush()

            old_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=hash_token(uuid7().hex),
                created_at=now - timedelta(days=50),
                expires_at=now - timedelta(days=45),
            )

            active_session = LoginSession(
                user_id=user.id,
                refresh_token_hash=hash_token(uuid7().hex),
                created_at=now - timedelta(days=1),
                expires_at=now + timedelta(days=6),
            )

            session.add_all([old_session, active_session])
            session.flush()

            old_session_id = old_session.id
            active_session_id = active_session.id

            history = RefreshTokenHistory(
                session_id=old_session_id,
                token_hash=hash_token(uuid7().hex),
                used_at=now - timedelta(days=48),
            )
            session.add(history)
            session.flush()

            history_id = history.id

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_SESSION_HISTORY_RETENTION_DAYS": 30,
        }
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["restling-admin", "cleanup-auth"],
    )
    monkeypatch.setattr(cli, "Settings", lambda: settings)

    def use_test_engine(_settings: object) -> Engine:
        return test_engine

    monkeypatch.setattr(
        cli,
        "create_database_engine",
        use_test_engine,
    )

    cli.main()

    with Session(test_engine) as session:
        assert session.get(LoginSession, old_session_id) is None
        assert session.get(RefreshTokenHistory, history_id) is None
        assert session.get(LoginSession, active_session_id) is not None

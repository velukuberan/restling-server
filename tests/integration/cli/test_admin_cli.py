"""Integration tests for the administrator CLI."""

import subprocess
import sys

import pytest
from pydantic import ValidationError
from sqlalchemy import URL, Engine, create_engine, delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from restling_server.users import cli
from restling_server.users.models import User
from restling_server.users.service import bootstrap_administrator


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

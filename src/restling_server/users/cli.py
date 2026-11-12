"""Command-line administration for Restling Server."""

import argparse
from getpass import getpass

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from restling_server.core.config import Settings
from restling_server.core.database import (
    create_database_engine,
    create_session_factory,
)
from restling_server.users.service import (
    AdministratorAlreadyInitializedError,
    bootstrap_administrator,
)


def main() -> None:
    """Run the Restling administrator CLI."""
    parser = argparse.ArgumentParser(
        prog="restling-admin",
        description="Restling Server administration commands.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser(
        "bootstrap",
        help="Create the initial server administrator.",
    )

    args = parser.parse_args()

    if args.command == "bootstrap":
        email = input("Administrator email: ").strip()
        display_name = input("Display name: ").strip()

        password = getpass("Password: ")
        confirm_password = getpass("Confirm password: ")

        if password != confirm_password:
            parser.error("Passwords do not match.")

        try:
            settings = Settings()  # pyright: ignore[reportCallIssue]
        except ValidationError:
            parser.error("Invalid or incomplete database configuration.")

        engine = None

        try:
            engine = create_database_engine(settings)
            session_factory = create_session_factory(engine)

            with session_factory() as session:
                bootstrap_administrator(
                    session,
                    email=email,
                    display_name=display_name,
                    password=password,
                )

        except AdministratorAlreadyInitializedError:
            parser.error("Server administrator is already initialized.")

        except ValueError as exc:
            parser.error(str(exc))

        except SQLAlchemyError:
            parser.error("Database operation failed. Check server configuration.")

        finally:
            if engine is not None:
                engine.dispose()

        print("Initial administrator created successfully.")

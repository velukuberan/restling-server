"""Command-line administration for Restling Server."""

import argparse
from getpass import getpass
from uuid import UUID

from email_validator import EmailNotValidError, validate_email
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.core.database import (
    create_database_engine,
    create_session_factory,
)
from restling_server.users.activation_links import (
    ActivationURLNotConfiguredError,
)
from restling_server.users.invitation_email import InvitationDeliveryError
from restling_server.users.invitations import (
    deliver_activation_invitation,
    prepare_activation_invitation,
)
from restling_server.users.models import User
from restling_server.users.passwords import verify_password
from restling_server.users.service import (
    AdministratorAlreadyInitializedError,
    InvitationNotAllowedError,
    bootstrap_administrator,
)


def authenticate_cli_administrator(
    session: Session,
    *,
    email: str,
    password: str,
) -> UUID:
    """Verify an active administrator for a privileged CLI operation."""
    error_message = "Invalid administrator credentials."

    try:
        normalized_email = validate_email(
            email.strip(),
            check_deliverability=False,
        ).normalized.casefold()
    except EmailNotValidError:
        raise ValueError(error_message) from None

    with session.begin():
        administrator = session.scalar(
            select(User).where(
                User.normalized_email == normalized_email,
                User.system_role == "administrator",
                User.status == "active",
                User.password_reset_required.is_(False),
            )
        )

        if (
            administrator is None
            or administrator.password_hash is None
            or not verify_password(
                password,
                administrator.password_hash,
            )
        ):
            raise ValueError(error_message)

        administrator_id = administrator.id

    return administrator_id


def find_pending_user_id(
    session: Session,
    *,
    email: str,
) -> UUID:
    """Resolve a pending account by its normalized email."""
    error_message = "Pending user account not found."

    try:
        normalized_email = validate_email(
            email.strip(),
            check_deliverability=False,
        ).normalized.casefold()
    except EmailNotValidError:
        raise ValueError(error_message) from None

    with session.begin():
        user_id = session.scalar(
            select(User.id).where(
                User.normalized_email == normalized_email,
                User.status == "pending",
            )
        )

    if user_id is None:
        raise ValueError(error_message)

    return user_id


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

    invite_parser = subparsers.add_parser(
        "invite",
        help="Issue an activation invitation for a pending user.",
    )

    invite_parser.add_argument(
        "--user",
        required=True,
        metavar="EMAIL",
        help="Email address of the pending user.",
    )

    invite_parser.add_argument(
        "--manual",
        action="store_true",
        help="Generate an activation link for manual delivery.",
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

    if args.command == "invite":
        administrator_email = input("Administrator email: ").strip()
        administrator_password = getpass("Administrator password: ")

        try:
            settings = Settings()  # pyright: ignore[reportCallIssue]
        except ValidationError:
            parser.error("Invalid or incomplete server configuration.")

        engine = None

        try:
            engine = create_database_engine(settings)
            session_factory = create_session_factory(engine)

            with session_factory() as session:
                administrator_id = authenticate_cli_administrator(
                    session,
                    email=administrator_email,
                    password=administrator_password,
                )

                user_id = find_pending_user_id(
                    session,
                    email=args.user,
                )

                manual_delivery = args.manual or settings.smtp_host is None

                if manual_delivery:
                    activation_url, expires_at = prepare_activation_invitation(
                        session,
                        settings=settings,
                        actor_id=administrator_id,
                        user_id=user_id,
                    )

                    print("WARNING: This link is a sensitive one-time credential.")
                    print("Share it securely with the intended recipient.")
                    print(f"Activation link: {activation_url}")
                else:
                    expires_at = deliver_activation_invitation(
                        session,
                        settings=settings,
                        actor_id=administrator_id,
                        user_id=user_id,
                    )

                    print("Activation invitation submitted through SMTP.")

            print(f"Invitation expires at: {expires_at.isoformat()}")

        except ValueError as exc:
            parser.error(str(exc))

        except InvitationNotAllowedError:
            parser.error("Invitation is not permitted.")

        except ActivationURLNotConfiguredError:
            parser.error("A trusted public URL must be configured.")

        except InvitationDeliveryError:
            parser.error("Invitation delivery failed. Reissue may be required.")

        except SQLAlchemyError:
            parser.error("Database operation failed. Check server configuration.")

        finally:
            if engine is not None:
                engine.dispose()

"""PostgreSQL integration tests for invitation workflows."""

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

import restling_server.users.invitations as invitations
from restling_server.core.config import Settings
from restling_server.users.activation_links import (
    ActivationURLNotConfiguredError,
)
from restling_server.users.invitation_email import InvitationDeliveryError
from restling_server.users.invitations import (
    deliver_activation_invitation,
    prepare_activation_invitation,
)
from restling_server.users.models import OneTimeToken, User
from restling_server.users.service import (
    InvitationNotAllowedError,
    issue_activation_token,
)
from restling_server.users.tokens import hash_token


def test_administrator_can_prepare_activation_invitation(
    test_engine: Engine,
) -> None:
    """An administrator can create a trusted activation invitation."""
    test_id = uuid7().hex
    admin_email = f"invitation-admin-{test_id}@example.com"
    user_email = f"invitation-user-{test_id}@example.com"

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": "https://restling.example.com",
            "RESTLING_INVITATION_EXPIRY_HOURS": 48,
        }
    )

    try:
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        before_issuance = datetime.now(UTC)

        with Session(test_engine) as session:
            activation_url, expires_at = prepare_activation_invitation(
                session,
                settings=settings,
                actor_id=administrator_id,
                user_id=user_id,
            )

        after_issuance = datetime.now(UTC)

        # Verify the trusted URL and activation credential.
        parsed = urlsplit(activation_url)

        assert parsed.scheme == "https"
        assert parsed.netloc == "restling.example.com"
        assert parsed.path == "/activate"

        query = parse_qs(parsed.query)
        assert "token" in query

        raw_token = query["token"][0]

        # The configured 48-hour expiry must be respected.
        assert before_issuance + timedelta(hours=48) <= expires_at
        assert expires_at <= after_issuance + timedelta(hours=48)

        # Verify the committed PostgreSQL state.
        with Session(test_engine) as session:
            stored_tokens = session.scalars(
                select(OneTimeToken).where(OneTimeToken.user_id == user_id)
            ).all()

            assert len(stored_tokens) == 1

            stored_token = stored_tokens[0]

            assert stored_token.purpose == "account_activation"
            assert stored_token.token_hash == hash_token(raw_token)
            assert stored_token.token_hash != raw_token
            assert stored_token.expires_at == expires_at
            assert stored_token.consumed_at is None
            assert stored_token.revoked_at is None

            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "pending"
            assert user.password_hash is None

    finally:
        # Clean up records created by this test.
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


def test_ordinary_user_cannot_prepare_activation_invitation(
    test_engine: Engine,
) -> None:
    """Ordinary users cannot issue account activation invitations."""
    test_id = uuid7().hex
    actor_email = f"invitation-actor-{test_id}@example.com"
    target_email = f"invitation-target-{test_id}@example.com"

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": "https://restling.example.com",
        }
    )

    try:
        with Session(test_engine) as session:
            actor = User(
                email=actor_email,
                normalized_email=actor_email,
                display_name="Ordinary User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )

            target = User(
                email=target_email,
                normalized_email=target_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([actor, target])
            session.commit()

            actor_id = actor.id
            target_id = target.id

        with Session(test_engine) as session:
            with pytest.raises(InvitationNotAllowedError):
                prepare_activation_invitation(
                    session,
                    settings=settings,
                    actor_id=actor_id,
                    user_id=target_id,
                )

        with Session(test_engine) as session:
            tokens = session.scalars(
                select(OneTimeToken).where(OneTimeToken.user_id == target_id)
            ).all()

            assert tokens == []

            target = session.get(User, target_id)

            assert target is not None
            assert target.status == "pending"

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([actor_email, target_email])
            )

            connection.execute(
                delete(OneTimeToken).where(OneTimeToken.user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(
                    User.normalized_email.in_([actor_email, target_email])
                )
            )


def test_missing_public_url_preserves_existing_invitation(
    test_engine: Engine,
) -> None:
    """Missing URL configuration must not revoke an existing token."""
    test_id = uuid7().hex
    admin_email = f"missing-url-admin-{test_id}@example.com"
    user_email = f"missing-url-user-{test_id}@example.com"

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": None,
        }
    )

    try:
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        # Issue an existing valid invitation.
        with Session(test_engine) as session:
            original_token, _ = issue_activation_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_hours=24,
            )

        # Attempt reissue with missing public URL configuration.
        with Session(test_engine) as session:
            with pytest.raises(ActivationURLNotConfiguredError):
                prepare_activation_invitation(
                    session,
                    settings=settings,
                    actor_id=administrator_id,
                    user_id=user_id,
                )

        # The original credential must remain usable.
        with Session(test_engine) as session:
            stored_tokens = session.scalars(
                select(OneTimeToken).where(OneTimeToken.user_id == user_id)
            ).all()

            assert len(stored_tokens) == 1

            stored_token = stored_tokens[0]

            assert stored_token.token_hash == hash_token(original_token)
            assert stored_token.revoked_at is None
            assert stored_token.consumed_at is None
            assert stored_token.expires_at > datetime.now(UTC)

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


def test_reissuing_invitation_revokes_previous_token(
    test_engine: Engine,
) -> None:
    """Only the latest activation invitation remains usable."""
    test_id = uuid7().hex
    admin_email = f"reissue-admin-{test_id}@example.com"
    user_email = f"reissue-user-{test_id}@example.com"

    settings = Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": "https://restling.example.com",
            "RESTLING_INVITATION_EXPIRY_HOURS": 24,
        }
    )

    try:
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        # Issue the first invitation.
        with Session(test_engine) as session:
            first_url, first_expiry = prepare_activation_invitation(
                session,
                settings=settings,
                actor_id=administrator_id,
                user_id=user_id,
            )

        # Reissue the invitation using a separate transaction.
        with Session(test_engine) as session:
            second_url, second_expiry = prepare_activation_invitation(
                session,
                settings=settings,
                actor_id=administrator_id,
                user_id=user_id,
            )

        first_token = parse_qs(urlsplit(first_url).query)["token"][0]
        second_token = parse_qs(urlsplit(second_url).query)["token"][0]

        assert first_token != second_token
        assert first_url != second_url
        assert second_expiry >= first_expiry

        # Verify the previous token was revoked.
        with Session(test_engine) as session:
            stored_tokens = session.scalars(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                    OneTimeToken.purpose == "account_activation",
                )
            ).all()

            assert len(stored_tokens) == 2

            old_token = next(
                token
                for token in stored_tokens
                if token.token_hash == hash_token(first_token)
            )

            new_token = next(
                token
                for token in stored_tokens
                if token.token_hash == hash_token(second_token)
            )

            assert old_token.revoked_at is not None
            assert old_token.consumed_at is None

            assert new_token.revoked_at is None
            assert new_token.consumed_at is None
            assert new_token.expires_at == second_expiry
            assert new_token.expires_at > datetime.now(UTC)

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


def test_smtp_invitation_is_delivered_after_commit(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SMTP delivery occurs after the activation token is committed."""
    test_id = uuid7().hex
    admin_email = f"smtp-admin-{test_id}@example.com"
    user_email = f"smtp-user-{test_id}@example.com"

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
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        deliveries: list[str] = []

        def fake_send_invitation(
            smtp_settings: Settings,
            *,
            recipient: str,
            activation_url: str,
        ) -> None:
            """Check the committed state at the SMTP boundary."""
            assert recipient == user_email
            assert not session.in_transaction()

            raw_token = parse_qs(urlsplit(activation_url).query)["token"][0]

            with Session(test_engine) as verification_session:
                stored_token = verification_session.scalar(
                    select(OneTimeToken).where(
                        OneTimeToken.user_id == user_id,
                        OneTimeToken.token_hash == hash_token(raw_token),
                    )
                )

                assert stored_token is not None
                assert stored_token.revoked_at is None

            deliveries.append(activation_url)

        monkeypatch.setattr(
            invitations,
            "send_invitation_email",
            fake_send_invitation,
        )

        with Session(test_engine) as session:
            expires_at = deliver_activation_invitation(
                session,
                settings=settings,
                actor_id=administrator_id,
                user_id=user_id,
            )

        assert len(deliveries) == 1
        assert expires_at > datetime.now(UTC)
        assert deliveries[0].startswith("https://restling.example.com/activate?token=")

        with Session(test_engine) as session:
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


def test_failed_smtp_invitation_can_be_reissued(
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An SMTP failure leaves the account pending and permits reissue."""
    test_id = uuid7().hex
    admin_email = f"smtp-failure-admin-{test_id}@example.com"
    user_email = f"smtp-failure-user-{test_id}@example.com"

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
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

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

        monkeypatch.setattr(
            invitations,
            "send_invitation_email",
            failing_sender,
        )

        with Session(test_engine) as session:
            with pytest.raises(InvitationDeliveryError) as exc_info:
                deliver_activation_invitation(
                    session,
                    settings=settings,
                    actor_id=administrator_id,
                    user_id=user_id,
                )

        assert str(exc_info.value) == "Unable to deliver account invitation."
        assert failed_url is not None

        first_token = parse_qs(urlsplit(failed_url).query)["token"][0]
        assert first_token not in str(exc_info.value)

        # SMTP failed, but the database transaction was committed.
        with Session(test_engine) as session:
            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "pending"
            assert user.password_hash is None

            first_stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                    OneTimeToken.token_hash == hash_token(first_token),
                )
            )

            assert first_stored_token is not None
            assert first_stored_token.revoked_at is None
            assert first_stored_token.consumed_at is None

        # Administrator reissues the invitation.
        with Session(test_engine) as session:
            second_url, _ = prepare_activation_invitation(
                session,
                settings=settings,
                actor_id=administrator_id,
                user_id=user_id,
            )

        second_token = parse_qs(urlsplit(second_url).query)["token"][0]

        assert second_token != first_token

        with Session(test_engine) as session:
            tokens = session.scalars(
                select(OneTimeToken).where(OneTimeToken.user_id == user_id)
            ).all()

            assert len(tokens) == 2

            old_token = next(
                token for token in tokens if token.token_hash == hash_token(first_token)
            )

            new_token = next(
                token
                for token in tokens
                if token.token_hash == hash_token(second_token)
            )

            assert old_token.revoked_at is not None
            assert new_token.revoked_at is None
            assert new_token.consumed_at is None

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

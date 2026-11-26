"""Integration tests for password-recovery security auditing."""

from datetime import UTC, datetime
from typing import Literal, cast

import pytest
from sqlalchemy import Engine, event, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AuditLog
from restling_server.users.service import record_password_recovery_failure


@pytest.mark.parametrize(
    ("reason", "expected_action", "expected_metadata"),
    [
        (
            "delivery_failed",
            "user.password_reset_delivery_failed",
            {"delivery": "email"},
        ),
        (
            "account_state_changed",
            "user.password_reset_discarded",
            {"reason": "account_state_changed"},
        ),
    ],
)
def test_password_recovery_failure_persists_audit_event(
    test_engine: Engine,
    reason: Literal["delivery_failed", "account_state_changed"],
    expected_action: str,
    expected_metadata: dict[str, str],
) -> None:
    """Recovery failures persist the expected security event."""
    user_id = uuid7()
    before = datetime.now(UTC)

    with Session(test_engine) as session:
        record_password_recovery_failure(
            session,
            user_id=user_id,
            reason=reason,
        )

        assert not session.in_transaction()

    after = datetime.now(UTC)

    # An independent session verifies committed persistence.
    with Session(test_engine) as session:
        audit_events = session.scalars(select(AuditLog)).all()

        assert len(audit_events) == 1

        audit_event = audit_events[0]

        assert audit_event.id is not None
        assert audit_event.actor_user_id is None
        assert audit_event.target_user_id == user_id
        assert audit_event.action == expected_action
        assert audit_event.event_metadata == expected_metadata
        assert before <= audit_event.created_at <= after


def test_unsupported_recovery_failure_reason_is_rejected(
    test_engine: Engine,
) -> None:
    """Unsupported failure reasons cannot produce audit records."""
    user_id = uuid7()

    unsupported_reason = cast(
        Literal["delivery_failed", "account_state_changed"],
        "unsupported_reason",
    )

    with Session(test_engine) as session:
        with pytest.raises(
            ValueError,
            match="Unsupported password-recovery failure reason.",
        ):
            record_password_recovery_failure(
                session,
                user_id=user_id,
                reason=unsupported_reason,
            )

        assert not session.in_transaction()

    with Session(test_engine) as session:
        audit_events = session.scalars(select(AuditLog)).all()

        assert audit_events == []


def test_password_recovery_audit_rolls_back_on_transaction_failure(
    test_engine: Engine,
) -> None:
    """A failed audit transaction leaves no committed audit record."""
    user_id = uuid7()

    def fail_after_flush(
        _session: Session,
        _flush_context: object,
    ) -> None:
        raise RuntimeError("Simulated audit persistence failure")

    with Session(test_engine) as session:
        event.listen(
            session,
            "after_flush_postexec",
            fail_after_flush,
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated audit persistence failure",
        ):
            record_password_recovery_failure(
                session,
                user_id=user_id,
                reason="delivery_failed",
            )

        assert not session.in_transaction()

    with Session(test_engine) as session:
        audit_events = session.scalars(select(AuditLog)).all()

        assert audit_events == []

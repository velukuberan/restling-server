"""HTTP routes for user authentication and activation."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from restling_server.core.dependencies import get_db_session
from restling_server.users.schemas import (
    ActivateUserRequest,
    ActivateUserResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
)
from restling_server.users.service import (
    InvalidActivationTokenError,
    InvalidPasswordResetTokenError,
    activate_user,
    reset_user_password,
)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

DbSession = Annotated[Session, Depends(get_db_session)]


@router.post(
    "/activate",
    response_model=ActivateUserResponse,
    status_code=200,
)
def activate_account(
    payload: ActivateUserRequest,
    session: DbSession,
    response: Response,
) -> ActivateUserResponse | JSONResponse:
    """Activate a pending account using a one-time credential."""
    try:
        activate_user(
            session,
            token=payload.token,
            password=payload.password,
        )
    except InvalidActivationTokenError:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "INVALID_ACTIVATION_TOKEN",
                    "message": "Invalid or expired activation credential.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )
    except ValueError:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "PASSWORD_POLICY_VIOLATION",
                    "message": "Password does not meet the required policy.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    response.headers["Cache-Control"] = "no-store"

    return ActivateUserResponse(message="Account activated successfully.")


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    status_code=200,
)
def complete_password_reset(
    payload: ResetPasswordRequest,
    session: DbSession,
    response: Response,
) -> ResetPasswordResponse | JSONResponse:
    """Complete password recovery using a one-time credential."""
    try:
        reset_user_password(
            session,
            token=payload.token,
            new_password=payload.new_password,
        )
    except InvalidPasswordResetTokenError:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "INVALID_PASSWORD_RESET_TOKEN",
                    "message": "Invalid or expired password-reset credential.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )
    except ValueError:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "PASSWORD_POLICY_VIOLATION",
                    "message": "Password does not meet the required policy.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    response.headers["Cache-Control"] = "no-store"

    return ResetPasswordResponse(message="Password reset successfully.")

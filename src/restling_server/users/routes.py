"""HTTP routes for user authentication and activation."""

from datetime import UTC, datetime
from typing import Annotated, cast

from fastapi import (
    APIRouter,
    Depends,
    Request,
    Response,
)
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.core.dependencies import get_db_session
from restling_server.users.dependencies import CurrentUser
from restling_server.users.schemas import (
    ActivateUserRequest,
    ActivateUserResponse,
    LoginRequest,
    LoginResponse,
    LoginTokenData,
    RefreshTokenRequest,
    ResetPasswordRequest,
    ResetPasswordResponse,
    UserDetail,
    UserDetailResponse,
    UserSessionDetail,
    UserSessionsResponse,
)
from restling_server.users.service import (
    InvalidActivationTokenError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    SessionLimitReachedError,
    activate_user,
    list_user_sessions,
    login_user,
    logout_session,
    refresh_session,
    reset_user_password,
)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

DbSession = Annotated[Session, Depends(get_db_session)]

logout_bearer_scheme = HTTPBearer(auto_error=False)

LogoutCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(logout_bearer_scheme),
]


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


users_router = APIRouter(
    prefix="/api/v1/users",
    tags=["Users"],
)


@users_router.get(
    "/me",
    response_model=UserDetailResponse,
    status_code=200,
)
def get_my_profile(
    current_user: CurrentUser,
) -> UserDetailResponse:
    """Return the authenticated user's profile."""
    return UserDetailResponse(
        data=UserDetail.model_validate(current_user),
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=200,
)
def login(
    payload: LoginRequest,
    session: DbSession,
    request: Request,
    response: Response,
) -> LoginResponse | JSONResponse:
    """Authenticate a user and issue session credentials."""
    settings = cast(Settings, request.app.state.settings)

    try:
        result = login_user(
            session,
            email=payload.email,
            password=payload.password,
            access_token_expiry_minutes=(settings.access_token_expiry_minutes),
            refresh_session_expiry_days=(settings.refresh_session_expiry_days),
            max_active_sessions=settings.max_active_sessions,
        )

    except InvalidCredentialsError:
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "code": "INVALID_CREDENTIALS",
                    "message": "Invalid email address or password.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    except SessionLimitReachedError:
        # Restricted session-recovery credentials will be
        # integrated when the recovery use case is implemented.
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "SESSION_LIMIT_REACHED",
                    "message": "Maximum active sessions reached.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    response.headers["Cache-Control"] = "no-store"

    return LoginResponse(
        data=LoginTokenData(
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            token_type="Bearer",
            expires_in=settings.access_token_expiry_minutes * 60,
            refresh_expires_at=result.session_expires_at,
            session_id=result.session_id,
        )
    )


@router.post(
    "/refresh",
    response_model=LoginResponse,
    status_code=200,
)
def refresh_login(
    payload: RefreshTokenRequest,
    session: DbSession,
    request: Request,
    response: Response,
) -> LoginResponse | JSONResponse:
    """Rotate refresh credentials for an existing session."""
    settings = cast(Settings, request.app.state.settings)

    try:
        result = refresh_session(
            session,
            refresh_token=payload.refresh_token,
            access_token_expiry_minutes=(settings.access_token_expiry_minutes),
        )
    except InvalidCredentialsError:
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "code": "INVALID_REFRESH_TOKEN",
                    "message": "Invalid or expired refresh credential.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    expires_in = int(
        (result.access_token_expires_at - datetime.now(UTC)).total_seconds()
    )

    response.headers["Cache-Control"] = "no-store"

    return LoginResponse(
        data=LoginTokenData(
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            token_type="Bearer",
            expires_in=max(0, expires_in),
            refresh_expires_at=result.session_expires_at,
            session_id=result.session_id,
        )
    )


def unauthorized_logout_response() -> JSONResponse:
    """Return the established authentication error envelope."""
    return JSONResponse(
        status_code=401,
        content={
            "error": {
                "code": "UNAUTHORIZED",
                "message": "Authentication is required.",
            }
        },
        headers={
            "WWW-Authenticate": "Bearer",
            "Cache-Control": "no-store",
        },
    )


@router.post(
    "/logout",
    status_code=204,
)
def logout(
    credentials: LogoutCredentials,
    session: DbSession,
) -> Response:
    """Revoke the current login session."""
    if credentials is None:
        return unauthorized_logout_response()

    try:
        logout_session(
            session,
            access_token=credentials.credentials,
        )
    except InvalidCredentialsError:
        return unauthorized_logout_response()

    return Response(
        status_code=204,
        headers={"Cache-Control": "no-store"},
    )


@users_router.get(
    "/me/sessions",
    response_model=UserSessionsResponse,
    status_code=200,
)
def get_my_sessions(
    credentials: LogoutCredentials,
    session: DbSession,
    response: Response,
) -> UserSessionsResponse | JSONResponse:
    """List active sessions belonging to the authenticated user."""
    if credentials is None:
        return unauthorized_logout_response()

    try:
        sessions = list_user_sessions(
            session,
            access_token=credentials.credentials,
        )
    except InvalidCredentialsError:
        return unauthorized_logout_response()

    response.headers["Cache-Control"] = "no-store"

    return UserSessionsResponse(
        data=[
            UserSessionDetail(
                session_id=item.session_id,
                created_at=item.created_at,
                expires_at=item.expires_at,
                last_used_at=item.last_used_at,
                login_ip=item.login_ip,
                last_seen_ip=item.last_seen_ip,
                machine_name=item.machine_name,
                is_current=item.is_current,
            )
            for item in sessions
        ]
    )

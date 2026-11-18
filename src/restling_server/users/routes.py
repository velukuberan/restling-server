"""HTTP routes for user authentication and activation."""

from datetime import UTC, datetime
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Query,
    Request,
    Response,
)
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from restling_server.core.config import Settings
from restling_server.core.dependencies import get_db_session
from restling_server.users.activation_links import (
    ActivationURLNotConfiguredError,
)
from restling_server.users.dependencies import CurrentUser
from restling_server.users.invitation_email import InvitationDeliveryError
from restling_server.users.invitations import (
    deliver_activation_invitation,
    prepare_activation_invitation,
)
from restling_server.users.schemas import (
    ActivateUserRequest,
    ActivateUserResponse,
    CreateUserRequest,
    CreateUserResponse,
    LoginRequest,
    LoginResponse,
    LoginTokenData,
    PaginationDetail,
    RefreshTokenRequest,
    ReissueInvitationRequest,
    ReissueInvitationResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    RestoreUserRequest,
    RevokeOtherSessionsData,
    RevokeOtherSessionsResponse,
    UserDetail,
    UserDetailResponse,
    UserInvitationDetail,
    UserSessionDetail,
    UserSessionsResponse,
    UsersResponse,
    UserSummary,
)
from restling_server.users.service import (
    InvalidActivationTokenError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    InvitationNotAllowedError,
    LastAdministratorError,
    SessionLimitReachedError,
    SessionNotFoundError,
    UserAlreadyExistsError,
    UserCreationNotAllowedError,
    UserDetailNotAllowedError,
    UserListingNotAllowedError,
    UserNotFoundError,
    UserRestorationNotAllowedError,
    UserSuspensionNotAllowedError,
    activate_user,
    authenticate_access_token,
    create_user,
    get_user_detail,
    list_user_session_history,
    list_users,
    login_user,
    logout_session,
    refresh_session,
    reset_user_password,
    restore_user,
    revoke_all_user_sessions,
    revoke_other_sessions,
    revoke_user_session,
    suspend_user,
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
    request: Request,
    response: Response,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    status: Annotated[
        Literal["active", "revoked", "expired"] | None,
        Query(),
    ] = None,
) -> UserSessionsResponse | JSONResponse:
    """List current and historical sessions for the caller."""
    if credentials is None:
        return unauthorized_logout_response()

    settings = cast(Settings, request.app.state.settings)

    try:
        result = list_user_session_history(
            session,
            access_token=credentials.credentials,
            status=status,
            limit=limit,
            offset=offset,
            retention_days=settings.session_history_retention_days,
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
                revoked_at=item.revoked_at,
                login_ip=item.login_ip,
                last_seen_ip=item.last_seen_ip,
                machine_name=item.machine_name,
                status=item.status,
                is_current=item.is_current,
            )
            for item in result.items
        ],
        pagination=PaginationDetail(
            limit=limit,
            offset=offset,
            total=result.total,
        ),
    )


@users_router.delete(
    "/me/sessions/{session_id}",
    status_code=204,
    response_class=Response,
    response_model=None,
)
def delete_my_session(
    session_id: UUID,
    credentials: LogoutCredentials,
    session: DbSession,
    response: Response,
) -> Response | JSONResponse:
    """Revoke an owned session without deleting its history."""
    if credentials is None:
        return unauthorized_logout_response()

    try:
        revoke_user_session(
            session,
            access_token=credentials.credentials,
            target_session_id=session_id,
        )
    except SessionNotFoundError:
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": "SESSION_NOT_FOUND",
                    "message": "Session not found.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )
    except InvalidCredentialsError:
        return unauthorized_logout_response()

    response.headers["Cache-Control"] = "no-store"
    response.status_code = 204
    return response


@users_router.post(
    "/me/sessions/revoke-others",
    response_model=RevokeOtherSessionsResponse,
    status_code=200,
)
def revoke_my_other_sessions(
    credentials: LogoutCredentials,
    session: DbSession,
    response: Response,
) -> RevokeOtherSessionsResponse | JSONResponse:
    """Revoke all other active sessions while preserving the caller."""
    if credentials is None:
        return unauthorized_logout_response()

    try:
        revoked_count = revoke_other_sessions(
            session,
            access_token=credentials.credentials,
        )
    except InvalidCredentialsError:
        return unauthorized_logout_response()

    response.headers["Cache-Control"] = "no-store"

    return RevokeOtherSessionsResponse(
        data=RevokeOtherSessionsData(
            revoked_count=revoked_count,
        )
    )


@users_router.delete(
    "/me/sessions",
    status_code=204,
    response_class=Response,
    response_model=None,
)
def revoke_my_all_sessions(
    credentials: LogoutCredentials,
    session: DbSession,
) -> Response | JSONResponse:
    """Revoke every session owned by the authenticated user."""
    if credentials is None:
        return unauthorized_logout_response()

    try:
        revoke_all_user_sessions(
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
    "",
    response_model=UsersResponse,
    status_code=200,
)
def get_users(
    current_user: CurrentUser,
    session: DbSession,
    response: Response,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    status: Annotated[
        Literal["pending", "active", "suspended"] | None,
        Query(),
    ] = None,
    system_role: Annotated[
        Literal["administrator", "user"] | None,
        Query(),
    ] = None,
    search: str | None = None,
    sort_by: Literal["created_at", "email", "display_name", "status"] = "created_at",
    sort_order: Literal["asc", "desc"] = "desc",
) -> UsersResponse | JSONResponse:
    """List user accounts for a system administrator."""
    try:
        users, total = list_users(
            session,
            actor=current_user,
            limit=limit,
            offset=offset,
            status=status,
            system_role=system_role,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )
    except UserListingNotAllowedError:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Administrator privileges are required.",
                }
            },
        )

    response.headers["Cache-Control"] = "no-store"

    return UsersResponse(
        data=[UserSummary.model_validate(user) for user in users],
        pagination=PaginationDetail(
            limit=limit,
            offset=offset,
            total=total,
        ),
    )


@users_router.get(
    "/{user_id}",
    response_model=UserDetailResponse,
    status_code=200,
)
def get_user_by_id(
    user_id: UUID,
    current_user: CurrentUser,
    session: DbSession,
    response: Response,
) -> UserDetailResponse | JSONResponse:
    """Retrieve user account details as an administrator."""
    try:
        user = get_user_detail(
            session,
            actor=current_user,
            user_id=user_id,
        )
    except UserDetailNotAllowedError:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Administrator privileges are required.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )
    except UserNotFoundError:
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": "USER_NOT_FOUND",
                    "message": "User account not found.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    response.headers["Cache-Control"] = "no-store"

    return UserDetailResponse(
        data=UserDetail.model_validate(user),
    )


@users_router.post(
    "",
    response_model=CreateUserResponse,
    status_code=201,
)
def create_user_account(
    payload: CreateUserRequest,
    credentials: LogoutCredentials,
    session: DbSession,
    request: Request,
    response: Response,
) -> CreateUserResponse | JSONResponse:
    """Create a pending user and issue an activation invitation."""
    if credentials is None:
        return unauthorized_logout_response()

    try:
        with session.begin():
            actor = authenticate_access_token(
                session,
                access_token=credentials.credentials,
            )
            actor_id = actor.id
    except InvalidCredentialsError:
        return unauthorized_logout_response()

    if (
        actor.system_role != "administrator"
        or actor.status != "active"
        or actor.password_reset_required
    ):
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Administrator privileges are required.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    settings = cast(Settings, request.app.state.settings)

    if settings.public_url is None:
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "INVITATION_UNAVAILABLE",
                    "message": "Account invitations are not configured.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    delivery = payload.invitation_delivery

    if delivery is None:
        delivery = "email" if settings.smtp_host is not None else "manual"

    if delivery == "email" and (
        settings.smtp_host is None or settings.smtp_from_email is None
    ):
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "INVITATION_UNAVAILABLE",
                    "message": "SMTP invitation delivery is not configured.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    try:
        user = create_user(
            session,
            actor_id=actor_id,
            email=payload.email,
            display_name=payload.display_name,
            job_title=payload.job_title,
        )
    except UserCreationNotAllowedError:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Administrator privileges are required.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )
    except UserAlreadyExistsError:
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "EMAIL_ALREADY_EXISTS",
                    "message": "A user with this email already exists.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )
    except ValueError:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Invalid user account data.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    # Account creation has committed. Invitation delivery
    # is handled separately, including SMTP communication.
    try:
        if delivery == "manual":
            activation_url, expires_at = prepare_activation_invitation(
                session,
                settings=settings,
                actor_id=actor_id,
                user_id=user.id,
            )

            invitation = UserInvitationDetail(
                delivery="manual",
                expires_at=expires_at,
                activation_url=activation_url,
            )
        else:
            expires_at = deliver_activation_invitation(
                session,
                settings=settings,
                actor_id=actor_id,
                user_id=user.id,
            )

            invitation = UserInvitationDetail(
                delivery="email",
                expires_at=expires_at,
            )
    except (ActivationURLNotConfiguredError, InvitationDeliveryError):
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "INVITATION_DELIVERY_FAILED",
                    "message": (
                        "Account created, but invitation delivery failed. "
                        "The invitation must be reissued."
                    ),
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    response.headers["Cache-Control"] = "no-store"

    return CreateUserResponse(
        data=UserDetail.model_validate(user),
        invitation=invitation,
    )


@users_router.post(
    "/{user_id}/invitations",
    response_model=ReissueInvitationResponse,
    status_code=200,
)
def reissue_user_invitation(
    user_id: UUID,
    payload: ReissueInvitationRequest,
    credentials: LogoutCredentials,
    session: DbSession,
    request: Request,
    response: Response,
) -> ReissueInvitationResponse | JSONResponse:
    """Reissue an activation invitation for a pending account."""
    if credentials is None:
        return unauthorized_logout_response()

    try:
        with session.begin():
            actor = authenticate_access_token(
                session,
                access_token=credentials.credentials,
            )

            actor_id = actor.id
            is_administrator = (
                actor.system_role == "administrator"
                and actor.status == "active"
                and not actor.password_reset_required
            )

            if is_administrator:
                try:
                    target = get_user_detail(
                        session,
                        actor=actor,
                        user_id=user_id,
                    )
                    target_status = target.status
                except UserNotFoundError:
                    target_status = None
            else:
                target_status = None

    except InvalidCredentialsError:
        return unauthorized_logout_response()

    if not is_administrator:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Administrator privileges are required.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    if target_status is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": "USER_NOT_FOUND",
                    "message": "User account not found.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    if target_status != "pending":
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "INVITATION_NOT_ALLOWED",
                    "message": "Account is not eligible for an invitation.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    settings = cast(Settings, request.app.state.settings)

    delivery = payload.invitation_delivery

    if delivery is None:
        delivery = "email" if settings.smtp_host is not None else "manual"

    if settings.public_url is None or (
        delivery == "email"
        and (settings.smtp_host is None or settings.smtp_from_email is None)
    ):
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "INVITATION_UNAVAILABLE",
                    "message": "Requested invitation delivery is not configured.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    try:
        if delivery == "manual":
            activation_url, expires_at = prepare_activation_invitation(
                session,
                settings=settings,
                actor_id=actor_id,
                user_id=user_id,
            )

            invitation = UserInvitationDetail(
                delivery="manual",
                expires_at=expires_at,
                activation_url=activation_url,
            )
        else:
            expires_at = deliver_activation_invitation(
                session,
                settings=settings,
                actor_id=actor_id,
                user_id=user_id,
            )

            invitation = UserInvitationDetail(
                delivery="email",
                expires_at=expires_at,
            )

    except InvitationNotAllowedError:
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "INVITATION_NOT_ALLOWED",
                    "message": "Account is no longer eligible for an invitation.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )
    except (ActivationURLNotConfiguredError, InvitationDeliveryError):
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "INVITATION_DELIVERY_FAILED",
                    "message": "Invitation could not be delivered. Reissue may be required.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    response.headers["Cache-Control"] = "no-store"

    return ReissueInvitationResponse(invitation=invitation)


@users_router.post(
    "/{user_id}/suspend",
    status_code=204,
    response_class=Response,
    response_model=None,
)
def suspend_user_account(
    user_id: UUID,
    credentials: LogoutCredentials,
    session: DbSession,
) -> Response | JSONResponse:
    """Suspend an active account and revoke its sessions."""
    if credentials is None:
        return unauthorized_logout_response()

    try:
        with session.begin():
            actor = authenticate_access_token(
                session,
                access_token=credentials.credentials,
            )

            actor_id = actor.id
            is_administrator = (
                actor.system_role == "administrator"
                and actor.status == "active"
                and not actor.password_reset_required
            )
    except InvalidCredentialsError:
        return unauthorized_logout_response()

    if not is_administrator:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Administrator privileges are required.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    try:
        suspend_user(
            session,
            actor_id=actor_id,
            user_id=user_id,
        )
    except LastAdministratorError:
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "LAST_ADMINISTRATOR",
                    "message": "The last active administrator cannot be suspended.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )
    except UserSuspensionNotAllowedError:
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "SUSPENSION_NOT_ALLOWED",
                    "message": "Account is not eligible for suspension.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    return Response(
        status_code=204,
        headers={"Cache-Control": "no-store"},
    )


@users_router.post(
    "/{user_id}/restore",
    status_code=204,
    response_class=Response,
    response_model=None,
)
def restore_user_account(
    user_id: UUID,
    payload: RestoreUserRequest,
    credentials: LogoutCredentials,
    session: DbSession,
) -> Response | JSONResponse:
    """Restore a suspended account without reviving old sessions."""
    if credentials is None:
        return unauthorized_logout_response()

    try:
        with session.begin():
            actor = authenticate_access_token(
                session,
                access_token=credentials.credentials,
            )

            actor_id = actor.id
            is_administrator = (
                actor.system_role == "administrator"
                and actor.status == "active"
                and not actor.password_reset_required
            )
    except InvalidCredentialsError:
        return unauthorized_logout_response()

    if not is_administrator:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Administrator privileges are required.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    try:
        restore_user(
            session,
            actor_id=actor_id,
            user_id=user_id,
            require_password_reset=payload.require_password_reset,
        )
    except UserRestorationNotAllowedError:
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "RESTORATION_NOT_ALLOWED",
                    "message": "Account is not eligible for restoration.",
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    return Response(
        status_code=204,
        headers={"Cache-Control": "no-store"},
    )

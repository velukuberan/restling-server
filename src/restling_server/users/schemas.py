"""HTTP schemas for user management."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
)


class ActivateUserRequest(BaseModel):
    """Credentials submitted to activate a pending account."""

    token: str = Field(min_length=1)
    password: str


class ActivateUserResponse(BaseModel):
    """Successful account activation response."""

    message: str


class ResetPasswordRequest(BaseModel):
    """Credentials submitted to complete password recovery."""

    token: str = Field(min_length=1)
    new_password: str


class ForgotPasswordRequest(BaseModel):
    """Request password recovery using an account email address."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(repr=False)


class ForgotPasswordResponse(BaseModel):
    """Generic acknowledgement of a password-recovery request."""

    message: str


class ResetPasswordResponse(BaseModel):
    """Successful password recovery response."""

    message: str


class AdministratorPasswordResetData(BaseModel):
    """Manually deliverable password-reset credential."""

    delivery: Literal["manual"]
    reset_url: str
    expires_at: datetime


class AdministratorPasswordResetResponse(BaseModel):
    """Response containing an administrator-issued reset link."""

    data: AdministratorPasswordResetData


class UserDetail(BaseModel):
    """Publicly exposed user profile fields."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    display_name: str
    job_title: str | None
    status: str
    system_role: str
    created_at: datetime
    updated_at: datetime
    activated_at: datetime | None
    password_reset_required: bool


class UserDetailResponse(BaseModel):
    """Response envelope for an individual user."""

    data: UserDetail


class UpdateUserProfileRequest(BaseModel):
    """Fields allowed in a user profile update."""

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = None
    job_title: str | None = None

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str | None) -> str:
        """Validate and normalize an explicitly supplied display name."""
        if value is None:
            raise ValueError("Display name cannot be null.")

        normalized = value.strip()

        if not normalized:
            raise ValueError("Display name is required.")

        if len(normalized) > 150:
            raise ValueError("Display name must not exceed 150 characters.")

        return normalized

    @field_validator("job_title")
    @classmethod
    def validate_job_title(cls, value: str | None) -> str | None:
        """Validate and normalize an explicitly supplied job title."""
        if value is None:
            return None

        normalized = value.strip()

        if len(normalized) > 100:
            raise ValueError("Job title must not exceed 100 characters.")

        return normalized or None


class RequestEmailChangeRequest(BaseModel):
    """Request a verified change to the current user's email."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1)
    current_password: str = Field(min_length=1, repr=False)


class VerifyEmailChangeRequest(BaseModel):
    """Confirm an email change using a one-time verification token."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, repr=False)


class AdminChangeUserEmailRequest(BaseModel):
    """Administrator request to change a user's login email."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1)
    current_password: str = Field(min_length=1, repr=False)


class CreateUserRequest(BaseModel):
    """Administrator request to create a pending account."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    job_title: str | None = None
    system_role: Literal["user"] = "user"
    invitation_delivery: Literal["email", "manual"] | None = None


class UserInvitationDetail(BaseModel):
    """Delivery result for the new account invitation."""

    delivery: Literal["email", "manual"]
    expires_at: datetime
    activation_url: str | None = None


class CreateUserResponse(BaseModel):
    """New account and its activation invitation result."""

    data: UserDetail
    invitation: UserInvitationDetail


class ReissueInvitationRequest(BaseModel):
    """Administrator request to reissue an account invitation."""

    model_config = ConfigDict(extra="forbid")

    invitation_delivery: Literal["email", "manual"] | None = None


class CorrectPendingEmailRequest(BaseModel):
    """Administrator request to correct a pending account's email."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1)
    invitation_delivery: Literal["email", "manual"] | None = None


class ReissueInvitationResponse(BaseModel):
    """Result of reissuing an activation invitation."""

    invitation: UserInvitationDetail


class RestoreUserRequest(BaseModel):
    """Administrator request to restore a suspended account."""

    model_config = ConfigDict(extra="forbid")

    require_password_reset: bool = False


class LoginRequest(BaseModel):
    """Credentials submitted for password authentication."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1)
    password: str = Field(min_length=1, repr=False)


class LoginTokenData(BaseModel):
    """Credentials and session information issued at login."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_expires_at: datetime
    session_id: UUID


class LoginResponse(BaseModel):
    """Successful login response envelope."""

    data: LoginTokenData


class RefreshTokenRequest(BaseModel):
    """Refresh credential submitted for token rotation."""

    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, repr=False)


class UserSessionDetail(BaseModel):
    """Safe metadata for a current or historical session."""

    session_id: UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    login_ip: str | None
    last_seen_ip: str | None
    machine_name: str | None
    status: Literal["active", "revoked", "expired"]
    is_current: bool


class PaginationDetail(BaseModel):
    """Offset pagination metadata."""

    limit: int
    offset: int
    total: int


class UserSummary(BaseModel):
    """Safe account fields exposed in administrator listings."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    display_name: str
    job_title: str | None
    status: str
    system_role: str
    created_at: datetime


class UsersResponse(BaseModel):
    """Paginated administrator user listing."""

    data: list[UserSummary]
    pagination: PaginationDetail


class UserSessionsResponse(BaseModel):
    """Paginated session history response."""

    data: list[UserSessionDetail]
    pagination: PaginationDetail


class RevokeOtherSessionsData(BaseModel):
    """Result of revoking other active sessions."""

    revoked_count: int


class RevokeOtherSessionsResponse(BaseModel):
    """Response for bulk revocation excluding the current session."""

    data: RevokeOtherSessionsData

"""HTTP schemas for user management."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


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


class ResetPasswordResponse(BaseModel):
    """Successful password recovery response."""

    message: str


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


class ReissueInvitationResponse(BaseModel):
    """Result of reissuing an activation invitation."""

    invitation: UserInvitationDetail


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

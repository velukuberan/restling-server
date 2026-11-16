"""HTTP schemas for user management."""

from pydantic import BaseModel, Field


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

"""HTTP schemas for user management."""

from pydantic import BaseModel, Field


class ActivateUserRequest(BaseModel):
    """Credentials submitted to activate a pending account."""

    token: str = Field(min_length=1)
    password: str


class ActivateUserResponse(BaseModel):
    """Successful account activation response."""

    message: str

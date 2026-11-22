"""FastAPI authentication dependencies for user management."""

from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from restling_server.core.dependencies import get_db_session
from restling_server.users.models import User
from restling_server.users.service import (
    InvalidCredentialsError,
    authenticate_access_token,
)


class AccessUnauthorizedError(Exception):
    """The request has no valid access credential."""


bearer_scheme = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db_session)]

BearerCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(bearer_scheme),
]


def get_current_user(
    session: DbSession,
    credentials: BearerCredentials,
) -> User:
    """Authenticate a request using an opaque bearer access token."""
    if credentials is None or not credentials.credentials:
        raise AccessUnauthorizedError()

    try:
        return authenticate_access_token(
            session,
            access_token=credentials.credentials,
        )
    except InvalidCredentialsError:
        raise AccessUnauthorizedError() from None


CurrentUser = Annotated[User, Depends(get_current_user)]

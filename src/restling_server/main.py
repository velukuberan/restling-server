"""Restling Server FastAPI application."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from restling_server.core.config import Settings
from restling_server.core.database import (
    create_database_engine,
    create_session_factory,
)
from restling_server.users.routes import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Initialize and release application database infrastructure."""
    settings = Settings()  # pyright: ignore[reportCallIssue]

    engine = create_database_engine(settings)
    app.state.session_factory = create_session_factory(engine)

    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(
    title="Restling Server",
    lifespan=lifespan,
)

app.include_router(auth_router)


@app.exception_handler(RequestValidationError)
def handle_request_validation_error(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return a consistent response for malformed HTTP requests."""
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Invalid request data.",
            }
        },
        headers={"Cache-Control": "no-store"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "restling-server",
    }

"""Restling Server FastAPI application."""

from fastapi import FastAPI

app = FastAPI(title="Restling Server")


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "restling-server",
    }

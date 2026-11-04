# Restling Server

Restling Server is the centrally hosted, multi-user backend for Restling, an API client. It will manage user accounts, project access, collections, environments, and synchronization.

## Technology Stack

- Python 3.13+ and FastAPI
- PostgreSQL, SQLAlchemy 2.x (synchronous), and Alembic (database setup planned)
- uv, Ruff, Pyright, and pytest

## Getting Started

Install [uv](https://docs.astral.sh/uv/) and run:

```bash
uv python install 3.13
uv sync
make check
make run
```

Commit the generated `uv.lock` file alongside `pyproject.toml`; CI uses `uv sync --locked` to validate reproducibility.

The development API runs at `http://127.0.0.1:8000`, with a basic process health check at `/health` and the generated OpenAPI documentation at `/docs`. Database integration is not yet implemented.

## Development Commands

Run `make help` for available commands. `make check` runs Ruff linting, formatting validation, Pyright, lockfile validation, and pytest.

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Technical Requirements](TECHNICAL_REQUIREMENTS.md)
- [Coding Standards](CODING_STANDARDS.md)
- [User and Role Management](docs/architecture/USER_ROLE_MANAGEMENT.md)

## Status

Early development. The architecture and feature requirements will evolve as implementation progresses.

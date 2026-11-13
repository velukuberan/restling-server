.DEFAULT_GOAL := help

.PHONY: help test lint format format-check type-check lock-check check run db-upgrade-local

help:
	@echo "Restling Server — Development Commands"
	@echo ""
	@echo "  make run           Start the local FastAPI server"
	@echo "  make test          Run pytest"
	@echo "  make lint          Check Ruff linting"
	@echo "  make format        Format Python code"
	@echo "  make format-check  Check formatting"
	@echo "  make type-check    Run strict Pyright checks"
	@echo "  make lock-check    Verify uv.lock"
	@echo "  make check         Run all quality checks"
	@echo "  make db-upgrade-local  Migrate local dev and test databases"

run:
	uv run uvicorn restling_server.main:app --reload

test:
	uv run pytest -v

lint:
	uv run ruff check .

format:
	uv run ruff format .

format-check:
	uv run ruff format --check .

type-check:
	uv run pyright

lock-check:
	uv lock --check

check: lint format-check type-check lock-check test

db-upgrade-local:
	@uv run python -c 'import sys; from restling_server.core.config import Settings; s = Settings(); sys.exit(0 if s.postgres_host in {"127.0.0.1", "localhost", "::1"} and s.postgres_db == "restling_dev" else "Refusing: expected local PostgreSQL and restling_dev configuration.")'
	POSTGRES_DB=restling_dev uv run alembic upgrade head
	POSTGRES_DB=restling_test uv run alembic upgrade head

.DEFAULT_GOAL := help

.PHONY: help test lint format format-check type-check lock-check check run

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

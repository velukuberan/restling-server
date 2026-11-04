# Restling Server — Coding Standards

**Status:** Initial baseline  
**Repository:** `velukuberan/restling-server`  
**Last reviewed:** 2026-11-04

## 1. Purpose and precedence

These rules govern how Restling Server code is written, tested, reviewed, and maintained. They complement rather than replace the architecture and technical requirements.

When documents conflict, use this order:

1. `ARCHITECTURE.md` — boundaries, responsibilities, and dependency direction.
2. `TECHNICAL_REQUIREMENTS.md` — technologies, constraints, and capabilities.
3. `CODING_STANDARDS.md` — implementation and quality practices.
4. `README.md` — overview and developer instructions.

Identify and resolve conflicts explicitly; do not silently reinterpret a higher-priority document. Until `ARCHITECTURE.md` is approved, do not treat any example package layout or layer name as an established directory contract.

## 2. General engineering principles

- Prefer readable, explicit, maintainable code over clever shortcuts or unnecessary brevity.
- Keep modules cohesive, responsibilities focused, and dependencies intentional.
- Apply SOLID pragmatically. Create an abstraction only when a present architectural need justifies it.
- Avoid hidden state, global mutable dependencies, service locators, and unrelated side effects.
- Do not engineer for hypothetical async migrations, alternate storage engines, or speculative scale.
- Keep changes focused; do not combine unrelated refactoring with feature work.
- Preserve documented module ownership, contracts, and dependency direction.
- Never change production design solely to accommodate tests or mocking tools.

Before proposing a change to established directories, module ownership, dependencies, or public contracts, describe the reason, affected paths, architectural consequences, and smallest compatible change.

## 3. Python style and naming

- Target Python **3.13+**, as required by `TECHNICAL_REQUIREMENTS.md`.
- Follow PEP 8 and the project's Ruff configuration. Ruff is the canonical formatter and linter.
- Use `snake_case` for files, modules, functions, methods, and variables.
- Use `PascalCase` for classes and exceptions; use `UPPER_SNAKE_CASE` for constants.
- Prefix genuinely internal implementation details with `_` where appropriate.
- Prefer descriptive names reflecting responsibility; avoid catch-all names such as `helper`, `common`, `misc`, `utility`, or vague `manager` types.
- Keep imports explicit. Do not use wildcard imports or introduce circular imports.
- Avoid mutable default arguments, unnecessary import-time work, and mutable application state at module scope.
- Prefer straightforward control flow and guard clauses where they improve clarity; do not impose arbitrary limits on function or class length.
- Use the standard library when it adequately serves the requirement; add dependencies deliberately.

Formatter-controlled details such as line wrapping and quote style must not be debated or manually enforced outside Ruff. Start with Ruff's default 88-character line length unless the project configuration explicitly changes it.

## 4. Typing and Pyright

- **Pyright is the sole required static type checker.** Configure strict checking as the project target.
- Annotate parameters and return values on production functions and methods, including non-public functions. Annotate meaningful class attributes and other values where inference is insufficient.
- Prefer modern Python types: `list[str]`, `dict[str, int]`, `User | None`, and precise collection or protocol types as needed.
- Use `Any`, casts, or Pyright suppressions only for justified, narrowly scoped interoperability or typing limitations. Document the reason at the point of use.
- Do not hide real typing errors with broad exclusions, unchecked casts, or blanket suppressions.
- Reflect genuine optionality and failure outcomes in signatures; do not claim a value is present when it may be absent.
- Preserve useful type information across module boundaries without creating interfaces solely for static typing or tests.
- Fix the source of type errors where practical rather than weakening global checks.

## 5. Documentation and comments

- Give public APIs clear names and document non-obvious contracts, behavior, invariants, and side effects.
- Use docstrings when a function, class, or module's behavior is not adequately communicated by its name and types.
- Explain **why** a decision was made rather than narrating what obvious statements do.
- Keep examples, configuration instructions, and OpenAPI documentation synchronized with implemented behavior.
- Do not document proposed behavior as though it already exists.

## 6. FastAPI and HTTP boundaries

- Keep route handlers focused on HTTP input/output, dependency wiring, and invoking application behavior.
- Use Pydantic request and response models for defined API boundaries; do not expose SQLAlchemy ORM instances as the public contract by default.
- Validate untrusted request data at the HTTP boundary and enforce business invariants in the responsible application logic.
- Keep domain/business rules independent of `FastAPI`, `Request`, `HTTPException`, and HTTP status codes.
- Use FastAPI dependency injection at the framework boundary, not as a hidden domain dependency.
- Return meaningful status codes and consistent, documented error responses. Centralize error mapping where appropriate.
- Avoid leaking internal errors, tracebacks, database details, credentials, or secrets to clients.
- Keep externally consumed API contracts intentional. Review breaking changes and document compatibility decisions.

### Synchronous execution policy

- The initial application uses **synchronous SQLAlchemy**, not `AsyncSession` or `async_sessionmaker`.
- Use ordinary `def` for FastAPI handlers that perform blocking database operations. FastAPI can execute these handlers in its thread pool.
- Do not perform blocking database calls directly in an `async def` handler on the event loop.
- Use normal `def` for synchronous service and domain methods. Do not add `async` or adapter layers for an imagined future conversion.
- If genuinely asynchronous behavior is introduced for a separately justified feature, document its boundaries and ensure blocking work does not run on the event loop.

## 7. SQLAlchemy and PostgreSQL

- Use **SQLAlchemy 2.x** and **psycopg 3** for synchronous PostgreSQL access.
- Prefer modern typed ORM declarations using `Mapped` and `mapped_column` for new models.
- Create sessions with `sessionmaker` and define their ownership, lifetime, and cleanup explicitly.
- Do not share a mutable `Session` between concurrently executing requests or threads.
- Define transaction ownership at the application-operation boundary. Repositories or persistence helpers must not independently commit unless their documented contract expressly owns the transaction.
- Roll back failed transactions and ensure sessions are closed. Use context managers or well-defined dependency cleanup.
- Keep transactions short; do not hold them open across unrelated slow network operations.
- Never build SQL by concatenating untrusted input. Use bound parameters or SQLAlchemy query APIs.
- Use database constraints for integrity, including foreign keys and uniqueness where required.
- Avoid unnecessary queries and N+1 retrieval patterns when relevant to a feature.
- Configure connection pools based on database capacity and observed workloads, not arbitrary assumptions.
- Keep persistence-specific behavior out of domain logic according to the architecture, without requiring a repository interface for every entity.

## 8. Alembic migrations

- Use **Alembic** for all production schema changes; do not rely on `metadata.create_all()` as a production migration mechanism.
- Keep migration revisions in version control and review autogenerated scripts before committing.
- Review constraints, indexes, defaults, data backfills, destructive changes, and compatibility with existing data.
- Migrations must be deterministic, safe to operate, and clearly named; document migration steps needing special operational care.
- Apply migrations as a controlled deployment step, not automatically and independently from each web worker.
- Test migration application against PostgreSQL when schema behavior or existing data may be affected.
- Do not edit already-applied shared migrations casually; use a follow-up revision when appropriate.

## 9. Authentication, authorization, and secrets

- Treat every request as untrusted, including identifiers, ownership claims, roles, and permission assertions.
- Authenticate protected operations and authorize access to each affected resource server-side.
- Test cross-user and cross-project isolation wherever ownership or sharing rules apply.
- Never store plaintext passwords. Use a vetted modern password-hashing scheme, chosen in the feature specification.
- Never invent custom cryptography or commit passwords, tokens, database credentials, or environment secrets.
- Do not log secrets or expose them in exceptions, API responses, examples, or test fixtures committed to Git.
- Use least-privilege database credentials and parameterized data access.
- Require secure transport in production and design abuse protection for sensitive endpoints.
- Treat synchronization and environment-secret access as security-sensitive operations; do not assume client-provided scopes are authoritative.

The exact authentication mechanism, roles, environment-secret policy, and synchronization protocol remain feature/architecture decisions, not conventions to invent in implementation code.

## 10. Error handling and logging

- Represent expected application outcomes deliberately; do not use generic exceptions as a substitute for clear behavior.
- Raise or propagate exceptions for genuine failures. Catch exceptions only to handle, translate, clean up, or deliberately re-raise them.
- Never use silent `except: pass` or conceal exceptions solely to make a test pass.
- Translate internal failures to stable, safe HTTP responses at the HTTP boundary.
- Include enough structured diagnostic context to investigate failures without logging personal data or secrets unnecessarily.
- Keep logs actionable. Do not log complete request bodies or authorization headers by default.

## 11. Test-first development and pytest

For new behavior:

1. Define observable behavior, edge cases, and failure modes.
2. Add or update the smallest meaningful test.
3. Implement the minimum code needed to satisfy the test.
4. Refactor while tests remain green.
5. Run the relevant checks.

A test-first mindset is expected; ceremony is not.

- Use **pytest** as the test runner.
- Tests must be deterministic, independent, and runnable in any order.
- Name tests by behavior and observable outcome; use parametrization when it improves clarity.
- Cover successful paths, failures, boundaries, regressions, and authorization/ownership rules as appropriate.
- Prefer testing public behavior and contracts over asserting incidental internal call sequences.
- Use real concrete collaborators where practical; mock external systems and genuine architectural/infrastructure boundaries, not arbitrary internal classes for convenience.
- Never add interfaces, change visibility, or restructure production code solely to facilitate mocks.
- Keep pure business-logic tests independent of FastAPI and PostgreSQL when those dependencies are irrelevant to the behavior under test.
- Use HTTP-level tests for endpoint contracts, and **real PostgreSQL integration tests** for persistence, transactions, constraints, and migration behavior.
- Do not substitute SQLite for PostgreSQL when validating PostgreSQL-specific behavior.
- Keep ordinary automated tests independent of live third-party services; use controlled responses at external boundaries.
- Treat coverage as a diagnostic aid, not as a replacement for meaningful assertions or a reason to write low-value tests.

## 12. Tooling and enforcement

The standard development toolchain is `uv`, Ruff, Pyright, pytest, SQLAlchemy, and Alembic. Keep project configuration in `pyproject.toml` where supported and commit the `uv.lock` file.

Required checks once the project tooling is configured:

```bash
uv lock --check
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

- Run the same substantive checks locally and in CI.
- Linting, formatting, typing, lockfile validation, and relevant tests must pass before merging.
- CI validates code; it should not silently rewrite committed code.
- Do not introduce global ignores, type-check baselines, or lint exclusions merely to make CI green. Document narrow justified exceptions.
- Add a `make check` convenience target if useful; it must delegate to the canonical checks rather than implementing divergent rules.
- Additional test/security tools may be adopted when needed; avoid overlapping enforcement without a clear benefit.

## 13. Change completion criteria

A change is ready for review or merge only when:

- Relevant behavior and regression tests pass.
- Ruff lint and format checks pass.
- Pyright passes under configured rules.
- The dependency lock is consistent; applicable migration checks pass.
- Transactions, schema constraints, and data ownership are correct where affected.
- Authorization, input validation, and secret handling are reviewed where relevant.
- Documented architecture boundaries, dependencies, and public API contracts remain intact or changes have been explicitly approved.
- Documentation and configuration examples reflect any changed behavior.
- No unrelated refactoring or unrelated files are included.

## 14. Scope and open architectural decisions

This document intentionally does **not** prescribe a package tree, compulsory repository pattern, service interfaces, authentication protocol, authorization matrix, sync conflict strategy, or API version identifier. Those choices belong to `ARCHITECTURE.md`, `TECHNICAL_REQUIREMENTS.md`, or focused feature specifications.

The initial execution model is **synchronous**. There is no requirement to preserve compatibility with a hypothetical async rewrite. If actual requirements change, evaluate and revise the architecture then.

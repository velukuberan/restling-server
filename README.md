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

The committed uv.lock file ensures reproducible dependency installation. Update and commit it whenever project dependencies change.
The development API runs at `http://127.0.0.1:8000`, with a basic process health check at `/health` and the generated OpenAPI documentation at `/docs`.

PostgreSQL-backed user management and database migrations
are implemented. Projects, collections, environments,
and synchronization remain future development milestones.

## Development Commands

Run `make help` for available commands. `make check` runs Ruff linting, formatting validation, Pyright, lockfile validation, and pytest.

### PostgreSQL Integration Tests

Restling Server uses real PostgreSQL databases for integration testing.

The test fixtures in `tests/integration/conftest.py` use the following isolation strategy:

1. Create a temporary PostgreSQL template database for each pytest session.
2. Apply all Alembic migrations to the template once.
3. Clone the migrated template into a separate database for each integration test.
4. Drop each test database after its test completes.
5. Drop the template database when the pytest session finishes.

This ensures database isolation while avoiding repeated migrations.

#### Requirements

- A running local PostgreSQL server.
- PostgreSQL credentials with permission to create databases (`CREATEDB`) and drop the databases owned by the test role.
- A local `.env` configuration containing:

```dotenv
POSTGRES_HOST=127.0.0.1
POSTGRES_DB=restling_dev
POSTGRES_USER=restling
POSTGRES_PASSWORD=your-local-password
```

Use a dedicated development/testing database role. Never use production credentials for integration tests.

The fixtures require `POSTGRES_DB=restling_dev` and a loopback PostgreSQL host (`localhost`, `127.0.0.1`, or `::1`).

#### Running Tests

```bash
uv run pytest
```

To run all quality checks:

```bash
make check
```

Tests automatically create temporary databases with generated names such as `restling_test_<uuid>`. These databases are deleted during normal fixture teardown.

**Safety:** The test fixtures execute PostgreSQL `CREATE DATABASE` and `DROP DATABASE` statements. They must only run against a trusted local testing server.

If pytest is forcibly terminated, temporary databases may remain and require manual inspection and cleanup.

CI environments must provide a compatible PostgreSQL instance, database privileges, and configuration before running integration tests.


### Production Authentication Rate Limiting

Production deployments must enforce rate limiting and request-abuse protection for authentication and credential-recovery endpoints at a trusted reverse proxy or API gateway.

This includes:

- `POST /api/v1/auth/activate`
- `POST /api/v1/auth/reset-password`
- Other authentication and session-management endpoints as they are introduced.

Rate limiting must be applied before requests reach the FastAPI application. Configure appropriate request thresholds, burst limits, and responses for excessive requests based on the deployment environment.

**Security considerations:**

- Do not rely on application-local, in-memory counters for multi-worker deployments.
- Use a trusted client IP address; do not blindly trust client-supplied forwarding headers.
- Avoid logging authentication credentials, activation tokens, or password-reset tokens.
- Rate limiting supplements token expiration, single-use enforcement, and credential validation; it does not replace them.

Restling Server does not currently implement application-level rate limiting. Deployments exposing authentication endpoints publicly must configure and verify this protection before accepting production traffic.

## Administrator CLI

Restling Server provides the `restling-admin` command for
privileged user-management operations.

### Initial administrator

Create the first administrator interactively:

```bash
uv run restling-admin bootstrap
```

The command prompts for an email address, display name,
and password. Bootstrap is only available before the
initial administrator has been created.

### Account invitations

An existing pending user can be invited using:

```bash
uv run restling-admin invite --user user@example.com
```

The command prompts for an administrator's email and password.

The administrator must be active, have the administrator
system role, and must not be required to reset their password.

With SMTP configured, Restling Server submits the invitation
by email. Without SMTP, the command displays a one-time
activation link for manual delivery.

To explicitly request manual delivery:

```bash
uv run restling-admin invite \
    --user user@example.com \
    --manual
```

The invitation expiry is controlled by
`RESTLING_INVITATION_EXPIRY_HOURS` (default: 24 hours).

Reissuing an invitation immediately invalidates earlier
activation links for that account.

### Invitation configuration

Set the trusted application URL in `.env`:

```dotenv
RESTLING_PUBLIC_URL=http://localhost:8000
RESTLING_INVITATION_EXPIRY_HOURS=24
```

Production application URLs must use HTTPS. Plain HTTP is
permitted only for supported loopback development addresses.

For local SMTP testing with Mailpit:

```dotenv
RESTLING_SMTP_HOST=localhost
RESTLING_SMTP_PORT=1025
RESTLING_SMTP_SECURITY=none
RESTLING_SMTP_FROM_EMAIL=restling@example.com
```

Mailpit's default web interface is available at
http://localhost:8025.

Unencrypted SMTP is permitted only for local loopback
connections. Production SMTP connections must use
STARTTLS or TLS.

### Authentication configuration

Restling Server supports configurable token lifetimes and
concurrent session limits:

| Environment variable | Default | Description |
| --- | --- | --- |
| `RESTLING_ACCESS_TOKEN_EXPIRY_MINUTES` | `15` | Access-token lifetime in minutes |
| `RESTLING_REFRESH_SESSION_EXPIRY_DAYS` | `7` | Absolute refresh-session lifetime in days |
| `RESTLING_MAX_ACTIVE_SESSIONS` | `2` | Maximum concurrent active sessions per user |

All three settings must be positive integers.

These settings are currently available in configuration.
Login, token issuance, refresh, and session management
endpoints are not yet implemented.

### Security and operational safeguards

- Run the administrator CLI only in a trusted server environment.
- Never include administrator passwords in command arguments.
- Manual activation links are sensitive bearer credentials.
  Share them securely and avoid captured terminal output,
  CI logs, and command-output recordings.
- Activation links must not appear in SMTP-mode CLI output.
- SMTP delivery failures do not automatically switch to
  manual mode. The administrator may reissue an invitation.
- SMTP submission does not guarantee inbox delivery.
- Concurrent invitation reissues may deliver messages
  out of order; only the latest valid link remains usable.
- The current CLI does not implement a separate failed-login
  rate limiter. Restrict CLI execution to trusted operators.
- The `/activate` URL is a planned client activation page.
  It is not yet implemented by Restling Server. The existing
  activation API is `POST /api/v1/auth/activate`.

The CLI currently invites existing pending accounts;
it does not create new users.

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Technical Requirements](TECHNICAL_REQUIREMENTS.md)
- [Coding Standards](CODING_STANDARDS.md)
- [User and Role Management](docs/architecture/USER_ROLE_MANAGEMENT.md)

## Status

Early development. The architecture and feature requirements will evolve as implementation progresses.

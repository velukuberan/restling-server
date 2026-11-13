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

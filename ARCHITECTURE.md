# Restling Server — Architecture

**Status:** Initial architecture baseline (proposed for adoption)  
**Repository:** `velukuberan/restling-server`  
**Last reviewed:** 2026-11-04

## 1. Purpose and authority

Restling Server provides the centrally hosted, multi-user backend for the Restling API client. Its responsibilities include account management and, progressively, access-controlled projects, collections, environments, and synchronization.

This document defines the intended **module boundaries, ownership, dependency rules, and execution model**. `TECHNICAL_REQUIREMENTS.md` defines selected technologies and capabilities; `CODING_STANDARDS.md` defines implementation and quality rules. This document does not itself approve an endpoint catalogue, data schema, authentication protocol, permission matrix, or sync conflict algorithm.

The architecture is a starting baseline, not a commitment to implement all planned modules immediately. Introduce files and packages when the first real feature requires them.

## 2. Architectural principles

1. **Cohesion over layers for their own sake.** Organize around meaningful capabilities. Keep each component small and responsible for a clear behavior.
2. **Explicit dependencies.** Dependency wiring and resource ownership must be visible. Avoid service locators and mutable global session state.
3. **Protected domain rules.** Business decisions and invariants should not rely on FastAPI request objects, HTTP status codes, or database session lifecycle mechanics.
4. **Pragmatism.** Do not introduce interfaces, base classes, event buses, generic repositories, factories, or adapter hierarchies without an actual requirement.
5. **Strong access boundaries.** Authentication is not authorization; protect resource ownership and sharing at the level of each operation.
6. **One consistent write transaction.** A use case that changes related records controls its transaction as a unit.
7. **No speculative migration architecture.** The initial implementation is synchronous. Do not design bridge layers for a hypothetical async rewrite.
8. **Incremental evolution.** Start with user management, add other capabilities when their scope and contracts have been agreed.

## 3. System context

```text
Restling desktop client / other authorized clients
                     |
                  HTTPS
                     |
          Restling Server (FastAPI)
                     |
          Application capabilities
                     |
       SQLAlchemy 2.x (sync Session)
                     |
               PostgreSQL

Controlled deployment step: Alembic -> PostgreSQL
```

The server is the authority for hosted accounts, resource permissions, and persisted synchronized state. Client-held identifiers or ownership assertions are never trusted without server-side verification.

The REST API is a server-facing interface; it is **not** the Restling client's HTTP execution engine. The desktop application's request-execution architecture is a separate concern.

## 4. Modular organization

Use a **feature-oriented modular monolith**: one deployable FastAPI application and one primary PostgreSQL database, with internal feature boundaries. This is a structural preference, not a microservice design.

The following is a **target layout**. Only create packages when needed. Paths are proposed because the current repository has not yet implemented source packages.

```text
restling-server/
├── ARCHITECTURE.md
├── TECHNICAL_REQUIREMENTS.md
├── CODING_STANDARDS.md
├── docs/
│   └── architecture/
│       └── USER_ROLE_MANAGEMENT.md # detailed identity, roles and authorization design
├── pyproject.toml
├── uv.lock
├── src/
│   └── restling_server/
│       ├── main.py                 # application construction and router registration
│       ├── core/                   # cross-cutting configuration / shared infrastructure
│       │   ├── config.py
│       │   └── database.py         # engine, session factory, request session lifecycle
│       ├── users/                  # first feature: accounts, identity, authentication
│       │   ├── routes.py           # FastAPI HTTP boundary
│       │   ├── schemas.py          # HTTP request/response models
│       │   ├── service.py          # use cases, rules, transaction ownership
│       │   └── models.py           # SQLAlchemy mapping where this is useful
│       ├── projects/               # project ownership, membership, scoped roles; add when needed
│       ├── collections/            # add when implemented
│       ├── environments/           # add when implemented
│       └── sync/                   # add when implemented
├── migrations/                     # Alembic environment and revisions
└── tests/
    ├── unit/
    └── integration/
```

Names such as `core`, `routes.py`, and `service.py` are conventions for clarity, **not** an instruction to create empty scaffolding or impose one service class per entity. Features may split responsibilities into additional files when the actual code warrants it. Do not add a shared `utils.py` or generic `BaseRepository` as a dumping ground.

User identity and authentication initially belong to `users/`. Project ownership, membership, and project-role assignments belong to `projects/` when that feature is implemented. Authorization checks remain application-level rules of the operation being performed, using the responsible feature’s membership and scope decisions. Shared authorization behavior may be extracted only when concrete repeated use warrants it; do not precreate a dedicated permissions framework.

For the detailed user, role, and capability design, see [`docs/architecture/USER_ROLE_MANAGEMENT.md`](docs/architecture/USER_ROLE_MANAGEMENT.md).

## 5. Responsibility boundaries

| Boundary | Owns | Must not own |
| --- | --- | --- |
| FastAPI HTTP layer (`routes.py`, `schemas.py`) | Parse/validate external input; resolve dependencies; call a use case; serialize results; map errors to HTTP | Business rules, raw SQL, transaction-policy decisions |
| Application feature logic (`service.py` or equivalent) | Use-case orchestration; invariants; authorization decisions; transaction scope | HTTP-specific exceptions and response formatting; framework lifecycle |
| Persistence code (`models.py`, feature query functions/classes as needed) | SQLAlchemy mappings, database access, queries, persistence constraints | HTTP contracts, authorization policy decisions, commits outside its contract |
| Shared infrastructure (`core/`) | Configuration, engine/session creation, common technical facilities | Feature-specific business behavior or generic abstractions with no users |
| Alembic (`migrations/`) | Versioned database schema evolution | Starting application services or migrating implicitly on every request |

**No mandatory repository interface or three-layer boilerplate:** A small feature may call a focused SQLAlchemy persistence function directly from its service. Introduce a dedicated repository class only if it provides meaningful cohesion or reuse. Regardless of the shape, keep SQLAlchemy session management and database query details from spreading into HTTP handlers and pure business rules.

Domain concepts may be represented by plain Python values/classes where that improves independence and clarity. Do not require a duplicate domain entity for every SQLAlchemy row merely to preserve theoretical purity. If ORM models are passed within an application feature, they remain internal and must not become the public API response contract by accident.

## 6. Dependency direction and feature collaboration

```text
FastAPI route / external adapter
              |
              v
      Feature use case / rules
              |
              v
     Feature persistence operations
              |
              v
      SQLAlchemy / PostgreSQL
```

This diagram describes **runtime invocation**, not permission to couple every layer to every downstream implementation.

Rules:

- HTTP handlers may import application logic and HTTP schemas, but must not contain database queries or business decisions.
- Application code may depend on concrete persistence collaborators where simplicity warrants it; no interface is required simply to enable mocking.
- Pure business-rule functions must not import FastAPI, Pydantic HTTP schemas, `HTTPException`, or SQLAlchemy session machinery.
- Persistence code must not import FastAPI routes or depend on HTTP status codes.
- Cross-feature calls must use a clear, documented application-level operation rather than reaching into another feature's private database implementation.
- For example, a collection operation must obtain project membership/scope authorization through the project feature’s application-level rules; it must not duplicate membership policy or query the project feature’s private persistence directly.
- Each feature still owns authorization for the resource operation it performs. Shared checks should not turn `core/` into a business-authorization module.
- Shared technical functionality goes in `core/` only when actually shared; avoid circular imports and a central all-knowing module.
- Test code follows production boundaries, not the reverse.

## 7. HTTP request and application lifecycle

For a typical database-backed request:

1. FastAPI receives and validates the request.
2. Framework dependencies resolve authentication context and create a request-scoped database session.
3. The route invokes the relevant feature operation.
4. The feature operation verifies identity, permissions, and business invariants.
5. The operation reads/writes through its persistence code; a write use case controls its transaction.
6. The route/HTTP error mapper translates the result or safe exception to a documented response.
7. The session is closed and released reliably, including on failure.

Use ordinary **`def` handlers** for blocking database-backed requests. Do not call blocking SQLAlchemy operations directly on an event loop inside `async def` handlers. Keep HTTP request and response Pydantic models separate from persistence mappings.

## 8. Database sessions and transactions

- Use SQLAlchemy 2.x **synchronous** `Session` with `sessionmaker`, backed by `psycopg` 3 and PostgreSQL.
- Initialize an engine and session factory as application/process infrastructure; create a fresh session for each independent request or task. A session is not thread-safe and must not be shared across concurrent requests.
- Scope sessions explicitly through context managers or FastAPI dependency cleanup. Always close them; roll back failed transactions.
- **Application use cases own write transaction boundaries**. A multi-step operation commits together or rolls back together.
- Persistence helpers should `flush()` when required, not commit independently unless explicitly defined as transaction-owning operations.
- Keep external HTTP calls, sleep, and unrelated slow work outside database transactions whenever possible.
- Configure connection pools against available database capacity and actual workloads. Do not prescribe numeric pool values until deployment characteristics are known.
- Avoid adding `AsyncSession`, `async_sessionmaker`, or an async-compatibility abstraction to the initial architecture.

**Migration policy:** Alembic revisions are reviewed, committed, and applied as controlled deployment steps. Production application startup does not perform ad hoc schema creation or run migrations independently in each worker.

## 9. Identity, authorization, and tenant boundaries

Restling Server uses **role-based authorization with capabilities**, inspired by WordPress. A successful login establishes identity, not permission to access arbitrary users, projects, collections, or environments.

- **System roles:** `administrator` and `user`. System administration does not automatically grant access to private project data or secrets.
- **Project roles:** `owner`, `admin`, `editor`, and `viewer`, assigned through membership in a particular project. A user can hold different roles in different projects.
- **Owner versus Admin:** The Owner has ownership-level authority, including project deletion and ownership transfer. An Admin manages ordinary project operations but cannot delete the project or transfer its ownership.
- **Capabilities:** Application operations evaluate the effective capability *and* the resource's scope; they do not authorize solely by comparing role names.
- **Private resources:** A personal collection is not accessible through another user's project role unless an explicit, authorized sharing mechanism exists.
- **Server-side authority:** Never trust client-submitted `owner_id`, role, membership, or resource scope as proof of access. Enforce checks consistently for reads, writes, lists, exports, and synchronization.
- **Initial scope:** Predefined roles and capability mappings; custom role creation and per-user overrides are excluded from the first implementation.
- **Isolation:** Test cross-user and cross-project denial, ownership controls, and privilege-escalation attempts.
- **Secrets:** Environment secrets and credentials need a specific access, storage, encryption/key-management, and redaction policy before implementation. Permission to view environment metadata does not automatically grant access to secret values.

Identity verification, authentication tokens/sessions, account recovery, and exact permission details remain separate design decisions.

**Authoritative subsystem design:** [`docs/architecture/USER_ROLE_MANAGEMENT.md`](docs/architecture/USER_ROLE_MANAGEMENT.md). Its role definitions, ownership boundaries, and outstanding decisions should not be duplicated in this top-level architecture.

## 10. Projects, collections, and environments

These are planned capability boundaries, **not yet finalized schemas**.

- **Projects:** Own project-level metadata and membership/ownership rules once project sharing is specified.
- **Collections:** Own collection metadata and request organization, including collection-specific access constraints.
- **Environments:** Own environment definitions, values, visibility, and secret policies; consumers resolve usable variables only after authorization.

The product discussions distinguish global, project-level, and collection-level environment scopes, with a top-down visibility principle and collection-local data not automatically exposed upward. This is a **design direction**, not a completed resolution algorithm or permission model. Before implementation, specify variable precedence, user-specific versus shared environments, multiple environments per collection, conflict behavior, and the exact definition of “global.”

Avoid encoding a speculative fixed relationship between every project, collection, and environment into database constraints before those semantics are agreed.

## 11. Synchronization boundary

Synchronization is a planned feature of the hosted server, not just a generic CRUD endpoint.

- Sync operations authenticate the actor and authorize every affected resource.
- The server validates scope and ownership independently of client-supplied IDs.
- Data updates should be atomic at an agreed unit of work; partial failure semantics must be explicit.
- Do not assume that client timestamps, object versions, or last-write-wins conflict resolution are trustworthy or adequate until the sync protocol is designed.
- Decide offline change representation, versioning, conflict detection/resolution, deletion semantics, and idempotency before implementing sync behavior.
- Do not introduce event buses, distributed queues, change-data-capture, or WebSockets merely as placeholders for possible future synchronization needs.

A separately documented, published API/protocol for third-party servers may be considered only when it becomes a committed requirement for this repository. The initial centrally hosted deployment does not imply a compatibility obligation to unimplemented alternate servers.

## 12. Error handling and observability

- Application code exposes meaningful outcomes or raises specific application exceptions where useful.
- HTTP boundary code maps those outcomes to consistent status codes and sanitized response bodies.
- Never expose SQL queries, driver errors, tracebacks, password hashes, access tokens, or environment secrets to API clients.
- Log diagnostic context with stable request correlation when implemented, but never log sensitive payloads by default.
- Provide suitable health/readiness endpoints and metrics only as required by the deployment; avoid committing to a monitoring platform in this document.

## 13. Testing architecture

- **Unit tests** target cohesive business behavior and invariants with minimal infrastructure.
- **API tests** exercise request validation, response contracts, authentication, and authorization through FastAPI.
- **PostgreSQL integration tests** exercise SQLAlchemy persistence, transaction rollback, constraints, query behavior, and important Alembic migrations.
- Use real internal concrete collaborators when practical. Mock genuine external systems or infrastructure boundaries; never reshape production code solely for a mocking library.
- Keep tests deterministic, isolated, and independent of execution order. A SQLite substitute does not validate PostgreSQL-specific behavior.
- Use pytest, Pyright, Ruff, and uv checks as defined in `CODING_STANDARDS.md`.

## 14. Delivery and deployment boundaries

The first deployment model is **one centrally hosted multi-user application** with PostgreSQL. The document does not require microservices, message brokers, caches, separate worker services, or a particular hosting provider.

Configuration is environment-specific and secrets are supplied outside source control. Migrations run as a controlled step before dependent application code is activated. Add background jobs or external infrastructure only when a defined feature requires them.

## 15. Incremental implementation sequence

1. Establish minimal Python/FastAPI packaging, configuration, database integration, migration setup, and quality tooling.
2. Implement user management and authentication with its own API and PostgreSQL tests; finalize identity and recovery requirements before choosing flows.
3. Define authorization rules and resource ownership before implementing protected project/collection access.
4. Implement projects and collections incrementally after their relationships and API contracts are agreed.
5. Specify environment scope, resolution order, ownership, and secret handling before persistence/API design.
6. Define sync API and conflict semantics before implementing synchronization.

Each increment adds only the packages and abstractions it needs, tests the relevant boundaries, and preserves the preceding contracts unless a deliberate design change is approved.

## 16. Open decisions and change control

The following are **not settled by this architecture baseline**:

- Authentication protocol, password hashing library, recovery and verification flows.
- Initial system and project roles are defined in `docs/architecture/USER_ROLE_MANAGEMENT.md`; exact capability details, project ownership cardinality, invitation lifecycle, and account/session workflows remain open.
- Database tables and ownership relationships.
- Project/collection/environment mapping, variable precedence, and visibility.
- Synchronization payload/version format, conflict handling, offline semantics, and idempotency.
- API routes, response envelopes, version identifier, pagination, and rate limits.
- Deployment provider/topology, worker count, pool sizing, and monitoring tools.

This architecture is a living baseline. As implementation reveals concrete requirements, update the relevant decision and documentation deliberately; do not preserve a design merely because it was written first. Avoid speculative redesign.

Before changing documented module responsibilities, directory ownership, API contracts, or dependency direction, record **why** the change is needed, **which repository paths** it affects, **the architectural consequences**, and **the smallest compatible change**. Update this document alongside the implementation when an architectural decision actually changes.

---

**Initial implementation principle:** Build a simple, well-separated, synchronous modular monolith for the capabilities Restling Server needs now. Revisit the architecture on evidence, not speculation.

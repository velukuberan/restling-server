# Restling Server — User and Role Management

**Status:** Initial subsystem design — agreed baseline with explicit open decisions  
**Repository:** `velukuberan/restling-server`  
**Document path:** `docs/architecture/USER_ROLE_MANAGEMENT.md`  
**Last reviewed:** 2026-11-04

## 1. Purpose and scope

This document describes the identity, membership, role, capability, and authorization design for Restling Server, a centrally hosted, multi-user service.

Restling uses **roles with capabilities**, inspired by WordPress, but does not copy WordPress's APIs, database tables, or complete permissions model. Authorization is always evaluated within the relevant scope and resource.

This document defines subsystem behavior and security invariants. It does **not** finalize the HTTP endpoint list, database schema, authentication/token format, environment-variable precedence, or synchronization protocol.

### Authority and related documents

- [`ARCHITECTURE.md`](../../ARCHITECTURE.md): overall module boundaries and dependency direction.
- [`TECHNICAL_REQUIREMENTS.md`](../../TECHNICAL_REQUIREMENTS.md): technology choices and system constraints.
- [`CODING_STANDARDS.md`](../../CODING_STANDARDS.md): implementation, typing, tests, and quality checks.

If this design conflicts with the main architecture or technical requirements, those higher-level documents take precedence until the conflict is resolved and recorded.

## 2. Design principles

1. **Authentication is not authorization.** A signed-in user cannot automatically access another user's or project's data.
2. **Roles group capabilities.** Business operations check effective permissions, not hardcoded role names throughout the codebase.
3. **Scope matters.** A user's system role and their role in each project are distinct.
4. **Deny by default.** Missing membership, missing capability, invalid account state, or an inaccessible resource results in denial.
5. **Ownership is explicit.** Being a project Admin does not automatically confer ownership.
6. **Server is authoritative.** Never trust client-submitted role, owner, membership, or resource-scope claims.
7. **Least privilege.** Limit access to the resources and actions needed.
8. **No speculative framework.** Start with predefined roles and a straightforward capability mapping; add configurable roles or overrides only for a demonstrated requirement.
9. **Decisions remain auditable.** Privileged membership and ownership changes should be attributable to an actor.

## 3. User identity and account state

A user represents one server account, identified by a stable server-generated identifier. A user may participate in multiple projects with different project roles.

Conceptual account attributes include an identifier, login identity, credential metadata (where applicable), status, and creation/update timestamps. Exact fields, unique constraints, and login identifiers will be decided with the authentication design.

Account lifecycle operations to specify before implementation:

- Registration or invitation and identity verification.
- Authentication and logout/session revocation.
- Account status and administrative suspension.
- Password or credential recovery, where applicable.
- Account deactivation or deletion and its effect on project ownership.

**Open:** email verification policy, login identifiers, password policy and hashing implementation, session/token format, MFA, recovery flows, deletion/retention policy, and account-status state machine.

## 4. Two authorization scopes

### 4.1 System-level roles

System roles govern server-wide administration, **not** automatic access to private project data.

Initial conceptual roles:

| System role | Intended responsibility |
| --- | --- |
| `administrator` | Server-wide account/operational administration, subject to explicit capabilities |
| `user` | Ordinary authenticated account; may own or join projects |

System administration capabilities and any operational break-glass access require separate design and audit controls. A system administrator must not silently bypass project membership to read secrets or private resources.

### 4.2 Project-level roles

Project roles are assigned **through project membership**. The same user can be Owner in Project A and Viewer in Project B.

Initial project roles:

| Role | Meaning |
| --- | --- |
| `owner` | Ultimate project control, including deletion and ownership transfer |
| `admin` | Full day-to-day project administration without ownership-level actions |
| `editor` | Create and update authorized project resources |
| `viewer` | Read authorized, non-secret project resources |

The initial implementation uses predefined roles. **Custom role creation and per-user capability overrides are out of initial scope.**

## 5. Roles, capabilities, and resource scope

A capability is a named action such as `collections.update`. A role grants a set of capabilities; the requested resource and its scope determine whether those capabilities apply.

An allow decision requires all relevant conditions:

1. The user is authenticated and eligible to act.
2. The requested resource exists and is within a scope the user may access.
3. The user's system or project context grants the required capability.
4. Resource-specific constraints, ownership rules, and secret-handling rules permit the action.

Conceptual example (not an API or interface requirement):

```python
if can(user, "collections.update", collection):
    update_collection()
```

Prefer capability names of the form `resource.action`, for example:

- `projects.view`, `projects.update`, `projects.delete`, `projects.transfer_ownership`
- `collections.view`, `collections.create`, `collections.update`, `collections.delete`
- `environments.view`, `environments.create`, `environments.update`, `environments.delete`
- `members.invite`, `members.remove`, `members.manage_roles`

These are **candidate names**, not a frozen permission registry or public API.

## 6. Initial project permission matrix

The matrix below is the **initial design baseline**. It does not grant access to secret values simply because an actor may view an environment definition.

| Action | Owner | Admin | Editor | Viewer |
| --- | :---: | :---: | :---: | :---: |
| View project and permitted resources | Yes | Yes | Yes | Yes |
| Update project settings | Yes | Yes | No | No |
| Create or edit project collections | Yes | Yes | Yes | No |
| Delete project collections | Yes | Yes | Proposed | No |
| Manage project environment definitions | Yes | Yes | Yes | No |
| Invite members | Yes | Yes | No | No |
| Remove non-owner members | Yes | Yes | No | No |
| Change non-owner member roles | Yes | Yes* | No | No |
| Delete project | Yes | No | No | No |
| Transfer project ownership | Yes | No | No | No |
| Remove or demote an owner | Only through approved ownership rules | No | No | No |

\* An Admin cannot assign `owner`, change an existing owner's role, or grant authority above their own.

**Still to confirm:** collection deletion by Editors, environment-specific write/delete permissions, invitation approval rules, and whether Admins can promote users to Admin.

## 7. Project membership

A project membership associates one user with one project and one project role. Membership and role assignments must be persisted and enforced server-side.

Invariants:

- A project member has only the permissions assigned **for that project**.
- Membership in Project A never implies access to Project B.
- Invites do not grant access until the invitation is validly accepted or activated under the chosen workflow.
- Membership removal or role changes must affect subsequent authorization decisions; cache invalidation and token freshness must not allow stale privileges.
- A user may be a member of several projects without any global project role.

The exact membership and invitation schema, pending/active states, and invite expiration are deferred to the implementation design.

## 8. Ownership and administrative authority

Ownership is deliberately distinct from administration.

- **Owner** may delete the project or initiate ownership transfer, subject to safeguards.
- **Admin** manages ordinary project operations and permitted memberships but cannot delete the project or transfer ownership.
- No member, including an Admin, can take ownership simply by changing a role.
- Project deletion must require reauthorization and a deliberate confirmation mechanism appropriate to the API.
- Ownership transfer must validate the intended recipient and must not leave a project ownerless.

**Ownership cardinality remains open:** single owner versus multiple owners must be decided before implementing transfer and owner-removal rules. Until then, do not hardcode a single-owner or multi-owner database constraint.

## 9. Personal collections and other resource scopes

Some resources may be personal to a user rather than shared with a project.

- A personal collection is accessible only to its authorized owner unless a defined sharing feature explicitly permits otherwise.
- A project role is not permission to access another user's private collection.
- Project collections inherit their **authorization context** from their project, with any explicitly defined collection constraints applied additionally.
- Direct object lookup, search, export, sync, and bulk operations must enforce the same resource-scope checks.

The broader product design also considers global, project-level, and collection-level environments. This document addresses **who may access them**, not how variable values resolve. The exact meaning of “global,” collection-specific visibility, personal overrides, secret-value read permissions, and environment precedence remain separate open decisions.

## 10. Authentication boundary

Authentication establishes the actor's identity; authorization decides whether that actor may perform an action on a particular resource.

Whichever authentication mechanism is selected:

- Authenticate on every protected request according to the selected session/token model.
- Do not use client-provided identity or ownership fields as trusted authorization facts.
- Treat expired, revoked, or otherwise invalid credentials as unauthenticated.
- Apply account-status restrictions consistently.
- Do not disclose password hashes, bearer credentials, reset secrets, or sensitive authentication internals in API responses or logs.

**Open:** credential format and lifetime, session/token revocation strategy, refresh behavior, account verification, and recovery.

## 11. Enforcement and module responsibilities

Authorization is a **server-side application rule**, not merely a UI feature.

- **FastAPI routes:** authenticate/request-validate, resolve dependencies, call application operations, and translate domain/application failures into HTTP responses.
- **Application operations:** enforce the required capability, resource scope, and business invariants before mutation or data disclosure.
- **Persistence:** retrieve authoritative memberships/resources and perform database writes; it must not decide authorization based on untrusted request fields.
- **Response assembly:** ensure private values and secrets are not inadvertently returned even after a resource-level access check.

Project features remain responsible for their project behavior; collections and environments remain responsible for their resource behavior. Shared authorization logic should be extracted only when repeated, concrete use cases justify it. Avoid a generic policy engine or new interface hierarchy solely for imagined future requirements.

The implementation uses **synchronous** SQLAlchemy 2.x `Session`, PostgreSQL, and Alembic, following the main architecture and technical requirements.

## 12. Database and transaction design constraints

The eventual schema needs to represent user identity, project membership, role assignment, and ownership without conflating them.

Required constraints:

- Enforce valid user/project membership and uniqueness as appropriate.
- Enforce ownership invariants under concurrent updates.
- Make a multi-step membership or ownership change atomic.
- Avoid committing separately inside each persistence helper; application operations own the write transaction.
- Use Alembic migrations for schema changes.
- Avoid prematurely defining tables for arbitrary custom roles or per-user overrides.

**No table names, columns, cardinalities, or migrations are approved by this document.** Those decisions belong to the corresponding implementation design.

## 13. Authorization failure and information disclosure

- Unauthenticated requests receive an authentication failure.
- Authenticated requests lacking permission are denied.
- For private resources, select consistent `403` versus `404` behavior that does not disclose the existence of inaccessible records.
- Never allow resource enumeration through list endpoints, filtering, search, exports, or synchronization.
- Never reveal secret environment values merely because a user can inspect environment metadata.
- Record security-relevant administrative and membership events without storing credentials or secret payloads in logs.

Exact response shapes and status-code conventions belong to the API contract.

## 14. Tests and security invariants

Tests must cover at least:

1. Each predefined project role's allowed and denied operations.
2. User with different roles in two projects.
3. No project membership, removed membership, and suspended account.
4. Cross-user private collection access denied.
5. Cross-project resource reads/writes and guessed identifiers denied.
6. Admin blocked from deleting projects or transferring ownership.
7. Owner transfer validation, rollback, and concurrent-change safety after cardinality rules are decided.
8. Privilege escalation attempts through modified role/owner fields.
9. Collection/environment list, export, and sync endpoints applying the same authorization rules.
10. Secret-value redaction and appropriate audit recording.

Use pytest for behavioral tests and PostgreSQL integration tests for constraints, transaction behavior, and concurrency-sensitive ownership rules. Do not modify production visibility or create interfaces solely for mocking.

## 15. Explicitly deferred decisions

Resolve these before implementing the relevant features:

- Account registration, verification, login, recovery, and session/token strategy.
- Server administrator powers, emergency access, and account suspension workflow.
- Single versus multiple project owners.
- Exact invitation lifecycle and membership management permissions.
- Full capability registry and final Editor/Viewer rights.
- Whether collections can have separate memberships or sharing rules.
- Personal versus shared environment scope, secret-value access, and variable precedence.
- Audit-event schema, retention, and administrative review.
- API endpoints, error schema, and database table/column definitions.
- Synchronization authorization details and conflict policy.

Until decided, these are **not** implicit permissions or implementation requirements.

## 16. Implementation sequence and change control

1. Finalize identity and authentication behavior needed for the first user-management slice.
2. Implement basic accounts and authentication with tests.
3. Define project ownership cardinality and the exact permission matrix before project membership APIs.
4. Implement project membership and scoped role checks with denial tests.
5. Apply authorization consistently to collections and environments as those features are introduced.
6. Specify synchronization-specific permissions before implementing synchronization.

Before changing documented module responsibilities, directory ownership, or dependency direction, explain why, identify affected repository paths, describe consequences, and propose the smallest compatible change.

**Current baseline:** predefined system and project roles, capability-based checks, explicit resource scope, and ownership separate from administration. Keep the implementation simple; revisit the model when real requirements justify it.

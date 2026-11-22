# Optional human lifecycle command host

`marty-delegation-commands` is a separate executable in this crate. It accepts the
human administration subset of P03 through the authenticated Gateway. It is
disabled unless `MARTY_DELEGATION_COMMANDS_ENABLED=true`. The approval executable
continues to own explicit consent and representation-authority production.

The command host neither exposes `START_USE`/`FINALIZE_USE` nor authenticates
machines, issues receipts, or executes a domain operation. Enabling its route is
not a delegated-use capability qualification or advertisement.

## Transport and authority

`POST /v1/organizations/{organization_id}/delegation-commands` accepts original
strict JSON bytes with profile `urn:marty:delegation-command:v1`. Its commands are
`CREATE_GRANT`, `APPROVE_GRANT`, `SUSPEND_GRANT`, `REINSTATE_GRANT`, `REVOKE_GRANT`,
and `RECOVER_RESULT`. Unknown fields, duplicate keys, explicit nulls, unsafe
numbers, noncanonical UUID/time spellings, query parameters, and unsupported use
commands are rejected. Bodies are bounded to 65,536 bytes and five seconds.

The internal hop requires `x-service-token` and the following Gateway-authenticated
headers. Duplicate values are rejected. Neither JSON actor fields nor general
`x-user-id` metadata can substitute for this session observation.

| Header | Meaning |
| --- | --- |
| `x-marty-command-organization-id` | Canonical UUID equal to path and configured organization. |
| `x-marty-command-user-id` | Canonical UUID of the currently authenticated human. |
| `x-marty-command-session-ref` | `urn:marty:session:sha256:<64 lowercase hex>` derived from the authenticated session cookie. |
| `x-marty-command-observed-at` | Authenticated observation time in UTC with `Z`. |
| `x-marty-command-valid-until` | Bound by actual Auth expiry and at most 30 seconds after observation. |

The service authenticates the service hop, validates this exact session binding,
then independently reads the active Organization, active membership, and exact
current permission from the Organization source. API keys are excluded. The
service token is a deployment trust boundary; direct access must be restricted to
the Gateway and tokens managed as service credentials.

| New mutation | Required current permission |
| --- | --- |
| `CREATE_GRANT` | `delegation-grant:create` |
| `APPROVE_GRANT` | `delegation-grant:approve` |
| `SUSPEND_GRANT` | `delegation-grant:suspend` |
| `REINSTATE_GRANT` | `delegation-grant:reinstate` |
| `REVOKE_GRANT` | `delegation-grant:revoke` |

All new mutations also require `delegation-grant:view` so the original result can
be returned. Creation uses the configured managed organization issuer/status
reference, the authenticated human grantor, the configured organization subject,
and KEY binding. Approval requires that same human grantor and the exact original
session-bound, producer-owned confirmation. The configured profile, adapter
version, artifact digest, review, confirmation, grant, terms digest, session,
consent reference, and authority reference are checked. Lookup never follows an
evidence URL and never accepts body-authored evidence records.

Inside the repository transaction, a new mutation obtains its command identity
lock and any existing grant row lock, checks the exact previous revision, and
rechecks current source permission. Reinstatement also rechecks the original
grantor's current representation permission if a different administrator acts.
It keeps the earlier access deadline rather
than extending it after a wait. A lost membership/permission during a lock wait
therefore prevents a new mutation. Original already-committed results instead
require fresh `delegation-grant:view` for the original typed actor/organization;
they do not retroactively require the original mutation permission. Historical
recovery preserves expired/revoked historical snapshots without asserting fresh
grant authority.

Consent/authority verification and Organization access are bounded observations
across separate owners. They are not a distributed atomic revocation transaction.
A source can change after an observation. This host retains that limitation and
does not provide final-use authorization. It neither retries external work nor
cancels COMMIT through an application timeout.

Successful mutations and recovery return HTTP 200 with the existing strict
`urn:marty:delegation-command-response:v1` response, original command ID/digest,
`recovered`, and `result.kind=GRANT_SNAPSHOT`. Responses have `Cache-Control:
no-store`. A missing result (404) does not prove an earlier request has stopped;
ambiguous outcomes must use the original command identity and expected digest.

## Configuration

| Variable | Required value / default |
| --- | --- |
| `MARTY_DELEGATION_COMMANDS_ENABLED` | Explicit `true`; otherwise disabled. |
| `DELEGATION_COMMAND_HTTP_ADDR` | `127.0.0.1:8020` by default. |
| `DELEGATION_COMMAND_DATABASE_URL` | Restricted grant/command writer. |
| `DELEGATION_COMMAND_RUNTIME_DATABASE_URL` | Independent evidence reader against the same delegated storage identity. |
| `DELEGATION_COMMAND_ORGANIZATION_DATABASE_URL` | Independent Organization reader. |
| `GRPC_SERVICE_TOKEN` | Shared authenticated-hop token, 32–1024 non-space printable ASCII bytes. |
| `DELEGATION_COMMAND_ORGANIZATION_ID` | Fixed canonical nonnil organization UUID. |
| `DELEGATION_COMMAND_STATUS_REF` | Trusted managed HTTPS status reference; no credentials or fragment. |
| `DELEGATION_COMMAND_APPROVAL_PROFILE` | Exact deployed approval profile URI. |
| `DELEGATION_COMMAND_APPROVAL_VERSION` | Exact deployed three-part version. |
| `DELEGATION_COMMAND_APPROVAL_ARTIFACT_DIGEST` | Exact deployed `sha256:<64 lowercase hex>` adapter pin. |
| `DELEGATION_COMMAND_CONFIRMATION_MAX_AGE_SECONDS` | 1–300; default 300. |
| `DELEGATION_COMMAND_AUTHORITY_VALIDITY_SECONDS` | 1–15; default 15. |

The three database URLs and service token support `<NAME>_FILE`. An inline value
and its file setting together are rejected. Configuration/debug/errors omit
credentials. Adapter pins compare the reviewed contract metadata; they do not
measure a running executable. The producer and command host must agree on pins.

Gateway composition uses the same opt-in flag, upstream name `delegated-commands`,
and `DELEGATED_COMMAND_SERVICE_URL`. The service has no dependency on producer
writer URLs. `/health` reports process liveness; `/ready` rechecks owned-schema
checksums/guards, actual connected roles, and source isolation.

## External migration and role provisioning

Run `marty-delegation-commands migrate` with `DELEGATION_MIGRATION_DATABASE_URL`
(or its `_FILE`) as a controlled owner step. This applies the existing checksum
verified migrations through 0006. Serving never applies migrations or creates
roles. `verify-owned-schema` uses `DELEGATION_COMMAND_RUNTIME_DATABASE_URL` for a
read-only schema check. Source Organization migrations are owned by that service.

Provision three distinct non-owner login identities outside the host. The
following SQL illustrates the exact local database privileges after migration;
credentials and PostgreSQL authentication policy are deployment responsibilities.
Use equivalent separately managed identities for sources on separate databases.
Do not add role memberships, grant options, schema/database creation rights, or
producer mutation privileges.

```sql
CREATE ROLE marty_delegation_command LOGIN NOINHERIT NOSUPERUSER
  NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE marty_delegation_runtime LOGIN NOINHERIT NOSUPERUSER
  NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE marty_delegation_org_read LOGIN NOINHERIT NOSUPERUSER
  NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

GRANT USAGE ON SCHEMA delegated_authority_service
  TO marty_delegation_command, marty_delegation_runtime;
GRANT SELECT ON
  delegated_authority_service.schema_migrations,
  delegated_authority_service.delegation_grants,
  delegated_authority_service.grant_lifecycle_events,
  delegated_authority_service.consent_confirmations,
  delegated_authority_service.consent_withdrawals,
  delegated_authority_service.representation_authority_sources,
  delegated_authority_service.representation_authority_assertions,
  delegated_authority_service.command_results,
  delegated_authority_service.approval_reviews,
  delegated_authority_service.approval_confirmation_bindings,
  delegated_authority_service.organization_authority_observations,
  delegated_authority_service.approval_storage_identity
  TO marty_delegation_command, marty_delegation_runtime;
GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(TEXT)
  TO marty_delegation_command, marty_delegation_runtime;
GRANT INSERT, UPDATE ON delegated_authority_service.delegation_grants
  TO marty_delegation_command;
GRANT INSERT ON delegated_authority_service.command_results
  TO marty_delegation_command;
GRANT SELECT, INSERT ON delegated_authority_service.command_identities
  TO marty_delegation_command;

GRANT USAGE ON SCHEMA organization_service TO marty_delegation_org_read;
GRANT SELECT ON
  organization_service.organizations,
  organization_service.members,
  organization_service.roles,
  organization_service.permissions,
  organization_service.member_roles,
  organization_service.role_permissions
  TO marty_delegation_org_read;
```

Migration-owned trigger functions journal grant changes and protect immutable
results atomically. Request roles do not need direct journal INSERT or EXECUTE on
security-definer trigger functions. Consent and authority producer roles remain
separate and retain only their documented own-table INSERT permissions.

Startup/readiness inspects actual role identity, inherited and SET ROLE reachable
privileges, ownership, unsafe server flags, grants, and same delegated storage
identity. It rejects a request writer that can alter consent/authority data, a
source reader that can write, or a role that can modify Organization permission
data. On separate clusters these catalog checks can see only roles present on
that cluster; deployment/network credential isolation still requires operational
qualification. They do not attest network policy or the runtime binary.

## Verification

`cargo test -p marty-delegated-authority --lib` includes strict HTTP context and
profile tests. Set `DELEGATED_AUTHORITY_TEST_DATABASE_URL` to a disposable owner
PostgreSQL database to execute the real PostgreSQL suites. The
`approval_postgres::tests::command_host` suite creates restricted connected roles
and covers lifecycle source provenance, session/pin mismatch, withdrawal,
historical current-view recovery, least-privilege readiness, and a membership
revocation while a command is observably waiting for its actual grant row lock.
Database-backed tests return early without that explicit test URL; a run without
the URL is not PostgreSQL integration evidence.

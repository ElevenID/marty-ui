# Full-machine access to delegated-use entrypoints

`MachineUseAccessOwner` is the human-administered Organization owner for access
to Marty's delegated-use commands and original Flow request/proof records. It
operates on an existing full `MachineIdentity` registration in one deployment.
It establishes component access, independently of network authentication,
registered-key proof, credential trust, consent, delegation and domain policy.

No HTTP route or executable automatically installs this owner. The configured
workload boundary must authenticate the caller before constructing a
`DelegationCommandCaller`. Rifare retains domain/resource permissions, business
execution, budgets, reservations, provider outcomes and business idempotency.

## Five independent rights

| Owner right | Permits access to |
| --- | --- |
| `START_USE` | Admission of a new use command for the caller's exact active KEY grant |
| `FINALIZE_USE` | Finalization of the original retained challenge and proof submission |
| `RECOVER_RESULT` | Reading an original retained result under current access |
| `RETRIEVE_REQUEST` | Retrieving the original Flow-owned wallet request |
| `SUBMIT_PROOF` | Retaining exact submitted proof bytes against the original Flow binding |

A right does not imply another. Proof submission only stores bytes; the actual
Core-backed verifier still has to verify them. Flow independently validates the
original tenant, typed actor, challenge and deadline. The use owner independently
validates the current grant, consent, operation and configured domain policy.

## Human administration and immutable history

Construct `MachineUseAccessOwner` from the actual `PostgresOrganizationStore`.
The application methods are:

- `grant(organization, human, machine, input)` with `machine-use-access:create`.
- `replace(organization, human, machine, expected_revision, input)` with
  `machine-use-access:update`.
- `revoke(organization, human, machine, expected_revision)` with
  `machine-use-access:revoke`.
- `inspect(organization, human, machine)` with `machine-use-access:view`.

The owner reads current Organization membership, role and permission records,
locks the relevant rows, and rechecks permission after waits and before commit.
API keys and machine principals cannot administer these records. Owner and admin
role templates receive the explicit mutation rights; access/catalog
administrators do not receive those mutations implicitly. Read-only role
templates may receive the separate view permission.

The current tenant, machine, principal and deployment are copied from the actual
registry and cannot be retargeted. A grant or replacement requires an active
machine. Revocation and inspection remain available after machine suspension or
terminal transition, subject to current human rights. Revocation is terminal
for that access record. An active record can be explicitly replaced with a new
rights set and validity window; revision checks prevent lost updates.

Input validity instants must use PostgreSQL microsecond precision. The owner
rejects duplicates, empty/unknown rights, invalid windows and stale revisions.
Each mutation records the exact serialized snapshot bytes, digest, original
administrator, request UUID and timestamp in immutable revision history, with a
matching Organization audit event. Deferred guards reject unpaired revisions.
DELETE/TRUNCATE of current access and mutation/removal of history are rejected.

## Current source and deployment selection

Construct `PgMachineUseAccessSource` with a separately connected restricted
PostgreSQL pool and `MachineUseAccessSelection::new(organization, deployment)`.
Neither a command body nor an actor header selects the deployment. The source
finds the exact registered principal in that configured tenant and deployment;
it never falls back to the SERVICE_ACCOUNT directory.

Every observation validates the actual login, schema and guards, then reads a
bounded read-only snapshot of current Organization, machine registry, access
and matching immutable history. The source checks canonical owner bytes,
digests, current status, exact requested right, original validity and registry
history equality. `CurrentMachineUseAccess` has no public constructor or
Deserialize implementation. Its retained administrative snapshot is not a
bearer permit and cannot be promoted into a fresh observation.

A source observation lasts at most 30 seconds from the original call start,
shortened by access expiry and, for fresh operations, current key expiry. All
source work is bounded by five seconds. The source checks the database clock
after awaited reads and the local clock after the read-only transaction ends;
no wait refreshes the original deadline. This is a bounded observation across
owners, not a distributed atomic revocation transaction. The command/Flow owner
must recheck current access at its own commit boundary.

Recovery checks current active Organization, full-machine identity and access,
including the explicit `RECOVER_RESULT` right. It deliberately does not require
the original grant still be active or the old proof/key still be live. Current
identity suspension/revocation/retirement, access revocation or access expiry
still denies recovery. Request retrieval and proof submission require a current
valid registered key, even though storing bytes itself is not key proof.

## Actual database reader boundary

The source login needs schema USAGE and SELECT on exactly:

- `organization_service.rust_schema_versions`
- `organization_service.organizations`
- `organization_service.machine_registry_entries`
- `organization_service.machine_registry_history`
- `organization_service.machine_use_access`
- `organization_service.machine_use_access_history`

It requires no application INSERT/UPDATE/DELETE privileges. Readiness rejects
ownership, administrative or replication flags, every reachable predefined
PostgreSQL `pg_` role, role-admin/grant-option paths, column-only mutations,
unrelated table reads and executable application SECURITY DEFINER functions.
It also rejects PostgreSQL 17 `MAINTAIN` grants. Only the literal system-schema
prefix `pg_` is excluded; application schemas such as `pgx_*` stay in scope.
`current_user` must equal the authenticated `session_user`; a privileged login
cannot hide behind `SET ROLE`. Every observation repeats this validation.

Additive Organization migration `0007_machine_use_access.sql` installs the two
tables, exact bytes/digest checks, immutable history and five guard bindings.
Readiness validates migration presence, exact primary keys, critical CHECK
expressions, trigger shapes and the exact reviewed function bodies. Existing
migration bytes are unchanged.

## Delegated Authority adapter and validation

`OrganizationDelegationUseCommandAuthorizer` in Delegated Authority implements
both `DelegationUseCommandAuthorizer` and `DelegationUseIngressAuthorizer`. It
requires a complete `MACHINE_IDENTITY` caller, exact tenant/delegate/KEY grant
correspondence, and exact START grant reference. START and FINALIZE require
current active grant bounds and the current registered key. Recovery uses the
original immutable grant identity with current read access. Flow ingress maps
request reading and proof submission to their separate rights.

The explicit `machine_use_access_postgres` integration target exercises the
real owner and restricted source with current membership/RBAC, all five rights,
exact immutable history, cross-selection rejection, key expiry, terminal
identity loss, permission revocation during a member-row lock wait, actual role
privilege drift and weakened schema guards/constraints. Delegated Authority
integration cases exercise both real adapter ports, historical grant recovery
and fresh denial after actual access or identity revocation. Tests do not
execute privileged server-file or server-program operations.

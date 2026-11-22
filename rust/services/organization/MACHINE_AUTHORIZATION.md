# Selected machine authorization policy owner

`machine_authorization::MachineAuthorizationPolicyOwner` owns an explicit
`MACHINE_AUTHORIZATION` selection in the existing Organization `policy_sets`
table. It adds no Protocol primitive, HTTP route, public discovery capability
or delegated-use executable. A qualified host must authenticate its operator
before invoking this internal application API.

## Attributable policy lifecycle

The dedicated owner supports `create`, `replace`, `activate`, `archive` and
`inspect`. Every call requires a current human Organization member and the
corresponding `machine-authorization-policy:create`, `update`, `activate`,
`archive` or `view` permission. API-key forwarding cannot administer this
selection. The owner reads and locks the active organization, member, actual
role edges and permission edges, then reloads current membership after lock
waits. Policy changes hold those locks through the same transaction that writes
the policy and its history.

Creation produces revision 1 in `DRAFT`. A replacement is allowed only from
`DRAFT` or `ARCHIVED` and returns to `DRAFT`. Activation selects an existing
draft or archived revision. An active policy must be archived before its text
or metadata can be replaced. Every mutation names the expected revision and
increments it exactly once. Policy, organization and creator identities are
immutable, and deletion is unsupported. The MAP independently selects the
exact active policy UUID; activation does not assign a policy to a machine or
grant domain permissions. Multiple policies may be active for independently
assigned MAPs.

The ordinary policy application CRUD and persistence save/delete operations
explicitly reject this type. General policy get/list reads, including internal
HTTP projections and mutation lookups, exclude these records; reading them uses
the dedicated owner and its independent `machine-authorization-policy:view`
permission. Existing HTTP parsers do not accept the new type.
Existing `CUSTOM`, access-control, credential-verification and approval policies
are never interpreted as machine authentication authority. A caller cannot
change one of those records into a machine policy by setting a schema label.

## Fixed, bounded Cedar selection

The named schema is `MartyMachine/1.0`, checked in as
`src/machine_authorization_schema.cedarschema`. The actual MMF validator and
engine validate the selected enabled statements against that schema before
every owner write and current source read.

The sole action is `urn:marty:machine:authenticate`. Its principal and resource
are `MartyMachine::Principal` and `MartyMachine::Identity`. Both have no
attributes or parent roles. A consuming source constructs those two entities
from the preceding full-machine authentication gate's exact principal and
machine UUID. No caller-supplied group, status, permission or owner attribute is
created. Policy expressions can use the exact tenant, deployment, runtime,
key, MAP, grant, challenge, verified proof reference and requested operation in
the fixed context. Machine authentication remains separate from delegated and
domain authorization.

The owner bounds names, descriptions, policy count, individual text and total
enabled text. Duplicate policy IDs, missing enabled statements, effect
mismatches, unknown actions or context members, fabricated entity attributes,
invalid Cedar and schema/type errors fail closed. Schema expansion requires an
explicit new reviewed selection; a deployment cannot supply arbitrary schema
text to this owner.

## Revision history and current reads

Migration `0006_machine_authorization_policy.sql` adds the revision column and
`machine_authorization_policy_history` without rewriting earlier migrations or
existing policies. Every revision retains exact JSON bytes, its parsed
document, SHA-256 digest, action, human actor and database timestamp. Row and
deferred transaction guards require history for every state revision, validate
state transitions, bind history to all current policy fields and reject history
updates, deletion or truncation. Ordinary direct writes cannot change the type,
drop history, rewrite identity or activate an unpaired revision.

`PgMachineAuthorizationPolicySource` uses a separate read-only identity. Its
readiness checks the schema, exact guards, byte/digest CHECK expressions,
primary key, required reads and actual reachable PostgreSQL role privileges.
Owner/admin credentials, replication capability, membership in predefined
`pg_` roles, policy writes, unrelated table access and executable
security-definer functions do not qualify.

`observe_current` reads the organization status, exact policy and matching
immutable revision under one read-only repeatable-read snapshot. It verifies
all stored bytes and fields, requires `ACTIVE`, rejects future source records
and preserves the original at-most-30-second deadline through the read and
post-COMMIT check. It returns an opaque current observation, distinct from a
historical snapshot. Its history reference resolves to the original owner
revision. The delegated-authority adapter separately retains the complete
operation-scoped observation and actual Cedar evaluation; see
[`MACHINE_POLICY_SOURCE.md`](../delegated-authority/MACHINE_POLICY_SOURCE.md).

This is a bounded observation across owners. It does not establish distributed
atomic revocation or host/workload authentication. Real operator ingress,
deployment-specific source credentials and network isolation still require
qualification. There is no automatic policy installation or allow-all seed.

## Verification

`tests/machine_authorization_postgres.rs` tests the real MMF schema and actual
local PostgreSQL owner/source. The database cases cover attributable lifecycle,
current status and revision reads, original deadline bounds, separate reader
privileges, human membership loss, API-key rejection, generic writer rejection,
history preservation and database mutation guards. They require the explicit
disposable `ORGANIZATION_MACHINE_AUTHORIZATION_TEST_DATABASE_URL`.

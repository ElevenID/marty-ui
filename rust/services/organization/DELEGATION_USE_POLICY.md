# Organization-owned delegated-use policy

`DelegationUsePolicyOwner` owns an explicit exact-operation delegation policy.
The dedicated `delegation_use_policies` and immutable history tables are separate
from the generic policy-set API, machine authentication policy and a consumer's
domain/resource authorization. This library installs no HTTP endpoint.

## Human administration and policy selection

Creation, replacement, activation, archival and inspection require the current
human tenant member and the corresponding `delegation-use-policy:create`,
`update`, `activate`, `archive` or `view` permission. Organization status,
membership, roles and permission mappings are locked and checked again after
waiting for the policy row. An API key cannot impersonate the human owner.

A policy starts DRAFT at revision 1. Activation adds an immutable revision.
An ACTIVE policy must be archived before its text, name, description or actions
can be replaced. Replacement produces a new DRAFT; reactivation is explicit.
Every revision retains exact publication bytes, their SHA-256 digest, the human
actor, mutation kind and original timestamps. Identity and creation attribution
cannot be rewritten. Database guards require a contiguous matching history in
the same transaction and deny deletion, history mutation and truncation.

The deployment constructs the delegated-authority adapter with an exact tenant
and policy UUID. A use command cannot select a different policy or supply Cedar
text, a schema, entities or a successful evaluation.

## Fixed schema and finite actions

The `MartyDelegatedUse/1.0` schema defines only an attribute-free Principal,
attribute-free Resource and the fixed request context already constructed by
the delegated-use evaluator. Human administration declares between 1 and 64
exact Action URI strings. The schema generator quotes those values as JSON
strings; it never interpolates a schema fragment. Wildcards, duplicate actions,
unknown attributes and incompatible policy types are rejected by the canonical
MMF Cedar parser and schema validator.

Context binds tenant, grant ID/revision, typed actor, grantor, represented
subject, delegate, audience, operation profile and digest, constraint evidence,
and the proof/consent facts from the trusted use evaluator. The entity IDs bind
the exact actor and requested resource. No role hierarchy, resource ownership,
budget balance or merchant permission is invented by this source.

This first concrete source supports **EXACT_OPERATION**. The constraint context
must contain precisely the service-built mode, original request profile and
request digest; its evidence digest must equal the operation digest. An
EXTERNAL_PROFILE request is rejected. The external domain adapter remains an
independently selected and qualified consumer-owned boundary.

## Current observations and retention

`PgDelegationUsePolicySource` reads the active Organization, current policy and
matching exact history. It verifies every requested action belongs to the
owner-approved schema. Each successful read appends a private observation with
the entire Cedar request scope, immutable policy snapshot, history digest,
effective schema, entities, policy digest and original timestamps.

The source role requires schema USAGE, SELECT on `rust_schema_versions`,
`organizations`, `delegation_use_policies`, `delegation_use_policy_history` and
`delegation_use_policy_observations`, and INSERT only on its own observation
table. It receives no human policy mutation, command, grant, proof or receipt
authority. Readiness rejects schema ownership, superuser/create/bypass/replication
privileges, membership in predefined PostgreSQL `pg_` roles, role administration,
grant options, column-only escalation, unrelated table reads/writes and executable
security-definer functions. The actual login must equal `current_user`; `SET ROLE`
cannot hide a privileged authenticated session.

The original source operation has a five-second timeout. PostgreSQL reads and
locks are separately bounded. Validity is no later than the original operation
time plus 30 seconds, rounded down to PostgreSQL precision. An overlong read,
clock regression or expiry fails closed. Only the final COMMIT is shielded from
caller cancellation. Dropping the caller leaves no positive result and does not
retry work. The source rereads exact stored bytes before COMMIT and checks the
original deadline again afterward. Database insertion and deferred commit guards
enforce the retained relationships and freshness.

`recover` returns private historical bytes and original times. It does not
construct a current policy observation, re-evaluate Cedar or renew authority
after archival, tenant suspension or expiry. A serving host must separately
authorize access to these private records.

## Migration and verification

Additive Organization migration `0008_delegation_use_policy.sql` creates the
three dedicated tables, immutable history and source guards. Readiness checks
the eight exact trigger bindings, six exact function bodies, eight critical
CHECK expressions, three primary-key shapes and three foreign-key relationships,
including on empty tables. It never repairs or backfills historical evidence.

The `delegation_use_policy_postgres` test target uses
`ORGANIZATION_POSTGRES_TEST_URL` and disposable loopback PostgreSQL. Database
tests are explicitly ignored until that gate is selected with `--include-ignored`.
It exercises actual current RBAC, lifecycle/history, exact source retention,
privilege and schema drift, and final-COMMIT cancellation. Predefined-role and
replication tests change grants/attributes only; they do not execute privileged
server-file or server-program operations.

See [the delegated-authority source adapter](../delegated-authority/DELEGATION_POLICY_SOURCE.md)
for policy evaluation and remaining serving qualifications.

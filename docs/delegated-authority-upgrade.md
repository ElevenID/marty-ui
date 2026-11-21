# Delegated-authority database preflight, upgrade and rollback

This runbook covers the managed PostgreSQL repository in
[`rust/services/delegated-authority`](../rust/services/delegated-authority/README.md).
The preflight is an operational inspection of that repository. It does not enable
Gateway routes, advertise a capability, authenticate a principal, grant consent,
or qualify a deployed delegated-authority service.

The companion
[`operations/preflight.sql`](../rust/services/delegated-authority/operations/preflight.sql)
recognizes the exact bundled migrations 0001–0008. It never applies migrations,
creates a grant, writes a source assertion, repairs a record or manufactures a
journal. Its successful report explicitly retains
`runtime_qualification: NOT_ASSESSED` and `execution_authorized: false`.

## Supported database states

| Observed state | Supported next step |
| --- | --- |
| No service schema | Provision separate connection roles, inspect, then install the bundled migrations. |
| Empty initial grant table, with or without its initial migration ledger | Inspect and run the unchanged migration sequence. No historical records need importing. |
| Nonempty initial grant table without a lifecycle journal | Stop. Preserve the original store and evidence. There is no supported automatic import into the managed journal. |
| Contiguous, checksum-matching migration prefix with consistent journaled grants | Inspect under maintenance, apply only missing bundled migrations, assign bounded privileges and inspect again. |
| Unknown version, changed original checksum, partial objects, inconsistent journal/result, disabled guard or excessive privileges | Stop and investigate with preserved evidence. Do not make the ledger appear compatible by editing it. |

Migration 0002 already refuses a nonempty initial grant table. The preflight
surfaces that condition before deployment with
`DA_PREFLIGHT_UNJOURNALED_GRANTS`. The refusal applies even to records that look
like harmless pending proposals: a snapshot alone cannot establish its original
lifecycle history.

## Prepare the maintenance boundary

1. Select the exact reviewed application artifact and its matching migration and
   preflight files. Keep migrations 0001–0006 byte-for-byte unchanged. The new
   machine-audit migration is additive; rewriting an applied migration is not
   an upgrade strategy.
2. Stop new lifecycle writes and drain in-flight request transactions. Also
   pause confirmation, withdrawal, authority-refresh and authority-revocation
   producers, any selected internal use writer and background lifecycle jobs. Confirm the old process and its
   connection pools cannot resume writes during maintenance.
3. Preserve a database backup or approved recovery point and the corresponding
   application/source audit artifacts. Verify restoreability in an isolated
   destination using the deployment's established backup procedure. Keep
   organization, grant, command and evidence identifiers intact; these are
   sensitive operational records, not sample data.
4. Inspect the authoritative writable database, not a replica whose lag could
   hide a committed withdrawal, revocation or command result. Use an operator
   connection that can inspect every service row and the relevant catalog and
   role metadata. The script requests `row_security=off`; it must fail rather
   than silently accept a filtered view.
5. Record the actual connection identities and privilege graph for the request
   process, confirmation producer and authority producer. Verify
   `SESSION_USER`/`CURRENT_USER` using each process's configured connection.
   Supply the original connection identity to preflight when it can `SET ROLE`;
   passing only its limited target role would hide reachable privileges.

Preflight uses one read-only, repeatable-read transaction, bounded statement and
lock timeouts, and the service's nonblocking migration advisory lock. This
prevents it from running alongside a cooperating migration. It does **not**
fence ordinary writers after inspection or replace the maintenance boundary.
Repeat inspection immediately after upgrade and privilege provisioning while
writers remain stopped.

## Separate migration, request and producer credentials

Provision four distinct role identities through the deployment's existing
credential-management process. Do not put passwords or connection URLs with
passwords into a command line, review log or this runbook. A libpq service file
or the deployment's existing protected connection configuration can identify
the operator connection without disclosing a secret.

| Identity | Lifecycle-service minimum access through migration 0008 |
| --- | --- |
| Migration owner | Owns the service schema, tables and functions; runs the reviewed migrator during maintenance. Its credentials are unavailable to request and producer processes. |
| Request role | Schema USAGE; SELECT/INSERT/UPDATE on `delegation_grants`; SELECT on `schema_migrations`, `grant_lifecycle_events` and the four evidence tables; SELECT/INSERT on `command_results` and `command_identities`; EXECUTE on `grant_instant(TEXT)`. |
| Confirmation producer | Schema USAGE; SELECT/INSERT on `consent_confirmations` and `consent_withdrawals`; EXECUTE on `grant_instant(TEXT)`. |
| Representation-authority producer | Schema USAGE; SELECT/INSERT on `representation_authority_sources` and `representation_authority_assertions`. |

The request process must never receive source INSERT privileges. The
confirmation producer cannot assert representation authority. Neither producer
needs command-result access. Journal writes occur through the fixed migration-
owned trigger; request credentials do not receive journal INSERT access.

The three non-migration identities must not be owners, superusers, role/database
administrators, replication identities, RLS bypass identities, or members of a
role that supplies those powers. Predefined PostgreSQL `pg_` roles are also
rejected, including server-program, server-file and monitoring roles. They must
not reach each other or the migration
owner through membership. The preflight conservatively audits every reachable
membership, including NOINHERIT paths, and checks effective table, column,
function, schema and grant-option privileges. It rejects database CREATE and
service-schema CREATE for those identities. It allows direct function execution
only for the pure timestamp helper; the producer and journal guards run through
their triggers.

Role membership or existing PUBLIC grants can make an otherwise correct direct
GRANT unsafe. Preflight reports such a failure; it does not automatically revoke
privileges or rewrite deployment policy.

## Run the pre-migration inspection

From the repository root, use psql with its startup file disabled and error
stopping enabled. The names below are examples to replace with the four actual
connection identities; `service=marty_migration` is an example libpq service
entry configured by the operator.

```sh
psql -X --no-password --set=ON_ERROR_STOP=1 \
  --dbname='service=marty_migration' \
  --set=phase=pre-migration \
  --set=migration_owner=marty_da_migration \
  --set=request_role=marty_da_request \
  --set=confirmation_role=marty_da_confirmation \
  --set=authority_role=marty_da_authority \
  --file=rust/services/delegated-authority/operations/preflight.sql
```

All five variables are mandatory. Missing identities, duplicate identities,
unsupported phases and failed checks exit unsuccessfully. The SQL expands role
arguments as quoted psql literals, then looks up exact role names in the
catalog; it never treats a supplied role name as executable SQL. Quote the whole
shell argument if a role name contains spaces or punctuation.

Retain the exit status and JSON report with the upgrade record. The report
contains version and record counts, not grant documents or credentials. A
`PRE_MIGRATION_INSPECTION_PASSED` result means the observed database is suitable
for the next maintenance step under this runbook. It is not permission to serve
delegated requests.

## Install or upgrade

Invoke `PgDelegationGrantRepository::migrate()` from the trusted deployment
integration, or run the candidate `marty-delegation-approval migrate` executable
with exactly one of `DELEGATION_MIGRATION_DATABASE_URL` or its `_FILE` configured
through protected deployment configuration. Both use the migration-owner
connection; there is no public migration route. The migrator applies the original embedded SQL and records its
SHA-256 checksums in `schema_migrations` in a transaction under the service
advisory lock. It must not be invoked with request-serving credentials.

An existing grant table is locked against concurrent access during migration so
a missed legacy writer is observed before the 0002 emptiness check. A row that
commits before that check still causes rejection and remains preserved. The lock
is additional protection, not a substitute for stopping and draining writers.

After successful migration, provision only the access in the table above. The
following psql SQL illustrates the bounded grants; run it with the same safely
supplied role variables under the deployment's role-provisioning authority.
Quoted identifier expansion `:"role_variable"` is required in GRANT statements.

```sql
GRANT USAGE ON SCHEMA delegated_authority_service
  TO :"request_role", :"confirmation_role", :"authority_role";
GRANT SELECT, INSERT, UPDATE
  ON delegated_authority_service.delegation_grants TO :"request_role";
GRANT SELECT ON delegated_authority_service.schema_migrations,
  delegated_authority_service.grant_lifecycle_events,
  delegated_authority_service.consent_confirmations,
  delegated_authority_service.consent_withdrawals,
  delegated_authority_service.representation_authority_sources,
  delegated_authority_service.representation_authority_assertions TO :"request_role";
GRANT SELECT, INSERT
  ON delegated_authority_service.command_results,
  delegated_authority_service.command_identities TO :"request_role";
GRANT SELECT, INSERT ON delegated_authority_service.consent_confirmations,
  delegated_authority_service.consent_withdrawals TO :"confirmation_role";
GRANT SELECT, INSERT ON delegated_authority_service.representation_authority_sources,
  delegated_authority_service.representation_authority_assertions TO :"authority_role";
GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(TEXT)
  TO :"request_role", :"confirmation_role";
```

Repeat the preflight command with `--set=phase=post-migration`. It now requires
every bundled migration and all required bounded privileges. It checks original
checksums, object ownership, fixed function search paths/security modes, enabled
unconditional guard bindings, journal continuity and current snapshot
consistency. Original command results must bind to their own lifecycle revision,
status, digest and exact occurrence time. A later suspension, revocation or
expiration does not make a valid historical result inconsistent. Migration 0005
adds checks for the storage identity, review/confirmation/authority-observation
tables and their eleven guard bindings. Its historical checks bind saved reviews
to the original pending revision and immutable terms, confirmations to their
original human/session/review and consent, and observations to the independent
authority assertion. Later revocation or withdrawal does not require rewriting
that history. The report includes counts for all three kinds of approval evidence.

Migration 0006 backfills the shared command identity registry from original
lifecycle results and adds immutable use claims, admissions, receipts and
results. The preflight checks its sixteen guard bindings, exact unique index
shapes, namespace coverage and retained Pending, CHALLENGE, PERMIT and DENY
histories. Receipt checks compare the stored payload and exact compact-JWS
digest; they do not cryptographically qualify the signer. A pending claim is a
valid retained state and must not be deleted because it has no final result.
The old lifecycle and producer roles receive no read or write access to the
four use-specific evidence tables.

Then invoke the repository's `readiness()` using the request connection. Both
checks must succeed before ending database maintenance. Re-enabling any hosted
feature still requires the separately qualified runtime composition described in
the service README: authentication, authorization, trusted confirmation and
representation sources, freshness, signing, audit, recovery and the relevant
deployment tests. Database readiness never creates that qualification.

## Additive machine-authentication audit retention

Migration 0007 adds private `machine_authentication_evidence` storage, four
audit guards and the `use_receipts_machine_evidence` guard. It does not rewrite
migrations 0001–0006, existing receipts or source evidence. The post-migration
inspection now requires all eight bundled checksums and verifies the exact
tenant/evidence primary key, enabled guard bindings, deferred retention
expiry check, exact bytes/digest/document constraint expressions and retained
correspondence, complete retained
scope and machine receipt linkage. Expired evidence remains immutable history.

The lifecycle/confirmation/authority roles above gain **no** audit access. A
qualified machine audit composition uses a separate nonowner connection with
schema USAGE, SELECT on `schema_migrations` and `machine_authorization_evidence`,
and SELECT/INSERT only on `machine_authentication_evidence`. Its runtime readiness rejects unrelated
reads, same-database source/ledger writes, destructive authority and reachable escalation.
A qualified future use writer additionally needs SELECT on this audit table
for its same-transaction receipt guard, never audit INSERT. The original
four-role preflight does not claim to qualify those future application roles;
the concrete audit repository performs its own connected-role readiness.

Every newly appended `MACHINE_IDENTITY` use receipt requires matching retained
machine evidence for its original tenant, typed actor, grant revision,
challenge, operation, key, proof times and deadline. A machine-reference prefix
on another principal type is rejected. Recovery does not turn stored evidence
into a new proof, regenerate a receipt, refresh a source or authorize a retry.

Pre-0007 machine receipts that have no retained aggregate audit are preserved
and reported as `legacy_machine_receipt_count`. No migration synthesizes that
missing record. The report also includes `machine_authentication_evidence_count`;
both counts are historical inspection, with `runtime_qualification=NOT_ASSESSED`
and `execution_authorized=false`. The selected full-machine host, live source connections, required attestation and production deployment remain
independent qualification gates. The concrete Organization, Trust Profile and
Issuance source owners are implemented separately from the serving host. See the service's
[`MACHINE_AUTH.md`](../rust/services/delegated-authority/MACHINE_AUTH.md).

## Additive machine-policy source and evaluation retention

Migration 0008 installs append-only `machine_authorization_evidence` for the
selected Organization policy source and actual MMF evaluation. Its three table
guards bind exact bytes, scope, source reference, policy revision and original
times, and reject expired COMMIT. A fourth guard requires every newly retained
aggregate machine audit selecting `MACHINE_AUTHORIZATION` to reference a matching
retained evaluation. A hash-only policy reference cannot satisfy that guard.

The policy evidence writer needs SELECT/INSERT on this table and SELECT on
migration metadata only. The aggregate machine audit writer additionally needs
SELECT on policy evidence for the new guard, with no policy-evidence INSERT.
Organization policy, machine registry, Trust Profile, Issuance and credential
source evidence use their independently checked connections. The existing
lifecycle, confirmation and representation roles gain no access to these sources.

Preflight verifies the exact new trigger bindings, function bodies, critical
CHECK expressions, primary key and retained source/evaluation correspondence.
It reports `machine_authorization_evidence_count` and
`legacy_machine_authorization_audit_count`. Aggregate audit recorded before
migration 0008 is preserved and counted as original history; it is not backfilled
with invented policy observations. Missing evidence for new records blocks
inspection. Expired retained observations remain historical evidence.

Organization migrations 0005–0006 separately install full-machine registration,
MAP assignment and the named machine-authorization policy owner. Trust Profile
migration 0004 retains explicit nested JWT-VC authority revisions. The concrete
credential source has its own additive evidence schema and three distinct roles.
See [machine registration](../rust/services/organization/MACHINE_REGISTRY.md),
[machine policy ownership](../rust/services/organization/MACHINE_AUTHORIZATION.md),
[policy source composition](../rust/services/delegated-authority/MACHINE_POLICY_SOURCE.md)
and [credential source composition](../rust/crates/machine-credential-source/README.md).
These are internal composition APIs; this migration enables no public use host.

## Additional roles and privileges for the organization approval candidate

The four-role preflight above remains usable for a lifecycle-only deployment.
It allows the following additional migration-0005 privileges without requiring
an approval host to be selected. When selecting the approval host, provision two
additional distinct identities: its runtime read role and its Organization
source read role. Do not use the lifecycle request writer as the approval
runtime reader. The host's `readiness()` checks their actual connected identities,
separation, storage identity and privileges, including reachable membership and
cross-database writes to the Organization source; this is an additional required
gate, not a result supplied by the four-role preflight.

| Approval host connection | Required bounded access |
| --- | --- |
| Runtime read | Schema USAGE; SELECT on `schema_migrations`, `delegation_grants`, `grant_lifecycle_events`, `command_results`, `consent_confirmations`, `consent_withdrawals`, `representation_authority_sources`, `representation_authority_assertions`, `approval_reviews`, `approval_confirmation_bindings`, `organization_authority_observations` and `approval_storage_identity`; EXECUTE on `grant_instant(TEXT)`. No writes. |
| Confirmation producer | Existing confirmation/withdrawal SELECT/INSERT plus SELECT/INSERT on `approval_reviews` and `approval_confirmation_bindings`; SELECT on `approval_storage_identity`. No command-result or authority-source reads are needed. |
| Representation-authority producer | Existing authority-source/assertion SELECT/INSERT plus SELECT/INSERT on `organization_authority_observations`; SELECT on `delegation_grants` and `approval_storage_identity`; EXECUTE on `grant_instant(TEXT)`. No consent writes. |
| Organization source read | In the authoritative Organization database: schema USAGE and SELECT on `organizations`, `members`, `roles`, `permissions`, `member_roles` and `role_permissions`. No writes to that source or delegation evidence. |

Use exact table grants, preserve the no-grant-option and no-schema-creation
boundaries, and verify the connected login identities. Different connection
strings do not establish separation. Apply Organization grants in its own
authoritative database when it is hosted separately. The lifecycle request role
may additionally read the four migration-0005 tables; it still cannot insert,
update or delete approval evidence.

Run the core preflight again with the actual confirmation and authority producer
identities after granting the additional access. Then run the approval host's
startup/readiness using all four configured host connections. The command
`marty-delegation-approval verify-owned-schema` checks the repository schema with
the runtime read credential; it does not replace the host's complete
multi-connection readiness check. See
[the candidate hosting contract](agent-identity-and-approval-candidate.md) for
configuration and role limits. An unsuccessful check leaves the host disabled;
it does not install schema, grant privileges or reconstruct evidence.

## Nonempty legacy grants without trustworthy journal evidence

Stop before 0002 and retain the original database read-only through the
deployment's maintenance/archive controls. Preserve its backups, original grant
documents, logs, source confirmations and any records needed to understand which
effects occurred. Keep the original checksums and identifiers. A read-only
archive serves investigation and retention; it does not become a current
authority source merely because it can be queried.

Do not delete or truncate old grants to make the migration pass. Do not insert
invented initial events, infer approval timestamps from a snapshot, copy a
current status into a supposed historical event, edit migration checksums or
disable guards to adopt the old data. This milestone provides **no automatic
import or reconciliation tool**, even if an operator believes historical
evidence may exist. A future import needs an independently reviewed provenance,
mapping and reconciliation design before it can be supported.

Where no trustworthy import is available, retain the old store and install a
separate clean managed store. Request new grant proposals with new identifiers,
fresh explicit confirmation of their exact terms, and a fresh independent check
of representation authority. Use the normal authorized lifecycle for those new
grants. Preserve the relationship to old business records in the consumer's
audited reconciliation process; do not transplant old records as freshly
authorized managed grants. Existing business effects require their own
reconciliation and cannot be repeated merely because a new grant exists.

## Failure and rollback

If preflight or migration fails, keep writers stopped and preserve the failure
report and records for diagnosis. A failed migration transaction rolls back its
own schema changes; that does not erase a legacy writer's earlier committed
records. Fix only the independently reviewed deployment or implementation issue
and rerun inspection against the retained data.

The supported rollback after a successful upgrade is to fail closed: stop new
delegated use, remove any associated public capability/routing activation, and
retain the database, journal, consent/authority records, command results and
supporting audit/proof material. Historical result recovery, if exposed by a
qualified runtime, still requires current caller/resource authorization. A
stored result is never current authority or permission to repeat a side effect.

Do not run down migrations, remove the 0004–0008 ledger entries, drop command, use or approval tables,
relax guards or reuse a command identity to make an older binary appear ready.
An older binary expecting a shorter migration list must fail readiness. Use a
compatible reviewed fix or an explicitly tested recovery deployment before
resuming operations. The present milestone supplies no qualified schema
downgrade or automatic reverse import. A restored historical backup must be
reconciled with later authoritative outcomes before it can serve writes; backup
restore alone does not prove that later effects never happened.

## What a passing inspection establishes

The result describes one database snapshot and its current catalog/role graph.
It is a bounded consistency and privilege check, not a complete attestation of
all installed function bodies, schema definitions, infrastructure or source
provenance. In particular, it does not recompute canonical protocol digests,
authenticate the original actor, validate a consent artifact/signature, prove a
source was genuinely independent, refresh old assertions or renew an expired
grant. Preserve stale and terminal records; decide current use through the
runtime's independent authorization and freshness checks.

The focused tests execute this SQL against disposable PostgreSQL databases with
real roles, migrations, records and privilege changes. Set
`MARTY_PREFLIGHT_TEST_DATABASE_URL` to an explicitly disposable loopback
administrative database and optionally `PG_BINDIR` to the PostgreSQL binary
directory, then run:

```sh
python -m pytest tests/test_delegated_authority_upgrade_preflight.py -q
```

The tests create and remove only their own disposable databases and roles.
Deliberate corruption is confined to synthetic test records. These cases prove
that inspection rejects inconsistent history without repairing it; they are not
production repair instructions. Without the explicit database setting the tests
are skipped, which must not be reported as live database validation.


## Optional human lifecycle command host

The separate `marty-delegation-commands` executable uses the same checksum-verified
Delegated Authority migrations, now through 0008, and is disabled by default.
It continues to support human lifecycle commands only. Its restricted command
writer additionally needs SELECT/INSERT on the shared `command_identities`
registry, whose trigger prevents lifecycle/use identity collisions. Provision that writer
writer plus distinct evidence and Organization readers as described in
[COMMAND_HOST.md](../rust/services/delegated-authority/COMMAND_HOST.md). The command
host does not receive either consent/authority producer writer credential.

Existing read-only preflight remains the owner/request/confirmation/authority
migration inspection. The new host's startup/readiness checks additionally check
its actual connected roles, same delegated storage identity and source mutation
boundaries. Running one check is not a substitute for the other.

Managed enrollment is an Organization-owned additive migration 0004 and separate
opt-in. See [the enrollment operator contract](managed-agent-enrollment-candidate.md).
Preserve retained challenges/outcomes and the existing original command results
when disabling either feature or rolling back application traffic. Historical
results do not restore expired/revoked authority.

## Internal delegated-use composition

The new `DelegationUseCommandService` is an internal library composition. It has
no selected public executable or production use-writer provisioning in this
candidate. Do not expand the lifecycle writer or the evidence-reader role to
make it a use host; their readiness checks reject access to use-specific tables.

A future qualified use host must select a separate bounded use role and the
actual `FlowDelegatedUseOwner`. Delegated Authority migration 0006 and Flow's
additive `0005_delegated_use_retention.sql` must be installed in the same
authoritative PostgreSQL database. The Flow adapter independently pins its
storage identity and checks it on the connection supplied by each use
transaction. The authoritative Flow challenge or consumption, retained nonce,
receipt and original response then commit together. Separate pools are allowed;
separate database transactions or a second Flow database are not this adapter's
contract. The four-role SQL preflight does not qualify that additional role or
the cross-owner Flow composition.

Reserve the original command identity before external preparation or signing.
If that work is uncertain, retain the pending claim and its challenge identity.
If a later local transaction fails, all of its Flow/result writes roll back
together, while the earlier claim remains. Never delete the claim, release its
nonce or retry signing automatically. No recovery lease or operator override is
provided by this candidate.

Flow migration 0005 adds four restricted retained tables, thirteen guard
bindings and a stable storage identity. Earlier Flow migrations retain their
original bytes. Preserve this state together with the five Delegated Authority
tables during rollback or backup reconciliation. The existing human host and
Gateway still reject `START_USE` and `FINALIZE_USE`; database installation alone
does not expose either operation.

See [USE_COMMANDS.md](../rust/services/delegated-authority/USE_COMMANDS.md),
[Flow's retained-use contract](../rust/services/flow/DELEGATED_USE.md), and
[the candidate milestone](delegated-use-runtime-candidate.md) for transaction,
source freshness, managed signing and remaining runtime qualification gates.

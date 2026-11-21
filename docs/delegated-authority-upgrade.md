# Delegated-authority database preflight, upgrade and rollback

This runbook covers the managed PostgreSQL repository in
[`rust/services/delegated-authority`](../rust/services/delegated-authority/README.md).
The preflight is an operational inspection of that repository. It does not enable
Gateway routes, advertise a capability, authenticate a principal, grant consent,
or qualify a deployed delegated-authority service.

The companion
[`operations/preflight.sql`](../rust/services/delegated-authority/operations/preflight.sql)
recognizes the exact bundled migrations 0001–0004. It never applies migrations,
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
   preflight files. Keep migrations 0001–0003 byte-for-byte unchanged. The new
   command-results migration is additive; rewriting an applied migration is not
   an upgrade strategy.
2. Stop new lifecycle writes and drain in-flight request transactions. Also
   pause confirmation, withdrawal, authority-refresh and authority-revocation
   producers and any background lifecycle jobs. Confirm the old process and its
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

| Identity | Required access after migration 0004 |
| --- | --- |
| Migration owner | Owns the service schema, tables and functions; runs the reviewed migrator during maintenance. Its credentials are unavailable to request and producer processes. |
| Request role | Schema USAGE; SELECT/INSERT/UPDATE on `delegation_grants`; SELECT on `schema_migrations`, `grant_lifecycle_events` and the four evidence tables; SELECT/INSERT on `command_results`; EXECUTE on `grant_instant(TEXT)`. |
| Confirmation producer | Schema USAGE; SELECT/INSERT on `consent_confirmations` and `consent_withdrawals`; EXECUTE on `grant_instant(TEXT)`. |
| Representation-authority producer | Schema USAGE; SELECT/INSERT on `representation_authority_sources` and `representation_authority_assertions`. |

The request process must never receive source INSERT privileges. The
confirmation producer cannot assert representation authority. Neither producer
needs command-result access. Journal writes occur through the fixed migration-
owned trigger; request credentials do not receive journal INSERT access.

The three non-migration identities must not be owners, superusers, role/database
administrators, replication identities, RLS bypass identities, or members of a
role that supplies those powers. They must not reach each other or the migration
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

Invoke the existing `PgDelegationGrantRepository::migrate()` from the trusted
deployment integration using the migration-owner connection. This crate exposes
a library migrator; this runbook does not invent a production CLI or public
migration route. The migrator applies the original embedded SQL and records its
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
  ON delegated_authority_service.command_results TO :"request_role";
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
expiration does not make a valid historical result inconsistent.

Then invoke the repository's `readiness()` using the request connection. Both
checks must succeed before ending database maintenance. Re-enabling any hosted
feature still requires the separately qualified runtime composition described in
the service README: authentication, authorization, trusted confirmation and
representation sources, freshness, signing, audit, recovery and the relevant
deployment tests. Database readiness never creates that qualification.

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

Do not run down migrations, remove the 0004 ledger entry, drop the command table,
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

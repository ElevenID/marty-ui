# D12 canonical native subset and maintenance evidence

This source slice does not execute a cutover, create a runtime profile, or qualify
passport hardware. It keeps D12 provenance separate from D02 and Canvas while
using their shared binary, Docker-read and private journal mechanics.

`scoped_passport_successor.select_canonical_binaries` reads the original
`build-receipt.json` using the original frozen `LinuxBuildJournal`. Its worker,
shared module, specification, run, root and actual stored SHA/value must match
the prepared canonical build. The terminal receipt must cover all29 official
d2de/Core432 binaries. Only Flow, gateway and issuance-native are selected; the
original29 receipt remains authoritative. No new build profile or smaller build
receipt is introduced. Loader/UID compatibility remains separate from compile
success and must prove those exact three ELF digests and UID10001.

The existing Compose adapter renders only executable-source replacements and
requires `--no-start` for this D12 selection. The existing all22 maintenance
preview retains exact graceful-stop, source, quiescence, fenced SQL, backup and
cleanup requirements. It does not grant dispatch authority.

`passport-maintenance-runtime.observeMaintenanceReadback` requires actual pinned
Docker and original-journal transports. It derives expectations from the closed
687 profile and exact09b binding, then observes every running PID1, ELF, UID,
mount and generation using the existing runtime observer. Selected3 must have
fresh noncolliding CIDs; retained19 must have their original CIDs and newer
start generations with their separate source/Core/hash/image/UID facts intact.
The result contains a v2 binding but is explicitly **readback only**, with no
runtime profile, apply authority or qualified migration outcome. A subsequent
profile producer must bind the actual durable maintenance/migration outcome;
these rows alone cannot replace that prerequisite.

The recorder Python bridge carries its existing validated functional v2 context
through the owned ACK channel. The D12 adapter rechecks the exact acknowledged
receipt/profile digests and functional-only flags. Simulator deployment,
public image markers, governed fixture custody and production invariants remain
independent checks; no single effective native revision is asserted for a mixed
stack. Recording remains disabled.

## Schema execution prerequisite

Frozen d2de `marty-flow` has **no schema-only CLI**. This slice adds `migrate`
and `verify-owned-schema` to future Flow source. They run before full service
configuration, reuse `migrate_flow_schema` and `validate_flow_schema`, use one
database connection, disable statement logging and exit before Redis/providers,
workers or listeners. Acquisition is bounded to10s and the whole command to120s.
Failure/timeout is nonzero; a timeout requires exact outcome reconciliation,
never an automatic retry.

These new commands must not be attributed to the frozen all29 binaries. Before
cutover, obtain a **separately source-bound migration-tool build** with the exact
accepted CLI source, actual terminal compiler/ELF evidence and loader/UID proof.
Bind its Git revision/tree and hashes of the following files, and compare its
migration implementation/SQL with the selected d2de source:

- `rust/services/flow/src/schema_command.rs`, `main.rs` and `lib.rs`
- `rust/services/flow/src/migration.rs`
- `rust/services/flow/migrations/0001_flow_schema.sql`
- `rust/services/flow/migrations/0002_builtin_flows.sql`
- `rust/services/flow/migrations/0003_physical_start_intents.sql`

The d2de issuer already has `migrate` and `verify-owned-schema`; use its real
source-bound executable with the same required0010/0011 SQL/owner/ledger proof.
The old Python SQL handoff remains retired. Reuse the existing five fenced SQL
helpers and their fixed hashes for maintenance/ACL/owner transitions; require
all22 known-terminal stops, backup, actual zero application connections,0009
ledger validation, exact migration/schema/ACL readback, known-terminal owned
tool cleanup, full start pass and actual22 health before producing any future
qualified functional-only profile. No reverse DDL, reset or blind rollback is
authorized by this source slice.

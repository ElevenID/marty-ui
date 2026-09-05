# Canvas worker initialized ownership and PostgreSQL disposal

The unrouted worker adopts protected MMF revision
`b4376cda59b3921598e1749f550595d7293e4624` (MMF #102/#103).
All nine direct and eleven locked MMF sources move together. The only additional
dependency edge is mmf-runtime to the already-locked Tokio; registry versions,
crypto pins, routes and deployment consumers are unchanged.

## Actual entry-point boundary

`spawn_with_postgres_cleanup` installs the shared MMF owner immediately after
the PostgreSQL pool is created, before invoking fallible worker construction.
The actual binary constructs its repositories, OAuth/vault/provider/native
processor inside that operation. Return, failure, panic and explicit
cancellation all reach awaited pool disposal. There is no second cancellation
supervisor implementation. The binary inspects both operation and cleanup
outcomes; cancelled work or failed cleanup cannot become process success.

`finish_on_shutdown` owns the signal future inline and awaits the resource
owner after a control event. There is no detached signal helper to abort without
joining. A graceful stop drains the current cycle; cancellation releases the
worker's owned concurrent job futures and lease maintenance before disposal.

Ctrl+C maps to cancellation: the inspected Python 3.12
`asyncio.runners.Runner._on_sigint` cancels the main task on first interrupt,
and the frozen worker uses `asyncio.run(_main())`. SIGTERM retains the Rust
candidate's graceful-drain policy; that is a deliberate native extension, not
a claim that the Python worker registers SIGTERM. Registration failure requests
cancellation rather than silently succeeding or waiting indefinitely.
Repeated interrupts do not abort acknowledged cleanup. Forced runtime shutdown,
process termination and host failure cannot guarantee asynchronous disposal.
OS process-signal delivery and exact exit-code parity are not established by
the local injected-control tests.
The [process-signal follow-up](canvas-worker-process-signals.md) freezes the
published SIGINT exit130 observation, corrects the binary mapping, and adds
the required Linux actual-binary PostgreSQL signal gate.

## Evidence and its limits

The frozen language-neutral initialized return/error/cancel floor comes from
credentials `b027e834d71dee0cc3550aac1150cdb0c40946ae`, lifecycle test blob
`b3c85cfa7bf03c11c90ed440221f47343ee1ae36`. Those legacy disposal tests replace
database factories; this Rust replay additionally uses real PostgreSQL.

The existing mandatory `canvas_sync_worker_postgres_contract` runs five new
scenarios: initialized return, operation error, initialization-factory panic,
active-worker cancellation and active-worker graceful drain. Each owns a
separate real pool on the already-guarded synthetic `*_test` database. Each
holds a checked-out connection while closure starts, proves join is still
pending, releases the connection, and verifies zero remaining connections and
rejected acquisition before completion acknowledgment. A separate observer pool
checks durable state after disposal. Late cancellation cannot abort cleanup.

Both active-worker cases use the actual worker loop and production SQL
repositories with two controlled processors. Cancellation cleans both scopes
and leaves both jobs leased/incomplete; graceful drain completes both jobs.
Both prove the signal scope is dropped. Operation-error identity is preserved.
Initialization panic is a stronger native property, not an observed legacy
pre-loop guarantee. All existing recovery, renewal, fencing, range and lifecycle
assertions remain in the same mandatory executable.

A negative control changed awaited closure to a detached closure task. The
contract failed because join completed before disposal was acknowledged. The
awaited implementation was restored, with no fixture changes. This verifies
test sensitivity, not a claim that the temporary mutation existed on main.

The worker binary previously had `test = false`, excluding its secret-fallback
unit tests from normal workspace test execution. Its target now enables tests;
the deployment contract prevents regressing that setting. Binary tests cover
both secret fallbacks and failure/success outcome handling. All-target clippy
alone is not test execution.

The local database is digest-pinned PostgreSQL 15.17 with tmpfs storage and
synthetic credentials. This is not published-migration, provider, process-signal,
whole-worker or deployment proof. Remaining loader-consumer removal, renewal/
provider/privacy/failure/concurrency/readiness differentials, all-consumer
cutover and aggregate beta acceptance remain required before Python deletion.

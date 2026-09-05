# Canvas worker lossless configuration — candidate implementation

The native worker now uses the shared `mmf_config::numeric_config` implementation
from protected MMF revision `9534d0e3be66bd63d65ee672516da8b8df5206af` (PR #101).
All workspace MMF dependencies select that same revision to preserve shared Rust
type identity. Existing crypto pins remain unchanged. The only added registry
dependency is read-only `hostname` 0.4.2, so generated identity uses the OS hostname
as Python's `socket.gethostname()` does, not mutable environment hints.

The factory preserves explicit identity whitespace, Python numeric separators
and Unicode decimal grammar, NaN/infinity duration bounds, and exact integers up
to the frozen 4,300-digit conversion policy. Integer limits remain lossless until
the consumer boundary. OAuth limits are capped before machine conversion; SQL
limits use checked conversion. Lease deadlines are validated before opening a
transaction, including on empty queues, and respect Python's year 9999 maximum.
One computed deadline is used for all rows leased by the operation.

## Frozen contract provenance

All three fixtures are byte-for-byte copies from protected credentials revision
`b027e834d71dee0cc3550aac1150cdb0c40946ae` (PR #262):

| Contract | Original Git blob |
| --- | --- |
| Configuration baseline | `fe7231ff360f2922d8d92dbc95a4445b0f652d8f` |
| Numeric lexical corpus | `3a9e8df0b605191eaf39990baf3e2e1821a63302` |
| Consumer range/loop corpus | `e6118c49cc0fd76bbc2b2f657c1a096d812b846b` |

The actual Rust factory replays 15 baseline cases, 18 malformed combinations,
64 lexical vectors and 36 range-startup cases without skipping reconciliation
flags. Integer outputs stay decimal strings. Only the two declared floating
duration fields normalize JSON integer/float representation (`600` versus
`600.0`); all numeric values and other fields still compare exactly.

Additional tests cover the generated identity's hostname/PID/nonce format,
checked signed SQL bounds, lease date bounds, and lease-range failure before an
unavailable database connection. Existing processor/worker assertions remain.

## Native PostgreSQL consumer replay

The existing mandatory `canvas_sync_worker_postgres_contract` executable now
also runs every frozen consumer observation through the actual Rust factory,
`CanvasSyncWorker::run_cycle` / `run_loop`, and PostgreSQL worker/OAuth
repositories. A test-only adapter records operation entry/outcome and supplies
the owned loop stop signal; all repository operations delegate to production
implementations. The empty-queue processor rejects unexpected work.

The comparison preserves event order, phase, result counts and loop survival.
Only the two explicitly frozen Python exception/driver identities map to
language-neutral `integer_sql_range` and `duration_range` categories; unexpected
errors and extra/missing events fail. OAuth query errors cannot be hidden by
the worker's recovery path because the observed queue outcome is also checked.

Local PostgreSQL 15.17 replay passed all 36 cycles and three two-cycle loops,
together with the existing recovery/renewal/fencing/race assertions. A negative
control changed the expected empty OAuth row count to one and failed on the
first real cycle. The original fixture was restored before the final replay.
The fixture itself remains unchanged from the recorded upstream Git blob.

Local database isolation: a new digest-pinned PostgreSQL container, ephemeral
tmpfs data, synthetic credentials, and a random port bound only to loopback.
These Rust tests use the existing contract suite's synthetic schema (plus the
OAuth queue projection), not an assertion that published migrations were run.
The legacy oracle separately records published-migration provenance. No beta
or production database is used. Set `MARTY_ISSUANCE_POSTGRES_CONTRACT_URL` only
to a disposable `*_test` database: the suite deliberately replaces its schema.
Without that variable the SQL test skips, which is not database evidence.

## Remaining gates — do not confuse consumer proof with cutover

This is not yet whole-worker parity. Full service/workspace CI, maintainer
review and protected merge remain required. All broader worker/provider/concurrency/readiness gates
still apply before routing changes or deleting the retained Python worker.
No release coordinate, production route, deployment or beta evidence is changed.

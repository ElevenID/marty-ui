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

## Remaining gates — do not confuse startup proof with cutover

This is not yet whole-worker parity. The full 36-cycle/3-loop corpus must execute
against real native PostgreSQL repositories, including event order, error phase
and loop survival; updated existing SQL recovery/renewal/race tests must run on
an isolated database. Full service/workspace CI, maintainer review and protected
merge remain required. All broader worker/provider/concurrency/readiness gates
still apply before routing changes or deleting the retained Python worker.
No release coordinate, production route, deployment or beta evidence is changed.

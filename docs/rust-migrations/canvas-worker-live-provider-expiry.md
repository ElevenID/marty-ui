# Live-provider lease expiry — published reference

## Current evidence — 2026-09-08

Capture A at `4fbe9fdcb` passed both actual published-worker cases in **113.34s**.
Its original JSON is **19,575 bytes**, SHA256
`455494bc6be253a73747116734c418c9c13e41d13eac09a1c31f721e5d44499d`.
Independent capture B passed in **112.78s** at the same clean
`4fbe9fdcbe57488a5653e8f932628413ff9d2a98`. Its 19,575 bytes compare byte-for-byte
equal to A with the same SHA256. All four exact-owned B fixture containers were
independently verified absent. The original bytes are frozen unchanged as
`contracts/canvas-worker-lease-expiry-oracle.json`. The ordinary
`worker_lease_expiry_reference_matches_published_process` gate is registered;
its first ordinary regeneration passed locally in **113.12s**, comparing the
exact frozen bytes. All four fixture IDs were verified absent afterward.
Final local validation passed **2,538 Python tests with three explicit skips in
170.56s**, Rust compilation in **17.83s**, and strict all-target Clippy in
**8.55s**. Current-head hosted CI remains pending; native BODY and live-provider
expiry behavior remain unqualified.

| Case | Identical actual observations in A and B |
| --- | --- |
| `renewal_lock_early_release` | One HTTPS request; all five body chunks flushed; queued renewal advanced the lease; job succeeded with one fact. |
| `renewal_lock_crosses_expiry` | Original stored lease really expired while renewal was blocked and provider input remained incomplete. After release, queued renewal advanced the lease; job succeeded with one fact. One HTTPS request and all five chunks flushed. |

Both cases retained the checked state through the late-response window, joined
handlers and shutdown; the published worker exited with `-2` after SIGINT and
matched the strict source-pinned shutdown output profile. These are published
Python observations, **not native Rust behavior or cutover qualification**.

## Boundary exercised

The unchanged immutable worker runs on fresh official-schema PostgreSQL with
the shared application/OAuth seed and one prequeued job. Configuration is set
before startup: job deadline 120s, lease 30s, loop poll 120s. A real authenticated
HTTPS response flushes incomplete JSON at offsets **0, 8, 16, 24, 34 seconds**;
the final delimiter is unavailable until the final chunk. The schedule operates
independently of worker outcomes and stays within the application's existing
15-second read-inactivity budget.

A separate owned transaction locks only the selected job row after request
receipt. The observer verifies the original generation, exact blocking backend,
pending renewal UPDATE and incomplete provider input. The early control releases
near request+12s while the original lease is current; the expiry case releases
in the declared original-expiry+1..2s window. No running job, lease, generation,
clock, provider, worker implementation or captured BODY input is rewritten.

The crossing case does not preselect a failure. Published renewal computes its
proposed expiry before awaiting the blocked save; original expiry while locked
does not establish continued expiry after release. Both captures actually observed
revival followed by successful effects. Any unsafe native/reference discrepancy
must be investigated and explicitly reconciled, not concealed by normalization
or by weakening authorization fences.

The harness samples first terminal state separately from the slower full idle
snapshot. Its elapsed brackets are internal and **not serialized**: the report
retains terminal category and the separate-observation flag, not a new exact
terminal-time parity claim.

## Source and capture provenance

The exact installed image is
`ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`.
An actual source-only image probe verified all four module hashes below and was
automatically removed; these are not merely inferred from a local checkout.

| Installed module | SHA256 |
| --- | --- |
| `issuance.canvas_worker` | `c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a` |
| `issuance.infrastructure.api.canvas_routes` | `f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943` |
| `issuance.infrastructure.adapters.postgres_repository` | `34ba42bd10227e0040c99378254c3652c388bab3131aadfdba2e0fe92cf89ccb` |
| `issuance.application.canvas_sync_jobs` | `e3cc45ef4b40cf9f80ad46699768e7d584bde53e75d29f36ab783780fa03e5f9` |

The runner checks **18 capture-input hashes** before and after execution: the
16 unchanged BODY inputs plus its new runner and scenario. Existing HTTP-factory,
HTTP dependency, warning and Python shutdown source/version checks remain.
Local text input hashing canonicalizes UTF-8 newlines to LF; this does not edit
observations or reserialize JSON numbers. The capture owner retains the original
full report strings and numeric spellings.

## Ownership, privacy and validation

The new runner reuses the BODY HTTPS, seed, snapshot, output and shutdown owners
without changing their captured source. Raw effect and operational rows are
compared privately; issued rows, encrypted material and target generation remain
checked. Only bounded reviewed projections enter the report. Unexpected output
fails closed; no arbitrary traceback, token, SQL text or backend identity is
admitted as diagnostic evidence.

The late window retains the maximum of final attempt+2s, observed outcome+2s and
last successful flush+15s+2s. Handler completion is not substituted for joining
the server. On failure, cleanup first rolls back/closes the owned lock, then
attempts barrier cancellation, worker reaping, handler joining and connection
disposal while preserving the original failure. Unlocking during failure cleanup
may permit pending writes and is not counted as successful stability evidence.

The registered ordinary reference gate and ignored capture share
`lease_expiry_raw_published_reports`, preserving both raw reports and requiring
each case's exact-owned cleanup. The ordinary gate compares bytes directly with
the frozen corpus and writes no output file; CI requires its registered name.
The ordinary gate passed locally in 113.12s. Neither registration nor this
published-reference regeneration is a native parity result.

The ignored `capture_worker_lease_expiry_published_process` requires
`MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1` and an explicit new absolute
`MARTY_CANVAS_LEASE_EXPIRY_CAPTURE_FILE`. It creates the output only after both
case observations and exact-owned cleanup pass. `create_new` refuses overwrite;
a subsequent write/sync failure may leave a partial new file, which is failed
evidence and must never be frozen.

Before A, 132 synthetic controls and 52 existing controls passed, along with
compilation and strict Clippy. Those checks validate fixture mechanics and do
not independently establish actual expiry or native behavior.

Separately, historical application-repair head `2d864723f` completed
[CI34200316184](https://github.com/ElevenID/marty-ui/actions/runs/34200316184)
successfully. Runtime job `101977399347` passed 146 configured published-schema
tests in 3379.26s and four worker/PostgreSQL tests in 98.32s. All four actual
header-timeout HTTPS cases, seven mixed-roster stages with 55 actual HTTPS
requests, and 104 operation-timeout/TLS cases passed. This qualification belongs
to `2d864723f`: it does **not** qualify the new expiry capture, the integrated
`4fbe9fdcb` candidate, or its still-unqualified native BODY replay.

## Remaining work

- Complete current-head hosted CI; full local validation passed as recorded above.
  Exact-byte registration, A/B equality, ordinary regeneration (113.12s) and
  exact-owned cleanup are complete;
  neither reference capture is native expiry qualification.
- Execute the actual native worker against the reviewed reference. Native
  `renew_lease` uses a single UPDATE with a `clock_timestamp()` predicate;
  side-effect `lock_current` locks first and then performs a fresh check. That
  source distinction alone does not prove blocked native renewal is stronger:
  the queued-update behavior needs an actual native experiment.
- Preserve explicit gate 4 scope, investigate any unsafe discrepancy, and retain
  fresh-head CI, signing/consumer reconciliation and beta acceptance separately.

No Python cutover, feature deletion, deployment or production change follows
from this reference capture.

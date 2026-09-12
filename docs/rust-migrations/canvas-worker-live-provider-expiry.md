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
The reference-integration checkpoint's local validation passed **2,538 Python tests with three explicit skips in
170.56s**, Rust compilation in **17.83s**, and strict all-target Clippy in
**8.55s**. Integrated head `ca1dcf00b` subsequently failed hosted
[CI34207893818](https://github.com/ElevenID/marty-ui/actions/runs/34207893818)
at BODY controller import because its Python environment lacked SQLAlchemy;
later full suites were skipped. The isolated harness dependency repair at
`53468331f3018b05a0fd8c1c81f7a258b6e0714d` completed with failure in
[CI34210124048](https://github.com/ElevenID/marty-ui/actions/runs/34210124048).
Runtime job `102008916081` passed the isolated setup and header parity (104.99s),
then failed BODY parity in 117.33s: both prompt cases and application progress
passed, but roster progress retried instead of succeeding after its final 24s
chunk. The later mixed/full groups were skipped. This is a separate runtime
read-inactivity mismatch, not another dependency-import failure.
Native BODY and full-worker live-provider expiry behavior remain unqualified.

The first actual Linux native expiry preflight ran at
`3967412b7fbe4627a12f313e9d4a4b8156f14f93` in
[CI34212739731](https://github.com/ElevenID/marty-ui/actions/runs/34212739731),
runtime job `102017341528`. Setup, compilation, actual AGS/NRPS and header parity
(108.69s) passed. Expiry failed in 15.00s because the coordinator exited during
`outcome-observed`, before result publication. Captured output counts alone do
not establish the failing invariant or a runtime cause. Closed diagnostics and
another actual replay are needed. Subsequent BODY/mixed/full groups were skipped;
the reference observations below remain unchanged.

The closed-diagnostic repair preserves all existing runtime, timing and state
checks. It emits only fixed coordinator phases and exact error categories, then
reads bounded complete records after owned cleanup; arbitrary panic/output text
is never copied into the report. Independent review passed. Local verification
passed all 2,648 Python tests with three explicit skips in 170.57s, four Rust
coordinator controls in 0.00s after 9.97s compilation, and strict all-target
Clippy in 5.17s. Both frozen BODY/expiry raw hashes remain unchanged. These
diagnostic tests do not identify the failure cause; a new native replay must.

That replay ran at `ce19e030cc88907e1c19daefdddc16fef4525ad5` in
[CI34214817411](https://github.com/ElevenID/marty-ui/actions/runs/34214817411),
runtime job `102024020884`: header parity passed in 106.41s; expiry failed in
15.14s with closed categories `AwaitRequest,VerifyInitial,LockHeld,FailureRenewalBlocker`.
BODY/mixed/full groups were skipped. Source inspection identifies a harness bug:
expiry added `application_name=canvas-native-expiry-worker`, then the shared
launcher appended `application_name=worker-rest`. SQLx's ordered URL parser uses
the last value, while the observer expected the first. The repository-only
experiment used explicit connection options and bypassed this launcher, so its
passes did not cover this identity composition. The repair uses one worker ID
for launch and observation, retaining exact backend/query/row/fence/timing checks
and adding a regression through the actual SQLx parser. This failure is not
evidence that native lease renewal itself failed; whole-worker parity remains due.

The identity repair passed independent review and three new pure Rust tests
through SQLx's real parser and both frozen cases. Final compilation passed in
7.96s and the three tests in 0.00s; four existing expiry controls also passed.
The targeted Python controller/diagnostic suite passed 82 tests in 0.39s.
Strict all-target Clippy passed in 3.24s after moving the unchanged test module
to the file end. The prior full Python suite at `e93a419a5` passed 2,662 tests
with three explicit skips in 191.74s; the identity follow-up changes Rust harness
support and documentation only. Both raw frozen corpus hashes are unchanged.
These local passes validate the repair composition, not actual provider parity.

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

## Local native repository evidence and replay implementation

The native renewal-lock-wait diagnostic passed **two actual PostgreSQL cases
and five pure controls in 43.35s**. Both early release and crossing original
expiry returned `renewed=true`; the crossing case observed actual original
expiry, then a current advanced lease after release. Exact job, owner, generation
and target identity checks passed, and the owned fixture was verified removed.
See `canvas_worker_renewal_lock_wait.rs`. This is actual native repository
behavior, **not a full-worker HTTPS replay**.

The result closes the source-only question about whether this single blocked
UPDATE can revive a lease. It does not establish provider effects, worker
recovery or complete reference parity. The stronger side-effect `lock_current`
path still locks first and performs a fresh check; no runtime fence was weakened.

The reviewed native coordinator and HTTPS controller are implemented and
registered as `worker_lease_expiry_matches_frozen_published_process` and
`worker_lease_expiry_native_child`. They preserve diagnostic idle-leased outcomes,
conservative release brackets, raw state comparison, late-handler stability and
owned cleanup instead of synthesizing success. An early expiry preflight is
integrated ahead of BODY; the full configured suite remains required.
**Actual Linux native expiry replay failed at `3967412b7` before outcome
publication; parity remains unqualified.** See the current evidence above.

Local implementation checks passed compilation in **11.23s**, three new Rust
pure controls in **0.00s**, and strict all-target Clippy in **33.18s**. The complete
LEASE Python suite passed **2,627 tests with three explicit skips in 195.22s**.
This includes the 61 controller controls and early-gate routing checks. The exact
workflow smoke also passed under the separate three-dependency Python environment,
loading six BODY and two expiry inputs without running either reference worker.

## Remaining work

- Repair the observed roster mismatch and complete fresh-head hosted CI.
  Exact-byte registration, A/B equality, ordinary regeneration (113.12s) and
  exact-owned cleanup are complete;
  neither reference capture is native expiry qualification.
- Execute the registered actual native worker replay against the reviewed
  reference. The local repository experiment above does not substitute for
  provider-pending expiry, full effects, recovery and shutdown parity.
- Preserve explicit gate 4 scope, investigate any unsafe discrepancy, and retain
  fresh-head CI, signing/consumer reconciliation and beta acceptance separately.

No Python cutover, feature deletion, deployment or production change follows
from this reference capture.

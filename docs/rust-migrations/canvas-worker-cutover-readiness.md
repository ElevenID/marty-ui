# Canvas worker cutover readiness — 2026-09-08

Latest local integration `1cce2d3c4` includes qualified gateway authentication
parity from `42ae6825f`: 41 native forwards, zero legacy, eleven pure controls
and the actual-process lifecycle regression passed. Base coverage is 39
represented names with seven remaining; lifecycle still has 13 full cases remaining.
Earlier `9a292d9cd` passed 2,924 root tests (three skips) and 118 service tests.
Subsequent unused webhook-helper retirement transferred both Python tests to
Rust: six native auth tests, 13 ownership/composition tests and all 116 retained
service tests passed. Its implementation/test inputs match the reviewed
retirement commit; the gateway helper matches its separately qualified commit.
Unused Python bootstrap helpers and unused Python-job database provisioning
are also removed with retained coverage. Hosted qualification is separate.
Credentials v0.1.73 preparation passed, but release tests fail against the old
Core dependency. Current Core's KMS-only DIDComm compatibility must be resolved
before a new immutable dependency/release can be selected; see the roadmap.

Current checkpoint: `afc8bd754` passed complete CI `34223397680`, including
169 configured published-schema tests (two explicit captures ignored) and
11 worker/PostgreSQL tests (two manual diagnostics ignored). Those ignored
paths are not parity gates. The newer `d498` CI `34233064711` runtime job
`102083828642` failed: all four preflights passed, but the full published suite
had 170 passes and one lease-expiry failure (two explicit captures ignored).
The late-response window observed leased/no terminal status and ended with
`FailureUnknown`; the exact cause is not yet established. Closed diagnostic
categories are being qualified without changing parity/timing gates. The
parallel Rust/database group, image, browser and UI jobs completed successfully.
Its stale service image assertion is repaired locally in `121b77737`; Rust 2021
formatting is repaired in `cca487a73`. Nine focused tests, 118 service tests and
229 target format checks passed. The separate root `tests/` run passed 2,891
tests but did not collect the service suite. Hosted repair qualification is
pending; the gateway lifecycle now has the local qualification above.
No gateway route cutover, reachable Canvas Python endpoint deletion or
deployment has been performed in this lane; those actions remain gated by the
required evidence. Credentials release preparation has passed after explicit
workflow activation approval; released-image qualification remains pending.
See the [current roadmap snapshot](../CONSOLIDATED_RUST_MIGRATION_ROADMAP.md#current-execution-snapshot--2026-09-08).

Earlier qualified composed checkpoint (historical; later failures and pending
statements below retain their original checkpoint scope):
`2d864723f74831d4338e1686c242b1bad534a4b9`.
[CI34200316184](https://github.com/ElevenID/marty-ui/actions/runs/34200316184)
completed successfully. Runtime job `101977399347` passed **146 configured
published-schema tests in 3379.26s** and **four worker/PostgreSQL tests in 98.32s**.
All four actual header-timeout HTTPS cases, seven mixed-roster stages with
55 actual HTTPS requests, and 104 operation-timeout/TLS cases passed.
Unconfigured test counts are not database qualification evidence.

Head `3e552ccaef5dd4f42f79fe7d41c2cf42b316ffb0` failed
[CI34216248461](https://github.com/ElevenID/marty-ui/actions/runs/34216248461),
runtime job `102028592657`, during expiry `child-done`. Header parity passed.
The early case observed `succeeded`, terminal `succeeded`, renewal true and
original-expiry false, but closed diagnostics reached `VerifyShutdown` followed
by `FailureUnknown`; that partial outcome is not a passing expiry case.
BODY/mixed/full groups were skipped. The follow-up adds distinct closed shutdown
wait, exit-status, post-shutdown state, output and final-parity categories while
retaining all existing gates. Local validation: 274 focused Python tests,
five Rust expiry controls, published-contract compilation (13.27s), and strict
all-target Clippy (1.03s) passed. Actual native replay remains required.

The subsequent head `67ee5c986e29ba81f311346797f37a937e947a8f` failed
[CI34218409667](https://github.com/ElevenID/marty-ui/actions/runs/34218409667),
runtime `102035585094`, with the now-specific `FailureOutput` after successful
shutdown-status and post-shutdown-state checks. The same early-case succeeded/
renewed result was observed; BODY/mixed/full groups were skipped. The new
generated beta-image configuration gate passed in the separate image job.

A bounded, payload-free output classifier now distinguishes the SQLx slow-query
warning signature from authentication material, oversized capture and other
output. This is diagnostic only: all nonempty output still fails the identical
strict gate, including recognized SQLx warnings. Both real owned streams have
regression coverage for classification plus rejection and later private appends.
No logging filter, runtime SQL, frozen outcome or timing gate changes. The actual
log signature remains to be observed; SQLx's default slow warning is only a
source-derived hypothesis until then.

That follow-up ran at `4b26aacb13e76736c97508c5b4c907dc642acbd5` in
[CI34220548320](https://github.com/ElevenID/marty-ui/actions/runs/34220548320).
Runtime `102042435358` failed with `OutputSqlxSlowQueries,FailureOutput` after the
same successful early renewal and shutdown checks. The hypothesis is now backed
by the actual worker's bounded log signature, not just a library-default guess.
The scoped repair configures only SQLx slow-statement severity to DEBUG, keeping
the one-second threshold, normal DEBUG statements, operator logging filters,
operational warnings/errors, connection settings and cleanup hooks unchanged.
It does not redact SQL at DEBUG or accept nonempty output in parity tests.

An actual PostgreSQL test uses the production connection options: stock SQLx
emits the slow warning at WARN; the repair keeps SQL quiet at WARN while retaining
explicit operational WARN/ERROR events; DEBUG retains both ordinary and slow
query events and the original threshold. It passed in 6.88s after a clean package
rebuild in 44.24s. All seven worker controls passed, including unchanged 16-case
published logging thresholds and Rust-directive precedence; strict all-target
Clippy passed in 26.09s and 66 affected Python controls in 1.89s. The configured
SQL logging test is mandatory. Actual full-worker expiry/BODY rerun remains due.

The newer integrated `4fbe9fdcb` candidate and subsequent reference registration
still require fresh-head hosted qualification; native BODY and actual native
live-provider lease-expiry behavior remain unqualified. The gate audit begun at
`a897c18d3` retains named historical qualifications below. Its new gate 6/7
composed regression passed the complete four-entry configured PostgreSQL suite
locally on Windows in 94.81s, including the 21-value-class, empty-result and
orphan marker. Mandatory Linux signal cases and fresh-head CI remain pending.
No whole-worker cutover, Python deletion or deployment is approved by this audit.

The [live-provider expiry reference](canvas-worker-live-provider-expiry.md)
passed independent A/B captures in 113.34s and 112.78s: identical 19,575 bytes,
SHA256 `455494bc6be253a73747116734c418c9c13e41d13eac09a1c31f721e5d44499d`.
The corpus is frozen and its registered ordinary regeneration passed locally in
113.12s with exact-byte equality; all four fixture IDs were verified absent.
The reference-integration checkpoint's local validation passed 2,538 Python tests with three explicit skips in
170.56s, Rust compilation in 17.83s and strict all-target Clippy in 8.55s.
Integrated head `ca1dcf00b` failed
[CI34207893818](https://github.com/ElevenID/marty-ui/actions/runs/34207893818)
before native BODY replay: SQLAlchemy was missing in the Rust job's Python
environment. Header parity passed in 107.46s; BODY setup failed in 3.80s and
mixed/full suites were skipped. The isolated harness dependency setup repair
does not change runtime or frozen inputs. Head
`53468331f3018b05a0fd8c1c81f7a258b6e0714d` completed with failure in
[CI34210124048](https://github.com/ElevenID/marty-ui/actions/runs/34210124048):
runtime job `102008916081` passed setup and header parity (104.99s), then failed
BODY parity in 117.33s. Application/roster prompt and application progress passed;
roster progress retried instead of succeeding after its final 24s chunk.
Mixed/full groups were skipped. A scoped roster read-inactivity repair and
fresh-head native BODY/expiry qualification remain required.

The candidate roster repair now selects shared 20s operation/read-inactivity
transport with one validated prepared DNS pin. Application 15s and unscoped,
LTI, OAuth and signing policies remain unchanged. Independent review passed;
local checks passed 362 issuance library tests in 15.89s, strict all-target
Clippy in 24.50s and all 104 actual TLS transport cases. The worker contract
executable compiled in 38.55s. Fresh-head worker BODY/expiry parity remains
unproven; these are not deployment acceptance gates.

The new local native repository lock-wait diagnostic passed two actual
PostgreSQL cases and five pure controls in 43.35s. Both early and expiry-crossing
renewal returned true; the crossing case proved original expiry followed by a
current lease. Exact identity checks passed and the owned fixture was verified
removed. This answers the
repository lock-wait question, not full-worker provider/effect/recovery parity.
The native expiry coordinator/controller are reviewed and registered. Their first
actual Linux run at `3967412b7` failed as recorded below. Local compilation passed in 11.23s, three new Rust
pure controls in 0.00s and strict all-target Clippy in 33.18s. The complete LEASE
Python suite passed 2,627 tests with three explicit skips in 195.22s. Its exact
isolated workflow import smoke passed for six BODY and two expiry cases.

At pushed head `3967412b7fbe4627a12f313e9d4a4b8156f14f93`,
[CI34212739731](https://github.com/ElevenID/marty-ui/actions/runs/34212739731)
runtime job `102017341528` passed dependency setup, compilation, actual AGS/NRPS
and header-timeout parity (108.69s). Native expiry preflight failed in 15.00s:
the coordinator exited during `outcome-observed`, before publishing its result.
Only output byte counts were exposed, so this does not yet identify a runtime
or harness invariant failure. BODY, mixed and full database groups were skipped.
Closed diagnostic classification and a new actual replay are required; no
frozen expectation or runtime fence is relaxed to accommodate this failure.

The reviewed closed-diagnostic repair passed 2,648 Python tests with three
explicit skips in 170.57s, four Rust coordinator controls in 0.00s (9.97s
compilation), and strict all-target Clippy in 5.17s. It changes neither the
frozen raw corpora nor any timing/state gate. Actual native replay remains due.

The subsequent `ce19e030c` replay in
[CI34214817411](https://github.com/ElevenID/marty-ui/actions/runs/34214817411)
passed header parity in 106.41s but failed expiry in 15.14s with
`FailureRenewalBlocker`. The observer expected a database application name that
the shared launcher overwrote. This is a harness identity-composition bug, not
proof of failed renewal. A single-identity repair and actual native rerun are
required; preserve exact backend/query/fence checks and all frozen expectations.

Local identity-repair validation passed independent review, three new SQLx/frozen
identity controls plus four existing expiry controls, 82 Python regressions
(0.39s), and strict all-target Clippy (3.24s). Final Rust compilation took 7.96s.
The full Python suite passed 2,662 tests with three skips at `e93a419a5` before
this Rust-only follow-up. Actual native provider replay remains the open gate.
The early expiry preflight is integrated; the full configured suite remains required.
Neither published nor native repository renewal revival authorizes weakening
the stronger fresh-lock side-effect fences. PR #814 remains draft and
unrouted; the successful historical run does not close the remaining gates.

Earlier unqualified candidate `cf5182ef73678b5e0d47cacf23c1f5b38150cd5d` failed
native timeout preflight in
[CI34197335937](https://github.com/ElevenID/marty-ui/actions/runs/34197335937),
runtime job `101967919625`. The prompt application case passed; the delayed case
observed `TerminalSucceeded` instead of the required retry, with job, fact,
snapshot and target differences. This supersedes the earlier byte-count-only
failure at `7ca035d03`. Roster cases and the later full configured suite were
not reached. At that historical head, Rust Service Tests and CI Gate failed.

The narrow application REST repair compiled in 65s before integration; after the additional malformed-header regression and test-spy
type alias, final unit execution passed 354 tests in 15.73s (8.94s compilation).
Strict all-target Clippy passed in 21.75s, followed by the successful `2d864723f`
hosted run above. Application/issued-drift
scope selects the shared 15s operation transport; roster, LTI and signing paths
remain unchanged, and roster inactivity remains unqualified. The scoped `f0`
checkpoint below is unchanged. The worker remains unrouted; no frozen outcome,
Python deletion or deployment changed.

Historical qualified deadline/composition checkpoint:
`f0b60073093a89567e43a6fd6452100b2ddc67ec`.
[CI34189450698](https://github.com/ElevenID/marty-ui/actions/runs/34189450698)
completed successfully; all required checks passed, including Rust CodeQL.
Runtime job `101944349432` passed **137 configured published-schema tests in
3639.20s** at `2026-09-08T06:21:43Z`, plus **four configured worker/PostgreSQL
tests in 96.32s**. Ignore unconfigured counts as qualification evidence.

Both actual native deadline cases (`early_release`, `deadline_cancel`) passed,
each with three real HTTPS requests. Fresh deadline and four-case timeout
published-reference comparisons passed, and the seven-stage mixed-roster replay
retained 55 actual HTTPS requests. Release checks passed 1,694 tests with one
existing skip, including both Linux coordinator/grandchild containment cases;
Rust Images and Rust CodeQL succeeded.

The scoped provider-I/O deadline, real-renewal and retained-prefix replay now has
hosted qualification. It does not close all lifecycle/provider/consumer gates,
real-provider lease expiry, signing or beta acceptance. The later native timeout
work (`395cab656` and its later follow-ups) and separate body-reference branch
`c5e77f260` are not qualified by `f0`; the later native timeout failure and repair
gates are recorded above. Body-reference A-v2 and independent B-v2 passed all six
cases in 265.68s and 266.63s at `ffb515200c4611bbaa188d84c510074bb4a98c81`.
Their 46,042 raw bytes agree exactly: SHA256
`e97d7fee361a11d4245876b725c8ac417045254d766693f772da53409c9b50eb`.
Exact-owned cleanup passed. Permanent corpus registration and all-six raw
regeneration passed in 263.15s at `c092509c7`; native body replay is implemented
and independently reviewed locally, with 2,365 Python tests / three explicit
skips, ten shared coordinator controls, 354 library tests and strict Clippy
passing. Actual Linux body replay is pending. Reference or synthetic evidence
does not establish native body parity.
PR #814 remains draft and unrouted. No Python feature deletion, deployment or
restore occurred.

## Historical 121-entry checkpoint

Previously qualified composed checkpoint
`9cbba6b7bc687614e8c2d74ef78fab532e5888fb`: CI `34109922914` and Rust CodeQL
`34109922824` succeeded. Runtime job `101703569433` passed **121 configured
published-schema tests in 3319.49s**, and four configured worker/PostgreSQL
tests in 96.40s. Exclude its unconfigured 121-test/0.34s and 4-test/0.01s results
from database qualification.

The mixed-roster early preflight passed seven stages and 55 actual HTTPS
requests in 365.39s. The full configured suite repeated native replay and fresh
published regeneration. Every stage's complete Canvas, token-scope, signer
request and signer-operation ledger matched the frozen arrays: totals
55/13/26/26. Stage 0 now matches 10/2/4/4, correcting the prior 12/4/8/8 failure
without changing the reference. These are enforced array counts, not individually
printed passing payloads. Synthetic signing does not qualify remote cryptography.

Image job `101703569310` passed all builds, nine worker preflight cases,
24 packaged startup cases and the 16-case published logging reference. It also
passed the 17-service bundle, 21 synthetic rollback merges and 15 complete
consumer-source compositions. The compiler-consumed examples remain packaged
and compiled. At that checkpoint the later deadline/timeout extensions were unqualified;
remaining whole-worker, loader/consumer, signing and beta acceptance gates stay
open. PR #814 remains draft and unrouted; no Python features were removed and no
deployment or restore occurred.

## Historical checkpoint evidence

Previously qualified composed checkpoint `6914387e563d1043948aaea7a5cc514be6055038`:
115 configured runtime tests passed in 2444.37s (CI34089906961,
runtime101641133956), with four configured worker/PostgreSQL entries in 95.63s.
The configured result is logged at `2026-09-07T07:01:57.0655556Z`; ignore the
earlier unconfigured 115-test result in 0.36s. All applicable exact-head checks
passed, including Rust CodeQL34089906881 and image101641134087 (nine preflight,
24 packaged startup and 16 logging-reference cases). Both native resource-race
markers (`platform_reconfigured`, `application_removed`) made one HTTPS request;
the post-validation resources-unavailable marker made zero. All five native
roster markers remain (0, 0, 1, 1, 1 requests), as does one-HTTPS recovery-first.

Latest attempt `f8670830b` is **not qualified**: CI `34104771356` failed its new
early mixed-roster preflight in 25.79s (job `101687206847`). Stage-0 metadata
assertions now pass, but transport parity fails: 12 requests versus 10, four
token exchanges versus two, and eight synthetic signer requests/operations
versus four. Fixture failure count is zero. The full configured suite was not
run after this early failure. A reviewed per-run token-reuse repair passed
local tests; no frozen expectation is weakened.

The token-session repair passed 347 issuance unit tests, including eight new
session/isolation/error/cancellation regressions, and strict all-target Clippy.
All five relocated compiler examples passed. These tests do not replace the
seven-stage native HTTPS replay or establish full-worker qualification.

Exact clean-worktree repair checkpoint `30292f4b8` passed 1,390 Python tests
with one existing skip in 113.98s, 347 Rust issuance unit tests in 16.49s and
five documentation tests in 0.41s. Independent review also repaired two gate
gaps: compiler-consumed Markdown now triggers Rust checks, and unsupported
release Compose array expressions fail validation instead of disappearing from
the tested model. The focused gate suite passed 156 tests in 5.03s; all 15 real
Linux consumer-source renders passed after hardening. Fresh exact-head CI remains.

Image job `101687206897` passed both configuration gates, then failed because
compiler-consumed documentation was under the intentionally excluded integration
test directory. The unchanged five compiler examples now live in the packaged
source tree. Fresh image qualification remains required.

Earlier attempted checkpoint `8e7f66d46` is **not qualified**: CI `34098106567`
finished with 118 configured published-schema tests passing and one failing in
2761.77s (runtime job `101666175141`). The mixed-roster native replay failed at
stage 0, `tail_positive_wrap`: persisted `worker_id` was `worker-rest`, while the
frozen published target expected null. The reference regeneration and controlled
transaction effect-expiry controls passed. Transport-count drift was not observed
in that earlier run; the target assertion stopped the child before ledger
comparison. The newer preflight supplies that evidence above.
The narrow pending repair reconciles only pre-touch heartbeat metadata, retaining
current unrelated fields and generation/lease fences. Exact-head Linux replay
and complete checks remain required. An early mixed-roster CI preflight now
supplements, rather than replaces, the mandatory full configured suite.

Earlier repair-batch verification: 1,331 Python tests passed with one existing skip
in 134.91s; 339 issuance unit tests passed in 27.63s; strict all-target issuance
Clippy passed. Ten configured metadata database cases passed in 104.27s. Both
Compose versions independently passed 21 config-only rollback merges. The 121
registered schema entries are not 121 hosted qualified passes. No worker routing,
Python deletion, deployment, restore or cryptographic implementation change
occurred in this repair batch.

The preceding `5dde6b69adbca467d7fefaa1b43bc2b77ac4aa19` roster checkpoint passed
109 configured tests in 2361.53s and four worker/PostgreSQL tests in 96.28s
(CI34085691302). Those historical results are retained, not substituted for
the current resource composition. Later local effect-expiry and mixed-roster
work is not qualified by the 115-entry head or by increased test registration.

The prior qualified checkpoint `c3e51a4d58083625aabd50de7fba37ef1ff53d4e` had
107 configured runtime tests passed in 2327.12s (CI34082559053, runtime101620519590).
All applicable exact-head checks passed, including Rust CodeQL34082559034. Image
job101620519633 passed nine preflight, 24 packaged startup and 16 logging-reference
cases. The separate configured PostgreSQL worker contract passed four entries in
96.94s. All 39 native
OAuth process/cycle markers were inspected: the prior33 plus six zero-request
secret-resolution cases. Real schema rejections, the native empty-token regression,
and both repository comparisons passed. Actual newer-target recovery also passed
with one HTTPS request and Rust's stronger complete-row generation preservation.
Both final-attempt repository race winners, actual completion-first process
atomicity and recovery-first process fencing now pass, including the exact
one-HTTPS-request native markers. Earlier
validation, privacy and startup boundaries remain retained. This qualifies those
scoped boundaries, including recovery-first and the LOG_LEVEL/image-default
repair, not whole-worker cutover.
Earlier worker gates
are retained. PR #814 remains draft and
unrouted. This is a source/test/consumer inventory, not a
whole-worker acceptance result. No deployment or Python deletion is authorized
by this inventory. The normative requirements remain
[`issuance-canvas-sync-worker.json`](../../contracts/issuance-canvas-sync-worker.json).

The [roster-failure extension](canvas-worker-roster-failures.md) adds five
published process captures and narrow Rust parity repairs, now qualified by the
109-entry Linux run and retained in the 115-entry composition. Four more
normative processor codes have actual-process evidence. The frozen HTTP 503
outcome is an additional generic worker error, not the
singular authoritative-read processor error or another normative processor code.

The subsequent [resource-race extension](canvas-worker-resource-races.md) freezes
two real published-worker outcomes: platform reconfiguration and application
removal during a held provider read. It adds a shared native replay and narrow
Rust error-classification repairs while retaining lease, row-lock and update
guards. Both cases now have actual native Linux process qualification at the
115-entry checkpoint; their two codes leave the remaining inventory on that
evidence, not on reference or repository tests alone.

The [resources-unavailable reference](canvas-worker-resources-unavailable.md)
captures the last previously unqualified composed outcome after completed
validation and before resource reload. Independent published regeneration and
the zero-request native process replay passed in the 115-entry run. The
seventeen-code inventory now has fourteen actual-process outcomes, one
controlled signing guard and two open typed-dispatch reconciliations. An empty
remaining-composed list does not close gate 9 or any broader effect/consumer gate.

## What the latest evidence does and does not prove

The JSON-depth implementation passed all 36 configured published-image/schema
tests locally, plus 325 library, 5 binary, 34 managed HTTP, 22 issuance behavior,
102 affected Python and 104 native TLS cases. Native depth replay covers 64
provider, 64 validation and 192 credential-route observations, with 32 additional
follow-up operations. These qualify their recorded boundaries, not worker boot,
complete provider combinations, deployment consumers or runtime acceptance.

The source inspection exposes a composition gap between existing suites:

- `tests/support/canvas_published_processor.rs` uses the real published schema,
  repositories and native processor, but controls `CanvasAuthoritativeProvider`.
  Its helper leases and validates a job and calls the processor and outcome
  repository directly; it does not call `CanvasSyncWorker::run_cycle`.
- `tests/support/canvas_worker_lifecycle_oracle.rs` and
  `canvas_worker_renewal_job_outcomes.rs` execute real worker cycles and durable
  outcomes, but use controlled processors and the worker test schema.
- `tests/support/canvas_authoritative_http.rs` and
  `canvas_authoritative_https.rs` exercise real provider transport, but reuse
  in-memory OAuth repositories and synthetic signing fixtures.
- `tests/support/canvas_worker_process_signals.rs` launches the actual binary
  with PostgreSQL. Its idle/blocked-queue cases do not establish active
  authoritative-provider shutdown or host-crash recovery.

None of these tests should be discarded or recaptured merely to obtain a
whole-worker pass. Reuse their owners and add the missing composed execution.

The [composed REST reference](canvas-worker-rest-reference.md) now independently
executes four nonempty published worker processes with real HTTPS, encrypted
OAuth storage and the official schema. Positive, negative, duplicate and
rate-limited outcomes are frozen twice. Native composed-worker replay is now
implemented using the real binary and native persistence; its mandatory Linux
execution passed at `0982a4a2c` (CI 34033818678, Rust 34033818668). That qualifies the
four assignment stages, not every worker/provider/consumer boundary.

The [all-four-fact reference](canvas-worker-facts-reference.md) extends the same
actual published-process harness across assignment, quiz, module and course
reads, including partial rate limiting. Two independent captures agree; native
adoption passed on Linux at `6977a70ba` (CI 34034992317, Rust 34034992376).
That qualifies these four fact projections for gate 12; broader worker/consumer
requirements and fresh exact-head checks for later extensions remain required.

## Normative legacy-gap reconciliation

The [validation/failure reference](canvas-worker-validation.md) captures twenty
actual published-worker cases with identical independent results. It covers
nine terminal codes (including five inactive variants), no Canvas reads and
preserved issued rows/token ciphertext. Native replay is implemented; focused
published-schema tests demonstrated and verified the shared Rust error-summary
correction. The two previously uncovered invalid-reference paths now have actual
published-process removal races, with matching independent captures and native
replay implemented through the shared database barrier. Four further cases cover
invalid requirements, missing LTI identity, unsupported candidate processing and
template removal after application read. Three roster-setting cases additionally
freeze job-local configuration errors and non-roster continuation; the native
binary's eager integer parsing has been replaced by deferred, lossless bounded
configuration in the shared processor. The twelve processor outcomes outside
this corpus are tracked separately. All twenty cases passed actual native Linux
replay at `f195ad484`, each with zero requests, including the three roster cases.
The latest cross-corpus accounting above supersedes that original partial
coverage: fourteen processor codes now have qualified process evidence. Gate 9
remains open for its two typed-dispatch reconciliations and broader requirements.

The existing PostgreSQL worker contract now also exercises the normative
no-signing guard through real `run_cycle` calls and durable repositories, using
the existing observed-worker owner with a controlled typed processor. All four
forbidden fields are checked independently with null, false, zero, empty string,
synthetic string, object and array values (28 failures), alongside two successful
controls. Assertions cover exact terminal code/static summary, attempt-one
dead-letter, empty persisted result, lease release, disabled target, no success
timestamp, successful sibling sanitization and no next-cycle retry. All three
configured PostgreSQL contract tests passed locally in 92.93 seconds; strict
all-target Clippy passed. The loopback-only tmpfs database was removed afterward.
The configured Linux PostgreSQL worker group subsequently passed all three
entries in 94.99 seconds at `f195ad484` (runtime job101550215184).
This is native boundary regression coverage, not published-process parity or
proof of signing-service effects/log privacy. No runtime or contract change was
needed for this guard; whole-worker gate 9 remains open.

The [Retry-After deadline reference](canvas-worker-retry-after.md) freezes seven
actual published-worker scheduling cases, including HTTP dates and oversized
integer clamping. Two captures agree; native replay is implemented. Focused Rust
tests confirmed overflow fallback and the shared lossless parser correction
passes local tests, including actual HTTP provider transport. Correction
`a6826de39` passed all 67 configured Linux tests in 1264.77 seconds, including
all seven actual native HTTPS/deadline cases (runtime job101535819282).
Image job101535819407 passed eight preflight and 24 startup cases; CI34051487770
and Rust CodeQL34051487785 succeeded. This qualifies the frozen scheduling
boundary, not remote OAuth, every header grammar or the whole-worker cutover.

The [retry/rejection reference](canvas-worker-retry-reference.md) adds actual
same-job retry eligibility, recovery and provider failure/OAuth rejection
observations for gates 6/8. Native adoption passed Linux CI at `32ec09029`
(CI34036161060, Rust34036161086), including five actual native HTTPS stages;
remote OAuth revocation,
all error/header variants and race/privacy requirements remain separate gates.

The [active-provider signal reference](canvas-worker-provider-signals.md) now
independently captures SIGINT/SIGTERM/SIGKILL with the real HTTPS response held.
Native SIGINT, graceful SIGTERM and SIGKILL passed configured Linux CI at
`499298659` (CI34038852781, Rust34038852821). Renewal and nonfinal crash/restart
qualification are recorded below; disposal remains open and cannot be inferred
from raw process exit.

The [provider renewal/recovery reference](canvas-worker-provider-recovery.md)
independently records actual lease/heartbeat renewal, then success or forced
process loss followed by real expiry/retry and same-job completion. Two capture
pairs agree and regeneration passes locally. Native replay passed at `d96a45ebe`
(CI34039828427, Rust34039828424; 52 configured tests in 839.16 seconds). Final-attempt recovery,
concurrent scheduler/reclaimer and ownership/generation fences remain separate.

The [concurrent scheduler reference](canvas-worker-concurrent.md) now has two
matching captures. PostgreSQL observes two actual worker scheduler queries
blocked at the owned fixture barrier; after release, one job/request succeeds
while both processes remain alive. Native replay passed at `a329b980e`
(CI34042598584, Rust34042598554; 59 configured tests in 948.70 seconds).
Other reclaimer/changed-target races remain separate; this does not close all of gate 5.

Numbers below preserve the order of all 14 `migration_gates.legacy_oracle_gaps`.
The [retryable two-reclaimer reference](canvas-worker-reclaimers-retry.md) has two
matching captures: both workers reach fresh idle with one durable retry and no
early read, then real eligibility permits same-job attempt-two success with the
target enabled. Native replay passed at `507b0def6` (CI34045421238,
Rust34045421228): 65 configured tests in 1182.10 seconds, with two actual provider
requests for this case. Remaining race requirements stay open.

The [two-reclaimer reference](canvas-worker-reclaimers.md) has two matching
captures after actual final-attempt renewal, process loss and real lease expiry.
Both actual job queries wait at an owned job-table barrier before release; both
workers then reach fresh idle with one dead-letter and no further provider read.
Native adoption passed at `54692c4e4` (CI34043971766, Rust34043971750), including
all 62 configured tests in 1038.42 seconds and the actual one-request reclaimer
case with both fresh idle heartbeat assertions. Other ownership,
nonfinal-reclaimer and final-completion races remain open.

The [final-attempt crash reference](canvas-worker-provider-final.md) now has two
matching independent captures and a mandatory regeneration gate. It seeds
historical attempts before worker startup, then observes actual attempt-eight
renewal, crash, real expiry and dead-letter/target-disable without another read.
Native final-attempt replay passed with exact generation-fence checks at
`e959e113d` (CI34041341592, Rust34041341506; 56 configured tests in 841.38 seconds).
Final-attempt and retryable concurrent reclaimers are qualified above;
Newer-target recovery after final-attempt crash is now implemented in the
[generation reference](canvas-worker-provider-generation.md), qualified at df3ed290b.
The subsequent final-attempt completion/recovery milestones are recorded below.

The [final completion/recovery repository boundary](canvas-worker-final-completion-race.md)
now executes both lock winners on the published schema with real expiry, observed
job/target locks and full-row preservation after every stale call. Local checks
pass; both directions are now qualified at 29bf8c226 in the 103-entry run above.
This alone does not close gate five.

The [actual completion-first process reference](canvas-worker-provider-completion.md)
now captures a terminal-write barrier, real expiry and the distinct reclaimer's
transitive lock chain. Independent regeneration agrees. The old process disables
the target despite one successful terminal job update; native replay explicitly
requires its stronger atomic completion behavior. The 103-entry extension is now
qualified on Linux at 29bf8c226. The [recovery-first process extension](canvas-worker-provider-recovery-first.md)
now has an actual capture and independent matching regeneration. Its native replay
requires fresh-clock rejection of stale completion while recovery owns the row,
one dead-letter terminal journal and preservation of valid pre-expiry provider
effects. This 107-entry extension is now qualified on Linux at c3e51a4d5, including
the actual one-request recovery_first marker. Expiry during
in-flight provider effects remains separate.

"Covered boundary" is deliberately narrower than "deletion gate closed".

Gate accounting below was reconciled against the configured section of
[runtime job 101703569433](https://github.com/ElevenID/marty-ui/actions/runs/34109922914/job/101703569433)
at `9cbba6b7b`: dispatch finished successfully at 11:17:54 UTC on September 7,
followed by both the valid-lease and real-expiry rollback controls; the mixed
worker replay recorded seven stages and 55 HTTPS requests. These scoped passes
do not substitute for the newer deadline/timeout or consumer cutover gates.

The following table tracks the exact fourteen normative boundaries, not an
unbounded requirement to repeat every failure through every provider. Historical
qualification is not a fresh-head pass. Controlled adapters, published-process
references, actual native HTTPS and consumer cutover remain distinct evidence.

| Gate | Inspected evidence | Remaining qualification or action |
| --- | --- | --- |
| 1. Environment parsing, bounds, malformed startup | Historically qualified: 133 configuration vectors, actual `worker_startup_matches_published_process_and_idle_heartbeat`, PostgreSQL consumer cycles and [LOG_LEVEL repair](canvas-worker-logging-configuration.md) with 16 frozen threshold cases and seven invalid-process checks; combined runtime/image qualification at `c3e51a4d5` | Fresh exact-head run pending. No additional parser behavior gap identified; deployed secret/entrypoint adoption remains a consumer cutover action, not missing configuration-factory evidence. |
| 2. Legacy processor loader and removal | Retained Credentials `tests/unit/test_canvas_worker_loader_oracle.py`, five published dispatch observations and native typed construction; see [dispatch reconciliation](canvas-worker-dispatch-reconciliation.md) | At qualified cutover, remove active loader selection from every consumer, updating commands/images and operational validators together. Preserve frozen legacy evidence and Python rollback compatibility while supported; do not recreate dynamic imports in Rust. |
| 3. Loop stop, cancellation, recovery, disposal | Historically qualified: `assert_owned_cycle_lifecycle`, `assert_initialized_pool_disposal`, privacy replay's failed-then-recovered actual `run_loop`, and actual-process signals. Both three-HTTPS deadline cases and reference regeneration qualified at `f0b600730` | Fresh exact-head run pending. Named lifecycle boundaries have evidence; controlled-processor awaited disposal is not inferred from process exit. The separate missing live-provider expiry composition is gate 4. |
| 4. Renewal heartbeat and fence loss | `canvas_worker_renewal_oracle.rs`, 60 frozen renewal-job combinations and lease-loss cancellation unit tests; actual provider renewal/recovery and deadline composition qualified at `f0b600730`. [Live-provider expiry reference](canvas-worker-live-provider-expiry.md): independent A/B complete, exact raw corpus frozen, ordinary regeneration passed locally in 113.12s with exact-owned cleanup. Native repository lock-wait diagnostic: two actual PostgreSQL cases and five pure controls passed locally in 43.35s; both cases renewed, including actual expiry followed by a current lease with preserved identities | Actual native provider-pending expiry, effects and recovery remain unqualified. The registered Linux replay failed at `3967412b7` before outcome publication; identify the invariant through closed diagnostics and rerun. Both published cases renewed and succeeded, and the separate native repository experiment also observed revival. Compare full-worker behavior without assuming original expiry prohibits all later writes; preserve fresh-lock side-effect fences and investigate unsafe discrepancies explicitly. Deadline/current-lease tests and repository-only evidence do not close this composition. |
| 5. Scheduler, reclaim, final-attempt crash races | Historically qualified actual-process concurrent scheduler, retryable/final reclaimers, final-attempt crash, newer-target recovery and both terminal-race winners; [recovery-first fencing](canvas-worker-provider-recovery-first.md). [Effect transaction expiry](canvas-worker-effect-expiry.md) and valid-lease control additionally qualified at `9cbba6b7b` | Fresh exact-head run pending. The named scheduler/reclaim/crash requirements have composed evidence; retain them. Controlled-provider effect expiry is not the missing live-provider case in gate 4, nor whole-worker disposal proof. |
| 6. Missing target and unexpected-error privacy | Unexpected runtime/429/503 durable and complete-log projections historically qualified in the twelve-case [privacy replay](canvas-worker-privacy.md) at `b02b77d13562db717d6e16cdf85ff430edbc2eeb`. New `assert_projection_cycles` composes a preseeded orphan and successful siblings through actual `run_cycle`/PostgreSQL | Complete four-entry configured PostgreSQL suite passed locally on Windows in 94.81s with the new marker. Mandatory Linux signal cases and fresh exact-head CI remain pending. The orphan is in the dedicated worker test schema, not a claim of published-schema FK/deletion reachability or actual-provider failure injection. |
| 7. Safe-result types and truncation | `canvas_worker_result_oracle.rs`: 483 JSON field/value cases plus empty/full allowlists. New `assert_projection_cycles` passes all 21 frozen value classes plus an empty control through actual worker persistence and compares raw result lexemes | Complete four-entry configured PostgreSQL suite passed locally on Windows in 94.81s with the new marker; fresh exact-head CI remains pending. Retain exhaustive scalar/projection vectors alongside composed representatives; do not infer non-JSON Python host-value coverage, native-binary parity or Linux signal qualification from this run. |
| 8. Retry-After edges | Historically qualified: seven actual native HTTPS/deadline cases and shared parser correction at `a6826de39`, retained at `29bf8c226`; parser vectors remain | Fresh exact-head run pending for date, malformed, negative, zero, clamp and huge-integer durable scheduling boundaries. No additional named edge gap identified; aggregate acceptance remains separate. |
| 9. Target validation and processor failures | All nine validation codes have qualified actual-process outcomes. [Cross-corpus audit](canvas-worker-processor-coverage.md): fourteen processor codes have process evidence and one has a controlled-processor worker/PG guard. [Typed dispatch proof](canvas-worker-dispatch-reconciliation.md) has five published-worker observations qualified at `9cbba6b7b`; five compiler tests also passed locally | Fresh exact-head dispatch/compiler evidence and all-consumer selector removal at cutover remain, shared with gate 2. Both typed-dispatch codes require the documented reconciliation, not Python import emulation; none of the seventeen codes is waived. Keep the no-signing guard. |
| 10. OAuth revocation failure and owner fences | Historically qualified: 39 native process/cycle observations plus selection/order, schema-rejection and empty-token regressions at `df3ed290b` | Fresh exact-head run pending. Retain the named [coverage audit](canvas-worker-oauth-revocation-coverage-audit.md) boundaries and stronger atomic cleanup; repository/counting-provider controls are not mislabeled as whole-process HTTPS. |
| 11. Cursor and terminal candidate preservation | Historically qualified: twelve-stage direct-processor replay plus [seven-stage published/native worker replay](canvas-worker-mixed-roster.md) at `9cbba6b7b`, with natural scheduling, one idle restart, resume/wrap, terminal preservation and exact mixed REST/AGS/NRPS ledgers | Fresh exact-head run pending; retain both complete corpora and ledgers. The named cursor/candidate boundary is qualified historically, not whole-worker cutover or signing/consumer acceptance. |
| 12. All four fact projections | Historically qualified: actual native worker, HTTPS, encrypted OAuth, official schema and durable effects match the independent assignment/quiz/module/course corpus at `6977a70ba` | Fresh exact-head run pending; retain both complete corpora. Other error/mutation/lifecycle boundaries remain in their named gates, not an unspecified extension of fact projection. |
| 13. Bounded signing error detail | Credentials PR269 landed at protected `d418ac0`; landed PR271 freezes 45 helper and six remote-operation observations, with two identical captures. Isolated Rust helper at `ceb5729a5` passed all 51 message/detail projections in 13 pure tests (0.01s), independent review and strict Clippy (23.02s); see the [privacy audit](canvas-worker-privacy.md) | Concrete gap: production adapter adoption and actual request/decoding/status behavior against all 51 observations. The isolated helper is not production-wired and its 500-character detail limit is neither an input-memory bound nor redaction. Coordinate overlapping crypto ownership before shared-file integration; coordination is pending. Pure projections do not establish remote signing parity. |
| 14. Allowlisted worker logs | Historically qualified: all twelve reference worker observations, actual PostgreSQL cycles/loops, complete producer/formatter output and known-error controls at `b02b77d13562db717d6e16cdf85ff430edbc2eeb`; CI34064588338 completed successfully | Fresh exact-head run pending. This qualifies the named allowlisted worker-log boundary, not every module, production collector, signing diagnostic or aggregate deployment. Preserve explicit mappings and redaction negatives in the [privacy audit](canvas-worker-privacy.md). |

An earlier historical source inspection used the clean local `marty-credentials`
checkout at `28b53d433031fe46b3f0c0c589d91f2c85d22c6e`; that statement does not
describe every later reference above or establish current protected-main state.
Signing diagnostic adoption uses the immutable repaired `d418ac0` source and
blob `5e84cfdcbdf289ec0059eb39dd54c4a5c79c5b3a`, not that earlier checkout.
Each later corpus retains its own recorded provenance. Check reference-source
ownership before changes and preserve the other worker's unrelated work.

The scoped repair [Credentials PR269](https://github.com/ElevenID/marty-credentials/pull/269)
landed at protected `d418ac0df283625f43b0c011fb1c72fd7d3013a9` after review of
`9c03b57e5826b7dce430a05eef91ee68e334d825`. CI34058252789 passed, including
1673 tests and 200 subtests on each of Python 3.11 and 3.12, PostgreSQL, Rust,
bindings, security and WASM gates. Merge-queue CI34058846815 and protected-main
CI34059299079 passed. Exact tree comparison confirmed the landed content before
retiring only the completed branch name; source and evidence remain recoverable.
No immutable earlier oracle was changed.

[Credentials PR271](https://github.com/ElevenID/marty-credentials/pull/271) landed at
`948bca975b493285c512c20a13d5abf8ee5e6305`. It adds
the 63-case hardened reference without changing runtime source. Its existing
tests are the single observation owner; two independent captures agree at SHA256
`2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05`.
Source trees, runtime blobs, test blobs and imported module locations are checked.
Maintainer-review additions bring local affected qualification to 741 tests and
200 subtests, followed by unchanged 63-case regeneration. Exact-head CI34061052204
and protected merge-queue CI34061438212 passed. Post-merge main CI34061898106
also passed. The completed capture branch name was retired only after exact
reviewed/merged tree comparison; source and evidence remain recoverable.

The [native privacy replay](canvas-worker-privacy.md) now compares twelve actual
worker/loop log-state observations through PostgreSQL, including ambient tracing
context. Failure-first tests identified swallowed OAuth queue-read errors and
missing stable event IDs. The disconnect-marker extension preserves real
encrypted-secret cleanup and another tenant's secret while restoring the exact
error event; cleanup behavior already matched. The final six cases use payload-free
unexpected processor categories and preserve known classified error behavior;
they verify all durable outcomes and complete producer/formatter log fields.
The complete corrections qualified at `b02b77d13562db717d6e16cdf85ff430edbc2eeb`
in CI34064588338 without removing the private SQL generation fence. Signing
diagnostic adoption remains a separate concrete gap; the empty remaining composed
processor-code inventory is not consumer cutover approval. Fresh exact-head
hosted checks must retain these scoped privacy boundaries.

Native adoption must not hide source-inspection differences by changing that
artifact: the resolver currently omits diagnostic detail on non-success, while
the signer bounds raw text instead of sharing JSON-detail selection. Worker
error events also need explicit class/severity/event comparison; existing renewal
tests collect selected job/class fields, not the complete log allowlist. These
are inspection findings, not yet native replay failures. Coordinate signing
adapter ownership with the crypto worker before editing overlapping code; keep
Rust's stronger tenant-atomic OAuth cleanup and generation fences intact.

[Credentials issue270](https://github.com/ElevenID/marty-credentials/issues/270)
retains a separate release-qualification discrepancy. Exact checksum-verified
published Windows Core 0.1.60 and 0.1.61 wheels each pass 141 issuance tests but
fail the same three binding-boundary assertions that pass with the CI-built
Core revision. A simple release-pin bump is not sufficient. Require reviewed
canonical Rust release/artifact qualification before aggregate adoption;
neither the global installed package nor another worker's crypto branch changed.

## Deployment consumer inventory

The [source consumer audit](canvas-worker-consumer-audit-2026-09-07.md) additionally
tracks conformance and generated/local image overlays, the eight still-Python
operations, and the cross-runtime rollback launch gap. Image-only restoration
from a current checkout does not prove compatibility with an earlier Python
worker. The discovered rollback repair requires synthetic round-trip tests and
review before any deployment or restore action.

| Consumer | Current source selection | Required cutover proof |
| --- | --- | --- |
| Base Compose | `docker-compose.base.yml`: immutable issuance image, `python -m issuance.canvas_worker`, `CANVAS_SYNC_PROCESSOR` | Native image/command, equivalent configuration and secrets, both migration dependencies, no ports, database heartbeat and restart behavior. |
| Beta overlay | `docker-compose.beta.yml`: only adds worker environment; inherits the base command/image | Render the exact aggregate beta composition and verify native selection; an environment-only overlay is not a cutover. |
| Self-host production definition | `docker-compose.selfhost.prod.yml`: shell secret loader followed by Python, with loader selection | Preserve file-secret and database-template handling, migration ordering and headless health semantics in source. Do not deploy to persistent self-host. |
| Self-host bundle override | `docker-compose.selfhost.bundle.override.yml` inherits the base issuance API, migrations and worker unchanged: immutable Python issuance image and their secret-loader definitions. The incompatible Rust-only-image/Python-command overrides were removed | Mandatory read-only Compose merge gate compares all three complete service models. At qualified cutover, render both image families and explicitly select the worker rather than the API while preserving the secret loader. Current inheritance is not Rust acceptance. |
| Kubernetes | `k8s/oracle/07-microservices.yaml`: Python command/args; `01-configmap.yaml`: loader selection | Native image provenance/command, ConfigMap cleanup, all secret inputs, migration job ordering and termination policy in rendered artifacts. Do not apply to production. |
| Shared Rust image | `services/Dockerfile` and `rust/services/Dockerfile.ci` contain the worker binary; the shared entrypoint now implements explicit worker selection | Qualify the [image launch gate](canvas-worker-image-entrypoint.md) and [24-case packaged startup gate](canvas-worker-image-startup.md), then remaining consumer configuration/secrets, headless health and migration ordering; startup alone does not prove active worker-cycle acceptance. |

Operational consumers must migrate with these definitions: the local beta release
and rollback runner (`scripts/deploy-local-beta-release.ps1`), beta capability and
OSS evidence checkers (`check_canvas_beta_capabilities.py`,
`check_canvas_oss_portability.py`), self-host preflight
(`check-selfhost-production.py`), deployment catalog and Kubernetes image-update
loop. They still rely on Python processor selection and/or issuance/worker image
identity. Preserve their digest, pilot, signer, timeout and key checks while
introducing reviewed runtime selection; changing manifests alone is insufficient.

The self-host bundle repair is source/render evidence, not an inspection of a
deployed release. `scripts/test_canvas_worker_compose_render.py` rejects the old
merged combination and passes the inherited definition, comparing all worker
fields, including secrets, URL template, migration dependencies, headless health
and restart policy. CI now runs this real read-only rendering check before image
builds. It disables interpolation, environment-file and path resolution; it does
not prove resolved secret values, image startup or the exact beta composition.

The follow-up API audit found the same mismatch: the bundle selected the shared
Rust-only image while retaining the API's Python Uvicorn command and OpenBao
startup wrapper. Removing only that image/selector override restores the base
immutable issuance image shared with `issuance-migrations`; it does not route
the unqualified native API. The expanded real Compose renderer failed before
this repair and passed afterward. All 48 focused deployment tests passed
locally, including mutation tests for both complete API/migration definitions.
This preserves existing functionality while API and worker cutover remain open.

The subsequent [shared-image audit](selfhost-bundle-image-audit-2026-09-07.md)
also found a packaging-only omission for `signing-keys`. The local repair selects
the existing shared image and `SERVICE_NAME=signing_keys`; the read-only merged
renderer now derives all seventeen converted services from base build targets
and compares their complete runtime definitions after the intended packaging
changes. The renderer failed on the omission and passed after repair. This is
source/render evidence, not deployed or exact-head hosted qualification, and
changes no cryptographic implementation. Coordinate any signing implementation
work with its existing crypto owner.

The initial local debug-binary diagnostic confirmed a startup obstacle: with
rollout disabled, synthetic keys, no LTI identity and an unavailable loopback
database, the process exits 1 with
`CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID is required`. Both `postgresql://` and
the deployed `postgresql+asyncpg://` URL reach that same error, so the latter
must not be reported as a reproduced URL-parser rejection. These owned children
had cleared environments and no deployment credentials; both exited normally
before the five-second diagnostic deadline. No database cycle was established.

The subsequent [actual-process startup gate](canvas-worker-startup.md) captures
eight independent published observations twice and reproduces the native early
exit before correction. The canonical signer now retains its deferred validation,
and all eight native processes reach matching idle heartbeats on the published
schema, including both deployed URL forms. The shared test-child helper preserves
Windows's standard OS path without inheriting application credentials. Linux CI
also checks SIGINT; Windows is not POSIX evidence. Actual provider/signing and
complete deployed entrypoint/secret-source behavior remain separate gates.

## Next implementation order

1. Retain the qualified eight-case startup/idle boundary; its exact-head hosted
   CI and security checks passed. Broader secret-source/entrypoint configurations remain consumer gates;
   do not repeat the repaired LTI-identity requirement as an open runtime bug.
2. Retain the qualified REST/facts/retry/signal/renewal and nonfinal recovery
   sequences on the pinned migrations with real native provider/OAuth adapters.
   Retain final-attempt, concurrent scheduler, two-final-reclaimer and retryable
   two-reclaimer qualification. Add the explicit live-provider lease-expiry
   composition in gate 4 and retain the locally passed gate 6/7 cycle projections
   in fresh exact-head hosted validation.
   Do not repeat completed boundaries as though native adoption were missing.
3. Retain the qualified worker-log privacy boundary; adopt the remaining Rust
   signing diagnostics against the repaired reference without changing frozen
   expectations. Coordinate overlapping crypto ownership before implementation.
4. Qualify whole readiness/activation and all eight candidate operation routes,
   then switch every intended consumer with executable packaging/configuration
   gates. Require fresh exact-head CI and maintainer review before merging.
5. Satisfy the normative deletion/acceptance ordering, remove only genuinely
   superseded reachable Python, and retain rollback/schema evidence.

The full goal also retains the broader issuance inventory, feature-preserving
branch/worktree cleanup, CSCA lifecycle-manager/monitor follow-up, all demo and
device/wallet evidence, release-pin reconciliation, and aggregate beta-only
acceptance/soak. Production and persistent self-host remain unchanged.

The [local-work inventory](post-wave3-local-work-inventory-2026-09-07.md) records
dirty dependency/wallet work, divergent branches, unregistered demo source and
equivalence candidates. Its cached-ref snapshots are preservation leads, not
authority to delete branches or evidence that all work is merged.

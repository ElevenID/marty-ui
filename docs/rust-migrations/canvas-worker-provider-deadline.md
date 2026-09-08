# Provider I/O and the whole-worker job deadline

This reference slice targets active-I/O cancellation (cutover gate 3) and real
renewal composition (gate 4). It does not close real-provider lease expiry
(gate 5), consumer cutover, signing qualification or beta acceptance.

## Two actual-worker cases

[The scenario matrix](../../contracts/canvas-worker-deadline-scenarios.json)
reuses the existing assignment, quiz and module REST requirements, successful
response bodies, official-schema seed and pre-start queued job. Neither runtime's
HTTP timeout is changed. Both cases configure the supported 30-second job deadline,
30-second lease (renewed normally every ten seconds), and 60-second loop poll.

Each of the first two real responses is held for approximately 11 seconds and
released before 14 seconds, after observing a durable lease renewal. The processor
commits each fact before beginning the next read. Both completed facts and all
effects already committed with them must be retained; a zero-effect cancellation
assertion would discard legitimate existing behavior.

- `early_release`: release the third response promptly, require actual success
  with three facts, and preserve that result after the response window.
- `deadline_cancel`: keep the third response pending and require the actual
  worker's retry outcome `canvas_sync_deadline_exceeded` before that request's
  15-second published HTTP timeout.
  The last observed renewed lease must still be current at that outcome. Release
  the response only afterward, retain every completed-prefix business row and the
  completed job/target state, and reject any extra transport work.

Both keep the same worker alive and idle beyond the third request's larger
20-second native HTTP-timeout window plus two seconds, join the owned HTTPS
handlers, then interrupt only that
owned worker and verify state again. Actual stdout/stderr with `LOG_LEVEL=WARNING`
are observed from owned temporary files before interruption; unexpected output
fails without retaining its payload. The revised preliminary positive capture
passed the two committed-fact and success assertions, but failed on nonempty
output. Two bounded diagnostics identified the exact source-derived warning
profile now explicitly represented below. Token, API-key, HMAC-key, database
password and master-key tripwires remain enforced. This does not qualify all log
levels or shutdown logs.

The [indexed fixture](../../scripts/canvas_worker_deadline_https_fixture.py)
extends the existing HTTPS observer through a small response-wait hook. It does
not replace application callbacks, HTTP clients, clocks or worker methods.
Cleanup releases all indexed barriers before the existing handler join. No live
job, lease, schedule, database clock, credential or production state is edited.

## Evidence limits

Implementation and synthetic fixture tests alone are not published behavior.
Two independent actual published captures must agree before freezing the new
artifact. Native whole-worker replay must subsequently compare the frozen
completed-prefix/outcome projections, exact three-request transport and preservation
predicates. Absolute timestamps and generated IDs remain in local raw-row
comparisons; only established public projections and explicit timing predicates
belong in the language-neutral artifact. No first committed effects are removed
to make comparison pass.

## Discovered timeout difference remains open

The preliminary two-read capture failed its required first-fact assertion and was
not frozen. Exact installed source from the pinned issuance image confirms that
`_synchronize_authoritative_canvas_application` creates a 15-second HTTP client
at `canvas_routes.py:5649`; `_read_canvas_rest_evidence` streams through that same
client at line 5400. Each successful fact is committed inside the requirement
loop at lines 5761–5770, not deferred until all reads finish. Holding the first
response for 15 seconds could race its timeout. The source SHA-256 matches the
existing frozen corpus: `f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943`.

The Rust binary currently configures 20 seconds in
`rust/services/issuance/src/bin/canvas_sync_worker.rs`. That is a separate unresolved
timeout-parity finding. The three-read design avoids changing either timeout;
passing the global job-deadline cases will not close that discrepancy.

An earlier revision passed independent two-case captures A (98.65s)
and B (104.78s) on 2026-09-07. Their 15,350-character raw aggregate JSON strings
are byte-identical, with no additional normalization; both saved files have
SHA-256 `5135d79f3b7ad45085ca9b45808ad6aca6fe504bc7e664570382a84823220fc8`.
Both runs passed completed-prefix, natural renewal, current-lease, exact transport,
late-effect, observed-log and shutdown assertions. The 67 focused fixture/privacy
tests also passed (8.61s). Subsequent independent review found a shared child/log
reader file-offset race and a timing projection that could accept a wrong 25s or
35s deadline. These captures are retained as historical evidence, **not ready to
freeze**. The current revision uses independent log readers, bounded reads and a
separate output directory, plus source-derived job-age and clock-agreement
guards. Revised independent A-v2 (102.79s) and B-v2 (98.95s) now pass both cases.
Their 16,082-character raw aggregate JSON strings are byte-identical, with no
additional normalization. Both saved files have SHA-256
`7031a301007f175119566db866b9c418d8f0d04be86212849d0babdd55efe60e`.
The 190 focused deadline/timeout/process/HTTPS tests passed in 14.89s before
these captures, including actual child-write/observer-seek and cleanup regressions.
The parent independently verified identical hashes and froze the unreserialized
[artifact](../../contracts/canvas-worker-deadline-oracle.json). The permanent
`worker_deadline_reference_matches_published_process` comparison and mandatory
configured CI registration are implemented. Integrated compilation passed in
30.62s, two native timing-boundary tests passed, and strict all-target Clippy
passed in 12.43s. The permanent reference regeneration then rejected database
versus monotonic clock disagreement twice (27.88s and 84.40s); the second run
passed early release before rejecting deadline cancellation. These are invalid
timing observations, not evidence of a specific host cause or a parity pass.
The bounds and frozen artifact remain unchanged. Reviewed narrow numeric
diagnostics are now implemented and independently tested. A third run rejected
the early-release observation in 28.08s: database elapsed time was 21.251852s,
outside the already-tolerance-expanded monotonic interval
21.5929737839906s–22.594262666010763s. This measures the disagreement but does not
establish its host/VM cause. The combined focused suite passed 297 tests in
10.83s; seven native timing/output tests and strict all-target Clippy passed.
The earlier freeze/fixture/CI checks passed 194 tests in 10.56s; the new
driver's 58 focused protocol/privacy/cleanup tests passed in 0.46s. Independent
review subsequently identified an additional forced-coordinator-exit cleanup
gap: direct-child reaping does not establish cleanup of its worker and database.
The repair is now implemented with the ownership boundary below; both actual
Linux process-group cases passed hosted Release checks at `f0b600730`. Native
whole-worker deadline replay is implemented locally but remains
**unqualified** pending actual Linux replay and the full updated suite.
Failed preliminary and diagnostic runs supply neither frozen
behavior nor a parity waiver.

## Native process ownership and local validation

The surviving outer Rust test owns a fresh disposable database for each case.
Its child receives only a closed `{postgres_id, scope}` descriptor, never a
caller-supplied connection string. Read-only Docker inspection verifies the
exact ID, canonical RFC version-4 scope, pinned running PostgreSQL image,
synthetic configuration, exact temporary-storage topology and one loopback
binding before deriving the test URL. The borrower cannot delete resources.
The outer owner verifies both container IDs disappear after cleanup.

The Python controller gives its inner Rust coordinator a dedicated Linux
session/process group. Non-reaping `waitid(WNOWAIT)` keeps the leader identity
reserved until exact parent/session/group checks and group termination, then
the leader is reaped. This covers harness-controlled forced termination and
unexpected inner-coordinator exit while Python survives. It does **not** claim
cleanup after uncatchable termination of Python or the outer runner itself.

The configured `outer_database_owner_survives_forced_borrower_exit` regression
passed in 5.55s: an actual borrowing child was killed, the database remained
usable, and both exact owned resources were removed. Pure descriptor/storage
negative controls also pass. The Windows driver/containment suite passed 97
controls; two real Linux child/grandchild tests remain explicitly skipped there.
Those tests retain an unrelated process and prove both owned reaps, not merely
that processes became zombies. The existing pinned local image has no pytest;
no packages were installed to change that reference image. Hosted Release
checks at `f0b60073093a89567e43a6fd6452100b2ddc67ec` subsequently passed **1,694
tests with one existing skip**, including both real Linux cases. This proves
the stated surviving-controller containment boundary, not whole-worker parity.
Rust Images and Rust CodeQL succeeded at that head. The larger runtime job
in [CI run 34189450698](https://github.com/ElevenID/marty-ui/actions/runs/34189450698)
was still running its isolated phase at 2026-09-08 05:33 UTC; its result remains pending.

The full local Python suite passed 1,691 tests with three explicit skips in
131.91s before the final CI dependency regression was added. All issuance Rust
tests (including 347 unit and five documentation tests) and strict Clippy passed;
the unconfigured 137-entry published-schema run is **not** database qualification.
The release-test CI job now explicitly installs SQLAlchemy for fixture imports.

The separate local commit `c17f1e1fa66af86cbd4392c0921540e1d260ef57` reuses these
owners for the [four-case native timeout replay](canvas-worker-native-timeout-replay.md).
Its local Python suite passed 1,760 tests with three explicit skips in 116.55s,
with compiled Rust controls and strict Clippy also passing. No actual native
timeout replay has run, and no runtime timeout policy or frozen expectation was
changed. Those local checks do not close this deadline qualification gate.

A separate [local clock audit](canvas-worker-local-clock-audit-2026-09-07.md)
reproduced a roughly -0.945s wall-clock step without importing worker code.
Local deadline failures therefore remain invalid timing observations; neither
the fixture tolerance nor frozen results were changed. Hosted Linux is the next
qualification route, not a waiver of the comparison.

The declared timing bounds are fixture tolerances, not a claim of exact timer
precision: initial persisted job age 0–2s, each timing query at most 1s, and the
first observed deadline outcome at job age 29.5–33s. The fresh job's identity,
attempt and `started_at` remain unchanged. Database age deltas must agree with
the monotonic query brackets within 0.5s. Negative controls reject wrong 25s/35s
deadlines, nonfinite/negative ages, exceeded budgets and clock discontinuities;
exact boundary controls pass. No clock is modified, and inconsistent observations
fail instead of widening these tolerances. Actual ages stay in the local check;
the repeatable artifact retains the declared bounds and verified predicates.

## Observed isolated-configuration warnings

Two bounded diagnostic captures identified the nonempty output without retaining
its payload: stdout is empty and stderr contains exactly two WARNING lines.
The second capture matched both complete lines to fixed templates in the exact
installed `/app/services/issuance/infrastructure/api/routes.py` at lines 354 and
356: missing revocation-profile service URL and missing credential-template
service URL, one each. There was no other output, and all synthetic secret
tripwires passed. Source SHA-256:
`2b6d2eb7cec34bb4596ef9b758d8af02a3172337e89bad3b5d26b558d0dd00b7`.
`canvas_routes.py:140` imports that module; these configuration warnings are
expected at WARNING level. The earlier logging-handler hypothesis is unnecessary.

The warnings accurately describe unavailable services in this isolated REST/fact
fixture; they do not qualify revocation or template operations. The reviewed
projection requires empty stdout and exactly one stderr warning in each category,
with no other output. It does not suppress logs, accept generic warnings, or ignore
extra text appended to either known template. The observed artifact also records
the installed warning source's hash. These diagnostic runs are not successful
reference captures and must not become the frozen artifact.

This is an explicit language-reconciliation boundary: the native worker must
validate and report its own actual log privacy/error profile, not manufacture
Python API-import warnings. Native absence of these unrelated configuration
warnings is not evidence that revocation or template functionality is qualified.

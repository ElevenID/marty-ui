# Target-specific Canvas worker timeout capture plan

Initial planning checkpoint: `30292f4b8`. The approved first four controls are
implemented in separate scenario, fixture, runner and test files below, and now
have a twice-captured frozen published reference. This is not a native timeout
repair or deployment qualification. Rust runtime behavior remains unchanged.

The new [runner](../../scripts/run_canvas_worker_timeout_oracle.py) exposes
`run(case_name)` for the four exact [scenario names](../../contracts/canvas-worker-timeout-scenarios.json).
Its [response fixture](../../scripts/canvas_worker_timeout_https_fixture.py)
reuses the shared HTTPS owner. [Focused tests](../../tests/test_canvas_worker_timeout_contract.py)
exercise synthetic contracts and actual loopback TLS, not published-worker parity.
The runner reuses the shared append-writer/independent-reader output owner;
independent file offsets prevent log inspection from overwriting subsequent
child output. Both actual captures passed the exact source-derived log profile.

## Verified published reference

Independent four-case captures passed in 110.30s and 109.39s. Their raw JSON is
byte-identical (14,358 JSON characters plus a newline), SHA-256
`d5c9bbfb30e841a1b695159a2e6ded4e5d13f428f7ca99bded6729d13c262f49`.
The parent froze the [artifact](../../contracts/canvas-worker-timeout-oracle.json)
without numeric reserialization and verified its hash against both captures.
All 16 exact owned capture containers were removed after completion.

The delayed application read retried with the captured authoritative-read error
within the declared 14.5s–16.5s window and before independent 17s release. The
delayed authenticated empty-roster read succeeded; both prompt controls succeeded.
Every case made exactly one GET, preserved the current original lease during
observation, and passed late-state, output and shutdown checks. Successful
roster results contain the four published safe counters, not `roster_remaining`;
the roster save removes pre-touch heartbeat metadata, unlike application results.

The permanent `worker_timeout_reference_matches_published_process` comparison
and mandatory configured CI registration are implemented locally. Its compiled
configured regeneration passed all four cases against the exact frozen artifact
in 115.08s. The combined freeze/fixture/CI checks passed 194
tests in 10.56s. Native timeout replay and the broader provider cases below remain
unqualified; no runtime timeout was changed to obtain these observations.

## Earlier pre-capture verification checkpoint

The extended Rust reference executable compiled successfully in 49.19s; it is
capture plumbing, not native timeout replay. At that earlier checkpoint no
timeout reference had been captured or frozen.

Review added an explicit 14.5s–16.5s application timeout observation window:
retry-before-the-17s-release alone could incorrectly accept a 5s/10s timeout.
These are declared fixture tolerances around the published 15s read limit, not
a runtime SLA or an observed result. Roster controls retain their separate
source behavior. Every case also rejects over-budget outcome observations.
Controller construction/join failures now still close the HTTPS owner.

A local pure-logic selection passed 54 tests with 96 deselected in 0.33s; lint
passed. Subprocess/TLS tests and full captures still require successful reruns:
the broader local attempt encountered filesystem permissions, and account usage
limits interrupted agents/elevated verification. The scenario changed after the
executable build; rebuild before final captures.

The [source audit](canvas-worker-provider-timeout-audit-2026-09-07.md) pins the
reference image and source hashes. Application REST uses a 15s inactivity limit;
background roster REST uses 20s. Current native authoritative transport uses a
20s total request deadline. The first slice isolates the numeric target-specific
boundary, not progress/inactivity semantics, lease expiry or all-provider parity.

## Minimal first matrix: two targets, two response timings

Use four independent fresh published-schema databases, each with exactly one
pre-start queued job and one real worker process. The two prompt controls prevent
a broken application seed or invalid roster response from masquerading as timeout
behavior. Do not replace them with a mocked provider or an idle-only control.

| Proposed case name | Target / response | Response release | Source-derived expectation, not recorded output |
| --- | --- | --- | --- |
| `application_prompt` | Existing assignment requirement and `initial_permit` REST body | After initial leased snapshot, within 2s of request | Successful application evidence processing |
| `application_delayed_headers` | Identical application inputs/body | 17s after observed request | HTTP read failure before release; retry outcome, not a job-deadline error |
| `roster_prompt` | Background roster with the same REST assignment requirement; valid empty users collection `[]` | After initial leased snapshot, within 2s of request | Successful completed empty roster scan |
| `roster_delayed_headers` | Identical roster inputs/body | 17s after observed request | Successful scan after consuming the response, still below its 20s limit |

The empty roster is a deliberate **definition of this first positive control**:
it proves a real authenticated collection request and completed roster job, not
candidate enumeration, individual candidate evidence, terminal-state preservation
or NRPS/AGS behavior. Those have separate existing corpora and later additions.
An empty queue, skipped feature or zero-request success cannot pass this matrix.

Keep the existing default roster limits for this first slice. Exact request
contracts are grounded in retained REST/roster observations:

```text
application: GET /api/v1/courses/42/assignments/9/submissions/7?include%5B%5D=assignment
roster:      GET /api/v1/courses/42/users?enrollment_type%5B%5D=student&per_page=100
```

Each request must have the existing synthetic OAuth bearer token and
`Accept: application/json`. Require exactly one request and zero token exchanges,
signer requests or unsupported methods. Retain the complete four-field observer
projection; do not compare counts alone.

## Reuse actual owners and seed contracts

| Responsibility | Existing API / source to reuse |
| --- | --- |
| Official schema and immutable image process | `PublishedDatabase` in [canvas_published_database.rs](../../rust/services/issuance/tests/support/canvas_published_database.rs); the [probe dispatcher](../../scripts/prepare_canvas_published_schema.py) already has separately allowlisted case entry points |
| Application seed, encrypted OAuth and trusted loopback setup | `seed_worker_database(engine, origin, spec, shared)` and `worker_case(origin, cert, extra)` in [run_canvas_worker_rest_oracle.py](../../scripts/run_canvas_worker_rest_oracle.py) |
| Assignment body and projections | [canvas-worker-rest-scenarios.json](../../contracts/canvas-worker-rest-scenarios.json), `initial_permit`, plus its `shared_seed` |
| Initial queued application job | `initial_job_seed` in [canvas-worker-validation-scenarios.json](../../contracts/canvas-worker-validation-scenarios.json), executed once before startup |
| Background target and initial queued job | The common two-statement `seed` in [canvas-worker-roster-failure-scenarios.json](../../contracts/canvas-worker-roster-failure-scenarios.json), not any failure case's OAuth mutations; reuse its metadata marker and cursor rather than inventing equivalent SQL |
| Retry projection | `jobs_sql` from [canvas-worker-retry-scenarios.json](../../contracts/canvas-worker-retry-scenarios.json); the REST projection's special 37s predicate is not the new timeout contract |
| Real Python process ownership | `start_worker(case, "worker-rest", stdout=..., stderr=...)` and `finish_worker(child)` in [run_canvas_worker_startup_oracle.py](../../scripts/run_canvas_worker_startup_oracle.py) |
| Read-only snapshots and waits | `snapshot(engine, spec, shared)` in [run_canvas_worker_provider_signals_oracle.py](../../scripts/run_canvas_worker_provider_signals_oracle.py); `wait_for`, `scalar`, `generation` in [run_canvas_worker_provider_recovery_oracle.py](../../scripts/run_canvas_worker_provider_recovery_oracle.py) |
| Actual HTTPS observation and response ownership | `WorkerHttpsFixture`, `ObservedRequestHandler`, `wait_for_response(index, path, stage)` in [canvas_worker_https_fixture.py](../../scripts/canvas_worker_https_fixture.py) |
| Native seed and preservation owners | `prepare`, `worker_environment`, `WorkerFixture.assert_preserved` in [canvas_worker_rest_replay.rs](../../rust/services/issuance/tests/support/canvas_worker_rest_replay.rs) |
| Actual native process ownership | `OwnedWorker::start_with_environment`, `signal`, `wait`, `Drop` in [canvas_worker_process_signals.rs](../../rust/services/issuance/tests/support/canvas_worker_process_signals.rs) |

For a roster case, apply the common roster seed through the existing
`post_oauth_seed` seam. For an application case, insert only the validation
contract's initial queued job. Never insert both jobs. Preserve original expected
job IDs from these seeds and verify attempt one remains the only attempt.

The roster seed starts with cursor 1 and a synthetic preservation marker. On a
successful empty scan the source suggests cursor wrap to 0 and roster size 0;
capture the actual target projection rather than imposing the failure corpus's
unchanged cursor expectation. Do not call `run_scenarios` unchanged: its existing
multi-stage scheduling and shutdown policy is not this timed single-job protocol.
Reuse its smaller seed/process/snapshot owners instead of copying the harness.

## Initial configuration and timed sequence

Set these supported values only before startup:

```text
CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS=120
CANVAS_SYNC_WORKER_LEASE_SECONDS=90
CANVAS_SYNC_WORKER_POLL_SECONDS=120
LOG_LEVEL=WARNING
```

Keep the real processor selector, feature/pilot setup, fixture CA trust and
synthetic token from `worker_case`. Do not override either runtime's HTTP timeout.
The longer job deadline and lease isolate request timeout from job cancellation
or expiration. This slice does not require a heartbeat renewal to occur; verify
the observed lease is still valid using database time while the job is leased.
The long poll prevents a natural retry/new scheduled cycle during the observation
window; verify that rather than rewriting its eligibility timestamp.

1. Finish seed and encrypted-token assertions. Snapshot genuinely existing
   issued rows/ciphertext, business rows and target configuration. Start bounded
   file-backed stdout/stderr capture, then the actual worker. Observe its first
   parsed request within a bounded startup allowance, failing on child exit.
2. The response hook validates index zero, exact path and GET method, records a
   monotonic receipt timestamp and signals a fixture event **before sending any
   response headers**. Existing `received` proves parse/observation; the hook's
   separate event proves the response barrier was entered. Query the leased job
   and current database-time lease, and verify no completed provider effects yet.
3. For prompt controls, release immediately after that initial snapshot and
   require a request-to-release interval below 2s. For delayed cases, release
   from an owned controller at 17s relative to the request
   timestamp. Record actual release time and require it to be in a predeclared
   safe band, for example 16.5s–18s. A missed scheduling window is a failed fixture
   attempt, not permission to widen the interval or freeze ambiguous evidence.
   Release timing must be independent of whether Python or Rust has produced an
   outcome; otherwise native mismatch could deadlock or change the stimulus.
4. Poll state concurrently. For the published application timeout, require the
   durable first-job outcome to have been observed while the response was still
   held. For the roster success, require it only after release and response
   handling. Neither may report the global job-deadline code. Keep outcome
   observation bounded to 25s after request receipt and fail on additional work.
5. Preserve the same live, idle worker through at least 22s after request receipt
   and at least two seconds after the outcome, provided the bounded case budget
   remains satisfied. Compare complete relevant business/operational rows with
   the immediately completed outcome. A late response may not change a retry
   into success, add facts, alter completed results or initiate another request.
6. Release barriers unconditionally, join all HTTPS handlers and recheck the
   final transcript before declaring transport success. Request shutdown only
   for the exact owned child after the observation phase, wait with the existing
   bounded owner, then recheck durable state. Always invoke owner cleanup in
   `finally`, including assertion failures, and dispose the SQLAlchemy engine.

The proposed new fixture should subclass `WorkerHttpsFixture` and override only
`wait_for_response`. Use its existing method handlers, certificate creation,
observer and cancellation-tolerant write behavior. Bound the release wait, always
release on failure, and do not add sleeps to application code. A controller must
not keep a shared request-observation lock held while waiting or querying the DB.

## Observation and safety contract

Freeze only observed language-neutral projections after two independent complete
captures agree. Proposed fields include case/schema/source hashes; exact request
ledger; attempt/max-attempt, status, code/static summary, safe result and released
lease; target success/cursor fields; actual fact/policy/review and roster counters;
OAuth state; and measured ordering predicates such as `outcome_before_release`
and `lease_current_while_response_held`. Derive each predicate from raw timestamps
or snapshots. Do not hard-code booleans from a case name. Retain raw timestamps,
IDs and ciphertext for local before/after comparison, not public artifacts.

The source suggests `canvas_authoritative_reads_failed` when the application's
only read is unavailable, with no new fact and the job retrying. Exact summary,
safe result, metadata and error/log projection must come from the capture. A
different observed code is a finding to review, not output to normalize away.
The roster prompt/delayed control must prove a completed scan and stable marker,
not merely `facts == []`. Preserve seeded issued rows and ciphertext exactly;
do not claim preservation of evidence heads or candidates that were never seeded.

Capture child output in owned temporary files, never undrained pipes. Enforce a
small size bound and reject raw synthetic tokens, API/HMAC keys, database secrets
and sentinel values. Use fixed severity/category counts and allowlisted static
diagnostics if needed; do not publish raw logger payloads or exception messages.
Do not assume timeout processing is silent: inspect its actual categories before
freezing. Observe pre-shutdown output separately from shutdown output. Current
native `OwnedWorker` discards stdout/stderr, so later native log parity needs an
owner-approved opt-in capture seam; it cannot be claimed from this existing API.

All database/container targets must continue through the exact-owned disposable
published-schema owner. No live endpoints, external signer, production secrets,
custom processor hooks, clock/lease/job mutations, database triggers, runtime
monkeypatches or cryptographic implementation changes are needed.

## Proposed file boundaries and executable regressions

After approval, create separate `canvas-worker-timeout-scenarios.json`,
`canvas_worker_timeout_https_fixture.py`, `run_canvas_worker_timeout_oracle.py`
and focused fixture/contract tests. These names are proposed, not existing APIs.
Keep the current deadline inputs frozen while their owner is using them. Parent
coordination is required for later probe registration and database-owner mounts;
do not create another disposable-container manager.

Before actual captures, test nonempty/unique/exact four-case selection, target/body
shape, both prompt controls, one initial job, fixed pre-start configuration, and
barrier ordering against actual loopback HTTPS. Negative controls must cover
unsupported POST, wrong path, second request, no release, worker exit, timeout,
release outside the timing band and an outcome incorrectly accepted after late
release. Assert cleanup on each failure and bounded file-backed diagnostics.
These tests prove fixture integrity, not worker behavior.

After A/B agreement, preserve raw JSON numeric types when freezing. Add a
separate native replay helper that reuses the existing seed and `OwnedWorker`
owners, with the same response-release timing. The existing
[REST HTTPS parent](../../scripts/test_canvas_worker_rest_https.py) has immediate
responses and is not itself a delayed-header harness. Reuse the shared fixture;
coordinate any new parent/child receipt/outcome markers without modifying worker
functions. Markers only synchronize test observation, never rewrite DB state.
Keep exact-case registration and mandatory configured Linux execution; a skipped
or unconfigured Rust test is not qualification.

## Follow-on order

1. Complete and independently freeze the four header cases, then run native
   replay and record the unmodified mismatch before choosing a runtime repair.
2. Extend target-sensitive coverage to AGS/NRPS grants and collection pages using
   the existing mixed-roster HTTPS/synthetic signer owners. Keep signer evidence
   explicitly separate from cryptographic qualification and preserve per-run
   successful-token reuse.
3. Add the audit's independent OAuth refresh 10s–15s control and revocation's
   separate 10s boundary, reusing encrypted-token and revocation owners.
4. Add progressing-body versus stalled-body cases using the existing
   [timeout-consumer corpus](../../contracts/canvas-timeout-consumer-scenarios.json)
   and operation-timeout transport owner, then compose their durable effects and
   cancellation into actual worker tests. Do not duplicate socket timers or
   replace bounded response readers with unbounded collection helpers.

The [three-read job-deadline reference](canvas-worker-provider-deadline.md) remains
independent throughout: its completed-prefix preservation and active-I/O
cancellation evidence neither closes nor is replaced by this timeout matrix.

# Whole-worker OAuth revocation qualification

Latest qualification: exact head `75d82c9fe5a41ed14a6939d77a95c26f5ffc2a87`
passed CI34069978028 and all applicable checks, including Rust CodeQL34069978088.
Runtime101585424129 passed all 81 configured tests in 1726.05 seconds and the
separate four-entry worker DB group in 104.35 seconds. All 23 actual native
revocation markers were verified, qualifying eight Retry-After and five backoff
cases alongside the ten earlier transport/ownership/marker-failure cases.
This supersedes their initial pending status in the historical sections below.
Queue and acquired-lease follow-ups still require their own hosted qualification;
gate 10, consumer cutover and aggregate beta acceptance remain open.

Gate 10 remains open. Seven actual published-worker observations are now frozen,
with two identical independent captures and native replay now qualified on
Linux at `31355d24a1ef5d87d2da98a121f73863ca8bcf7e`. Existing repository/provider tests and the native
disconnect-marker privacy replay are retained; neither proves the complete
remote revocation failure and owner-fence matrix through the deployed worker.

## Transport fixture preparation

Both reference and native providers issue `DELETE /login/oauth2/token` with
Bearer authorization and JSON Accept headers. The shared owned-loopback
`WorkerHttpsFixture` previously implemented GET only. Four new DELETE controls
failed against that fixture while all twenty existing controls passed.

DELETE now shares the GET handler, response/header selection, request recording,
held-response release, failure propagation and deterministic owned cleanup.
No provider response selection or application outcome policy is implemented by
this change. Existing GET observations are unchanged, including the unauthenticated
control. Synthetic authenticated DELETE recording is checked separately.

The full local Python suite passed 911 tests with one existing opt-in skip in
41.92 seconds; focused lint and whitespace checks passed. These are fixture
regressions, not published-process/native-worker parity evidence. No reference
artifact, signing adapter, consumer or deployment is changed.

## Next reference and adoption sequence

The first transport matrix is now captured in
`contracts/canvas-worker-oauth-revocation-oracle.json`, canonical LF SHA256
`43679e0883a269993c879958815992885dc9b4e9fac55d4223f1af35bcd21b39`.
Two independent seven-case captures matched in 89.41 seconds. They execute the
pinned published image and official migrations; worker, route and OAuth-provider
source hashes are retained. Both real token secrets disappear after 200/204/404,
while the unrelated tenant's encrypted secret remains unchanged. 429, 503,
redirect and held-response timeout preserve all token ciphertexts, persist one
retry and leave the platform connected. Redirect/timeout are classified as
`canvas_oauth_revoke_rejected` by the actual published composition. Every case
has exactly one observed DELETE with the synthetic Bearer and Accept headers,
zero background jobs, unchanged issued rows and an actual idle heartbeat.

The native replay shares the published-schema seed, encrypted vault and owned
binary lifecycle. Complete HTTP observations are checked by the HTTPS owner;
all durable observations are checked against the frozen artifact by Rust.
Reference regeneration and native parent/child entries are registered in the
mandatory hosted Linux test gate. That seven-case native boundary is now qualified;
the later ownership and marker-failure extensions still require their own hosted run.

An exploratory Windows native execution returned unavailable/retry outcomes even
for positive HTTPS cases and is **not** accepted as application parity evidence.
The process client uses platform certificate verification; this fixture's
environment-scoped trust setup is qualified on Linux, not Windows. Native launch
now explicitly requires Linux. Do not change the host trust store or weaken TLS
verification to obtain a local pass. Fresh Linux execution must establish the
actual composed outcomes before any claim of full native adoption.

A separate focused test uses the existing explicitly allowed loopback HTTP
policy to execute the actual native revocation adapter and worker classification
against all seven frozen categories. It first failed exactly redirect and timeout
(`unavailable`/`timeout` versus the reference's `rejected`), while all five other
categories matched and every method/header observation was checked. This is
adapter-category evidence, not HTTPS or durable whole-worker qualification.

The canonical Rust HTTP revocation adapter now returns its known rejection
category for those transport/redirect outcomes. Exchange/refresh transport
classification is unchanged; explicit controls preserve the worker's raw timeout
and unavailable categories for other provider implementations. No retry hint,
schedule policy, lease fence, token transaction or TLS verification is changed.

Capture setup corrected two new harness assumptions before freezing: SIGINT
retains the already-qualified published process exit semantics, and the retry
deadline retains the contract's inclusive 30–37-second first-attempt jitter.
No old artifact, application clock or runtime was changed. The HTTPS fixture
also sends an actually empty 204 response, with GET/DELETE regression coverage.

Remaining sequence:

1. Retain the shared published-schema seed, encrypted-secret persistence,
   subprocess owner and HTTPS fixture with the two-token and unrelated-tenant
   controls. Do not emulate worker scheduling or database transitions in the harness.
2. Retain the captured seven-case transport matrix; extend Retry-After edge
   cases through the same response-time header helper without rewriting existing
   observations.
3. Reuse the native published-schema/binary owner to compare those exact
   observations, with explicit storage/type mappings only where justified.
   Extend through held-request owner-fence loss and disconnect-patch failure;
   preserve Rust's stronger tenant-atomic cleanup rather than weakening it to
   match a reference implementation detail.
4. Correct demonstrated differences in the canonical shared Rust implementation,
   retain earlier worker corpora, and require fresh exact-head Linux qualification.

The initial classification finding is now captured and demonstrated at the native
adapter boundary as described above. Remaining origin, owner-fence and patch
outcomes need their own captured evidence; do not rewrite expectations on
inspection alone.

This work is independent of signing/crypto adapter ownership. Gates 13 and 14,
consumer cutover, Python deletion and aggregate beta acceptance remain separate.

## Final local follow-up evidence

- New seven-case frozen reference regenerated unchanged in 49.23 seconds.
  The existing four-stage REST and four-fact captures also remained unchanged
  (11.34 and 9.27 seconds), verifying the shared seed's default behavior.
- Corrected native adapter-category test and all 334 library tests passed,
  alongside five worker-binary and 23 behavior tests.
- Configured PostgreSQL worker group: four passed in 94.11 seconds, retaining
  all twelve privacy cases, known-error controls, signing guard, lifecycle/
  disposal and 60 renewal combinations. The owned tmpfs fixture was removed.
- Python: 919 passed, one existing opt-in skip, in 46.49 seconds; strict
  all-target Clippy, focused Ruff, integration-test compilation and whitespace
  checks passed. New fixture controls fail on child exit, timeout, missing/
  duplicate reference cases and unexpected HTTP requests, with owned cleanup.

These results do not qualify the seven complete native HTTPS/SQL cases on
Windows. Their Linux parent, actual binary child and independent reference
regeneration are mandatory in fresh exact-head hosted CI before adoption.

## Held-response ownership transfer extension

Two additional published-process observations are frozen separately in
`contracts/canvas-worker-oauth-revocation-fence-oracle.json`, canonical LF SHA256
`025a31983550db5a734c8aed38e0b0d8dbafe7309db5b4b64863a6beefc905e9`.
Independent captures passed in 13.50 and 11.27 seconds; regeneration against
the frozen artifact passed in 11.39 seconds. The original seven-case artifact
is unchanged and regenerated successfully in 47.35 seconds.

For remote 200 and 429, the shared HTTPS fixture holds the actual DELETE. After
receipt, a scoped transaction transfers the synthetic connection from its
observed, unexpired worker lease to a replacement owner and sets distinctive
retry state. Only after commit does the harness release the response, within
five seconds of receipt and before the ten-second provider timeout. The actual
published worker returns to durable idle without changing the replacement row,
platform configuration, issued rows, either token ciphertext or the unrelated
tenant's ciphertext. Complete before/after row equality includes lease expiry,
retry deadline, timestamps and token references; the frozen projection records
the deterministic ownership/retry fields and the verified equality result.

The native extension reuses the encrypted vault, seed, real worker binary,
owned database and existing request/response marker protocol. It compares the
same complete row and durable projections; the Python HTTPS owner compares
the full request. This is an explicit competing-owner database transition, not
a second worker scheduler implementation or a timing-based claim of concurrency.
No production runtime, lease predicate, token transaction or feature is changed.

The configured Linux gate now registers 75 top-level entries, including separate
reference and native fence tests sharing the existing native child. Native
qualification for this extension remains pending. Fixture integrity controls
reject missing requests, missing transfer acknowledgements, slow transfers and
child timeouts, and verify response release and bounded owned-child cleanup.
The complete Python suite passed 926 tests with one existing opt-in skip in
52.33 seconds; strict all-target Rust Clippy and integration compilation passed.

This covers replacement-owner success/retry preservation only. Other fence
dimensions, disconnect-patch failure, Retry-After edges and the remaining
whole-worker cutover requirements are not declared complete by these captures.

## Disconnect-marker write failure extension

An additional actual published-worker capture is frozen separately in
`contracts/canvas-worker-oauth-revocation-patch-oracle.json`, canonical LF SHA256
`6ac1bb861acd23f3e7a3f71427177d8ff9de2cf6a571c25d03a33dd9a2006b1e`.
Two independent captures matched exactly (5.83 and 5.51 seconds); frozen
regeneration passed in 5.37 seconds. The ownership and original transport
references also regenerated unchanged (12.05 and 47.33 seconds).

The fresh, exact-owned test database installs a trigger that rejects only the
synthetic platform's disconnected projection. The existing shared database-barrier
owner holds a compatible table lock until the real worker's platform UPDATE is
observed waiting. Releasing that barrier permits the trigger's fixed synthetic
error. This proves an actual attempted update; merely omitting the update cannot
pass. Neither production tables nor a running deployment receive the fixture.

After successful remote DELETE and the failed marker update, the published worker
deletes the connection and both access/refresh tokens, preserves the unrelated
tenant's encrypted secret and issued rows, and reaches durable idle. The platform
projection remains connected because its update failed; this does not mean tokens
remain usable. Native replay checks these same final observations and shares the
existing barrier, process, seed, encrypted-vault and HTTPS owners. It retains
Rust's stronger atomic connection/token deletion, not the reference's intermediate
transaction order. No runtime or feature is changed by this extension.

The mandatory Linux gate now registers 77 top-level entries. Full native patch
and ownership replay qualification remains pending. Strict all-target Rust
Clippy and integration compilation pass locally. The full Python suite passed
934 tests with one existing opt-in skip in 45.37 seconds, including closed-matrix
and failure/cleanup controls for the new parent path. Earlier transport and fence
artifacts are unchanged; remaining Retry-After edges and other whole-worker
requirements are still open.

## Hosted seven-case transport qualification

Exact head `31355d24a1ef5d87d2da98a121f73863ca8bcf7e` passed CI34066329798
and Rust CodeQL34066329814, with all applicable PR checks green (scorecard
skipped). Runtime job101575640066 includes all seven actual native OAuth
revocation PASS markers, each with one request: 200, 204, 404, 429, 503, redirect
and timeout. The configured 73-entry group passed in 1632.34 seconds; the
separate configured four-entry worker PostgreSQL group passed in 96.54 seconds.
The image job passed too. The earlier 0.37-second unconfigured group is not
being counted as database/process parity evidence.

That checkpoint qualified the seven-case native transport/durable cleanup
boundary and scoped adapter correction. The subsequent 77-entry Linux gate at
`d0a09792b7866d60bc20284570d395e0b252477b` now also qualifies both ownership
cases and marker-write failure: CI34068063872, runtime101580260455, all 77
configured tests in 1668.72 seconds and the separate four-entry worker DB group
in 96.66 seconds. All ten actual native revocation PASS markers and applicable
exact-head checks, including Rust CodeQL34068063928, were verified.
Remaining Retry-After, backoff, queue and whole-worker consumer requirements keep
gate 10 and PR814 open; no live Python deletion or beta acceptance is claimed.

## Remote revocation Retry-After extension

Eight actual published-worker timing observations are frozen separately in
`contracts/canvas-worker-oauth-revocation-retry-after-oracle.json`, canonical LF
SHA256 `a3e6b63b50230d30823b98d3399d24d1819472476ab48af169b259bf1b03b0b0`.
Independent captures matched exactly in 41.85 and 41.74 seconds. Final frozen
regeneration passed in 41.29 seconds; the original seven-case transport reference
also regenerated unchanged in 50.14 seconds.

Each case executes a fresh published worker and actual DELETE429, then observes
the stored revocation retry deadline, rate-limit code, one retry, released lease,
unchanged token ciphertexts, connected platform, unchanged issued rows and idle
heartbeat. Missing, malformed, negative, zero and past-date headers preserve
the first-attempt 30–37-second backoff. A future HTTP date is generated at actual
response time and compared to the stored deadline within 1.1 seconds. Both an
over-cap integer and an integer larger than u64 retain the one-day cap. No clock,
retry timestamp, runtime scheduler or old reference value is modified to pass.

Native replay reuses the existing encrypted vault, process and HTTPS owners.
The existing Rust timestamp producer is shared with ordinary worker retries;
OAuth `revoke_retry_at` maps explicitly to the comparator's neutral `available_at`
field. The HTTPS parent uses the existing deadline comparator to check every
actual native timestamp record against the emitted date or frozen bounds.
Rust does not manufacture a timing-success flag: only this field is delegated
to the parent alongside its full request comparison, while Rust checks all other
durable projections. Missing/duplicate records, naive timestamps, wrong dates,
missing dates and incorrect bounds fail the parent and retain owned cleanup.

The complete local Python suite passed 948 tests with one existing opt-in skip
in 45.22 seconds. Strict all-target Clippy and integration compilation passed;
79 top-level configured entries are now registered. Full native Linux timing
qualification remains pending; ownership/marker cases are now qualified at
d0a09792 above. No production runtime, consumer or feature is changed here.
Gate 10 still needs those exact-head qualifications and a requirement-by-requirement
audit against the normative OAuth selection, retry and ownership contract before
closure; this extension alone is not whole-worker cutover acceptance.

## Later-attempt backoff and coverage audit

The [contract coverage audit](canvas-worker-oauth-revocation-coverage-audit.md)
identified later-history timing as unproven by first-attempt captures. Five actual
published-process observations are now frozen separately in
`contracts/canvas-worker-oauth-revocation-backoff-oracle.json`, canonical LF SHA256
`810f653d2d5a400df8744078b02bd41dc2f3f528461c8befe68811ab326b9fad`.
Independent captures matched exactly in 25.25 and 25.38 seconds; regeneration
against the frozen artifact passed in 29.17 seconds.

Historical retry counts 1, 9, 10, 11 and 999 are seeded and checked before any
worker starts. Actual remote 503 responses produce retry counts 2, 10, 11, 12
and 1000 and persist deadlines within 60–75, 15360–19200 and the capped
21600–27000-second bounds. The actual worker chooses its own jitter and timing;
no running state or clock is modified. Every case preserves both token ciphertexts,
the unrelated tenant's secret, platform configuration and issued rows, and
reaches idle with no background jobs. Native replay uses the same owned seed,
vault, process and HTTPS helpers and checks the same complete observations.

An additional native helper regression checks the captured bounds with absent,
zero, one-day and oversized Retry-After hints without mocking randomness or
requiring any particular random draw. All 24 behavior tests and strict all-target
Clippy pass. Python regressions pass 954 tests with one existing opt-in skip in
53.81 seconds. Full native process qualification remains pending; 81 top-level
configured entries are now registered. No runtime or live feature is changed.

The audit retains specific remaining gaps in nonempty queue ordering/eligibility,
batch and lease boundaries, returned cycle counters and secret-resolution branches.
These are named contract requirements, not a claim that an unspecified set of
additional tests must continue indefinitely. All cutover and beta gates remain open.

The [nonempty queue extension](canvas-worker-oauth-revocation-queue.md) now adds
two frozen actual-process captures, native replay and a real repository
regression. It corrects the observed Rust null-order mismatch while preserving
all excluded rows and existing features. The repository regression is locally
red-before/green-after; whole-process Linux qualification remains pending.

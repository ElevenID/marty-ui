# Whole-worker OAuth revocation qualification

Gate 10 remains open. Seven actual published-worker observations are now frozen,
with two identical independent captures and native replay implemented but not
yet qualified on Linux. Existing repository/provider tests and the native
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
mandatory hosted Linux test gate. Full native process qualification remains pending.

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

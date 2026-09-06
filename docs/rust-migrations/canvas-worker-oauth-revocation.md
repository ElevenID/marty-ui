# Whole-worker OAuth revocation qualification

Gate 10 remains open. Existing repository/provider tests and the native
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

1. Reuse the existing published-schema worker seed, encrypted-secret persistence,
   subprocess owner and HTTPS fixture. Add a revocation-pending connection with
   both access and refresh secrets and an unrelated-tenant retention control.
   Do not emulate the worker's scheduling or database transitions in the harness.
2. Capture actual published-process outcomes twice for remote 200/204/404
   success, 429 retry, rejection/redirect and transport timeout. Freeze method,
   endpoint/header observations, durable retry code/count/deadline, owner state,
   connection/token cleanup and platform projection. Include Retry-After edge
   cases through the same response-time header helper.
3. Reuse the native published-schema/binary owner to compare those exact
   observations, with explicit storage/type mappings only where justified.
   Extend through held-request owner-fence loss and disconnect-patch failure;
   preserve Rust's stronger tenant-atomic cleanup rather than weakening it to
   match a reference implementation detail.
4. Correct demonstrated differences in the canonical shared Rust implementation,
   retain earlier worker corpora, and require fresh exact-head Linux qualification.

Source inspection found classification differences worth testing first: the
reference provider wraps redirects and HTTP transport failures in its known
OAuth error, whereas native redirects currently use the unavailable category
and native timeouts retain a timeout category. These are not yet reproduced
whole-worker parity failures. Do not change mappings or expected artifacts on
inspection alone; capture the actual composed reference first.

This work is independent of signing/crypto adapter ownership. Gates 13 and 14,
consumer cutover, Python deletion and aggregate beta acceptance remain separate.

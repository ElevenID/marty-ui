# Actual worker roster failure parity

Status: five published-worker scenarios captured in 25.39s and independently
regenerated against the complete frozen reference in 31.08s. All five cases now
pass actual native Linux process replay at
`5dde6b69adbca467d7fefaa1b43bc2b77ac4aa19`. Its configured suite passed 109
entries; this does not qualify later local extensions. PR #814 stays draft
and unrouted.

## Captured behavior

| Scenario | HTTPS reads | Durable result | Target |
| --- | ---: | --- | --- |
| OAuth reauthorization required | 0 | Retry: `canvas_roster_oauth_unavailable` | Enabled |
| AGS-only binding without verified NRPS context | 0 | Retry: `canvas_nrps_roster_unavailable` | Enabled |
| Three-user response with batch 1 / complete-read limit 2 | 1 | Dead letter: `canvas_roster_collection_too_large` | Disabled |
| Successful HTTP response containing a non-collection | 1 | Retry: `canvas_authoritative_read_failed` | Enabled |
| HTTP 503 roster response | 1 | Retry: `canvas_sync_unexpected_error` | Enabled |

The 503 case is additional to the four normative processor codes: the published
REST helper raises `HTTPException`, whose worker diagnostic is
`Canvas synchronization failed (HTTPException)`. It must not be conflated with
the malformed-collection error. Provider response text is never persisted.

The published AGS-only path performs OAuth setup before checking NRPS context.
Its encrypted token is marked used despite zero HTTP requests. The initial
reauthorization-required case leaves it unused. Actual captures freeze this
distinction; secret use does not necessarily imply network traffic.

## Ownership and comparisons

Existing isolated published-schema/REST owners supply fresh official-schema
databases, immutable published images, real worker processes and loopback HTTPS.
One exact queued job, target cursor/marker and case-specific binding or OAuth
state are seeded after OAuth creation, before any worker starts. No application
clock, running job, lease or schema constraint is changed. Workers are interrupted
only after the real durable outcome and idle heartbeat.

Both paths compare full jobs (summaries, attempts, result, lease release and retry
backoff bounds), facts, events, issued/application projections, OAuth state and
target metadata. Only the volatile target heartbeat timestamp is normalized to
a valid, non-future timestamp predicate; worker ID, cursor and marker stay exact.
Issued credential/transaction rows and ciphertext must remain unchanged within
each run. The candidate table is empty and must stay empty. This is not populated
candidate lifecycle or complete mixed-roster cursor qualification.

## Rust repairs and regression scope

The shared collection reader distinguishes REST from LTI while retaining one
bounded paging implementation. REST first-page requests include the published
`per_page` bound; REST `items` envelopes remain distinct from LTI envelopes; and
ordinary REST HTTP status failures receive a payload-free typed classification.
Existing LTI, 401/403 and rate-limit mappings are unchanged. The worker rebuilds
the HTTPException diagnostic from that type, rejecting forged diagnostic fields.
Roster setup retains the published OAuth lookup order and oversized-roster summary.

A reference-derived Rust test failed on the old oversized-roster summary, then
passed after repair. All 338 issuance library tests pass, including protocol
query/envelope controls, ten actual loopback HTTP status/protocol combinations,
and unexpected-diagnostic canonicalization. Strict all-target Clippy passed in
30.52s. The original published REST reference regenerated unchanged in 8.65s.
The final full Python regression, including qualification accounting, passed
1,039 tests with one existing skip in 39.98s.

The first full Python attempt used Strawberry Perl's OpenSSL and failed ten
certificate-generation tests. With Git OpenSSL on this process's PATH, all 26
HTTPS-fixture tests and the full suite passed. No global configuration changed.

## Exact native Linux qualification

[CI34085691302](https://github.com/ElevenID/marty-ui/actions/runs/34085691302)
completed successfully at the exact head above. Runtime job `101629197299`
logged 109 configured tests passing in 2361.53s at `2026-09-07T05:56:08Z`.
Ignore the separate unconfigured 109-test result in 0.37s: it is not runtime
qualification. The configured worker/PostgreSQL suite passed four tests in
96.28s. All five actual native roster markers were inspected and matched the
table's request counts: 0, 0, 1, 1 and 1. Complete frozen-state comparisons,
secret-use distinctions, preserved cursor/issued rows and post-exit checks
remain part of the replay, not just the request count.

The retained recovery-first marker made one HTTPS request. Image job
`101629197264` passed with all 24 startup markers, Rust CodeQL run `34085691297`
passed, and every exact-head check was successful or skipped. At that checkpoint,
this evidence moved four normative processor codes into actual-process coverage
(11 total), leaving three composed outcomes and two typed-dispatch reconciliations open.
The HTTP 503 generic worker code is additional to that seventeen-code partition.

The later resource composition passed independently at
`6914387e563d1043948aaea7a5cc514be6055038` (CI `34089906961`): 115 configured
tests in 2444.37s, four worker/PostgreSQL tests in 95.63s, with all five roster
markers retained. That evidence qualifies the two resource-race cases and the
post-validation resources-unavailable case, bringing processor actual-process
coverage to fourteen. Two typed-dispatch reconciliations remain open. Later
local effect-expiry and mixed-roster work is not qualified by either checkpoint.
No previous frozen reference, normative requirement, production consumer or
Python feature was deleted. No candidate dispatch, deployment or cryptographic
signing implementation changed. Further roster pagination, successful/mixed
candidate lifecycles, lease expiry during effects and other cutover gates remain open.

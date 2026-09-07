# Actual worker resource-race parity

Status: two published-worker scenarios captured in 11.76s and independently
regenerated against the complete frozen reference in 11.13s and 10.57s. The configured
twelve-case native Rust repository regression passes in 47.22s. Native Linux
full-worker replay remains unqualified. The suite registers 113 entries; that
registration is not evidence that all 113 have passed. PR #814 remains draft
and unrouted.

The last fully qualified composed checkpoint is
`5dde6b69adbca467d7fefaa1b43bc2b77ac4aa19`: 109 configured integration tests passed
in 2361.53s, with four worker/PostgreSQL entries in 96.28s (CI `34085691302`,
runtime `101629197299`). All exact-head checks passed, including Rust CodeQL.
That qualifies the preceding roster work, not this later resource-race extension.

## Captured behavior

Both scenarios observe one actual assignment-submission HTTPS GET, hold its
response while changing the exact synthetic resource, then release HTTP 503.
They use an actual published worker and a fresh official-schema database.

| Resource change during the held read | Durable job outcome | Resource outcome |
| --- | --- | --- |
| Platform configuration version changes from 1 to 2 | Retry: `canvas_platform_reconfigured`; attempt 1 of 8; retry delay within the frozen backoff bounds | New configuration and `synthetic-reconfigured` marker survive; target stays enabled; application remains present |
| Target is detached from its application and that application is deleted | Dead letter: `canvas_application_unavailable`; attempt 1 with maximum attempts reduced to 1 | Target is disabled and detached; application remains absent; platform records completed validation with `canvas_authoritative_reads_failed` |

The exact platform diagnostic is
`Canvas platform configuration changed during synchronization`.
The exact missing-application diagnostic is
`Canvas application became unavailable during synchronization`.
Both release the job lease, retain an empty result and produce no facts or
events. OAuth remains connected and its secret is marked used in both cases.
The immutable reference includes the request method, path and synthetic
authorization header, not just the final error code.

## Ownership and preserved state

The shared published-schema, REST and HTTPS owners supply the database, worker
process, fixture and bounded cleanup. The scenario matrix is
[`canvas-worker-resource-race-scenarios.json`](../../contracts/canvas-worker-resource-race-scenarios.json);
the frozen output is
[`canvas-worker-resource-race-oracle.json`](../../contracts/canvas-worker-resource-race-oracle.json).
The reference records exact published source hashes:

- `issuance.canvas_worker`: `c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a`.
- `issuance.infrastructure.api.canvas_routes`: `f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943`.

Resource changes occur only after the fixture observes the real HTTPS request.
Each mutation must affect exactly one synthetic row. No running job, lease,
application clock, worker function or schema constraint is modified. The full
raw job row must be identical immediately before and after the resource change.
The durable outcome must belong to that same job.

Both paths compare the complete frozen observable projections: job status,
attempts, diagnostic, result, lease release and backoff predicates; heartbeat;
facts and events; application and credential state; OAuth state; and resource
configuration, validation and target state. Issued credential and transaction
rows and ciphertext are preserved within each run. The existing shared lease
comparison handles Rust's private lease-generation bookkeeping rather than
requiring byte equality between language-specific processing-state storage.

Only after the actual durable outcome and idle heartbeat does the owner send
SIGINT. The observable snapshot, full raw job row and resource state must then
remain unchanged. Published Python exits with signal return code `-2`; native
Rust is expected to exit with code `130`. The native expectation is implemented
but has not yet passed the configured Linux full-worker replay.

## Rust repair and regression scope

The first configured repository regression failed on the old generic stale
diagnostic instead of the frozen platform-specific summary. The repaired
repository retains the failed scope guard and classifies a changed platform
version through a tenant-scoped locked read; that classification never permits
a stale write. Shared error constructors supply the exact published diagnostics.

The application guard locks the tenant-scoped application row and distinguishes
absence from an edited row. A missing application is terminal; a changed status
or integration context remains retryable. Scope checks, row locks, update
compare-and-set conditions and the final lease check remain in place.

`worker_resource_race_repository_preserves_stale_write_fences` now passes twelve
cases, each using a fresh official-schema database and an actual Rust repository:
platform reconfiguration, application deletion, application status change and
application context change; target-only and binding-only reconfiguration; and
wrong-owner/wrong-attempt captured leases combined with platform reconfiguration,
application deletion or application context edits. The binding control models
an already revalidated active configuration, retaining the published activation
constraint and unchanged target generation. Invalid lease controls change only
the captured typed identity, never the durable lease or its clock.

It verifies exact frozen errors for the original two cases, exact generic stale
errors for edited resources and lease-loss precedence for all six invalid-lease
controls. Complete platform, binding, application, target and job rows remain
unchanged after rejected patches; issued rows and ciphertext are preserved. This is
repository-level evidence, not evidence of the full worker's HTTPS ordering,
durable transition or shutdown parity.

The independent maintainer review found no weakened lease or write guard and
led to the additional target/binding and invalid-lease controls. Harness review
also added a nonempty-matrix guard, so an empty reference and empty scenario list
cannot report success without starting a native child. Shared failure tests
cover child exits, timeout, missing response release and wrong request sequences.
All 338 issuance library tests pass (16.07s), as does strict all-target Clippy.
The complete Python regression suite passes 1,051 tests with one existing skip
(45.68s), including the delegated harness controls.

The independent published regeneration is covered by
`worker_resource_race_reference_matches_published_process`. Native full-worker
qualification remains assigned to
`worker_provider_resource_race_matches_frozen_published_process` and its native
child, using the existing HTTPS parent and real request/release markers.

## Remaining qualification

These two error-path races do not qualify successful in-flight fact writes,
lease expiry during provider effects, populated mixed-roster processing, all
resource-unavailable cases, or the complete worker cutover. The native Linux
two-case replay and the retained aggregate gates must pass before these cases
are counted as full Rust process parity.

No Python feature, production consumer or frozen reference was removed. There
was no candidate dispatch, deployment, signing implementation change or
production change. These results do not authorize routing the draft worker.

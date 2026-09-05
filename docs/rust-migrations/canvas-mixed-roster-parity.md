# Published Python / native mixed-roster parity

Status: all twelve sequential mixed REST/AGS stages pass locally on separate
databases using the published issuance migrations. Hosted integration and
protected landing remain required. The standalone worker remains unrouted.

The baseline `contracts/canvas-mixed-roster-oracle.json` (Git blob
`8eccf5b6219f9b7528eb5c3f955b3ad5e3936ab3`) was captured twice, identically,
from the pinned published Python image before implementing Rust replay.
The loaded `canvas_routes.py` hash is
`f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943`.
Each test reruns Python and checks the entire frozen corpus before replaying
Rust. Neither expectations nor published migration constraints were weakened.

## Discovered and repaired difference

Python returns `roster_remaining`; Rust omitted it. The first native replay
failed on this missing field even though candidate state and all other results
matched. Rust now preserves the published result: zero after a complete cycle,
otherwise total deduplicated roster size minus the next cursor. The existing
bounded-batch unit test now asserts both a partial batch and completed cycle.
This is the only runtime change in this follow-up.

## Covered behavior

The shared data-only scenario file drives actual published Python and native
processors with their actual PostgreSQL repositories. Rust additionally uses
the shared real-job lease, validation and durable outcome helper. No policy,
identity lookup, candidate persistence or observation repository is replaced.

- Missing identity, subject-only verification, and linked-but-inactive NRPS
  membership prevent evidence reads and require identity linking.
- A verified numeric/opaque join permits both REST and AGS observations.
- Duplicate observations reuse current heads and preserve payload hashes.
- Provider outages preserve heads; negative AGS evidence blocks pending claim;
  later positive evidence recovers it.
- Quarantining an identity blocks reads; relinking restores eligibility.
- Claimed and dismissed candidate states survive subsequent evidence changes.
- Duplicate numeric roster entries are deduplicated; an unrelated opaque
  subject is not treated as another numeric candidate.

Every stage compares the whole selected result, exact provider-read identity
sequence, candidate identities/states, all observation assertions, verification
methods, hashes, current/supersession flags, and roster cursor/size. Applications,
issued credentials and issuance evidence facts remain absent. UUIDs and clock
values are excluded from cross-language projections. Python additionally checks
that synthetic roster name/email sentinels never enter stored candidate or
observation rows.

## Shared execution and limits

The existing exact-owned migration runner now supports two statically selected
oracle modes, reusing image provenance, migrations, container identity guards,
read-only mounts and cleanup. Each mode adds only its own two public inputs.
The mandatory `MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1` CI executable runs the
original schema contract, ten-stage issued-review differential, and this
twelve-stage mixed-roster differential. Five separate disposable databases are
used across the combined run. Default unconfigured test returns are not proof.

Provider transport is controlled. Python receives raw synthetic REST/NRPS/AGS
responses; Rust receives matching normalized observations and active subjects.
This proves processor/database identity behavior, not the Rust HTTP adapter's
NRPS status filtering, pagination, privacy filtering or token exchange. Real
HTTP-provider parity, concurrency/rollback, manual resolver endpoints, readiness,
all deployment consumers and beta acceptance remain required before deleting
the reachable Python worker. No production or beta deployment changed here.

# Hardened worker privacy replay

The complete `contracts/canvas-worker-privacy-reference.json` is copied unchanged
from Credentials PR271, landed at `948bca975b493285c512c20a13d5abf8ee5e6305`.
Its production-reference source is the earlier protected privacy repair
`d418ac0df283625f43b0c011fb1c72fd7d3013a9`, not Rust-generated expectations.
The SHA256 of the canonical LF text is
`2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05`.
The replay checks this digest, source revision and all 63 retained cases.
No old immutable oracle or observation is rewritten.

## Newly replayed boundaries

Four of the twelve worker observations now execute through actual Rust worker
cycles/loops and PostgreSQL, using the existing observed-repository owner:

- An escaped target-read error leaves that job leased while a sibling succeeds.
- A first OAuth queue-read error fails the cycle, then the next real cycle
  reaches idle without stopping the loop.
- Each branch runs once without ambient context and once inside a real tracing
  span carrying a synthetic correlation identifier.

As in the reference, only the repository failure and successful processor are
controlled. Other operations use the real native repositories. This is not a
published-process, actual driver-failure or full deployed log-collector test.
No API credential, external signing endpoint or deployment database is used.

The native observer captures every field of every event from the worker producer,
and separately captures its actual JSON formatter output. Both complete maps are
compared; it does not select only known-safe fields. Downstream envelope fields
and optional span metadata are checked exactly before projection. A regression
deliberately emits synthetic extra, exception and backtrace fields in both modes
and proves that the observer retains them and the parity comparison rejects them.
This does not attest log events from every other service/module or a production
collector configuration.

## Explicit language and storage mappings

- The reference's injected `RuntimeError` maps to the payload-free native
  `CanvasSyncRepositoryUnavailable`. The exact native class must match before
  this mapping; severity, event identifiers and static messages are not hidden.
- Generated job identifiers are normalized only after equality with the actual
  failed durable job ID is asserted.
- PostgreSQL retains `target_config_version` in the unfinished job result as an
  internal generation fence. The in-memory reference has no such stored field.
  The replay first asserts that the entire native unfinished result contains
  exactly that field, with the actual target generation, then projects the
  business result. The stored fence and all production fencing code remain intact.
- Completion and lease-state facts replace absolute timestamps, as in the frozen
  reference. No clock is changed and no scheduling, retry or completion code is
  reimplemented by the fixture.

## Failure-first correction

All four cases failed against the unmodified worker. The escaped-job cases
exposed the absent stable event identifier and the explicit storage distinction
above. The loop cases exposed swallowed OAuth queue-read failure: Rust logged a
warning and continued scheduling, unlike the reference's cycle failure/recovery.

The canonical Rust worker now propagates the queue-read error to the existing
loop handler, adds stable event IDs to escaped-job/cycle errors, and preserves
the reference's static cycle message. Queue acquisition, remote revocation,
tenant-atomic cleanup, job concurrency and generation fences are unchanged.
The test also asserts ordered heartbeat writes and exactly one completed
scheduling phase across the two loop attempts. An initial test-only assumption
of one idle write was corrected to the actual post-lease and final idle writes;
the frozen output was never changed.

All four native observations passed locally. The original three-entry configured
PostgreSQL group passed in 93.43 seconds, including the 28+2 signing guard,
range/lifecycle/disposal and 60 renewal combinations. The subsequent observer
regression passed independently. The final four-entry configured PostgreSQL
group passed in 93.77 seconds, including all four native observation markers
and the observer regression; its loopback-only tmpfs fixture was removed.
Library 332, worker binary 5 and behavior 23
tests passed, as did strict all-target Clippy and 907 Python tests with one
existing opt-in skip. Fresh exact-head hosted checks must pass before treating
this follow-up as qualified. Windows does not attest the Linux process-signal
cases; those remain mandatory in hosted CI.

## Still required

The six unexpected-processing and two disconnect-marker worker observations
still need native adoption, as do all 51 signing helper/operation observations.
Coordinate overlapping signing-adapter work with the crypto worker. Whole-worker
driver/provider failures, remote OAuth, races, all consumers and aggregate
acceptance remain their own gates. This four-case replay does not close gates
6, 13 or 14, authorize deleting live Python, or change production deployment.

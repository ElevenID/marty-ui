# Canvas processor per-job write authorization

The [frozen whole-job oracle](https://github.com/ElevenID/marty-credentials/blob/e3e79c96ab655f4ac699074c6452cd8c4c43dcb6/contracts/canvas-worker-renewal-job-outcomes.json)
records 60 actual Python handler/maintainer cases, merged in Credentials #265.
Operational renewal failure can precede legitimate processor outcome persistence;
owner, expiry and attempt changes still reject stale final outcomes. Python also
masks cancellation with the renewal error during cleanup, which is not a behavior
the native cancellation/SIGINT contract should copy.

Before changing the native renewal policy, processor effects need the individual
job identity. Existing tenant and target/platform/binding/application generation
checks are retained, but cannot stand in for that job's lease authorization.

## Implementation

`CanvasSyncLease` carries job, tenant, target, worker and attempt identity. Its
constructor validates a complete owned leased-job snapshot, but the value is
explicitly not a cached authorization grant and contains no trusted local expiry.
The worker passes it to the processor. The native processor checks its target and
worker association, then binds a new repository instance to that lease while
sharing only the connection pool. Concurrent jobs never overwrite an ambient
current-job slot. Test processors implement the same explicit interface.

The shared SQL guard locks the job before resource rows, consistent with worker
completion/recovery ordering, then checks current status, owner, attempt and the
database clock after acquiring the lock. Processor writes recheck before commit,
so expiry during resource waits or effects rolls back the entire transaction.
Ownership cannot change while the job row lock is held. These checks do not alter
the existing resource generation or business-effect predicates.

Fact/policy transactions carry the typed lease in the existing sync commit fence;
their shared function checks it before resource locks and before commit. Its
non-worker callers retain their existing path and authorization. Application
sync metadata, platform validation, target disabling, roster candidate saving,
candidate observations and cursor updates use shared begin/commit helpers.
An unscoped repository remains available for reads but all seven effect methods
reject writes. Target disabling now participates in an explicit transaction.

## Verification and limits

The existing mandatory management PostgreSQL executable retains its original
activation, readiness, archive, cursor and six stale-resource assertions. It
leases the real roster job already created by binding activation, rather than
inventing a second active job. Added checks establish:

- All seven write entry points reject an unscoped handle.
- Valid leases still support partial/completed cursor updates.
- Missing/mismatched job, tenant, target, owner, attempt and status reject writes.
- Creating invalid handles does not change another handle's valid authorization.
- Deterministic test-only expiry inside an effect transaction rolls back both
  the effect and the injected expiry.
- Expiry while waiting for a job lock cannot grant a write from a pre-wait clock.

The shared guard's SQL behavior is exercised through the real cursor writer.
This is not a claim that every fact/policy/provider success path has new complete
PostgreSQL coverage; their existing tests and processor simulators remain, and
full authoritative-processor/published-schema differentials remain mandatory.
Only the existing guarded synthetic `*_test` database is used. No unsafe baseline
or vulnerability reproduction is required to test the implemented refusals.

Renewal-error processing policy is deliberately unchanged in this patch. The
next step is to preserve legitimate fenced processor outcomes while retaining
immediate cancellation on known lease loss and acknowledged external shutdown.
The worker remains unrouted; no Python consumer, feature, deployment, dependency
pin, contract corpus or release coordinate is removed or changed here.

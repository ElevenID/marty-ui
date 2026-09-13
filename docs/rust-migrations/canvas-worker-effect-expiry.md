# Native evidence transaction and real lease expiry

This defensive regression exercises the native processor and PostgreSQL
repositories against fresh databases initialized by the pinned published
issuance migrations. Its provider is a controlled synthetic implementation.
It is not a real-HTTPS, complete-worker, renewal/cancellation or published
behavioral-parity qualification.

## Observed boundary

`worker_effect_transaction_obeys_real_database_lease_expiry` runs two separate
owned databases. Both acquire a real 30-second lease through the repository,
commit an initial allowed observation, and invoke the same native processor
again with a newer denied observation. The second invocation rereads the
application context produced by the first.

An owned transaction holds a SHARE lock on `issuance_events`, delaying the
normal event INSERT after the evidence transaction has begun. The test observes
the exact application name, blocker PID, ungranted relation lock and INSERT,
and independently verifies that the writer retains the job-row lock. Ordinary
SELECTs remain possible, proving pending effects are not externally visible.

- The positive control releases the barrier before expiry. A denied fact/head,
  open policy review and corresponding events must actually commit. Existing
  issued credentials, transactions, encrypted material, unrelated rows and
  prior immutable facts/events remain unchanged.
- The expiry case waits for actual database time to invalidate the unchanged
  lease row. It rechecks the event barrier before release. The complete business
  snapshot must roll back: facts, heads, reviews, events, applications,
  platforms, bindings, targets, issued credentials, transactions and encrypted
  integration/OAuth material.

Both cases await operation completion and bounded operation-pool closure, then
recheck durable state. Fixture setup occurs before processing. No clock,
deadline, running job, trigger, constraint or production implementation is
modified. Cleanup targets only the exact labeled containers owned by each test.

## Error classification and limits

The fact persistence adapter currently maps rejection to the existing retryable
`canvas_sync_repository_unavailable` error, with no retry delay. The regression
asserts this exact structure. That category also includes other repository
failures; the category alone is not proof of lease enforcement. The observed
barrier, real elapsed expiry, unchanged job, full rollback and successful
positive control supply the relevant evidence together.

The initial configured local run passed both cases in 38.16 seconds. The
post-expiry barrier recheck was subsequently added following independent
review; that configured local rerun also passed both cases in 38.14 seconds.
These are local repository results, not hosted qualification of this addition.
The mandatory configured CI runner checks that this test is registered. An unconfigured
early return must never be reported as runtime evidence.

Continue the real-provider in-flight expiry/cancellation and composed worker
gates in [cutover readiness](canvas-worker-cutover-readiness.md). This regression
does not authorize a consumer switch, Python deletion or deployment.

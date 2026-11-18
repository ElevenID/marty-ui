# Canvas job outcomes after operational renewal errors

The native worker now distinguishes confirmed lease loss from an operational
renewal/heartbeat error. Confirmed loss still drops the owned processor promptly.
An operational error ends renewal but leaves the already bounded processor and
its wall-clock deadline active. It does not grant a new lease or restart renewal.
All processor effects retain the explicit per-job transactional authorization
introduced in [the prerequisite](canvas-processor-job-authorization.md), alongside
the existing tenant/resource/application/template predicates.

When processing finishes, the normal complete/retry/dead-letter/deadline path
attempts its durable lease-fenced write. The original renewal error is surfaced
after that attempt. Secondary persistence failures remain separately observable;
an early `?` must not bypass this error ordering. Existing exceptional-cycle
counters remain zero for these escaped handlers even when a valid durable job
result was recorded. This preserves native accounting, not an unproven claim
about the Python full-cycle summary.

Already-ready renewal failures take precedence over simultaneously ready
processing in the owned select. Pending renewal I/O cannot block processor or
deadline progress. External cancellation still drops owned futures synchronously;
it is not converted into the legacy renewal exception. Existing acknowledged
pool cleanup and actual-binary SIGINT130/SIGTERM drain tests remain required.

## Frozen and native evidence

`contracts/canvas-worker-renewal-job-outcomes.json` is byte-identical (Git blob
`3a6825977603e7c8c2ebec8104130dff48b37a29`) to Credentials #265, protected commit
`e3e79c96ab655f4ac699074c6452cd8c4c43dcb6`. It freezes the unchanged Python worker
blob `b516ed3d0855f16e9ec899a452a22df49d2cafe5`. No expected outcome is rewritten.

The mandatory native PostgreSQL worker executable consumes all 60 combinations:
three failed writes (lease, target heartbeat, process heartbeat), five processor
outcomes (success, retry, terminal, deadline, cancel), four durable fences
(unchanged, owner, expiry, attempt). Each combination has its own target, durable
job and controlled processor. Six real cycles share elapsed renewal time without
replacing any worker cycle, renewal method, deadline or clock. Production config
parsing sets a 60-second lease, real 20-second renewal interval and real minimum
30-second processing deadline, leaving the unchanged lease valid at deadline.
The pilot rollout is explicitly enabled for the fixture tenant, as in the Python
oracle, so the actual repository target validation runs before every processor.

The test uses the actual native worker, PostgreSQL repositories, existing guarded
test schema and shared SQL failure probes. It checks rollback-surviving attempt
counts, all processors still active after errors, then removes only those probes
before allowing normal outcome writes. Changed owner/expiry/attempt and external
cancellation must leave the entire durable job and target rows unchanged.
Successful valid-lease processing also preserves `facts_changed: 1`, as in the
actual Python processor fixture. Retry, terminal and deadline retain the frozen
error codes and completion-timestamp semantics.

A future-local tracing observer records the actual escaped handler's job ID and
exception class: all non-cancelled handlers must report their original repository
renewal error after persistence, including when final writes reject stale leases.
Cancelled cycles must emit no masked handler error. No global subscriber or
runtime error handler is replaced. Processor cleanup is checked before any yield
or database read can hide delayed cancellation.

The preceding three partial-write scenarios keep every attempt, committed-row,
timestamp and no-false-completion assertion. Their lifetime assertion deliberately
changes: processing stays active after operational error, then explicit parent
cancellation cleans both scopes. Unit tests retain known-lease-loss cancellation,
pending-renewal progress, deadlines, later success/error observation and prompt
cancellation after renewal error. No baseline case is deleted to make parity pass.

## Remaining gates

This is actual worker/handler and durable-outcome evidence with controlled
processors, not authoritative provider effects or published migration-schema
equivalence. Full native processor/provider/privacy/readiness and all-consumer
parity must still be proved before routing the worker or deleting Python.
Configured hosted Linux execution, exact-head required checks and normal protected
landing remain mandatory. No deployment, release dispatch, dependency pin,
production change or consumer cutover is part of this patch.

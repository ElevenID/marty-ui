# Final-attempt provider crash reference

Status: two independent published-process captures agree and the mandatory
regeneration gate passes locally; native final-attempt replay qualified at
`e959e113d` (CI34041341592 and RustCodeQL34041341506).
This is not a cutover, Python deletion or deployment qualification.

The existing renewal/recovery process owner, real HTTPS fixture, official schema
and encrypted OAuth fixtures are reused. A queued job with historical attempt
count 7 of 8 is inserted into an empty queue before any worker starts. Those
seven earlier attempts are fixture history, not executed evidence. The actual
published worker leases attempt 8 and makes one authenticated HTTPS request.

With that response held, the real 30-second lease and both heartbeats must
advance while job identity, attempt, owner and original start remain unchanged.
Only the owned worker is killed. After actual PostgreSQL lease expiry, another
worker must dead-letter the same job with `canvas_worker_lease_expired`, clear
its lease, preserve attempt count 8 and disable the target. There must be no
second provider request, no fact issuance and no changes to existing issued
rows or encrypted token bytes. A fresh idle heartbeat distinguishes the
restarted worker. The original job ID and start time remain unchanged.

No running lease, attempt, timestamp, outcome or clock is edited. The raw crash
exit is -9 and the idle restarted worker exits -2 after SIGINT. These exit
observations do not by themselves prove application disposal.

Independent raw captures have identical SHA-256:
`70c4ab0e515f95bf330740b77d233d2689e6c5f7679e7bea1d943d9e7087f226`.
The frozen artifact preserves tokens with whitespace-only formatting. Required
configured test `worker_provider_final_reference_matches_published_process`
regenerates the reference from the immutable published image.

Local verification: all 17 selected configured worker entries pass in 220.22
seconds (36 unrelated entries filtered), including all seven reference/startup
gates and two comparison unit tests. The eight native Linux parent/helper
entries are not Windows runtime proof. All 60 affected Python tests pass in
3.60 seconds; strict Clippy, Rustfmt, Ruff, Bash syntax and diff checks pass.

The shared reference helper retains the original renewal and nonfinal recovery
cases; their frozen artifacts must not change to accommodate this extension.
Native replay retains and explicitly tests Rust's internal target-generation
fence, rather than removing it to match Python's empty stored result.

## Native replay

The mandatory `worker_provider_final_matches_frozen_published_process` parent
uses the existing real HTTPS owner and a separate native child on the official
schema. The child seeds the same historical queue before startup, observes
actual renewal, kills its owned process, waits for real expiry and starts the
reclaimer. It requires fresh idle dead-letter state at attempt eight, disabled
target, preserved original job/start, no facts and unchanged issued rows and
ciphertext. The parent checks the single exact authenticated provider request.

The shared state comparison permits only the known native integer generation
in addition to the full published projection. For a dead-letter exception it
requires lease-expiry classification, exhausted attempts, completed state and
both lease fields cleared. Negative tests reject missing, wrong, string or
extra generation data, unrelated status/errors, unexhausted attempts, active
leases, incomplete results and unrelated OAuth changes. Successful terminal
results and the existing changed-target repository fence remain strict.

Local native validation: three exact-comparison tests and all 60 affected Python
tests pass; the native executable compiles and strict Clippy passes. This does
not replace mandatory Linux execution of the actual process and HTTPS scenario.

Linux job 101508565579 at `e959e113d` explicitly records final-attempt recovery
with one actual HTTPS request, retained renewal/recovery and all three signals,
and all 56 configured tests passing in 841.38 seconds. The separate 0.25-second
unconfigured run is not runtime proof. Later extensions require fresh checks.

Concurrent reclaimers/schedulers, changed-target generation, owner-fence loss,
completion races and full consumer deployment remain separate requirements in
the [cutover inventory](canvas-worker-cutover-readiness.md).

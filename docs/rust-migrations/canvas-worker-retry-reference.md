# Actual worker retry and rejection reference

Status: independent published reference frozen; native adoption qualified on
Linux at `32ec0902969aec4d404a7d7d4b7b485a35f3a21f`. CI34036161060 and
Rust CodeQL34036161086 passed. Configured job101494520922 explicitly records
five native retry, sixteen all-fact and four original REST requests, with all
44 tests passing in 653.61 seconds. Its earlier unconfigured 0.38-second run
is not runtime evidence. Later changes still require fresh exact-head checks.
The existing composed worker/HTTPS/OAuth/published-schema owners are reused.

Five processes exercise three durable jobs:

1. Positive evidence succeeds normally.
2. A second job receives HTTP 429 with Retry-After: 2. Its first-attempt backoff
   remains within 15–20 seconds, and the existing evidence is retained.
3. After the database says that exact job is due, a new worker retries it and
   succeeds on attempt 2. Its identity is unchanged, old error fields clear, and
   the new negative evidence opens a correction review without altering issuance.
4. A third job receives 503, preserves the evidence/review and schedules retry.
5. After that exact job becomes due, its second attempt receives 401 with the
   Bearer challenge. The grant becomes reauthorization_required while facts,
   review, full issued rows and token ciphertext remain unchanged; the job retries.

The fixture never edits retry availability, attempt counts, job status, leases,
or the application clock. It waits on actual PostgreSQL eligibility before each
retry, with a 30-second watchdog, and verifies the entire ordered job-ID list is
unchanged. Expected job/attempt counts are static scenario inputs used to avoid
mistaking an earlier idle state for completion. Raw SIGINT remains -2 (native 130).

## Reference fidelity and limits

Final independent captures match byte-for-byte with SHA-256
`d51296ff3173aad7245e1cb3ca76020debb166fc66571d6e260e2ee0310cb86b`.
Whitespace-only formatting preserves every token, including floating-point values.
No native observations supplied expectations; prior corpora are unchanged.

Because backoff is randomized, observations check its permitted range rather
than freeze a sampled delay. The first/second attempt bounds are 15–20/30–40 seconds,
with an explicit 0.1-second allowance for separate database timestamp evaluations.
The older corpus's exact 37-second flag was deliberately excluded from this new
projection before qualification: 37 is a possible random second-attempt delay,
not this scenario's retry requirement. Earlier preliminary capture A is diagnostic
only; final captures C/D use the stable range projection. No jitter source or
transport policy is mocked or weakened.

`worker_retry_reference_matches_published_process` is required by the configured
CI runner. Reference validation passed 7 entries in 75.92 seconds: all
three reference regenerations and startup, plus three Linux-only parent/helper
entries that do not establish native HTTPS execution on Windows. The 36 unrelated
entries were filtered here; fresh full Linux CI remains required. Strict lint,
formatting, Bash syntax and 53 affected Python tests passed.

Native adoption reuses the same process, HTTPS, database and OAuth owners as the
qualified assignment/all-fact replays. A third static scenario waits on actual
retry eligibility, compares the job-ID list, requires the expected attempt count,
and preserves all original durable-state and issued-row assertions. The new
`worker_retry_matches_frozen_published_process` parent is mandatory in full Linux
CI; compilation is not an execution pass. Neither frozen expectations nor runtime
behavior were changed to implement this replay.

This proves neither every retry/header form nor OAuth refresh/remote revocation,
active-I/O shutdown, lease races or full privacy behavior. Continue the complete
[worker cutover inventory](canvas-worker-cutover-readiness.md). No runtime code,
feature, consumer selection, dependency or deployment changes in this reference.

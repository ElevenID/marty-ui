# Actual worker retry and rejection reference

Status: independent published reference frozen; native adoption pending.
The existing composed worker/HTTPS/OAuth/published-schema owners are reused.

Five processes exercise three durable jobs:

1. Positive evidence succeeds normally.
2. A second job receives HTTP429 with Retry-After2. Its first-attempt backoff
   remains within15–20seconds, and the existing evidence is retained.
3. After the database says that exact job is due, a new worker retries it and
   succeeds on attempt2. Its identity is unchanged, old error fields clear, and
   the new negative evidence opens a correction review without altering issuance.
4. A third job receives503, preserves the evidence/review and schedules retry.
5. After that exact job becomes due, its second attempt receives401 with the
   Bearer challenge. The grant becomes reauthorization_required while facts,
   review, full issued rows and token ciphertext remain unchanged; the job retries.

The fixture never edits retry availability, attempt counts, job status, leases,
or the application clock. It waits on actual PostgreSQL eligibility before each
retry, with a30second watchdog, and verifies the entire ordered job-ID list is
unchanged. Expected job/attempt counts are static scenario inputs used to avoid
mistaking an earlier idle state for completion. Raw SIGINT remains-2 (native130).

## Reference fidelity and limits

Final independent captures match byte-for-byte with SHA-256
`d51296ff3173aad7245e1cb3ca76020debb166fc66571d6e260e2ee0310cb86b`.
Whitespace-only formatting preserves every token, including floating-point values.
No native observations supplied expectations; prior corpora are unchanged.

Because backoff is randomized, observations check its permitted range rather
than freeze a sampled delay. The first/second attempt bounds are15–20/30–40seconds,
with an explicit0.1second allowance for separate database timestamp evaluations.
The older corpus's exact37second flag was deliberately excluded from this new
projection before qualification:37 is a possible random second-attempt delay,
not this scenario's retry requirement. Earlier preliminary captureA is diagnostic
only; final capturesC/D use the stable range projection. No jitter source or
transport policy is mocked or weakened.

`worker_retry_reference_matches_published_process` is required by the configured
CI runner. Local affected-worker execution passed7entries in75.92seconds: all
three reference regenerations and startup, plus three Linux-only parent/helper
entries that do not establish native HTTPS execution on Windows. The36unrelated
entries were filtered here; fresh full Linux CI remains required. Strict lint,
formatting, Bash syntax and53affected Python tests passed.

This proves neither every retry/header form nor OAuth refresh/remote revocation,
active-I/O shutdown, lease races or full privacy behavior. Continue the complete
[worker cutover inventory](canvas-worker-cutover-readiness.md). No runtime code,
feature, consumer selection, dependency or deployment changes in this reference.

# Actual provider renewal and process-loss recovery

Status: independent published-process reference captured twice and regeneration
gate passed locally; native adoption open. No cutover, reachable Python
deletion or deployment follows from this work.

The existing owned HTTPS, published-schema, worker process and encrypted OAuth
fixtures are reused. Both cases configure the supported minimum 30-second lease
and hold a real authenticated provider response until actual renewal is observed.
The lease expiry, target heartbeat and worker heartbeat must all advance while
job ID, attempt, owner and original start remain unchanged. The before/renewed
business projections and full issued rows/token ciphertext must be unchanged.

The renewal case then releases the response and requires the same job to succeed.
The recovery case kills only the owned worker after renewal, leaving the response
held until that process exits. It waits for PostgreSQL to report real lease expiry,
starts another worker and observes `canvas_worker_lease_expired` with a durable
retry. No second provider request is allowed before retry eligibility. It stops
that idle reclaimer, waits for the actual 15–20-second persisted backoff, then
starts a third worker and requires the original job to succeed on attempt two.
Original `started_at`, full issued rows and encrypted token bytes are preserved.

No lease, attempt, retry timestamp, outcome or clock is edited. Fresh heartbeat
timestamps distinguish each restarted process's idle result without truncating
the heartbeat table. Raw process exits are recorded independently. Random backoff
is checked against its permitted range, not a sampled exact delay; the older
REST corpus's 37-second flag remains deterministically false for this first-attempt
recovery backoff. All earlier frozen scenarios and observations remain unchanged.

Independent capture pairs match byte-for-byte:

- Renewal: `ca6d7f7d83944db8de5b3a77e381957886d5f3e44812af18bbe95355dabde890`
- Recovery: `8d5183b4bcd1cd7e96f0e54c5eefeee0e169ea578ea5a2635f47f39caede3ea5`

The combined reference retains every token, including floating-point evidence
values, using whitespace-only formatting. Required configured test
`worker_provider_recovery_reference_matches_published_process` regenerates both
cases independently. One provider request is observed for normal renewal and two
for recovery. SIGKILL is raw -9; idle reclaimer/completed-worker SIGINT is raw -2.

All 12 selected configured worker entries passed in 175.25 seconds, with 36
unrelated entries filtered: six reference/startup gates execute here; six native
Linux parent/helper entries are not Windows runtime proof. All 57 affected Python
tests pass, as do strict Clippy, formatting and CI Bash syntax. Hosted exact-head
qualification remains required, including correction of the preceding signal
gate's separately identified native generation-metadata comparison.

This qualifies only the captured cases once their mandatory gates pass. It is
not evidence of final-attempt crash handling, concurrent reclaimers/schedulers,
owner-fence loss, target-generation mutation or finally/disposal execution. Keep
those requirements in the complete worker cutover inventory; do not infer them
from an owned process exit or a successful normal renewal.

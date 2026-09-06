# Actual competing reclaimers preserve retry and eventual success

Status: two independent published-process captures agree. The mandatory reference
regeneration gate and all selected worker regressions pass locally.
Native replay is implemented and awaits Linux qualification. This is not
whole-worker or deployment acceptance.

The actual published worker schedules and leases attempt one, begins authenticated
HTTPS I/O, and renews its lease and both heartbeats. After forced process loss,
the fixture waits for real lease expiry. It never edits running job attempts,
timestamps, leases or outcomes, and does not seed final-attempt history.

Two actual replacement workers must be observed waiting at the shared job-table
barrier before release. The same job then enters durable retry on attempt one
with its lease cleared and the classified lease-expired error. Both workers must
remain alive and report fresh idle heartbeats. The full job, OAuth and issuance
projection is checked again after both heartbeat observations; no additional
provider read may occur at this boundary.

Both reclaimers are interrupted and reaped. Only after the persisted retry delay
really expires does a successor start. The original job succeeds on attempt two,
creates exactly one fact, and preserves its original start, issued rows and token
ciphertext. The target remains enabled. Exactly two authenticated provider reads
occur across the entire sequence. Raw process exits remain SIGKILL -9 and SIGINT
-2, with the existing native signal mapping retained for later replay.

Independent raw capture SHA-256:
`769081f69726ff67c50b1281497bd714031d0ac2f80014905f5887f8713e9992`.
The frozen reference preserves every token with whitespace-only formatting,
including floating-point tokens. The configured test
`worker_reclaimers_retry_reference_matches_published_process` regenerates the
observation using the pinned published image and isolated database. CI requires
that exact test to exist before executing the configured suite.

The implementation extends the existing recovery owner. It shares only the
allowlisted worker identities, barrier queries and heartbeat projection from the
final-reclaimer scenario; it must not inherit that scenario's historical attempt
seed. The common heartbeat observer is used at the retry boundary here and the
terminal boundary in the final-attempt case. Existing frozen artifacts stay
unchanged and require regeneration after this extraction. Process cleanup and
barrier rollback retain their existing owners and failure tests.

Changed-target/owner-fence loss, final-completion races, disposal, native qualification
and every other open [cutover requirement](canvas-worker-cutover-readiness.md)
remain separate. No production or persistent self-host changes are made.

Local verification: 27 selected configured worker entries pass in 329.06 seconds
(36 unrelated entries filtered): ten reference/startup gates, three strict
comparison units, and fourteen native Linux parent/helper entries. The latter
are not Windows runtime qualification. All 68 affected Python tests pass in
3.36 seconds; strict Clippy, Rustfmt, Ruff, Bash syntax and diff checks pass.
The earlier frozen worker artifacts remain unchanged and regenerate successfully.

## Native replay

The mandatory native parent/child extends the shared recovery replay. Only
contention settings are reused from the final-reclaimer scenario; its historical
seed is explicitly excluded. Both fresh idle heartbeats and the full retry
projection are checked before the contender is interrupted. Taking ownership
out of its optional slot ensures the later successor-completion check cannot
mistake the already-reaped contender for a live replacement worker.

The HTTPS parent observes exactly one request at the retry boundary before
acknowledging successor restart. Actual persisted backoff must expire, then the
same job must succeed on attempt two with exactly two requests and an enabled
target. Internal generation one is checked exactly for leased/retry state;
successful terminal results and all other state remain strict comparisons.

The new parent's pre-restart acknowledgment deadline is 110 seconds, covering
the child's existing bounded real-expiry, barrier, idle, second-heartbeat and
contender-exit checks. Its final communicate bound is 150 seconds, as for the
dual-final reclaimer. Existing cases and individual assertions are unchanged.
Process RAII, barrier rollback and all fixture cleanup owners remain intact.

Local native compilation and all three strict comparison tests pass (62 other
entries filtered); 68 affected Python tests pass in 3.59 seconds. Strict Clippy,
Rustfmt, Ruff, Bash syntax and diff checks pass. The next configured Linux suite
contains 65 entries; that new exact-head runtime result remains pending.

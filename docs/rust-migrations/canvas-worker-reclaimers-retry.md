# Actual competing reclaimers preserve retry and eventual success

Status: two independent published-process captures agree. The mandatory reference
regeneration gate and all selected worker regressions pass locally.
Native adoption remains open. This is not whole-worker or deployment acceptance.

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

Changed-target/owner-fence loss, final-completion races, disposal, native replay
and every other open [cutover requirement](canvas-worker-cutover-readiness.md)
remain separate. No production or persistent self-host changes are made.

Local verification: 27 selected configured worker entries pass in 329.06 seconds
(36 unrelated entries filtered): ten reference/startup gates, three strict
comparison units, and fourteen native Linux parent/helper entries. The latter
are not Windows runtime qualification. All 68 affected Python tests pass in
3.36 seconds; strict Clippy, Rustfmt, Ruff, Bash syntax and diff checks pass.
The earlier frozen worker artifacts remain unchanged and regenerate successfully.

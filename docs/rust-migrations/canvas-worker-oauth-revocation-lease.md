# Actual OAuth revocation lease bounds

Four actual published-worker captures measure committed acquired leases for
configuration inputs -1, 120, 301 and 999999999999999999999999 seconds. Each
process acquires three eligible connections and stores leases of 30, 120, 300
and 300 seconds respectively. Independent captures match exactly (20.37s and
20.02s); frozen regeneration passes in 20.85s.

Frozen oracle canonical LF SHA256:
`6283dc55201a3214b908432f58181af487999233ab995d4488ab04b06751620e`.

The lease matrix inherits the existing queue matrix, which inherits the original
revocation seed. Only this matrix extends the test-only acquisition journal to
store NEW.refresh_lease_expires_at and NEW.updated_at at actual acquisition.
Every duration must match the case expectation within 0.1 seconds. No clock or
running lease is rewritten. Original queue and prior reference artifacts remain
unchanged. The same journal, SQL snapshots, encrypted vault, process and HTTPS
owners serve reference and Rust replay.

The oversized configuration needs a precise boundary: OAuth revocation completes
its three retry writes with capped leases, but the later ordinary job-leasing
stage cannot represent the huge duration. Existing consumer-range evidence
separately records that failure. Initial captures waiting for idle timed out;
the reference was not discarded or relabeled as a successful whole cycle.
For this case only, the capture requires all three real acquisition records and
owner-released retry writes, observes the actual oauth_revocation heartbeat,
then stops the owned process. It does not assert idle or prove the later error
class. The three ordinary cases still require actual idle. Rust uses the same
explicit completion predicate and compares the observed heartbeat in full.

All four cases retain actual three-request HTTPS evidence, all encrypted secrets,
issued rows and complete unchanged unselected connections. Nested matrix loading
rejects cycles and nonlocal paths. Lease evidence controls reject missing values,
wrong counts, out-of-bound values, strings, booleans and nonfinite numbers.
Database-only imports remain scoped to execution so these pure harness controls
do not add a dependency to the lighter release-contract test lane.

Two permanent configured entries bring the suite to 86. Native replay compiles
and strict all-target Clippy passes; hosted Linux process qualification remains
pending. No runtime, crypto adapter, consumer or feature is changed by this
extension. The exact nonempty 500-row selection cap, returned cycle counters and
secret-resolution composition remain separate named gaps in the
[coverage audit](canvas-worker-oauth-revocation-coverage-audit.md).

Local Python regression: 976 passed, one existing opt-in skip, 41.37 seconds.
Strict all-target Clippy passed in 2.25 seconds. No native Linux parity is inferred
from these checks or from Windows-only early returns.
The final seven-matrix sweep passed in 163.92 seconds: all 29 actual published
reference cases and the real repository selection regression matched. Eight of
the 16 top-level entries returned early on Windows and are not parity evidence.

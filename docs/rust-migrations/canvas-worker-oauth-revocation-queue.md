# OAuth revocation queue parity

Qualification update: Both native queue cases and the real repository order comparison
passed at e70e3abccd83b4f6893ea655f9a97b000aa97e54 (CI34074425466,
90 configured tests in 1960.69s; all applicable exact-head checks passed).
This supersedes the initial pending status recorded below, not the scoped
evidence limitations. Later secret/generation additions remain unqualified;
see the [current audit](canvas-worker-oauth-revocation-coverage-audit.md).

Two independently matching published-worker captures freeze actual lease order
for batch sizes 3 and 25 across eight connections: dated due retries, an undated
connection, future retry, connected status, an active lease and an expired lease.
The reference processes dated retries first and the undated connection last.
The limited batch leaves that undated connection untouched.

Frozen oracle canonical LF SHA256:
`88e877702779ca03687d3d36b550f182333a7697ba0d71376b783052c5398a88`.

This exposed a real Rust discrepancy: `NULLS FIRST` selected the undated
connection before the older retries. The real repository regression failed
against the captured order before the scoped correction to `NULLS LAST`.
No credential, consumer, crypto adapter or live Python capability is removed.

The fixture uses the existing owned published-schema database, encrypted vault,
worker process and HTTPS owner. A test-only AFTER UPDATE trigger records actual
committed lease acquisitions; it does not implement a scheduler. Both replays
compare every request and the complete portable connection projection. Every
unselected row is compared exactly before/after, including timestamps and secret
references. Every selected row must have its actual one-day retry deadline;
all three ciphertexts, issued rows and zero-job state remain unchanged.

The published schema rejects a lease owner without an expiry. An initial seed
attempt violated that constraint and was corrected to a valid unleased row;
the constraint was not dropped. No impossible-schema case is claimed as parity.

Static matrix selection and fixture preparation are shared between native
process replay and the real repository regression. The reference and native
process entries plus repository regression bring the configured suite to 84
entries. Hosted Linux process qualification remains pending; local repository
success is not a substitute for native HTTPS/worker evidence.

Local checks: repository regression failed before the fix, then passed in 3.55
seconds; frozen two-case reference regeneration passed in 10.55 seconds.
All 24 Rust behavior tests and strict all-target Clippy passed. Python passed
960 tests with one existing opt-in skip in 53.60 seconds.
The final revocation sweep passed in 141.34 seconds: all six published matrices
(25 actual reference cases) regenerated unchanged, and the real repository
regression passed. The other seven top-level entries returned early on Windows
and are explicitly not counted as native whole-process qualification.

This closes a named queue-order/eligibility and normal-batch evidence gap, not
the exact 500-row cap or acquired lease-duration boundaries. Returned retry and
fence-loss counters and secret-resolution branches remain in the bounded
[coverage audit](canvas-worker-oauth-revocation-coverage-audit.md).

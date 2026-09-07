# Deployed worker logging configuration

The consumer audit found a feature-preservation gap: Base Compose and self-host
pass `LOG_LEVEL`, and the immutable Python worker uses it in `logging.basicConfig`.
The Rust candidate previously read only `RUST_LOG`, silently retaining INFO when
the operator selected DEBUG or another deployed level.

The new reference executes the exact AST-extracted published logging expression
without importing the worker or replacing its code. Sixteen inputs cover the
default, every standard named Python level and aliases, empty/lowercase/padded/
numeric/unknown values. The four worker severities are observed, not reimplemented
in the capture. Source SHA256 matches the immutable startup reference. Independent
regeneration through the permanent isolated-image runner matches the full artifact.
This is configuration evidence, not whole-worker or production log qualification.

The native replay first failed on DEBUG: INFO filtering suppressed the expected
debug level. The Rust correction uses one selection helper before secret or
database setup. It preserves case-sensitive `LOG_LEVEL` acceptance and rejects
invalid settings with a static diagnostic that does not echo the operator value.
`WARNING`/`WARN` select warn; `NOTSET` leaves all worker severities enabled.
`CRITICAL`/`FATAL` suppress the four ordinary worker severities, matching Python;
Rust has no distinct critical/fatal event level. A valid explicit `RUST_LOG`
directive retains precedence, including module-specific filters. Invalid Rust
directives fall back to the deployed setting, or INFO when it is absent.

All seven worker binary tests pass, including the sixteen-case threshold replay
and explicit Rust-directive controls. All three executable smoke tests pass,
including seven actual child-process failures with exactly the static error and
no operator-value output (2.67s). Existing API health/readiness/version and disabled
gRPC checks are retained. Strict all-target Clippy passes (2.43s).
The final full Python suite passes 1,032 tests with one existing opt-in skip
(40.53s after the final image-default correction). The first full run caught an omitted ninth-case name in the preflight
inventory test; that inventory was corrected without removing any prior case.
Ruff and patch checks pass.

CI regenerates the immutable reference and adds an invalid-logging packaged-image
preflight case, retaining all eight prior cases and all 24 startup cases. The new
image gate requires the updated image to fail before secret setup without echoing
the synthetic invalid value. Final image review also found that the dedicated
issuance CI image baked in `RUST_LOG=info`, which would mask the deployed setting.
That redundant image default is removed only from issuance: both binaries retain
their INFO fallback and explicit operator Rust directives still take precedence.
An inventory assertion prevents reintroducing the hidden override; the shared
production Dockerfile has no such override. Native filtering is exercised by the real tracing
subscriber; neither Windows unit checks nor the reference-expression capture is
claimed as complete Linux worker execution. Fresh exact-head CI and the nine-case
image gate remain required. No deployment definition or persistent service changed.

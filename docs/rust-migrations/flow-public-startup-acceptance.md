# Flow actual-main acceptance

This slice launches the same-build `marty-flow` executable after bounded canonical
secret-loader capture with actual rendered base-native configuration. Only a
closed roster of endpoints/database/listeners is rebound to exact-owned fixtures.
The actual main migrates the previously absent Flow schema, connects PostgreSQL,
Redis, four gRPC channels and six HTTP health boundaries, then activates its twelve
required readiness components. Dependency peers are synthetic; native issuance
admission and both PostgreSQL repositories are real.

The gate exercises public service HTTP start, artifact read and QR retry, missing
principal and foreign-tenant membership refusal, authenticated actual Flow gRPC
health and missing/wrong-token refusal. Complete stored projections are compared;
denials and failed startup preserve scoped durable state. A configured, counted
legacy RPC trap must remain unused. Physical-document HTTP remains legacy, with
its two real startup health calls; the existing complete seven-operation physical
gate is retained separately. Child output/deadlines and cleanup are bounded using
the existing owned-process helper. No operator environment, deployment, KMS or
production configuration is changed.

The first actual-main run found a Rust QR retry defect: the HTTP handler supplied
a later replacement time but the shared retry preparation left the instance's
timestamp unchanged, so the repository correctly refused its CAS binding and
the public call returned 503. The narrow runtime repair advances `updated_at`
only after successful offer preparation. Repository CAS checks and the caller's
monotonic timestamp selection remain intact. The unit regression passes an
unchanged input, and the prior PostgreSQL consumer test no longer pre-advances
the timestamp (which had masked the public caller's bug).

The first Windows run also found that Git sh `exec` retained a separate Flow
process after the shell was reaped. The earlier shell-terminal observation did
not prove native-child cleanup. That exact leftover PID was identity-checked and
removed. The corrected harness captures only declared synthetic environment via
the unchanged loader, then starts Flow directly with no wrapper arguments. It
prints the exact owned PID, verifies its terminal handle, joins its output monitor,
and on Windows checks the executable image lock is released (open-only, no write).
Loader tests preserve multiline/equal/quote values and actual file-alias removal;
direct-child output/early-exit controls remain mandatory. No operator environment
or operator secret values are captured; synthetic loaded values are never logged.
The older finite rendered-provider helper is retained separately; its shell-exec
timeout path is not claimed to provide universal descendant-process cleanup.

Local Windows qualification passed with Rust 1.95.0, Python 3.12 and pinned
Compose 5.4.0: the exact actual-main gate (12.76 s), retained PostgreSQL consumer
gate (5.53 s), retained rendered provider-selection gate (9.98 s), three loader/
process controls, three Flow side-effect tests, strict issuance lib/tests and
Flow lib/side-effect-test Clippy, and 141 repository guards. The current Flow
binary was rebuilt before the configured run. Both logged main PIDs and all
seven exact-owned PostgreSQL/probe/Redis container IDs were independently verified
absent after execution. Linux execution remains required in the hosted gate.

Passing this gate is **not** production image or deployed acceptance. Its remaining
stages are explicit: real gateway JWT/auth forwarding, actual callback-worker
delivery, selfhost workload TLS handshakes, and exact release-image boot through
the unchanged packaged entrypoint/non-root secret-file boundary. The test's
direct service `X-User-ID` boundary is not represented as external authentication.
The sibling binary path and CI executable prerequisite identify the expected
same-build artifact; file existence alone is not authenticated source provenance.
Presentation-policy is a real eager channel connection here, not a policy RPC
behavior claim. Output files are monitored every 25 ms throughout child life and
oversize terminates the owned child; this is sampled enforcement, not a filesystem
quota. Process shutdown proves bounded terminal cleanup, not graceful-drain parity.

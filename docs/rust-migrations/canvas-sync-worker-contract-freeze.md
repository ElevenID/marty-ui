# Canvas synchronization worker contract freeze

Status: language-neutral behavior inventory frozen; Rust implementation intentionally not started.

The normative contract is
`contracts/issuance-canvas-sync-worker.json`. It pins the protected
`ElevenID/marty-credentials` tree at
`cbda2ac7e3376b858c1e8d5d010a304474c659cf`. The pins cover every identified
worker-reachable behavior owner: the worker and processor, rollout flags,
OAuth, evidence revision and policy services, domain entities and ports,
Canvas routes and signing context, PostgreSQL adapter and models, the portable
Canvas migration, integration-secret encryption, and eight Python oracle test
files. Git object IDs make later source movement visible before the deletion
boundary can change.

## Normative behavior versus legacy wiring

The replacement contract is state-, provider-, persistence-, privacy-,
liveness-, and shutdown-oriented. A Rust executable does not have to preserve
Python module names, imports, commands, framework types, or SQLAlchemy call
shapes. `legacy_python_wiring` records those strings only so cutover cannot
leave a Python consumer behind.

Deployment wiring is frozen separately. Compose uses the headless
`canvas-sync-worker` service in the base and self-host production definitions,
with both migration jobs as successful startup dependencies. Kubernetes has
its own Deployment command and args, ConfigMap, three secret inputs, literal
signing-service URL, and an ordering gate that applies and waits for issuance
migrations before microservices. Contract tests inspect both forms rather than
assuming they are interchangeable.

Python's `postgresql+asyncpg` URL rewrite and SQLAlchemy pre-ping,
`pool_size`, `max_overflow`, and parameter-hiding switches are recorded only
as legacy wiring. The replacement requirement is language-neutral: accept the
PostgreSQL URLs supplied by deployment, bound connection creation, detect
unusable connections safely, and redact connection and bind parameters.

## Whole-worker boundary

The Rust replacement must retain all of the following before Python deletion:

- the headless scheduling loop, bounded configuration, interruptible shutdown,
  engine disposal, durable heartbeats, and OAuth revocation polling;
- due-target scheduling, idempotent one-active-job conflicts, setting
  `last_enqueued_at` even on an insert conflict, and setting `next_run_at` to
  `now + max(60, schedule_seconds)` while counting only inserted jobs;
  concurrent leasing, renewal generation fences, crash reclaim,
  final-attempt races, backoff, Retry-After, and dead-letter behavior;
- target validation, rollout gates, secret rejection, configuration-version
  fencing, the closed processor result/error-code set, no-signing invariant,
  and bounded durable and log projections;
- exact private-origin and self-managed-origin allowlists, fail-closed DNS,
  validated-IP connections retaining Host and TLS SNI, no proxy, no redirect,
  same-origin pagination, and provider bounds and error mapping;
- DID-mediated RS256 LTI signing through `SIGNING_KEYS`, exact verification
  method matching, public-only JWKs, local readiness verification, and no
  private routing identifiers;
- the existing standard-base64 `nonce[12] || AES-256-GCM ciphertext || tag[16]`
  integration-secret format with empty AAD and a 32-byte decoded master key;
- learner evidence reconciliation, immutable idempotent revisions, newer-head
  selection, policy evaluation, and the correction-review lifecycle in one
  transaction;
- one open correction review per application, manual-action claim fencing,
  lifecycle-before-finalize ordering, recovery during an active claim, claim
  release on failure, and evidence/review audit events;
- background roster identity joining, stable cursor continuation, candidate
  and observation reconciliation, and the 90-day post-issuance drift window;
- all existing PostgreSQL tables, tenant keys, constraints, indexes,
  projections, ciphertext access, and migration ownership.

The executable fixtures specify the expected case sets for scheduler conflicts,
PostgreSQL reclaim and final-attempt races, renewal fence loss, shutdown and
disposal, Retry-After formats and bounds, and log redaction. They are
implementation-independent inputs for both the Python oracle and Rust
candidate; they do not encode Python imports as a Rust contract.

Two security properties are deliberate improvements, not claims about current
Python parity. The signing client bounds text error detail at 500 characters
but currently leaves JSON string/object detail unbounded. Worker
`logger.exception` calls can also emit exception messages and tracebacks. Add
Python hardening and oracle coverage for bounded serialized signing detail and
allowlisted structured logging before treating the shared redaction fixtures
as a cross-language deletion gate.

## Existing Rust ownership

The migration must extend or refactor the already-landed Rust
`canvas_oauth`, `canvas_oauth_postgres`, `integration_secret`, and Canvas
readiness components. It must not create parallel OAuth, cipher/vault, or
readiness implementations.

There is one deliberate parity decision to test. Python's pending-revocation
worker has typed failure codes, a larger exponential cap, jitter, and a
24-hour delay cap. Current Rust disconnect is request-path-only, uses a generic
error, a smaller cap, and has no due queue. Python deletes the fenced
connection, best-effort patches the platform, then deletes secrets outside the
transaction. Rust atomically deletes the tenant-scoped connection and secrets,
then patches the platform. The worker should add Python's due selection,
leasing, typed retry behavior, and external projection while retaining Rust's
stronger atomic tenant-scoped cleanup. Differential tests must explicitly
approve that ordering improvement.

## Remaining gate

The current Python suite is useful but is not yet a complete deletion oracle.
Before Rust implementation begins, add the gaps enumerated in
`migration_gates.legacy_oracle_gaps`, including configuration/loader failures,
loop cancellation, database races, privacy projections, all validation and
processor shape failures, OAuth failure paths, cursor continuation, and all
four fact assertion projections. Verify every Python and Rust provenance pin,
then run the same language-neutral fixtures against the Python oracle and Rust
candidate with fresh PostgreSQL and bounded provider simulators.

Delete Python only after whole-worker differential and failure parity,
migration evidence, every Compose/self-host/Kubernetes consumer cutover,
readiness parity, and beta-only acceptance and soak pass. Production and
persistent self-host remain unchanged without a separate promotion decision.

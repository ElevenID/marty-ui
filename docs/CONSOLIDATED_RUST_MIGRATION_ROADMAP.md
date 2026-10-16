# Consolidated Rust Migration Roadmap

Status: retained ownership and qualification requirements, 2026-10-16.
The migration implementation waves have landed. Source migration, released
artifacts and installed product acceptance are separate decisions; completed
wave/PR/run logs are available in Git history.

## Objective

Reduce the amount of Python and other non-Rust protocol code in the Marty stack by replacing it with a single authoritative Rust implementation for each capability. The migration must preserve externally observable features and behavior, improve fail-closed security, and remove superseded Python or Dart implementations after each cutover.

This is not a line-for-line translation project. Rust owns deterministic protocol, policy, validation, cryptographic, and state-machine behavior. Python remains only where it is useful for API composition, persistence adapters, scheduling, OCR, and third-party integrations until a whole service is deliberately replaced. Flutter/Dart remains responsible for application UI and platform integrations.

The immediate deployment boundary is beta. Production and persistent self-host environments are not changed by this roadmap without a separate approval and promotion decision.

## Non-negotiable outcomes

1. There is exactly one maintained implementation of each migrated kernel, written in Rust.
2. Python and Dart callers use that implementation through generated or deliberately thin bindings; they do not reproduce its decisions.
3. Existing REST, gRPC, event, storage, and mobile-facing contracts retain feature parity unless a versioned change is explicitly approved.
4. Required native code fails closed. Production-like environments never silently fall back to Python, Dart, permissive defaults, `None`, empty results, or mock validation.
5. Superseded source, tests, dependencies, feature flags, and fallback branches are deleted as soon as implementation-independent behavioral, failure, ownership, packaging, and regression gates pass.
6. Rollback selects a previous deployable image or release. Runtime fallback to a second implementation is not an accepted rollback mechanism.

## Architecture and ownership

The canonical implementation must live at the lowest reusable Rust layer. A binding, service, or application may adapt inputs and outputs, but it must not fork the algorithm.

The machine-readable ownership inventory is
[`rust-migration-ownership.json`](rust-migration-ownership.json). CI validates
its schema, exact production Python crypto-import baseline, and source rules
that prevent unsigned token decoding or direct native binding surfaces from
being added. Every migration PR that removes an approved non-Rust import must
shrink the manifest in the same change; stale allowances fail CI.

| Capability | Canonical owner | Consumers | Consolidation rule |
|---|---|---|---|
| Cryptography, document verification, presentation policy, status lists, OIDC validation, device proof, DID/JWK utilities | `marty-core` | Python services, credential packages, wallet, Rust services | Public reusable kernels live in one `marty-core` crate or module and are re-exported rather than copied. |
| Credential bindings | `marty-credentials` and canonical Core binding crates | Native and WASM callers | Compose `marty-core`; retired Python service/SDK packaging is not a runtime owner. |
| Service transport and storage orchestration | Owning service repository, primarily `marty-ui` | Deployed backend | Rust service binaries may own HTTP/gRPC/event and repository adapters, while shared decision logic stays in `marty-core`. |
| Mobile protocol handling | `marty-core` exposed through Flutter Rust Bridge | `marty-authenticator` | Dart owns UI, camera, deep links, and platform APIs; Rust owns protocol parsing and verification. |
| License verification and entitlement evaluation | `marty-subscriptions/packages/verifier_entitlements/marty-license` | Backend and packaged applications | Extend the existing private Rust crate and remove equivalent Python evaluators. |
| Legacy compatibility | `Marty` adapters only | Older callers during migration | Compatibility code may translate contracts temporarily but may not contain an independent kernel. Delete it when callers move. |

### Binding surfaces

- Python uses the existing `_marty_rs` package as the preferred public native surface. Additional extension modules require an explicit reason and shared error/version conventions.
- Flutter uses generated Flutter Rust Bridge bindings from canonical crates. Hand-written Dart protocol implementations are not compatibility layers.
- Rust services depend directly on canonical crates through pinned workspace or released dependencies.
- Every binding exposes backend name, semantic version, build revision, enabled features, and a readiness result.
- Native errors map to stable, normalized service error codes. Binding-load failure and invalid native operations are typed errors.

## Contract-preservation inventory

Before implementation begins for a workstream, its PR must capture a feature-parity matrix covering all applicable contracts:

- REST routes, methods, status codes, request/response schemas, and error bodies;
- gRPC services, methods, protobuf field semantics, deadlines, and status codes;
- produced and consumed event types, ordering, idempotency, and retry behavior;
- database schema, transaction boundaries, Redis keys, TTLs, and concurrency guarantees;
- environment variables, defaults, secret references, health checks, and readiness behavior;
- authentication, authorization, tenancy, rate limiting, and audit events;
- metrics, logs, traces, dashboards, and alerts;
- supported algorithms, credential/protocol formats, limits, and interoperability fixtures;
- mobile deep links, QR payloads, user-visible outcomes, and offline behavior where applicable.

The matrix becomes executable contract tests wherever possible. A Rust replacement is incomplete if it passes unit tests but drops an existing contract or operational behavior.

## Per-workstream migration method

Every workstream follows the same sequence:

1. **Inventory:** locate all implementations and callers; record behavior, dependencies, contracts, and test gaps.
2. **Specify:** define canonical Rust inputs, outputs, error taxonomy, resource limits, and fail-closed semantics.
3. **Vectorize:** turn current valid/invalid behavior and standards fixtures into language-neutral golden vectors.
4. **Implement once:** add the capability only to its canonical Rust owner.
5. **Bind/adapt:** expose generated or thin adapters; no business decision may be repeated in the adapter.
6. **Compare:** run differential, property, fuzz, contract, integration, and performance tests.
7. **Cut over beta:** deploy one Rust-backed path, with observability and image-level rollback.
8. **Remove:** delete the old implementation and dependencies in the same workstream or an immediately linked cleanup PR.
9. **Enforce:** add a CI rule or architectural test that prevents the duplicate from returning.

## Python/Dart deletion gate

Non-Rust implementation code can be removed only when all of the following are true, and removal is mandatory once they are true:

- every production-code caller in scope uses the canonical Rust implementation;
- shared golden vectors and differential tests pass;
- REST/gRPC/event/mobile contracts and integration suites pass;
- malformed, unsupported, unavailable-backend, and adversarial inputs fail closed;
- beta or an isolated production-like lane shows acceptable correctness, reliability, and latency;
- rollback uses an earlier image rather than an alternate implementation;
- repository search confirms no runtime imports or references remain;
- package manifests and container images no longer carry dependencies used only by the removed code;
- tests of the removed implementation are either deleted or converted into canonical Rust/binding tests;
- a CI ownership check prevents reintroduction.

Adapters that contain serialization, DTO mapping, or framework glue may remain temporarily, but they must be small enough to review as adapters and must not select trust, protocol, policy, or cryptographic outcomes.

## Test strategy

### Shared conformance and golden vectors

- Keep language-neutral fixtures in one versioned location with provenance and expected normalized results.
- Execute the same vectors directly in Rust and through every supported binding.
- Cover valid, invalid, malformed, boundary, unsupported-algorithm, missing-trust, replay, concurrency, and oversized inputs.
- Include interoperability fixtures from standards or external suites where licensing permits.

### Rust assurance

- Unit and integration tests for every public decision path.
- Property tests for parsers, encoders, state transitions, allocation, and normalization.
- Fuzz targets for untrusted JWT, CBOR/COSE, QR/deep-link, policy, DID/JWK, status-list, and license inputs.
- Resource limits for input size, nesting, decompression, collection count, and execution time.
- Dependency auditing, unsafe-code review, and reproducible release artifacts.

### Service and application parity

- Behavioral tests must target published protocols, generated schemas, fixtures,
  executable artifacts, or public APIs. They must not instantiate, mock, import,
  or inspect the implementation being replaced as proof of parity.
- OpenAPI and protobuf compatibility checks.
- Recorded-request differential tests with secrets and personal data removed.
- Database/Redis migration and concurrency tests.
- Event ordering, duplicate delivery, retry, and reconnect tests.
- Mobile integration tests for QR routing and user-visible outcomes.
- Fault injection for unavailable native libraries, stale keys, external-provider failures, storage failures, and disconnects.

### Performance

Benchmark the canonical kernel and end-to-end caller before cutover. Rust must not introduce an unacceptable regression in p95 latency, throughput, memory, startup, or binary/image size. Security and correctness take precedence over microbenchmark gains.

## Beta rollout and observability

The completed migration waves used staged beta validation and commit-pinned
aggregate checks. Future promotion still requires immutable artifacts and the
complete applicable smoke, conformance, end-to-end, failure and observability
gates. Historical wave acceptance does not qualify a new release or install.

Observe normalized failure codes, native availability, panic/crash rate,
latency, memory, event lag, provider errors and public contract failures.
Persistent production/self-host changes require their own supported approval
and acceptance; migration-source completion does not authorize deployment.

Before v1, elapsed-time soak windows are supporting release evidence rather than
code-deletion blockers. A superseded implementation is removed as soon as its
implementation-independent behavioral, failure, ownership, packaging, and
regression gates pass. A release owner may still require an explicit soak for a
specific promotion, but that does not preserve a second runtime implementation.

Daily read-only service samples use the sanitized
[`marty.rust-beta-soak/v1`](rust-migrations/beta-soak-evidence.md) collector.
Each sample is supporting evidence only; it does not replace contract,
lifecycle, failure, or protected-device gates.

Rollback redeploys the last known-good beta artifact. Databases and events must remain forward/backward compatible across the rollback window or have a tested forward repair. No phase modifies production or persistent self-host deployment configuration.

## Git and delivery workflow

- Use one clean git worktree per repository and workstream; never implement in a dirty primary checkout.
- Branch from the current protected default branch using a focused name such as `rust/<capability>-kernel`, `rust/<service>-migration`, or `cleanup/remove-<capability>-python`.
- Keep canonical-crate, binding, caller, deployment, and deletion changes in reviewable PRs with explicit dependency ordering.
- Sign off every commit as required by project contribution guidance.
- Merge prerequisite Rust API PRs before dependent binding/service PRs. Temporary compatibility re-exports must have a tracked removal PR.
- Include the feature-parity matrix, test evidence, beta rollout effect, rollback procedure, and deleted-code inventory in each migration PR.
- Do not mix unrelated cleanup or user worktree changes into migration commits.

## Measures of completion

The implementation waves completed their source-migration boundaries. Preserve
the following invariants, and assess new signed-artifact and installed-release
acceptance separately against the current qualification gates:

- all unconditional workstreams have passed their deletion gates;
- every conditional DTC/VDS-NC service has been migrated or retired;
- each migrated capability has one identified Rust owner and no second Python/Dart implementation;
- required native backends fail closed and report useful health/version diagnostics;
- beta uses the Rust service images and bindings for all migrated paths;
- public and operational contracts retain feature parity;
- source and dependency inventories show the corresponding Python/Dart source and runtime dependencies removed;
- CI enforces the ownership model; and
- a production promotion package exists, based on beta evidence, for separate approval.

The completed wave-one and wave-two beta evidence reports are retained in Git
history at `053102a80`. Those historical receipts do not qualify new source or
authorize production or persistent self-host promotion.

## Deliberate non-targets

The following should not be rewritten merely to increase Rust percentages:

- React/TypeScript user interfaces;
- Flutter widgets and platform UI integration;
- Canvas/LTI and other provider-specific orchestration;
- OCR model invocation and image-processing integrations unless profiling identifies a concrete bottleneck;
- database migrations and straightforward repository mapping code;
- billing, email, CRM, and similar third-party adapters.

They become candidates only when a measured correctness, security, reliability, deployment, or performance problem justifies the migration.

## Key risks and controls

| Risk | Control |
|---|---|
| Behavior is lost during translation | Feature-parity inventory, contract snapshots, differential replay, and deletion gates. |
| A second Rust copy replaces a Python duplicate | Canonical ownership table, dependency reviews, re-exports, and CI source-boundary checks. |
| Native packaging fails at runtime | Required-backend readiness, version diagnostics, packaging tests, and fail-closed startup. |
| Standards behavior diverges | Shared external/golden vectors, fuzzing, and one canonical encoder/validator. |
| A large service rewrite stalls | Kernel-first slices, event-stream service template, focused PRs, and independent beta gates. |
| Rollback depends on insecure fallback | Immutable deployable artifacts and image-level rollback only. |
| Language reduction becomes vanity work | Target ranking is based on security, duplication, operational simplification, and whole-service removal. |
| Beta changes leak into persistent environments | Beta-only deployment changes and separate production/self-host approval. |

## Current qualification gates

- The deployed service plane belongs to the Rust owners in `marty-ui`, shared
  platform behavior to `mmf-*`, and canonical protocol/crypto behavior to
  `marty-core`. Frozen fixtures support regression checks; historical capture
  generators and deletion-approval programs are retired when no longer needed.
- Select the release coordinate from [the current stack lock](../release/stack-lock.json).
  Source eligibility does not establish signed-image, installed KMS-only,
  device/provider or cutover acceptance. Follow the
  [KMS requirements](remote-kms-hardening-plan.md) and
  [architecture/product queue](architecture-feedback-improvement-plan.md).
- The verification candidate workflow retains the reviewed source floor
  `b2b2953f9fe00d848761830623935773419bdf60`; its ancestry and exact-main checks
  remain enforced by the workflow and tests.
- `v0.1.72` is a valid issuance component, not a failed verifier artifact.
  `v1.2.76` is retained held evidence only and grants no cutover authorization.
  These historical release distinctions do not change the current stack lock.
  See the [verifier release incident](rust-migrations/verifier-release-incident-2026-08-31.md)
  for the detailed producer chronology and held-artifact boundaries.
- Current public-only BYOK certificate handling and tenant/key binding supersede
  the old local trust-adapter proposal. The KMS requirements and current source
  tests retain that boundary; stale worktree reports are not authorization to
  delete unmerged local work.

## Historical records

Completed execution snapshots and the September branch/worktree inventories
were retired from the working tree. They remain recoverable at Git commit
`c86b2f8c6b34ba7ec1bac5461ded03b28adb7745`. Deleting those reports does not delete or release any local
worktree, recorder snapshot, lockfile edit or unmerged branch.

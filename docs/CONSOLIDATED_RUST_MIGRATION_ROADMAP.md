# Consolidated Rust Migration Roadmap

**Status:** Implementation active — source cutovers landed; beta evidence and final removals pending

**Scope:** Marty backend services, protocol kernels, security-sensitive mobile logic, and licensing

**Initial rollout environment:** Beta only

**Last updated:** 2026-08-14

## Objective

Reduce the amount of Python and other non-Rust protocol code in the Marty stack by replacing it with a single authoritative Rust implementation for each capability. The migration must preserve externally observable features and behavior, improve fail-closed security, and remove superseded Python or Dart implementations after each cutover.

This is not a line-for-line translation project. Rust owns deterministic protocol, policy, validation, cryptographic, and state-machine behavior. Python remains only where it is useful for API composition, persistence adapters, scheduling, OCR, and third-party integrations until a whole service is deliberately replaced. Flutter/Dart remains responsible for application UI and platform integrations.

The immediate deployment boundary is beta. Production and persistent self-host environments are not changed by this roadmap without a separate approval and promotion decision.

## Implementation status (2026-08-14)

The selected deterministic protocol, cryptographic, policy, validation,
state-machine, wallet, licensing, DTC, and VDS-NC kernels now have one
canonical Rust owner. The final Flow P-256 `did:jwk`/`did:key` caller cutover
is included in the closing source-cleanup change. The machine-readable
inventory records these workstreams as `native-active` and keeps only the two
whole-service runtime cutovers below open.

| Remaining gate | Current state | Completion evidence required |
|---|---|---|
| Event-stream whole-service removal | Rust is active on beta v1.1.165; this change deletes `services/event_stream` and makes the shared service image dispatch the canonical Rust binary for every stack | Black-box HTTP/gRPC behavior, unchanged-consumer, failure, packaging, and regression contracts pass against the executable before merging |
| Revocation-profile whole-service removal | Rust HTTP/gRPC/storage/runtime implementation and beta overlay are packaged; legacy Python orchestration remains | A black-box issuance, status publication, revocation, and re-verification lifecycle plus failure, concurrency, storage, packaging, and regression contracts pass before deleting the superseded Python service |
| Phase 9 release and evidence | Source cutovers are merged or in the closing dependency-ordered release/caller change; beta remains pinned | Immutable Rust/UI releases, one beta-only update after the deletion set lands, language/dependency measurements, and a production-promotion evidence package without promotion |

Until those gates pass, this roadmap is not complete. Production and
persistent self-host configurations remain unchanged.

## Non-negotiable outcomes

1. There is exactly one maintained implementation of each migrated kernel, written in Rust.
2. Python and Dart callers use that implementation through generated or deliberately thin bindings; they do not reproduce its decisions.
3. Existing REST, gRPC, event, storage, and mobile-facing contracts retain feature parity unless a versioned change is explicitly approved.
4. Required native code fails closed. Production-like environments never silently fall back to Python, Dart, permissive defaults, `None`, empty results, or mock validation.
5. Superseded source, tests, dependencies, feature flags, and fallback branches are deleted after the beta cutover gate passes.
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
| Credential issuance and verification packaging | `marty-credentials` | Issuer/verifier services | Compose `marty-core`; do not maintain duplicate crypto, policy, protocol, or status-list algorithms. |
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

## Current findings and immediate safeguards

The investigation identified these high-value targets beyond the document-verification and ISO 18013 migrations already underway:

1. Presentation-policy evaluation.
2. Revocation-profile and status-list processing.
3. OIDC token validation.
4. Device registration, challenge proof, and key rotation.
5. Event-stream service replacement.
6. Flow state-machine and DID/JWK utilities.
7. Wallet QR and OID4VC protocol parsing.
8. License and entitlement evaluation.
9. Conditional legacy DTC and VDS-NC migration or retirement.

Current `main` already rejects unknown presentation constraints and verifies device challenge signatures. Those fail-closed behaviors are migration baselines and must not regress. The OIDC adapter still decodes JWT claims without signature verification and incorrectly treats PKCE as token validation; fixing that is a phase-zero security requirement. The Python revocation implementation also uses zlib compression for both token and bitstring lists while the existing Rust implementation distinguishes raw DEFLATE and GZIP. Golden-vector conformance must resolve that divergence before cutover.

## Delivery roadmap

Phases are ordered by shared dependency and risk. Workstreams inside a phase may run in parallel only when they do not create competing canonical implementations.

### Phase 0 — Inventory, guardrails, and security corrections

**Purpose:** Establish a trustworthy baseline before moving callers.

- Create a machine-readable ownership manifest mapping each kernel to its canonical Rust module and all current non-Rust implementations.
- Add CI checks that reject new protocol/crypto implementations in designated Python and Dart paths without an approved exception.
- Standardize native backend diagnostics and typed unavailable/operation errors across Python bindings.
- Record contract snapshots and shared fixtures for every selected service.
- Replace the OIDC adapter's unsigned claim decoding with complete Rust-backed validation: discovery/JWKS handling, signature, issuer, audience, authorized party where required, nonce, time claims, and algorithm policy.
- Add regression tests preserving fail-closed unknown presentation constraints and device proof-of-possession.
- Resolve status-list compression semantics with standards fixtures and make the Rust output authoritative.
- Detect and reject mock or placeholder validation in beta runtime paths.

**Exit gate:** Ownership is unambiguous, immediate security defects are closed, native availability is visible in readiness, and CI can detect reintroduced fallback code.

### Phase 1 — One presentation-policy engine

**Canonical owner:** `marty-core/marty-verification`

- Inventory every constraint and policy composition behavior used by backend and wallet callers.
- Implement the complete evaluator and normalized decision/error model in Rust.
- Expose the same evaluator through `_marty_rs` and Flutter Rust Bridge.
- Run backend Python, mobile Dart, and direct Rust against the same golden policy vectors.
- Convert Python and Dart policy layers into mapping/orchestration adapters only.
- Delete Python and Dart constraint evaluators, duplicate normalizers, permissive branches, and their now-unused dependencies.

**Parity gate:** Existing policy fixtures produce equivalent decisions and reasons; malformed or unsupported constraints are denied; no caller contains independent evaluation logic.

### Phase 2 — Rust service foundation and event stream

**Canonical shared logic:** `marty-core`; **binary owner:** `marty-ui`

Use the event-stream service as the first whole-service replacement because it has a narrow transport contract and establishes the reusable Rust service template.

- Build the common service foundation: configuration, structured logging/tracing, metrics, health/readiness, graceful shutdown, authentication middleware, error envelopes, and database/Redis clients.
- Reimplement the event-stream HTTP/gRPC and event-bus behavior in Rust while preserving protobuf and operational contracts.
- Run Python and Rust implementations against shared contract, ordering, reconnection, backpressure, and failure tests.
- Deploy the Rust image to beta, observe it, then remove the Python service and packaging.

**Exit gate:** The template is reusable, the beta deployment has no Python event-stream process, and all consumers pass unchanged integration tests.

### Phase 3 — Status and revocation consolidation

**Canonical owner:** a public `marty-core` status module/crate; **service binary owner:** `marty-ui`

- Move or refactor the existing status-list Rust implementation out of credential-specific ownership into the canonical public layer.
- Temporarily re-export it from `marty-credentials` to avoid a second implementation or a flag-day dependency change.
- Cover Token Status List and Bitstring Status List encoding, compression, allocation, mutation, validation, and error semantics with standards and property tests.
- Rebuild revocation-profile orchestration as a Rust service, preserving REST, gRPC, persistence, Redis atomicity, issuer configuration, tenancy, and events.
- Keep certificate-provider or external revocation integrations as adapters to the canonical Rust decisions.
- Delete `status_list_manager.py` and the superseded Python service code after implementation-independent behavioral, parity, and failure gates pass.

**Parity gate:** Existing credentials remain readable, indices and status transitions are preserved, concurrent allocation is safe, and all published bytes match the approved vectors.

### Phase 4 — OIDC and device-authentication kernels

**Canonical owner:** new or existing focused crates in `marty-core`

- Consolidate OIDC discovery, JWKS caching/rotation, authorization response checks, token validation, and normalized identity extraction in Rust.
- Consolidate device public-key parsing, RFC 7638 thumbprints, challenge construction, proof verification, replay prevention, expiry, and key-rotation eligibility in Rust.
- Preserve Python service routing, persistence, organization checks, and provider adapters initially.
- Use shared vectors for valid and invalid signatures, key rotation, stale JWKS, nonce mismatch, replay, algorithm confusion, issuer/audience mismatch, and clock boundaries.
- Delete unsigned JWT decoding and Python cryptographic/proof code as each caller moves.
- Evaluate full Rust service replacement only after the kernels are stable; do not duplicate them inside a service binary.

**Parity gate:** All authentication paths validate the complete trust context, device behavior remains compatible, and no production-like path can accept decoded-but-unverified claims.

### Phase 5 — Flow engine and DID/JWK utilities

**Canonical owner:** `marty-core`, reusing `marty-didcomm` and existing credential/protocol crates

- Specify the flow lifecycle as a versioned Rust state machine with legal transitions, guards, terminal states, replay/idempotency rules, and normalized failures.
- Move graph validation, request-object validation, DID/JWK normalization, key selection, and protocol-specific decision logic to Rust.
- Keep database repositories, API composition, and third-party callbacks in orchestration layers until a whole-service replacement is justified.
- Differentially replay recorded beta flows through old and new paths, comparing state, events, responses, and side effects.
- Remove Python state-transition, DID/JWK, and request-validation implementations after all callers use Rust.

**Parity gate:** Recorded and synthetic flows remain behaviorally equivalent, invalid transitions fail closed, and exactly one state machine determines outcomes.

### Phase 6 — Wallet QR and OID4VC consolidation

**Canonical owner:** existing `marty-core` ISO 18013 and OID4VC crates, exposed through Flutter Rust Bridge

- Inventory every supported QR/deep-link form and user-visible routing outcome.
- Move protocol-aware classification, parsing, validation, and request evaluation to the existing Rust crates.
- Keep camera capture, UI navigation, permissions, secure platform storage, and OS integration in Dart.
- Replace mock validation and hand-written Dart protocol parsers with generated bindings and typed results.
- Share malformed-input, size-limit, Unicode, deep-link, mDoc, OID4VCI, and OID4VP vectors across Rust and Flutter tests.
- Delete superseded Dart protocol code after mobile beta parity.

**Parity gate:** Every supported QR journey retains its user-visible behavior; malformed or unsupported requests fail safely; no Dart protocol evaluator remains.

### Phase 7 — License and entitlement runtime

**Canonical owner:** `marty-subscriptions/packages/verifier_entitlements/marty-license`

- Inventory Python license parsing, signature validation, expiry, feature, quota, organization, cache, and telemetry behavior.
- Extend the existing private Rust crate to cover the complete runtime contract.
- Provide a backend-safe binding or sidecar interface with typed decisions and diagnostics.
- Preserve billing/provider synchronization adapters in Python where they are integration orchestration rather than entitlement decisions.
- Disallow development allow-through behavior in beta/production-like profiles; missing keys, malformed licenses, invalid signatures, and unavailable native code fail closed.
- Delete duplicate Python license and entitlement evaluators after parity.

**Parity gate:** All licensed features and quotas behave identically for valid inputs, failure behavior is stricter and explicit, and only the Rust crate decides entitlements.

### Phase 8 — DTC and VDS-NC decision gate

These legacy services are conditional targets. For each service, make and record one decision:

- **Retain:** place create/sign/verify/encode/decode/validate behavior in a canonical Rust crate, migrate all callers, and delete the Python kernel; or
- **Retire:** migrate required data/callers, remove the deployed service, and delete the Python implementation.

Maintaining an unused Rust rewrite beside a legacy Python implementation is not an acceptable outcome.

**Decision:** Retain both capabilities. DTC create/sign/verify and governed
lifecycle validation are canonical in `marty-verification::dtc`. VDS-NC
canonicalization, barcode policy, create/sign/inspect/verify, field consistency,
and temporal validation are canonical in `marty-oid4vci` and
`marty-verification`. Marty preserves its gRPC, storage, provider, DTO, and visa
mapping adapters, but no longer owns a cryptographic or protocol kernel. The
evidence and allowed adapter boundary are recorded in
[`rust-migration-phase8-dtc-vds-decision.md`](rust-migration-phase8-dtc-vds-decision.md).

**Exit gate:** Satisfied for implementation and caller cutover. Final completion
still follows the roadmap-wide beta evidence and removal enforcement gates.

### Phase 9 — Removal and enforcement

- Delete all superseded Python/Dart implementation files and fallback flags.
- Remove no-longer-used packages and native build exceptions from manifests and images.
- Add dependency and source-boundary checks preventing canonical logic from returning to orchestration layers.
- Remove compatibility re-exports after downstream consumers have migrated.
- Update architecture, operations, SBOM, threat-model, and contributor documentation.
- Compare language composition, image size, startup time, p50/p95/p99 latency, memory, failure rates, and native-backend errors against the baseline. Generate commit-pinned source and dependency measurements with [the language-composition evidence tool](rust-migrations/language-composition-evidence.md).
- Prepare a separate production/self-host promotion proposal using beta evidence. Do not promote as part of this phase without approval.

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

Each workstream uses staged beta deployment:

1. Build and test the Rust-backed artifact in CI.
2. Deploy to an isolated beta lane or a limited beta service set.
3. Run smoke, conformance, and end-to-end verification.
4. Observe normalized failure codes, native availability, panic/crash rate, latency, memory, event lag, and contract errors.
5. Expand to the full beta lane.
6. Remove the superseded implementation after its deletion gate passes.

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

The roadmap is complete when:

- all unconditional workstreams have passed their deletion gates;
- every conditional DTC/VDS-NC service has been migrated or retired;
- each migrated capability has one identified Rust owner and no second Python/Dart implementation;
- required native backends fail closed and report useful health/version diagnostics;
- beta uses the Rust service images and bindings for all migrated paths;
- public and operational contracts retain feature parity;
- language-composition reporting shows the corresponding Python/Dart source and runtime dependencies removed;
- CI enforces the ownership model; and
- a production promotion package exists, based on beta evidence, for separate approval.

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

## Initial dependency order

The first implementation queue is:

1. Phase-zero ownership/CI/native diagnostics and OIDC verification correction.
2. Canonical presentation-policy engine.
3. Rust service foundation plus event-stream replacement.
4. Canonical status module, followed by revocation-profile replacement.
5. Device-auth consolidation and the remaining OIDC migration.
6. Flow/DID/JWK consolidation.
7. Wallet QR/OID4VC consolidation.
8. License/entitlement consolidation.
9. DTC/VDS-NC retain-or-retire decisions.
10. Cross-repository cleanup, dependency removal, and beta evidence package.

This order may be adjusted when a dependency is discovered, but a change must preserve the single-owner rule and be recorded in the active implementation goal.

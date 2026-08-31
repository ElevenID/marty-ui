# Credentials verification-image consolidation plan

Status: `contract-freeze-active`. This workstream is owned by the coordinated
`rust-verification/consolidation-v1` worktrees in `marty-ui` and
`marty-credentials`. It proceeds independently from the active Canvas route
work and does not change production.

## Objective

Replace the separately published `marty-credentials-verification` Python image
with the existing canonical `marty-ui` Rust verification service without
losing an intended API, governance, privacy, persistence, migration,
concurrency, deployment or release contract. The replacement extends the
canonical service with thin compatibility adapters; it does not create a
second Rust verifier or replace the existing `/v1/verify` product surface.

The Python service remains the parity oracle until the full differential,
database, migration, packaging and consumer gates pass. The reusable
`marty-verification-python` binding is a separate public dependency and is not
removed by retiring the service image.

## Frozen floor

The source-derived `marty.verification-runtime-surface/v1` manifest is owned by
`marty-credentials/contracts/verification-runtime-surface.json`. Its generator
and mutation tests fail on drift in:

- all seven live method/path operations;
- request and response DTO fields, forbidden-extra policy and result validator;
- route dependencies and declared HTTP error mappings;
- required configuration and secret lookups;
- all three governed purposes, their required-check definition, the four
  processing states and the complete native capability set;
- startup validation hooks;
- both Alembic revisions, their ancestry and normalized upgrade/downgrade
  bodies;
- the one API runtime mode and digest-pinned image command, port and health
  target.

Behavior fixtures follow the surface manifest. They must be independent JSON,
JSONL or SQL inputs that both Python and Rust execute; Rust-only unit tests do
not establish parity.

## Canonical ownership and DRY boundaries

| Concern | Owner | Rule |
|---|---|---|
| Governance digests, authorization, purpose checks, snapshot/resume and request validation | `marty-core/marty-verification` | Expose or wrap the existing canonical API once; do not recreate governance rules in handlers |
| OID4VP, VCDM, VDS-NC, canonical decisions and evidence validation | focused `marty-core` crates | Reuse the pinned public kernels; no service-local crypto or policy implementation |
| DID parsing and governed resolution policy | canonical `marty-core` DID crates plus one service provider | Keep network I/O behind one bounded provider; never scatter resolver/JWK validation across routes |
| Session lifecycle and durable state transitions | one typed verification application kernel | HTTP namespaces, gRPC and repositories call the same transition model |
| PostgreSQL and Redis adapters | verification service repository ports using MMF data primitives | Preserve durable history in PostgreSQL; Redis may coordinate but cannot replace the released audit record with expiring data |
| HTTP compatibility | `marty-ui/rust/services/verification` | `/v1/verification` adapters map exact legacy DTOs/errors into typed use cases; `/v1/verify` remains unchanged |
| Lifecycle, configuration, migrations, secrets, telemetry, resilience and authorization context | MMF Rust crates | Compose shared implementations; do not copy framework behavior into the service |

Application code must use typed requests, decisions and records. A single
module may adapt Core's current JSON governance boundary until typed Core
types are published; JSON construction must not leak into routes or
repositories.

## Compatibility gaps that block deletion

1. The Python and Rust HTTP namespaces, DTOs, authorization and error bodies
   differ. Both surfaces must coexist in one native binary during cutover.
2. Python selects exact API-key-bound governance for session creation, direct
   verification and VDS-NC. Rust currently has only trusted management
   principal headers.
3. Direct structured/JWT and VDS-NC compatibility routes are absent in Rust.
4. Python owns durable `public.verification_sessions` history and Alembic head
   `202608091200`; Rust currently stores expiring Redis sessions only.
5. Lifecycle invariants diverge: nonce entropy/length, hashed worker fences,
   lease configuration, `IN_PROGRESS`, duration bounds and database-clock
   expiry.
6. Python persists the schema-v2 minimized canonical-evidence envelope; the
   current Rust record is a different Flow-oriented projection.
7. The Python image owns port 8006, migration execution, public artifact name,
   SBOM/provenance/signature and release smoke behavior. The canonical Rust
   service uses port 8012 internally and a shared service image.

## Ordered implementation

1. **Contract and provenance freeze.** Land the generated surface manifest,
   language-neutral HTTP/governance/evidence/session/resolver/startup fixtures,
   exact upstream commit and digest coverage, and mutation gates.
2. **Typed shared application boundary.** Replace untyped service projections
   needed by both namespaces with typed results. Introduce explicit caller and
   authorization policies rather than boolean behavior switches.
3. **Governance and evidence adapters.** Consume canonical Core governance and
   decision/evidence APIs through one typed service adapter. Preserve exact
   purpose bindings, mandatory checks, provenance and all four processing
   states.
4. **Unified durable lifecycle.** Define one transition kernel with 32-byte
   nonces, SHA-256 worker-token fences, constant-time comparison, configurable
   5-300 second leases, bounded 30-3600 second sessions, database-clock expiry,
   immutable terminal results and privacy-minimized records.
5. **PostgreSQL compatibility ownership.** Reproduce the released two-revision
   fresh/upgrade result and legacy-row conversions under a Rust migration
   runner. Implement the existing table through a repository port and run real
   two-client race, lease recovery, stale-worker and terminal retry tests.
6. **Thin compatibility routes.** Add the seven exact operations with legacy
   validation, authorization, status/detail and projection behavior. Preserve
   the current public session-ID capability semantics unless a separate,
   versioned security correction is approved.
7. **Direct and VDS-NC providers.** Compose canonical verification kernels and
   one governed issuer-resolution provider. Preserve the current fail-closed
   non-`PASS` boundary where complete evidence is not yet performed.
8. **Packaging and consumer cutover.** Package migrations with the native
   image, add database readiness, preserve the external compatibility boundary,
   update Compose/Kubernetes/catalog/release/integration consumers and prove a
   Python-free digest-pinned image.
9. **Deletion and acceptance.** Move release/SBOM/provenance ownership,
   preserve the independent Python binding, delete the Python service/image and
   Alembic runtime only after every gate passes, add anti-reintroduction checks,
   then perform one aggregate beta deployment and soak.

## Required parity and failure gates

- Exact HTTP method, path, default status, DTO, extra-field rejection, header,
  error status/detail, time, nonce and legacy projection behavior.
- Missing, invalid and wrong-purpose API keys; invalid governance, digests,
  required checks, snapshots, component provenance and rotated registries.
- Canonical evidence reconstruction plus tampering of every governance,
  result, check, context, record and digest binding.
- `COMPLETED`, `UNSUPPORTED`, `UNAVAILABLE` and `ERROR` remain distinct; an
  incomplete verification never becomes `PASS`.
- Tenant and issuer hiding, internal resolver request/response binding,
  public-fallback gating, SSRF/redirect/DNS/size/content-type rejection and
  public asymmetric JWK enforcement.
- First claim, same/different digest replay, live lease contention, expired
  lease recovery, stale finalize, database-clock expiry, immutable terminal
  retry and multi-replica races.
- Fresh schema, upgrade from each released revision, protected legacy-copy
  rehearsal, raw-presentation redaction, constraint/index equivalence and
  interruption recovery.
- Dependency unavailability, timeouts, bounded input, secret redaction,
  privacy-safe logs/metrics, accurate readiness and graceful shutdown.
- Image contents, migration-before-start, port/ingress compatibility,
  digest/SBOM/provenance/signature, external consumer pins and rollback before
  traffic.

## Review and delivery discipline

Every slice is a focused commit with its own tests and a maintainer-style
self-review. An independent reviewer checks the complete commit stack for
feature loss, security, correctness, DRY ownership, unnecessary duplication,
failure coverage and deployment gaps. All findings are fixed in a follow-up
commit and the reviewer repeats the audit. A slice is accepted only when the
reviewer reports no issues and the full affected test suites pass.

Python deletion, production promotion and retirement of public SDK/binding
surfaces are not implicit in any implementation slice and require their stated
gates or separate approval.

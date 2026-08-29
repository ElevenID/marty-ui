# Native issuance service plan

Status: `cutover-in-progress`. This plan extends the accepted wave-three
method: freeze behavior, implement against canonical Rust crates, prove parity,
delete the superseded Python service immediately after all gates pass, and
deploy only the aggregate beta. Production remains unchanged.

## Frozen feature floor

The source-bound contract in
[`contracts/issuance-runtime-surface.json`](../../contracts/issuance-runtime-surface.json)
is mirrored byte-for-byte from `ElevenID/marty-credentials`. Its provenance and
SHA-256 are enforced by
[`issuance-native-coverage.json`](../../contracts/issuance-native-coverage.json).
The floor currently contains:

- 131 HTTP operations;
- 12 gRPC methods, including unary-stream event delivery;
- API and Canvas synchronization-worker runtime modes;
- 44 Alembic revisions with one head; and
- every literal and dynamic configuration lookup site.

The native candidate now owns eighteen frozen HTTP operations: the exact legacy
`GET /health` representation, global issuer metadata, SD-JWT type metadata,
the global plus three organization-scoped OAuth discovery variants, and all
three tenant-backed credential-issuer metadata variants. The six deterministic
discovery responses replay the Python oracle contract in
[`issuance-static-discovery.json`](../../contracts/issuance-static-discovery.json)
through typed `marty-oid4vci` Final-spec documents. Tenant discovery replays
[`issuance-tenant-discovery.json`](../../contracts/issuance-tenant-discovery.json)
through a pure two-phase Rust planner, an organization-scoped Postgres
projection, and a fail-closed signing-policy adapter. It preserves format
filtering, claims and display metadata, DID-selected proof policy, and Google
and Apple wallet variants without moving database or HTTP I/O into the core
protocol crate. The five read-only offer/transaction operations replay
[`issuance-offer-transaction-reads.json`](../../contracts/issuance-offer-transaction-reads.json)
through one tenant-safe transaction model, one Postgres projection, MMF's
constant-time secret comparison, and the existing `marty-oid4vci` offer
builder. They preserve management authentication, hidden cross-tenant
resources, expiration, repeated and missing query validation, Python timestamp
shapes, and the distinct list-summary and detail projections. A disposable
PostgreSQL contract exercises the production projection, tenant-bound list,
nullable lifecycle fields, and fail-closed persisted status decoding.
The OID4VCI token endpoint replays
[`issuance-token-exchange.json`](../../contracts/issuance-token-exchange.json)
through a typed Rust state machine and the canonical `marty-oid4vci` engine.
It preserves authorization-code and pre-authorized-code flows, PKCE, exact
OAuth failures, registered tenant client authentication, DPoP key binding,
single-use atomic claims, one-way token persistence, and the configurable
per-client sliding-window guard. Real ES256 verification and disposable
PostgreSQL race gates complement the language-neutral response oracle.
The OID4VCI proof-nonce endpoint replays
[`issuance-proof-nonce.json`](../../contracts/issuance-proof-nonce.json) with
32 bytes of cryptographic entropy, no-store caching, shared OAuth rate
limiting, five-minute database-clock expiry, SHA-256 digest-only persistence,
and atomic single use. Its reusable capability repository is also the nonce
consumer required by credential issuance.
The credential endpoint replays the frozen admission and signing contracts,
performs proof and capability validation, builds every supported credential
format through the shared Rust crates, and preserves persisted status,
delivery, renewal-revocation, and Canvas eligibility transitions. Its
production repository is exercised against disposable PostgreSQL, including
tenant isolation and renewal revocation behavior.
The same contract binds legacy request-ID propagation/generation and allowed
and denied CORS behavior so route ownership includes transport semantics, not
only JSON bodies.

MMF-owned readiness, lifecycle, and version diagnostics remain additive. The
shared service image and entrypoint package the native binary. Beta uses a
separate `issuance-native` sidecar and the gateway sends only the initial eighteen
contract-owned paths to it. The first two Canvas/LTI login operations add
server-owned state/nonce generation, exact trust-profile validation, and the
existing PostgreSQL launch-state schema, bringing the split to twenty native
paths; the other 111 HTTP operations and all 12 gRPC
methods remain on the Python issuance service. Production Compose remains
unchanged and selects only the Python issuance service.

## Dependency and removal order

1. Land the MMF system-route representation adapter without changing default
   framework behavior.
2. Land this native host, contract mirror, provenance, configuration adapter,
   lifecycle, and executable smoke gate without deployment wiring.
3. Port offer/transaction reads using canonical `marty-oid4vci` types and MMF
   transport/configuration primitives. All issuer discovery and the five
   read-only offer/transaction operations are complete in Rust.
4. Port token exchange and credential issuance, reusing `marty-core` for
   cryptography and credential formats and preserving idempotency/race gates.
   Token exchange, nonce issuance, and credential issuance are complete in the
   beta path split.
5. Port revocation/status lifecycle, physical-document paths, Canvas/LTI
   orchestration, all 12 gRPC methods, and the Canvas worker. Canvas/LTI login
   and experience-login initiation are complete in the beta path split.
6. Replay the frozen positive, negative, concurrency, database, protocol, and
   migration contracts against both implementations; resolve every divergence.
7. Atomically move image/SBOM/provenance ownership, delete the Python issuance
   service and its now-unused dependencies, and mark ownership `native-active`.
8. Deploy the resulting aggregate to beta only and run acceptance/soak gates.

No route, method, worker mode, environment contract, migration, or supported
provider integration may be removed merely because it is difficult to port.
Any intentional retirement requires separate evidence and explicit approval.

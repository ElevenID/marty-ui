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

The coverage contract currently records 63 of the 131 frozen HTTP operations
and all 12 gRPC methods as implemented in Rust, leaving 68 HTTP operations in
its remaining inventory. Implementation ownership is not proof that every
deployment consumer has switched. The Canvas worker is a separate unrouted
candidate; see [worker cutover readiness](canvas-worker-cutover-readiness.md).

The earlier 32-operation HTTP checkpoint included the exact legacy
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
The native Canvas surface now owns eleven Canvas/LTI operations: login and
experience-login initiation, launch verification, experience launch and code
exchange, current-session lookup and bootstrap, Deep Linking response signing,
evidence status and synchronization, and tool JWKS publication. The paired
Canvas OAuth lifecycle owns authorization start, callback completion, and
durable disconnect. Their frozen contracts preserve tenant binding, signed
launch capabilities, cache boundaries, bearer authorization, state and nonce
handling, secret encryption, retry behavior, and checked token expiry.
The same contract binds legacy request-ID propagation/generation and allowed
and denied CORS behavior so route ownership includes transport semantics, not
only JSON bodies.

MMF-owned readiness, lifecycle, and version diagnostics remain additive. The
shared service image and entrypoint package the native binary. Beta's source
configuration uses a separate `issuance-native` sidecar and the gateway's
contract-owned HTTP path split. The 31-route Canvas management migration brings
the HTTP ownership inventory to 63. The other 68 HTTP operations, complete API
runtime cutover, the Canvas synchronization worker, and final packaging and
schema ownership remain open. All 12 gRPC methods now have native ownership;
consumer routing and runtime acceptance must be verified separately. These are
source/contract facts, not a fresh beta health or deployment attestation.
Production remains unchanged by this migration lane.

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
5. Reconcile the remaining HTTP/runtime and Canvas worker consumers. Native
   ownership includes the Canvas/LTI and OAuth paths above, all 31 Canvas
   management routes, and all 12 gRPC methods; do not port them again based on
   the older checkpoint prose. Qualify the eight additional Canvas operations
   and standalone worker candidates before advancing their routing/deletion
   boundary. Keep the coverage contract authoritative for the remaining HTTP
   inventory and verify implementation and consumer adoption separately.
6. Replay the frozen positive, negative, concurrency, database, protocol, and
   migration contracts against both implementations; resolve every divergence.
7. Atomically move image/SBOM/provenance ownership, delete the Python issuance
   service and its now-unused dependencies, and mark ownership `native-active`.
8. Deploy the resulting aggregate to beta only and run acceptance/soak gates.

No route, method, worker mode, environment contract, migration, or supported
provider integration may be removed merely because it is difficult to port.
Any intentional retirement requires separate evidence and explicit approval.

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

The native candidate now owns ten frozen HTTP operations: the exact legacy
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
protocol crate.
The same contract binds legacy request-ID propagation/generation and allowed
and denied CORS behavior so route ownership includes transport semantics, not
only JSON bodies.

MMF-owned readiness, lifecycle, and version diagnostics remain additive. The
service is still a compile/test candidate only: the shared service image,
entrypoint, Compose topology, beta, and production continue to select the
Python issuance image.

## Dependency and removal order

1. Land the MMF system-route representation adapter without changing default
   framework behavior.
2. Land this native host, contract mirror, provenance, configuration adapter,
   lifecycle, and executable smoke gate without deployment wiring.
3. Port offer/transaction reads using canonical `marty-oid4vci` types and MMF
   transport/configuration primitives. All issuer discovery is complete in
   Rust.
4. Port token exchange and credential issuance, reusing `marty-core` for
   cryptography and credential formats and preserving idempotency/race gates.
5. Port revocation/status lifecycle, physical-document paths, Canvas/LTI
   orchestration, all 12 gRPC methods, and the Canvas worker.
6. Replay the frozen positive, negative, concurrency, database, protocol, and
   migration contracts against both implementations; resolve every divergence.
7. Atomically move image/SBOM/provenance ownership, delete the Python issuance
   service and its now-unused dependencies, and mark ownership `native-active`.
8. Deploy the resulting aggregate to beta only and run acceptance/soak gates.

No route, method, worker mode, environment contract, migration, or supported
provider integration may be removed merely because it is difficult to port.
Any intentional retirement requires separate evidence and explicit approval.

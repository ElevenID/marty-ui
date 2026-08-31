# Credentials verification-image consolidation plan

Status: `release-order-repair-required`; deployment is held. The standalone
Python verifier source deletion merged before its release order was proven.
Immutable `marty-credentials@v0.1.72`, stale
`marty-integration-tests@v1.2.76`, and intermediate
`marty-integration-tests@v1.2.77` are ineligible. Published preliminary harness
`marty-integration-tests@v1.2.78` is non-activating, does not pin a corrected
Rust runtime, and is not an aggregate input. `marty-ui@v1.1.209` and unsigned
tag `marty-ui@v1.1.210` are quarantined partial publications. All affected
release workflows remain disabled, the UI release environment prevents self-
approval, and no corrected Credentials release, corrected Rust artifact,
corrected-Rust-pinned integration release, or aggregate UI release is selected.
The separate public Python binding and still-used Credentials adapter remain
supported, and
production is unchanged.

Exact partial-publication coordinates and containment controls are retained in
[`verifier-release-incident-2026-08-31.md`](verifier-release-incident-2026-08-31.md).

## Objective

Replace the separately published `marty-credentials-verification` Python image
with the existing canonical `marty-ui` Rust verification service without
losing an intended API, governance, privacy, persistence, migration,
concurrency, deployment or release contract. The replacement extends the
canonical service with thin compatibility adapters; it does not create a
second Rust verifier or replace the existing `/v1/verify` product surface.

The last safe `v0.1.71` Python service image and frozen pre-deletion source
remain parity and rollback oracles until the corrected Rust artifact passes the
full differential, database, migration, packaging and consumer gates. Rust
remains the intended canonical architecture. If parity fails, cutover stops and
the required legacy boundary is restored or a forward Rust repair is completed
before traffic. The reusable `marty-verification-python` binding is a separate
public dependency and was not removed.

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

## Implementation checkpoint — 2026-08-31

The compatibility DTO, governance, canonical-decision/evidence, durable
PostgreSQL lifecycle, migration adoption, HTTP, application, native
JWT/structured/VDS-NC and organization-first issuer-resolution slices are now
implemented through protected PRs `marty-credentials#249` and `marty-ui#718`.
Production route mounting is operational-state gated; startup validates the
released schema rather than silently migrating it. The same canonical Rust
image exposes the explicit
`migrate` command, and the beta Compose plane runs that one-shot before enabling
the compatibility namespace with explicit governance.

Real PostgreSQL migration/application/race coverage, strict Rust linting and
container/deployment contract tests are green at this checkpoint. A fresh
canonical image build has also run its `migrate` command twice against a
disposable PostgreSQL 17 database, reached released head `202608091200`, then
started both its ordinary and compatibility-enabled runtimes healthy from that
same artifact. The rendered beta stack binds the migration and runtime to the
same immutable image and waits for migration completion. Production,
self-host-production and Kubernetes-production manifests have no changes in
this slice.

Bootstrap `marty-ui` release `v1.1.208` published the first immutable services
artifact, but post-merge review found two corrections that make it ineligible
for cutover: the database monitor must remain supervised and URL-safe session
tokens must be scoped before use as canonical Core identifiers. Those fixes
and their regression tests merged through protected
`ElevenID/marty-ui#721` at
`b2b2953f9fe00d848761830623935773419bdf60`.

The same-image CI smoke now runs the Rust artifact's migration twice, asserts
Alembic head `202608091200`, starts compatibility mode against disposable
PostgreSQL and Redis, checks readiness and both health contracts, creates a
governed session, submits a malformed presentation, proves canonical
fail-closed scoped identifiers, and confirms terminal nonce minimization. The
release workflow invokes the same gate against the exact pushed shared
services digest through its production dispatcher before attestation and
signing. The deployment, contract and implementation reviews are clean, as are
the PR-head and protected merge-group gates.

The bootstrap `v1.1.208` services image was published without deployment. The
Rust consumer pin merged in `ElevenID/marty-integration-tests#396` and was
published as immutable `v1.2.76`, but that release is stale and ineligible
because it pins an artifact that predates required correction PR `#721`.
Standalone Python verifier deletion merged in
`ElevenID/marty-credentials#250`. Immutable `v0.1.72` then published only its
issuance image at
`sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`;
no verification image was published, and PyPI publication was skipped. All
four Credentials release workflows are disabled. Credentials PR `#253` merged
the adapter-preservation and verifier-retirement guard at
`cbda2ac7e3376b858c1e8d5d010a304474c659cf`; it does not make `v0.1.72`
eligible or re-enable a release workflow.

Annotated tag `v1.1.209` records the correction binder, but its interrupted
release produced only the quarantined UI image
`sha256:c223ee06d86dc85bc960a22aec4328f1e22fb6f38124bc261d38c3c21c0ac995`.
It produced no services image, migrations image, or GitHub release. Unsafe PR
`#725` then merged at `4326524a1c6a265bad6f6b46945e248345af0451`, and
unsigned annotated tag `v1.1.210` was pushed to that commit. Its fourth release
attempt published and signed only the quarantined UI image at
`sha256:28f48e7ed885046ae753c1f4eea8855b8769cd166602741a8783cbc3dba64643`;
cancellation stopped the services build. The tag has no services or migrations
image, GitHub release, stack manifest, deployment, or downstream integration
pin. Both UI release workflows are disabled. The release environment permits
only inert tag `release-hold-disabled`, cannot be bypassed by administrators,
and prevents self-approval by the dispatching identity. Exact registry and
workflow evidence is retained in
[`verifier-release-incident-2026-08-31.md`](verifier-release-incident-2026-08-31.md).

Protected `ElevenID/marty-integration-tests#398` expanded the artifact
differential across stateful session create/reload/restart, minimized database
persistence, retry/concurrency/fencing, direct verification, authorization and
purpose isolation, resolver failures and VDS-NC. Published release `v1.2.77`
has independently verified release checksums, five Sigstore bundles, and five
GitHub provenance attestations bound to source commit
`5c008faa44859eb7d7528adc1ee2dba55bcca19a`. Its source archive is
`sha256:39356e447f121f7eb9bc587d71f2d99b0ad9988601771c26631902b81448b52b`
and its SPDX SBOM is
`sha256:ff2afea7146954c51f8f7e3612443ad80853fb036f43d7e65307eaa07e56e4ac`.
That supply-chain result does not make the harness cutover-eligible. The exact
behavior audit found false-pass paths in VDS privacy checks, terminal-row
minimization, and negative outcome/code comparison.

Protected PRs `#400` and `#401` corrected those source-level gaps on `main` at
`a2ab449d2bbaa8c42734de1a6890c5f2d9868a2b` and
`bd3abf0792bad5c61faa2ff3b0f56fb4df0807d7`. Those corrections were later
combined with protected PRs `#402` and `#403` and packaged by PR `#404` as
preliminary harness release `v1.2.78`; that release is not a corrected-Rust
pin or aggregate input. A post-merge audit also reproduced a frozen `v0.1.71`
session-ID limitation: the service generates URL-safe IDs and passes the raw
value to Core as a transaction ID, while a leading `-` or `_` violates Core's
scoped-ID grammar. The affected submission fails closed with persistent
`CANONICAL_RESULT_BUILD_FAILED` and no canonical result. This is not readiness
and a same-digest retry cannot repair it.

Protected PR `#402` completed that harness-side correction: it removed the
generic retry, bounded pre-submission resampling to exact allowlisted frozen
artifacts, and retained only a sanitized resample count. Future or ready Rust
artifacts receive no allowance and must return an immediate canonical terminal
result for every submitted session. The separate product-side repair prefixes
the adapter transaction identifier before it enters Core.

Protected `ElevenID/marty-ui#727` merged the fail-closed eligibility interlock
at `569d74b10fcae9d6eadc6fceaf9f6d3eaf9b7c5b`; the checked-in lock remains
`hold` on safe Credentials `v0.1.71` and integration `v1.2.75` anchors. No
corrected Credentials release, corrected Rust artifact, corrected-Rust-pinned
integration release, or aggregate UI release is selected.

Protected `ElevenID/marty-ui#737` merged the non-publishing candidate producer
at `83a2557735dfe2a33e401f3cacde8c63e05546f4`. It is only an unexercised,
correction-required candidate producer: it has never been dispatched, supplies
no candidate evidence, and does not satisfy the candidate gate. Before it may
produce admissible evidence, it must reject every unreferenced archive member,
enforce bounded archive and layer expansion plus member-count limits, add one
end-to-end test that consumes an actual Buildx archive end to end on a declared
supported backend, and enforce an exact five-file name/type allowlist.

Protected `ElevenID/marty-integration-tests#400` merged the post-`v1.2.77`
differential strengthening at
`a2ab449d2bbaa8c42734de1a6890c5f2d9868a2b`: deterministic Ed25519 fixtures,
canonical input-digest and verification-method assertions, malformed-input
ordering, and bounded retry scoped to the known ineligible negative control.
Its PR-head artifact gates passed for both the Python oracle and rejected Rust
control. Protected follow-up `ElevenID/marty-integration-tests#401` merged at
`bd3abf0792bad5c61faa2ff3b0f56fb4df0807d7`, adding exact VDS-NC outcome/code
projections and mutation-tested response/database privacy minimization for
decoded claims, malformed terminal rows, expired sessions and all worker lease
fields. Its Python-oracle and rejected-Rust artifact jobs passed. The corrected
artifact repin must build on that protected-main tree. Both superseded source
worktrees were removed after tree-equivalence checks; their generated,
untracked `uv.lock` was absent from both PRs and was not release input.

Protected `ElevenID/marty-integration-tests#402` merged at
`cfdbebb4def784794aee9f0671e742c90cedffad`. It removed the generic canonical-
omission retry, resampled incompatible generated session identifiers only
before submission and only for exact frozen artifacts, bounded that selection,
and recorded only a sanitized count. Future Rust artifacts receive no allowance
and remain fail-closed. Preliminary release `v1.2.78` packages this protected
tree.

Protected `ElevenID/marty-integration-tests#403` merged at
`f0062b4e48ea1a7a489d2576bcea0e5d1fce484b`, adding the remaining migration-
idempotence, compatibility-mode, exact check-set comparison, and trusted-
positive projection gates. Its deterministic OID4VP PASS fixture is a
contract assertion, not runtime evidence: neither retained Python `v0.1.71`
nor rejected Rust `v1.1.208` can exercise that complete positive path. Release
clearance therefore remains explicitly blocked on
`canonical.oid4vp-positive-runtime-not-exercised`. The compatibility inputs do
not contain enough authenticated holder, transaction-binding,
presentation-policy, or status-source information to construct those facts
without a product-policy decision. Implement the frozen decision through the
existing canonical `marty-verification` policy service; never manufacture a
PASS in the compatibility adapter.

Protected `ElevenID/marty-integration-tests#404` packaged the exact protected
`#400`-`#403` harness lineage as immutable `v1.2.78` at merge commit
`3baad4b5dbccc720a50ff9ae5a280349180c02a8`. It carries 19 portable checks
plus one Rust-only default-disabled compatibility check, remains preliminary
and non-activating, retains `release_clearance=blocked` on
`canonical.oid4vp-positive-runtime-not-exercised`, and pins no corrected Rust
services image. It grants no aggregate, publication, deployment or product-
activation authority.

Repair proceeds in order: preserve `v1.2.78` only as preliminary harness
evidence; publish a corrected Credentials release; pass the incident record's
non-publishing candidate, trusted-positive runtime/parity, digest-first
resumable-release, and cancellation-point gates; select and prepare a then-
unused Rust artifact; create a new exact integration pin; pass the full
differential matrix; merge
that exact pin tree through protection; publish and independently verify a
distinct immutable post-pin integration release; and only then bind that
release with corrected Credentials into a later beta-only aggregate. The
preliminary harness release `v1.2.78` is not an aggregate pin. `v0.1.72`,
`v1.2.76`, `v1.2.77`, `v1.2.78`, `v1.1.209`, and `v1.1.210` remain
nondeployable evidence. Production is unchanged.

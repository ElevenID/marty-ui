# Credentials verification-image consolidation plan

Status: `eligible-corrected-artifact-required`; deployment is held. The
standalone Python verifier source/image deletion is merged in
`marty-credentials@v0.1.72`. `v0.1.72` is a valid issuance component, not a
failed verifier artifact. Release audit found that
`marty-integration-tests@v1.2.76` pinned bootstrap `marty-ui@v1.1.208`, which
predates the required corrections in `marty-ui#721`; `v1.2.76` is retained held
evidence only and grants no cutover authorization. Pre-interlock
`marty-ui@v1.1.210` is quarantined: its canceled attempts produced no GitHub
release or services artifact, but one UI-only registry coordinate remains from
the partial publication. Exact `v1.1.209` and `v1.1.210` evidence is retained in
[`verifier-release-incident-2026-08-31.md`](verifier-release-incident-2026-08-31.md).
`v1.2.77` is intermediate evidence only: it is published and independently
verified with the Python image as passing oracle and `v1.1.208` as bounded
negative control. `v1.2.78` is preliminary, non-activating evidence: it packages
protected parity corrections through PR `#403`, remains explicitly blocked,
and does not pin a corrected Rust runtime. PR `#737` introduced the candidate
producer; its first dispatch occurred only after the later hardening described
below. PR `#741` hardened the producer but retained raw tar-header offset
defects. PR `#744` corrected those specific defects. Producer run `33465702948`,
attempt `1`, was dispatched from exact protected-main commit
`2fa1ffa3b36a0c978a41377dd64ab084bc8fc204` before the trusted consumer landed.
It failed bundle validation with `OCI layer tar is empty` before attestation or
artifact upload, so it supplies no admissible candidate-gate acceptance. A
corrected producer run and authenticated, inspected consumer result are still
required. The
fail-closed eligibility interlock is merged. A future corrected Rust artifact,
a later exact fully passing consumer release, and a later aggregate binder are
required before beta acceptance; no future UI coordinate is selected or
reserved by this plan.
The separate public Python binding and the still-used Credentials adapter
remain supported. Production is unchanged.

## Objective

Replace the separately published `marty-credentials-verification` Python image
with the existing canonical `marty-ui` Rust verification service without
losing an intended API, governance, privacy, persistence, migration,
concurrency, deployment or release contract. The replacement extends the
canonical service with thin compatibility adapters; it does not create a
second Rust verifier or replace the existing `/v1/verify` product surface.

The immutable Python service image remains the parity oracle until the
corrected Rust artifact passes the full differential, database, migration,
packaging and consumer gates. Release `marty-integration-tests@v1.2.77`
packages that complete oracle and intentionally retains `v1.1.208` only as a
negative control for the session-scoping regression. The reusable
`marty-verification-python` binding is a separate public dependency and was not
removed when the service image was retired.

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

The bootstrap `v1.1.208` services image and provenance were independently
verified without deployment. The Rust consumer pin merged in
`ElevenID/marty-integration-tests#396` and was published as immutable
`v1.2.76`; its ten-gate matrix, checksums, SBOM and provenance passed for that
bootstrap artifact. Those results are retained held evidence only and do not
authorize cutover. The standalone Python verifier deletion merged in
`ElevenID/marty-credentials#250`, preserving the separate adapter and binding,
and was published as issuance-only `v0.1.72`; its retained 939-test Python
lane, cross-platform native matrix, checksums, SBOM and OCI provenance passed.
It remains a valid issuance component in the held stack.

Those results do not authorize cutover because `v1.1.208` is not a descendant
of required correction PR `#721`. Annotated `v1.1.209` records the intervening
correction binder but has no published release. Annotated `v1.1.210` was
created before an explicit release-eligibility interlock; all attempts were
canceled, leaving no GitHub release and no services artifact. Both attempts did
publish UI-only registry coordinates before cancellation. Their exact digests
and workflow evidence are recorded in
[`verifier-release-incident-2026-08-31.md`](verifier-release-incident-2026-08-31.md).
They are quarantined and must not be retargeted or deployed.

Protected `ElevenID/marty-integration-tests#398` expanded the intermediate
artifact differential across stateful session create/reload/restart, minimized
database persistence, retry/concurrency/fencing, direct verification,
authorization and purpose isolation, resolver failures and VDS-NC. The
published intermediate release
`marty-integration-tests@v1.2.77` preserves Python verifier `v0.1.71` as the
passing oracle and proves that Rust `v1.1.208` fails the expected canonical
transaction-ID session-scoping gate. Its release checksums, five Sigstore
bundles and five GitHub provenance attestations bind exactly to source commit
`5c008faa44859eb7d7528adc1ee2dba55bcca19a` and tag `v1.2.77`. The source
archive is
`sha256:39356e447f121f7eb9bc587d71f2d99b0ad9988601771c26631902b81448b52b`
and the SPDX SBOM is
`sha256:ff2afea7146954c51f8f7e3612443ad80853fb036f43d7e65307eaa07e56e4ac`.

Protected `ElevenID/marty-ui#727` merged the fail-closed eligibility interlock
at `569d74b10fcae9d6eadc6fceaf9f6d3eaf9b7c5b`; the protected-main lock remains
`hold`. PR `#737` introduced the candidate producer; its first dispatch occurred
only after the later hardening described below. PR `#741` hardened the producer
but retained raw tar-header offset defects. PR `#744` corrected those specific
defects. Producer run `33465702948`, attempt `1`, was dispatched from exact
protected-main commit `2fa1ffa3b36a0c978a41377dd64ab084bc8fc204`
before the trusted consumer landed. It failed bundle validation with
`OCI layer tar is empty` before attestation or artifact upload, so it supplies
no admissible candidate-gate acceptance. A corrected producer run and
authenticated, inspected consumer result are still required. Before any future
corrected artifact coordinate may be selected, reserved, prepared, or published, an
exact protected-main descendant containing PR `#744` must pass the
non-publishing candidate, trusted-positive OID4VP runtime, the landed
artifact-differential parity gates, and digest-first resumable release
requirements in
[`verifier-release-incident-2026-08-31.md`](verifier-release-incident-2026-08-31.md).
It must then bind the reviewed harness baseline, pass the hardened release gates and
publish without deployment. The differential must pin that exact image and
pass every group before a new
immutable corrected-Rust-pinned integration release is published using a
new coordinate selected after the harness-only `v1.2.78`. A later aggregate
stack, also selected only after its prerequisites pass, owns the single
beta-only deployment, demos, acceptance soak and cleanup. Production is
unchanged.

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
`cfdbebb4def784794aee9f0671e742c90cedffad`. It removes the generic
canonical-omission retry, resamples incompatible generated session identifiers
only before submission and only for exact frozen artifacts, bounds that
selection, and records only a sanitized count. Future Rust artifacts receive
no allowance and remain fail-closed. The forward harness must build on this
protected tree.

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

Protected PR `ElevenID/marty-integration-tests#404` packaged that exact
protected harness lineage as immutable `v1.2.78` at merge commit
`3baad4b5dbccc720a50ff9ae5a280349180c02a8`. It remains preliminary evidence:
`release_clearance` is still blocked on the positive OID4VP runtime, it does
not pin a corrected Rust services image, and it grants no publication,
deployment or activation authority; it is explicitly non-activating.

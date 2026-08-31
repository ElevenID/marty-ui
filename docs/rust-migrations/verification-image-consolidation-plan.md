# Credentials verification-image consolidation plan

Status: `release-order-repair-required`; deployment is held. The standalone
Python verifier source deletion merged before its release order was proven.
Immutable `marty-credentials@v0.1.72` and stale
`marty-integration-tests@v1.2.76` are ineligible. Integration `v1.2.77` is
containment-harness evidence only, not a corrected candidate pin, and
`marty-ui@v1.1.209` is a quarantined partial publication. Unsigned tag
`marty-ui@v1.1.210` is also
quarantined: it points to an unsafe binder, and its UI image was briefly
published, attested and signed and remains publicly accessible. No services or
migrations image or GitHub release exists. All affected release workflows remain disabled, the UI release
environment is interlocked, and no replacement UI version is selected. The
separate public Python binding and still-used Credentials adapter remain
supported, and production is unchanged.

## Objective

Replace the separately published `marty-credentials-verification` Python image
with the existing canonical `marty-ui` Rust verification service without
losing an intended API, governance, privacy, persistence, migration,
concurrency, deployment or release contract. The replacement extends the
canonical service with thin compatibility adapters; it does not create a
second Rust verifier or replace the existing `/v1/verify` product surface.

The last safe `v0.1.71` Python service image and frozen pre-deletion source
remain the parity and rollback oracles until the corrected Rust artifact passes
the full differential, database, migration, packaging and consumer gates. Rust
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
The full immutable-oracle harness subsequently shipped in integration
`v1.2.77`; protected PR `#400` hardened it further at
`a2ab449d2bbaa8c42734de1a6890c5f2d9868a2b`. Protected PR `#401` then closed
same-named privacy/minimization gaps at
`bd3abf0792bad5c61faa2ff3b0f56fb4df0807d7`: exact VDS check-code projections,
decoded VDS private-data exclusion, malformed-terminal raw-submission
minimization, and complete expired-row/lease cleanup. PR `#401` or an exact
reviewed descendant is the complete 17-gate floor and is not yet released. That
lane deliberately treats
`v0.1.71` as the passing Python oracle and `v1.1.208` as a known-ineligible
negative control. It proves containment, not a corrected Rust candidate pin,
and therefore does not authorize cutover.
Standalone Python verifier deletion merged in
`ElevenID/marty-credentials#250`. Immutable `v0.1.72` then published only one
service image, the issuance image
`sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`;
no verification image was published, and PyPI publication was skipped. All
four Credentials release workflows are disabled.

Annotated tag `v1.1.209` records the correction binder, but its interrupted
release produced only one OCI image, the quarantined UI image
`sha256:c223ee06d86dc85bc960a22aec4328f1e22fb6f38124bc261d38c3c21c0ac995`.
It produced no services image, migrations image, or GitHub release. Unsafe PR
`#725` then merged at `4326524a1c6a265bad6f6b46945e248345af0451`, and
unsigned annotated tag `v1.1.210` was pushed to that commit from preparation
run `33406442463`. The retained preparation bundle is artifact `9763321737`,
SHA-256
`a70de185f8d3fa6d0e62af98123af375eaaadd675d756cf02358626737a425fb`.
Four release dispatches (`33406717748`, `33407206697`, `33407461450`, and
`33408972797`) completed cancelled. The last dispatch's `build-ui` job had
already pushed, attested and signed `ui:1.1.210` at historical digest
`sha256:28f48e7ed885046ae753c1f4eea8855b8769cd166602741a8783cbc3dba64643`
before cancellation. Both `ui:1.1.210` and the exact digest remain publicly
resolvable. No `services:1.1.210` or `migrations:1.1.210` image or GitHub
release exists, the public stack smoke and manifest publication did not
complete, and there is no deployment or downstream integration pin. OCI image
tags omit the leading `v` used by Git tags. Both UI workflows are disabled;
the release environment permits only inert tag `release-hold-disabled` and
cannot be bypassed by administrators.

The fail-closed aggregate eligibility repair merged in PR `#727` at
`569d74b10fcae9d6eadc6fceaf9f6d3eaf9b7c5b` with
`release_state: hold`; that hold remains mandatory while corrected
prerequisites are produced. The first Rust candidate is therefore built by a
dedicated nondeployable workflow from the exact reviewed PR `#721` descendant
and exported only as short-retention Actions artifacts: services OCI archive,
SBOM, provenance statement, and source/build metadata. That workflow creates
no registry or Git tag, GitHub release, UI or migrations image, stack manifest,
or deployment record; it has no registry or deployment credentials and changes
no lock, catalog, or deploy surface. Its run, source commit, archive digest, and
image-config digest identify the candidate without reserving a release version.

Load the candidate archive locally and pass the complete hardened 17-gate
differential matrix against the retained exact `v0.1.71` oracle before any
publication binder. Candidate, final-image, and public-pin runs must use PR
`#401` merge `bd3abf0792bad5c61faa2ff3b0f56fb4df0807d7` or an exact reviewed
descendant; unchanged gate names do not permit PR `#400`. After the corrected
Credentials release and that candidate gate pass, publish a protected
integration release containing that exact harness floor/evidence, repeat the
exact no-`v` registry absence audit, and select a then-unused UI version. A
reviewed aggregate binder may then replace the
ineligible component coordinates and change `release_state` from `hold` to
`eligible` for one release attempt; this is not deployment authorization, and
every deployment entry point remains held. Before the first image push, the
release must fail if any exact no-`v` UI, services, or migrations tag resolves
and atomically create a draft GitHub release as its durable attempt claim. The
claim binds the prepared tag object, preparation run, source commit, and sole
release run ID. Every later run, including `workflow_dispatch`, rejects an
existing draft/published release, attempt claim, or any one of those OCI
coordinates.

The same stack release must run all 17 gates against the exact newly built and
pushed services digest before `publish-manifest`; the release build embeds its
own version and source commit, so candidate evidence cannot substitute. Every
unsuccessful or cancelled claimed run—whether a build, attestation, smoke,
matrix, or later pre-publication job fails—leaves the draft claim, skips/fails
final publication, durably tombstones the version, quarantines all pushed
coordinates, and requires repository/environment holds to be restored before a
new reviewed fix/version cycle. The durable claim and coordinate preflight keep
this fail-closed even when cancellation prevents cleanup. After a clean run
publishes the claimed draft, pin its exact services image, SBOM, provenance,
tag, and source commit in a protected public integration release. Bind that consumer
release, retained oracle, exact matrix run, and official stack manifest in a
reviewed `verification-cutover-evidence` record that also proves the released
harness contains PR `#401` or an exact descendant. Beta preflight must verify
the record and manifest digest without rebuilding the UI image; no later
aggregate release may replace the proven digest before promotion.
`v0.1.72`, `v1.2.76`, `v1.1.209`, and `v1.1.210` remain nondeployable evidence.
The standalone Python verifier deletion remains provisional through this exact
public consumer pin/evidence record, beta acceptance and soak, and the governed
rollback window. Retain the frozen pre-deletion source and executable `v0.1.71`
oracle/restore path throughout. No beta or production deployment has occurred.

Before any cleanup claim or replacement-version selection, repeat and retain
the exact registry audit:

```bash
docker buildx imagetools inspect ghcr.io/elevenid/marty-ui-oss/ui:1.1.210
docker buildx imagetools inspect ghcr.io/elevenid/marty-ui-oss/ui@sha256:28f48e7ed885046ae753c1f4eea8855b8769cd166602741a8783cbc3dba64643
docker buildx imagetools inspect ghcr.io/elevenid/marty-ui-oss/services:1.1.210
docker buildx imagetools inspect ghcr.io/elevenid/marty-ui-oss/migrations:1.1.210
```

The first two must resolve to the recorded digest and the latter two must be
absent. Any other result, including an indeterminate lookup, keeps the release
hold in place. Apply the same no-`v` three-image audit to a proposed replacement
version before its tag is prepared; every coordinate must be absent.

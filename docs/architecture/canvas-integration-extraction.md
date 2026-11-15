# Canvas integration extraction and hard boundary

Status: architecture decision and extraction baseline. No production routing or deployment is changed by this document.

## Non-negotiable boundary

The new `ElevenID/canvas-integration` repository is an external API consumer. Every request it makes to ElevenID core MUST use the public Common Gateway API with an organization-scoped API key, exactly as a customer-operated integration would.

The connector MUST NOT:
- connect to any Marty database or read/write core-owned tables;
- call issuance, signing, identity, organization, or other internal service URLs;
- import Marty internal Rust crates, Python packages, or private application modules;
- use internal service API keys, signing grants, private signing endpoints, or service-to-service credentials;
- join internal service Docker/Kubernetes networks or rely on trusted-network bypasses;
- mutate EvidenceFact, policy, application, credential, DID, status, or audit persistence directly;
- invoke core signing, approval, or credential lifecycle functions locally.

The connector MAY own Canvas-side state needed to operate Canvas: LTI registrations and launch state, Canvas OAuth grants/tokens, Canvas resource mappings, synchronization cursors/jobs, retry/dead-letter metadata, provider observations, and Canvas Credentials projection delivery state. It must store those in connector-owned storage, isolated from Marty core databases. Sensitive Canvas tokens must use connector-owned secret custody and must never be sent to the browser or logged.

## Direction of trust

There are two different traffic directions and they must not be confused:

1. Canvas LMS calls the connector's public LTI/OIDC/JWKS callback endpoints. The connector validates Canvas signatures, issuer, audience/client, deployment, nonce/state, redirect/origin and replay constraints.
2. The connector calls ElevenID only through the public Common Gateway, with its dedicated organization-scoped API key in `X-API-Key`. The gateway authenticates the key, enforces organization ownership, permission/scope, validation, rate limits and audit.

Canvas-facing unauthenticated protocol callbacks are not an exception permitting unauthenticated connector-to-Marty calls. No connector endpoint may call a core internal service.

## Ownership

### Connector repository owns
- Canvas LTI 1.3/OIDC login and launch protocol adapter, JWKS publication for the tool signer, deep linking and Canvas-facing experience endpoints;
- Canvas OAuth authorization, token refresh/revocation and secret storage;
- Canvas REST, AGS and NRPS clients, origin/DNS/redirect protections, pagination and rate-limit handling;
- Canvas catalog/resource mapping and evidence observation normalization;
- synchronization scheduler, worker, lease/job/dead-letter state and operational tooling;
- optional Canvas Credentials mirror provider and its delivery state;
- Canvas-specific administration UI package and connector API client;
- connector deployment, images, Compose/Kubernetes manifests, source-build/OSS portability tooling and connector acceptance tests;
- versioned connector-side contracts and Canvas behavior oracles that do not encode core-private schemas.

### Marty core retains
- Common Gateway, API-key authentication and organization/permission enforcement;
- organization, membership, API-key and integration-secret governance;
- MIP EvidenceFact schema, persistence, current-head semantics and audit history;
- Cedar policy evaluation and approval decisions;
- application lifecycle and issuance transactions;
- credential templates, issuer DID, key selection, KMS/OpenBao, signing grants and signing;
- credential status, suspension/revocation and canonical credential records;
- shared public API contracts and gateway route authorization.

Canvas is a provider adapter. It submits evidence through public gateway operations; core decides what that evidence means and whether issuance is permitted. A Canvas binding cannot override issuer, credential format, key, status profile or policy.

## Public Gateway contract

Use existing public endpoints wherever possible. The extracted route matrix in `contracts/canvas-integration-gateway-boundary.json` records 63 unique Canvas-related method/path pairs: 58 under `/v1/integrations/canvas` and five Canvas Credentials mirror/health operations elsewhere. Seventeen are Canvas-facing protocol callbacks currently hosted by Marty and must move to the connector edge. These are not all automatically suitable as a customer connector API: classify each as:
- connector-to-core public operation (must require organization API-key authorization);
- Canvas-to-connector protocol callback (moves to connector; must not remain a core bypass);
- administrator/browser experience endpoint (must be redesigned as connector UI calling the connector backend, which then calls gateway);
- obsolete/legacy route (retire only after consumer and migration proof).

Existing API-key scopes exposed in the console include `integrations:read` and `integrations:write`. Existing gateway authorization maps Canvas integration read operations to `integration-connector:view` and write/administrative operations to `integration-connector:edit`; integration writes must not be authorized by read scope. Existing tests explicitly verify that `integrations:read` cannot perform integration edit and that an API key for another organization is rejected.

The new connector must start with a least-privilege key, normally read + write only where each operation requires it. Do not give it credential-signing, issuer-key administration, user administration or broad application-approval permissions merely to simplify integration. If a required public operation is missing, add it to the Common Gateway with an explicit API contract, tenant ownership check, narrow permission, audit behavior, and tests. Do not add an internal shortcut.

## Current implementation evidence and extraction classification

The current `ElevenID/marty-ui` main tree (observed at `8ff6cefaa2856ab8a00be7e449981198943960dd`) contains 814 paths with Canvas in their path. This is a discovery set, not a move-all list: many files are core-owned behavior or frozen test evidence.

| Current path family | Disposition | Notes |
|---|---|---|
| `ui/src/components/console/deploy/CanvasIntegrationsPage.jsx` and its tests | Move connector UI; rewrite imports | Current page imports shared ConsoleContext, permissions, templates, deployment profiles, delivery destinations and shared components. Replace these with a standalone connector UI and public Gateway client. |
| `ui/src/components/canvas/CanvasMirrorProvenanceLookup.jsx` | Split | Connector-owned lookup UI; canonical credential/provenance data remains core-owned and must be read via Gateway. |
| `ui/src/components/pages/CanvasLtiExperiencePage.jsx`, `ui/src/services/canvasLtiExperience.js` | Move/rewrite | Canvas-facing experience surface belongs with connector; any core reads/writes must go through Gateway. |
| `ui/src/services/canvasIntegrationsApi.js` and tests | Move/rewrite | Existing client is coupled to Marty UI `api.js`, idempotency, query and console context. Replace with connector-owned HTTP client that sends only the scoped Gateway API key from server-side code. Never embed a privileged API key in browser JavaScript. |
| `rust/services/issuance/src/canvas_lti_*.rs` | Extract protocol logic; rewrite core access | LTI/OIDC protocol handling moves to connector. Remove direct issuance repository/service access from connector. Core-facing work becomes public Gateway API calls. |
| `rust/services/issuance/src/canvas_oauth*.rs`, `canvas_provider_http*.rs`, Canvas catalog/provider adapters | Move provider code | OAuth/Canvas HTTP behavior is connector-owned. Core integration-secret storage references must be replaced with connector-owned secret custody; do not copy core master keys. |
| `rust/services/issuance/src/canvas_sync_*.rs`, `rust/services/issuance/src/bin/canvas_sync_worker.rs` | Rebuild as connector worker | Current worker directly uses PostgreSQL repositories and internal signing/issuance URLs and credentials. It is not portable as-is. Reimplement the worker against connector storage plus public Gateway calls. |
| `rust/services/issuance/src/canvas_mirror_*.rs`, `canvas_credentials_*.rs` | Split | Canvas Credentials HTTP provider and delivery orchestration move. Canonical credential/status/provenance and lifecycle actions remain core and are invoked through public APIs. |
| `rust/services/issuance/src/canvas_award_candidate*.rs`, `canvas_lti_evidence*.rs`, `canvas_claim_projection.rs`, `canvas_review_resolution.rs` | Retain core semantics; replace provider coupling | EvidenceFact, policy, application and credential state remain core. Expose missing narrow gateway operations if needed. Do not move core persistence into connector. |
| `rust/crates/canvas-demo-seed`, `rust/crates/canvas-sandbox` | Move/rebuild as connector tools | Seed only disposable Canvas and connector resources; use public Gateway APIs for Marty resources. No production key or core DB fixture. |
| `rust/crates/canvas-acceptance`, `rust/crates/canvas-worker-acceptance` | Split tests by owner | Connector protocol/worker tests move. Core persistence, policy, gateway authorization and issuance composition tests stay in core. Keep existing acceptance evidence until equivalent replacement coverage is landed. |
| `contracts/canvas-*`, `scripts/run_canvas_*`, `tests/test_canvas_*` | Split by behavior owner | Canvas provider oracles move with connector. Core authorization/evidence/issuance contracts remain in Marty. Never discard or regenerate frozen oracle evidence solely to ease extraction. |
| `config/canvas`, `docker/canvas-*`, Canvas Compose profiles, OSS portability workflows and deployment scripts | Move connector deployment ownership | Preserve beta/production boundaries, pinned source/image provenance, host capacity checks, rootless/security restrictions and current runtime ownership guards. |
| `docs/CANVAS_PORTABLE_INTEGRATION.md`, `docs/CANVAS_PRODUCTION_OPERATIONS.md`, LTI setup docs | Split and cross-link | Connector operations go to new repo; public API/core governance contracts remain in Marty docs. |

## Known blocker: worker is currently an internal service

`rust/services/issuance/src/bin/canvas_sync_worker.rs` currently constructs PostgreSQL-backed Canvas OAuth/worker repositories, a PostgreSQL integration-secret vault, uses internal signing-key endpoints and signing credentials, and passes an issuance API key into Canvas OAuth/provider services. This is direct internal coupling and must not be copied into the new repository.

The extraction requires public Gateway capabilities for every worker action. The worker must store only Canvas-side state and job metadata in its own database. It submits normalized evidence through a tenant-scoped Gateway API; it does not persist EvidenceFact or call signing/approval code. Credential mirror lifecycle operations must likewise use public Gateway endpoints.

## Required gateway API gap audit

Before moving runtime code, enumerate each connector use case and bind it to an existing public route, method, request/response schema, required API-key scope, tenant-ownership rule and audit event. Specifically verify:
- platform registration and installation metadata;
- LTI launch-to-application/session mapping;
- course/activity catalog reads;
- AGS result and Canvas REST evidence submission;
- NRPS roster identity mapping without email-based identity joins;
- background evidence sync enqueue/status/retry/dead-letter operations;
- binding validation and readiness;
- Canvas Credentials publish/status/revoke operations;
- canonical credential/provenance/status reads.

Where no suitable route exists, add the route to the Common Gateway and publish its schema first. Avoid exposing core-private models; use stable protocol DTOs. All write operations must be idempotent where retries can create duplicate effects.

## Deployment and credential model

- Connector gets its own deployment, network, database and service identity.
- The only Marty destination permitted by network policy is the public Common Gateway origin.
- Connector-to-Gateway traffic uses HTTPS and `X-API-Key`; API key is stored server-side in connector secret storage and never shipped to React.
- Connector secret rotation/revocation is independent from core service credentials.
- Canvas OAuth tokens and LTI tool private signing material remain connector-owned; issuer credential signing remains core-owned.
- No shared DB, schema, SQL migration, Redis queue, internal service hostname, Docker network, or service API key between connector and core.
- Use separate beta/production connector environments; preserve existing live deployments during migration.
- The new integration must remain deployable without a local Marty checkout or Marty source tree.

## Mandatory architecture enforcement

The new repository CI must fail closed on:
1. imports or dependencies on Marty internal crates/packages;
2. database drivers or connection configuration targeting Marty databases;
3. internal service URLs, `/internal/*` paths, service API key variables, signing grants or private signing routes;
4. direct network aliases/Compose dependencies for core services;
5. browser bundles containing API keys or Canvas OAuth secrets;
6. Gateway requests without the scoped `X-API-Key` client and explicit organization context;
7. any integration operation whose route lacks an API-key scope, organization binding, request schema and authorization test.

Runtime network policy is the backstop: allow Canvas endpoints, connector-owned storage/secret services and the public Gateway; deny private Marty service networks and database endpoints. Static checks alone are insufficient.

Core Marty CI must also test the Gateway contract: API-key-only success, missing-key rejection, wrong-organization rejection, insufficient-scope rejection, read-vs-write separation, tenant isolation, audit emission, idempotent retries, and rejection of any newly introduced internal connector route.

## Migration sequence and exit gates

1. **Inventory and contract freeze:** complete file-level ownership map and public API gap matrix. No runtime changes.
2. **Gateway readiness:** implement missing public APIs and permission tests. Connector can perform all required operations using a customer-style API key.
3. **Create new repository:** private initially; independent CI, release policy, threat model, server-side Gateway client, connector DB and deployment skeleton. No core source copied into it.
4. **Extract provider layer:** LTI/OAuth/Canvas REST/AGS/NRPS, Canvas token custody, resource mapping and Canvas-side sync state.
5. **Extract UI:** connector UI package/app; Marty console may link to it but must not import internal connector implementation. All privileged API calls remain server-side.
6. **Rebuild worker and mirror:** no SQL against Marty; only public Gateway APIs for core actions.
7. **Parallel qualification:** replay frozen Canvas behavior oracles and run full OB3 integration with a customer-style organization API key. Compare old and new behavior without production writes.
8. **Cutover:** only after live beta acceptance, security review, backup/rollback plan and operator approval. Preserve old implementation and deployment until cutover evidence is complete.
9. **Retirement:** remove old Canvas provider/runtime code only after every consumer and required acceptance suite has moved or been replaced.

No production or beta service is changed by this baseline.

# Consolidated Rust Migration Roadmap

**Status:** Waves one and two complete and behaviorally accepted at beta; wave three active; production promotion requires separate approval

**Scope:** Marty backend services, protocol kernels, security-sensitive mobile logic, and licensing

**Initial rollout environment:** Beta only

**Last updated:** 2026-08-21

## Objective

Reduce the amount of Python and other non-Rust protocol code in the Marty stack by replacing it with a single authoritative Rust implementation for each capability. The migration must preserve externally observable features and behavior, improve fail-closed security, and remove superseded Python or Dart implementations after each cutover.

This is not a line-for-line translation project. Rust owns deterministic protocol, policy, validation, cryptographic, and state-machine behavior. Python remains only where it is useful for API composition, persistence adapters, scheduling, OCR, and third-party integrations until a whole service is deliberately replaced. Flutter/Dart remains responsible for application UI and platform integrations.

The immediate deployment boundary is beta. Production and persistent self-host environments are not changed by this roadmap without a separate approval and promotion decision.

## Wave three — Rust service plane and complete MMF replacement

Wave three replaces the remaining deployed Python service plane with Rust and
replaces the Python Marty Microservices Framework with a complete, reusable,
DRY Rust platform. Removing MMF must not remove either currently consumed or
intended framework features. The authoritative feature inventory and crate
architecture live in `marty-microservices-framework` at
`docs/RUST_PLATFORM_MIGRATION_ROADMAP.md`.

The MMF work is a replacement, not a retirement shortcut. Its Rust workspace
must preserve REST/gRPC/hybrid runtime behavior; configuration and secret
providers; SQL, MongoDB and Redis infrastructure; migrations; Kafka, outbox,
DLQ and replay; workflows, saga, CQRS and event sourcing; security and identity;
observability; resilience; discovery, gateway and service mesh; plugins; push;
ML; documentation and contract tooling; deployment support; built-in services;
testing; and the developer CLI.

### DRY ownership rule

Generic service behavior lives once in feature-oriented MMF crates and is
consumed by every Rust service. `marty-ui` service binaries may contain only
their domain routes, use cases, repositories and provider adapters. They may
not copy service lifecycle, health/readiness, configuration, secret loading,
migrations, event envelopes, outbox, retry/circuit-breaker, telemetry,
authorization-context, discovery or error-normalization implementations.
`marty-core` remains the sole owner of protocol, policy, verification and
cryptographic kernels.

### Ordered `marty-ui` ports

Work proceeds in descending removable Python size after the MMF foundation is
available. Completed services retain their historical production-source
estimates. Remaining services are remeasured from all tracked Python below the
service boundary, including implementation-specific tests and migrations that
will be replaced by language-neutral contracts and Rust-owned schema history;
generated protobufs and caches remain excluded.

| Order | Service | Approximate removable Python | Required preservation |
|---|---|---:|---|
| 1 | Gateway | 16,961 | Every public/internal route, proxy behavior, auth context, tenancy, signing/KMS orchestration, provider routing, limits, errors and observability |
| 2 | Flow | 9,154 | OID4VCI/OID4VP/SIOP/mDoc/DIDComm transaction orchestration, persistence, callbacks, outbox, idempotency and expiry |
| 3 | Organization | 7,952 | Organization, membership, RBAC, SCIM, invitations, tenant boundaries, events and storage |
| 4 | Auth | 6,498 | OIDC, Keycloak administration, provisioning, sessions, claims, tenancy, errors and audit behavior |
| 5 | Credential template | 13,418 | CRUD/versioning, issuance context, wallet registry and routing, delivery destinations, validation, seeds and storage |
| 6 | Presentation policy | 11,631 | CRUD/versioning, trust resolution, credential-format dispatch, status lookup, native evaluation adaptation and exact decision responses |
| 7 | Trust profile | 8,618 | CRUD/versioning, registry synchronization orchestration, trust material, scheduling, storage and authorization |
| 8 | Applicant | 3,692 | Applicant/application state transitions, vetting, evidence, biometrics, reviewer locks, issuance orchestration and storage |
| 9 | Verification | 1,867 | Session APIs, OID4VP construction, provider/service integration, persistence and canonical results |
| 10 | Device registration | 1,845 | Registration lifecycle, challenge consumption, key rotation, preferences, organization checks and storage |
| 11 | Deployment profile | 1,558 | CRUD, validation, versioning, authorization and storage |
| 12 | Compliance profile | 857 | CRUD, policy metadata, authorization and storage |

### Gateway port status

The gateway's 434 method/path declarations and eight-middleware execution
order are frozen in `contracts/gateway-routes.json`. The Rust gateway now
builds one MMF route table, classifies public and gateway-owned boundaries,
uses the canonical MMF reverse proxy, and has provider adapters for static
service discovery and bounded Reqwest transport. Gateway-specific tenant
authorization is separated from the reusable Cedar engine: route permissions,
resource-owner lookups, authorization skips, and published API-key scope
compatibility execute `contracts/gateway-authorization-behavior.json`, while
schema validation and policy evaluation remain solely in `mmf-security`.

Generic protocol-version, content-type, ETag, and idempotency behavior now
lives once in `mmf-platform`; rate limiting remains in `mmf-security`. Marty
policy values, auth-provider ports, exact rate-key behavior, and normalized MIP
errors are covered by `contracts/gateway-middleware-behavior.json`. A bounded,
timeout-aware gRPC adapter now validates sessions, API keys, and exact tenant
memberships without exposing backend details; malformed successful responses
fail closed. The Axum library runtime now composes the frozen MIP, distributed
rate-limit, authentication, content-type, ETag, tenant authorization,
distributed idempotency, and credentialed-CORS stages in their exact legacy
execution order. Organization resolution preserves path, resource-owner,
query, JSON body, and authenticated-state precedence; membership/API-key
decisions inject only trusted downstream identity. The language-neutral
`contracts/gateway-runtime-authorization.json` and black-box Axum tests cover
that boundary, including provider failures and observable middleware order.

The Rust binary is now executable. Fail-closed environment and `_FILE` secret
configuration, production Redis enforcement, static discovery, bounded HTTP
resource-owner lookup, authenticated gRPC identity/membership channels,
optional gRPC CA validation, graceful shutdown, readiness checks and release
identity are composed at startup. The real binary starts and serves health in
an executable smoke test. `/ready` and `/health/ready`, which the original AST
extractor missed because FastAPI registered them dynamically, are now explicit
members of the language-neutral route contract. The shared service image is
prepared to dispatch `gateway` to `marty-gateway`; the image cannot be built or
published until the temporary MMF path dependencies are replaced by the
landed MMF revision.

The complete 688-test Python gateway suite and the Rust gateway's 79 unit and
black-box tests plus three executable health/fail-closed tests are green. The post-executable
adapter audit is now closed: service-credential injection, route-bound tenant
projection, request DTO canonicalization, response privacy projection,
dependency preflight, organization composition, Hosted Pilot purge
orchestration and scheduling, and the tenant-filtered gRPC-to-SSE bridge all
execute in Rust under shared behavioral contracts. The Python package remains
only as the parity oracle until the final Redis, executable/container,
immutable-dependency and anti-reintroduction cutover gates pass; it is never a
runtime fallback for an enabled Rust path. No deployment has occurred, and
beta will not be updated until all wave-three slices land.

The proxy trust-boundary slice now has executable parity for issuance service
credentials and public Canvas exceptions, trusted identity forwarding,
resource-owner lookup credentials, special service ownership, applicant
evidence rewrites, retired state-addressed Canvas HTTP 410 responses, and
organization query projection. `contracts/gateway-proxy-trust-boundary.json`
runs against Python and Rust. The shared MMF proxy now exposes a distinct
trusted-query override channel at local MMF commit `c3a378e`; unlike ordinary
query defaults, these post-authorization values replace forged client tenant
selectors. Rust black-box tests verify the replacement at the upstream request
boundary. Body-scoped request canonicalization is complete in the DTO slice.

The first privacy projection and request-canonicalization kernels are also
active in Rust. Python and Rust
execute `contracts/gateway-issuance-response-projection.json` for issuance
initiation, transaction lists, transaction records, issued-credential records,
lifecycle mutations and renewal offers. Lifecycle revoke, suspend and reinstate
requests are canonicalized in Rust and reject undeclared custody or provider
state. The Rust gateway removes redemption, custody and delivery-routing
state, restores public defaults, validates status enums, rewrites management
reads to the canonical transaction paths, and fails malformed successful
upstream payloads with HTTP 502. Issuance creation now executes in Rust under
`contracts/gateway-issuance-create-behavior.json`: strict public request
validation rejects custody selectors and private wallet keys, template
ownership and issuer-DID consistency are enforced, signing identity resolution
fails closed, optional public wallet-client registration is preserved, and
only the canonical DID plus public issuance fields reach the issuance service.
Authenticated DIDComm delivery now also has explicit Rust request and response
ownership under `contracts/gateway-didcomm-delivery-behavior.json`. Rust rejects
unknown resolver/provider selectors, binds the request organization to the
authenticated session rather than a query/body projection, injects only the
issuance service credential, and strips provider delivery receipts from exact
public responses. The same fixture executes against the Python parity oracle
and Rust, including malformed and cross-tenant failures.
Organization create/update canonicalization and public response validation now
execute in Rust under `contracts/gateway-organization-behavior.json`. The
adapter preserves create defaults and partial-update semantics, strips the
body tenant selector in favor of the authorized path scope, rejects legacy
no-op/private request fields, validates nested public membership projections,
omits null public optionals exactly as Python does, and returns a normalized
HTTP 502 when the organization service adds any undeclared/private field.
Credential-template claim translation and public privacy projection now run in
Rust under `contracts/gateway-credential-template-behavior.json`. Public claim
display, derived-claim and mdoc namespace fields are translated to the one
canonical service representation; responses reverse that mapping while
removing derivability hints, validation constraints, custody selectors and
unknown internal metadata. Draft updates and creation execute through this
kernel. Creation now preserves the Python model defaults and format-specific
identity validation, verifies optional trust-profile existence, verifies
compliance-profile existence and tenant ownership, and resolves the issuer DID
through the canonical signing service before forwarding the canonical internal
request. Rust rejects cross-tenant or malformed dependencies and private JWK
material fail closed. One language-neutral fixture now exercises the create
request, claim translation, and privacy-safe response in both implementations.

Issuer-entity and trust-profile issuer-relationship request and response
contracts now execute in Rust under
`contracts/gateway-trust-behavior.json`. The Rust adapter preserves create
defaults, partial-update semantics, case-insensitive accreditation uniqueness,
relationship policy defaults and exact protocol UUID shapes. It recursively
rejects custody selectors and private JWK parameters from public metadata and
strictly projects successful single and list responses, omitting only declared
null optionals and failing closed on service drift. The same Rust kernel now
owns trust-profile create/update defaults, nested validation rules, revocation
and time policies, credential-free standard-port HTTPS registry-source checks,
and exact profile and registry-sync response projections. The Axum path and
shared Python/Rust fixture exercise these policies end to end.

OID4VP verification-flow start now executes as a composed Rust operation under
`contracts/gateway-verification-flow-behavior.json`. Rust validates and
canonicalizes response type, transport, request-URI method, HAIP constraints,
expiry, verifier DID and tenant scope; resolves presentation-policy and optional
trust-profile ownership through the resource-owner provider; and forwards only
the canonical request. The response is reduced to the exact public verification
request resource, so flow-definition and signing selectors cannot escape.

Presentation-policy create and update now execute as composed Rust operations
under `contracts/gateway-presentation-policy-behavior.json`. The Rust kernel
validates every nested requirement, requested claim, predicate, alternative,
holder-binding proof, issuer/freshness constraint and ranking policy; accepts
proof-only policies without weakening the obligation rule; and rejects private
or undeclared selectors. Every referenced credential template is loaded in the
authenticated tenant, and its canonical payload format replaces caller input
before forwarding. Successful create/update/get/list/activate responses are
allowlisted, validated and normalized, with disabled holder binding reduced to
the exact public `{required:false}` shape.

Deployment-profile and lane adapters now execute in Rust under
`contracts/gateway-deployment-behavior.json`. Profile creation preserves the
public defaults and biometric compatibility alias, requires a trust profile and
at least one effective presentation policy, verifies policy/template ownership,
and forwards only canonical fields. Profile and lane responses restore public
defaults, remove API keys/device secrets/internal runtime state, and fail closed
on malformed service output. The shared fixture runs against both language
implementations and the Axum test exercises preflight and projection end to end.

Flow-definition and flow-instance request and response kernels now execute in
Rust under `contracts/gateway-flow-behavior.json`. Definition writes preserve
all built-in flow types, approval modes, hooks, triggers and custom extension
steps/transitions; preflight every credential, application, presentation,
delivery and trust dependency; and forward canonical defaults. Instance starts
recursively reject tokens, KMS selectors, private keys and signing state from
initial context. Definition, instance and verification-result reads strip
internal execution fields and fail closed if private service state appears in
context, step results, metadata or history. Verification results now deeply
validate and project every credential and claim result, preserve all public
trust/freshness/signature/revocation fields and defaults, and strip nested
provider state under the same language-neutral fixture.

Organization cross-service composition now executes in Rust under
`contracts/gateway-organization-composition-behavior.json`. The gateway derives
runtime issuance/verification readiness from live credential-template, policy,
deployment and flow artifacts; counts applicant lifecycle states; renders
configured integration quick-start metadata; and composes organization
lifecycle data with issuance retention summaries. Manual Hosted Pilot purge is
a bounded transaction that validates retention enablement, forwards the exact
retention window, privacy-projects the purge result and best-effort persists the
last-purge timestamp only after successful deletion. The Rust executable also
runs the paginated due-only automatic sweep with the legacy enabled/interval/
batch configuration and cancels it during shutdown. Shared Python/Rust vectors,
Axum route tests and a complete scheduled-sweep transaction test pass.

Tenant-filtered event delivery now executes in Rust under
`contracts/gateway-sse-behavior.json`. The gateway subscribes to the canonical
event-stream gRPC service, binds organization and optional user filters to the
authenticated session, rejects forged cross-tenant selectors and unsafe event
types, drops cross-tenant backend events, and emits the exact connected, event
and public failure SSE frames. The response uses bounded buffering and cancels
and drops the live backend stream when the HTTP client disconnects. Streaming
responses bypass ETag body buffering so an unbounded SSE body cannot deadlock
the middleware chain. Shared Python/Rust vectors, backend-failure tests and a
live disconnect/drop test pass.

### Flow port status

The Flow migration inventory is frozen before implementation. The removable
surface is 9,154 lines of production Python excluding tests, migrations and the
migration runner. It contains 28 explicit HTTP operations, 16 gRPC operations,
12 built-in flow types, custom extension graphs, PostgreSQL persistence,
atomic nonce consumption and terminal-result finalization, application-event
idempotency, leased callback delivery, expiry, and protocol-provider calls.
The port must preserve all of these behaviors; the Python package remains the
parity oracle until the complete executable and persistence gates pass.

Protocol ownership is already consolidated: the pinned `marty-core` revision
owns lifecycle transitions, graph validation and next-step selection, OID4VP
request construction/evaluation, mDoc handover binding, HAIP response-key and
JWE operations, verifier DID/X.509 identity, and SIOPv2 token verification.
The Rust Flow binary will call those crates directly and will not reproduce
their decisions. Generic durable workflow, messaging, retry and callback
delivery behavior belongs to MMF. The MMF messaging crate now has
language-neutral fenced-lease behavior at local commit `05d858a`, including
expired-lease recovery, stale-worker rejection, retry/dead-letter transitions,
and bounded-retention payload scrubbing. This framework primitive will be
shared by Flow and later service ports. MMF Push also owns tenant-bound callback
destination templates at `a1806b9` and the canonical header-and-payload-bound
event HMAC at `6d4462f`, eliminating two more Flow-only Python utilities.
Its registry now exposes its configured/empty state at local commit `d6743be`,
allowing Flow to require at least one valid deployed destination without
copying MMF's private registration representation or matching rules.

The first `marty-flow` crate slice now executes the checked-in
`contracts/flow-service-behavior.json`. Twelve Rust tests freeze all 28 HTTP and
16 gRPC operations, every built-in type/reference/sequence, public status and
private-context behavior, callback defaults, and atomicity obligations. The
corrected HTTP inventory counts the separately released GET and POST Request
Object retrieval operations that the first frozen catalog omitted; retaining
both methods preserves the live wallet and Digital Credentials API surface.
The domain delegates transitions and graph validation directly to
`marty-verification`; callback retries use `mmf-workflow`, delivery composition
uses `mmf-push`, and fenced storage uses `mmf-messaging`. Its repository tests
prove concurrent finalization commits one nonce/result/callback exactly once,
terminal decisions are immutable, application event plans are replay-safe and
payload-conflict-safe, and issuance artifacts are transaction-idempotent.

The PostgreSQL repository now implements the same fenced finalization and
callback lifecycle over the released `flow_service` tables. It uses database
clock time and one SQLx transaction for expired-nonce cleanup, nonce insertion,
live-state compare-and-swap, terminal result persistence and callback enqueue.
Callback claims use `FOR UPDATE SKIP LOCKED` and per-attempt UUID leases;
completion, retry and dead-letter updates reject stale workers and successful
delivery scrubs the destination and payload. The Rust-service CI job now
provisions the isolated `marty_atomic_test` database. Its behavioral test runs
the concurrent-winner, expiry rollback, retry/reclaim, stale-lease rejection
and retention-scrubbing vectors against PostgreSQL. Compilation and all
non-container tests pass locally; the real PostgreSQL execution remains a CI
landing gate because the local Docker daemon is unavailable.

The native HTTP and gRPC application adapters are complete. The remaining Flow
gates are listener/lifecycle composition, container startup/readiness,
packaging parity and the final executable acceptance suite. Provider, DTO,
definition mutation, generic instance execution, start-side-effect, Request
Object retrieval, OID4VP and SIOPv2 submission, application-event processing,
terminal persistence and all 16 released gRPC operations now share the same
Rust records and kernels. After those executable gates pass, the Python Flow
runtime and its service dependencies are deleted immediately; this pre-v1
migration has no compatibility waiting period. No deployment occurs during
these slices; beta receives one aggregate update only after all wave-three work
lands.

The public request boundary is now also represented in Rust. Strict DTOs cover
definition create/PATCH (including unset-versus-explicit-null semantics),
custom extension graphs, hooks and triggers, instance start/advance, OID4VP and
SIOP starts/submissions, Digital Credentials API responses, and authenticated
application-approved events. Unknown fields, missing type-specific references,
private context injection, invalid graph topology, unsupported OID4VP transport
combinations, oversized fields and unsafe callback destinations fail with
normalized codes. `contracts/flow-api-behavior.json` supplies 12 accepted and
13 rejected transport-neutral vectors. Four Rust tests pass, and a Python
conformance test consumes the same vectors so the legacy boundary remains the
parity oracle until deletion. That Python test compiles locally but its runtime
execution is deferred to service CI because the available local environment is
missing `grpc_health`; CI installs the full locked service dependency set.

Provider ownership is now explicit and fail-closed. A shared tenant-membership
port and authorization decision live in `mmf-security` at local commit
`1a2bf0a`, with nine language-neutral allow/deny vectors; this removes the need
for Flow to create another membership model and gives the gateway a later DRY
consolidation target. `marty-flow` declares typed ports for all seven required
runtime capabilities: tenant membership, credential templates, presentation
policies/evaluation, issuance, signing identity, flow-key envelopes and
physical-document operations. Startup composition reports every absent port
instead of enabling a partial runtime. Signing identities and signatures are
bound to the exact organization, public DID, verification method, purpose,
credential format and algorithm; private JWK members, mismatched curves and
mismatched signer responses are rejected. The provider behavior contract now
also freezes all seven physical-document operations and exact downstream
method/path pairs. Live gRPC and bounded HTTP adapters consume these contracts;
common mTLS/channel composition and executable readiness remain in the active
provider step.

The released protobuf contracts now generate Rust clients and the future Flow
server directly at build time. Live typed gRPC adapters cover organization
membership, credential-template lookup, presentation-policy lookup/evaluation
and issuance initiation. They propagate the internal service token, bound JSON
responses to one MiB, preserve nested issuance claims through the canonical
JSON field, normalize gRPC failure classes, and reject mismatched tenant,
resource, policy/nonce, template and issuance identities. The crate compiles,
all 23 non-container behavior tests pass, and strict Clippy is clean. The HTTP
adapters now cover signing-identity resolution/signing, tenant-bound flow-key
wrap/unwrap and every physical-document lifecycle operation. They preserve
gateway path prefixes, disable redirects, bound response bodies to one MiB,
apply operation timeouts, reject malformed or incomplete responses, and accept
the generic signature field only when its declared encoding is raw IEEE P1363.
The public definition, instance, verification-result and artifact projections
now also execute in Rust against `contracts/flow-response-behavior.json`.
These DTOs preserve protocol status, resolved steps, tenant/subject metadata,
timestamps, references, hooks, trigger, verification details and artifact
lifecycle fields while recursively removing private service state. Malformed
persisted timestamps, custom extensions, context types and protocol fields fail
closed. The same golden vectors compile into the Python parity suite; all 25
Rust non-container tests pass individually and strict Clippy is clean. The
Windows host cannot link every test binary concurrently because of its PDB
limit, so the aggregate suite remains a Linux CI landing gate. Flow now
consumes the canonical `mmf-platform` channel factories for all organization,
credential-template, presentation-policy and issuance clients. Both eager
startup/readiness and lazy development composition inherit the shared bounded
plaintext, TLS and mutual-TLS policy; no Flow-local endpoint or certificate
constructor remains. The focused provider suite, all applicable Rust test
groups, and strict Clippy pass. HTTP/gRPC executable
composition is now the next Flow runtime gate. Its first prerequisite is now
frozen in `contracts/flow-startup-behavior.json` and implemented by the Rust
configuration boundary. Beta and production must explicitly configure
PostgreSQL, Redis, all nine downstream endpoint origins and all four service/webhook
credentials; every secret is at least 32 bytes, endpoint origins are
credential-free, listener addresses cannot collide, and connection/database
bounds fail closed. Local development may default only non-secret service
locations. Four behavioral tests and strict Clippy pass. The next executable
slice must connect these dependencies into MMF lifecycle/readiness and must
expand the Rust persistence records to preserve every released definition,
instance and artifact field before any application operation is advertised as
ready. That record boundary is now implemented under
`contracts/flow-persistence-behavior.json`: 28 definition fields, 20 instance
fields and 17 artifact fields round-trip losslessly, then feed the smaller
canonical protocol kernels and privacy-safe public projections through
explicit fail-closed conversion. This preserves legacy step details,
preconditions, retry/resume settings, all linked profiles, localized offers,
issuance lifecycle data and timestamps instead of narrowing storage to the
security kernel. Three behavioral tests and strict Clippy pass. The contract
also requires a dedicated `state_history` JSON column during Rust migration;
the Python object previously accumulated this history in memory but its
PostgreSQL adapter never stored it. Rust now also owns the complete install and
upgrade schema under an advisory lock, adding dedicated `state_history` and
`retry_cooldown_minutes` columns without replacing Alembic's legacy version
record. SQLx CRUD covers definition create/update/get/list/delete, immutable
terminal instance create/update/get/filtered-list, and transaction-idempotent
artifact create/update/get/list/code lookup. The existing atomic nonce,
terminal result and callback transaction now persists state history as well.
Two migration contract tests, three record tests, the PostgreSQL integration
binary (which runs the real migration/CRUD/atomicity vectors when its isolated
CI database is configured), and strict Clippy pass. Seed ownership and MMF
lifecycle/readiness are the next sub-gates before the HTTP/gRPC listeners are
enabled. The reusable lifecycle portion is now complete at local MMF commit
`06a52ac`: required components block activation unless healthy and immediately
remove live readiness when they degrade. Flow consumes that primitive under
`contracts/flow-runtime-behavior.json`, registers PostgreSQL, Redis nonce
storage, four typed gRPC dependencies, three HTTP provider adapters, callback
delivery and both application listeners as mandatory, and exposes the shared
`/health`, `/ready`, `/version` routes plus native backend/version/capability
diagnostics. Two Flow runtime tests, five MMF runtime tests and strict Clippy
pass. Dependency connection, seed ownership and HTTP/gRPC application listener
composition are now complete in the executable described below.

The startup boundary also preserves the released container contract instead
of requiring a flag-day configuration rewrite. It accepts the existing
`ORG_GRPC_TARGET`, `FLOW_SERVICE_PORT`, `FLOW_GRPC_PORT`, `ISSUANCE_API_KEY`
and AsyncPG-tagged PostgreSQL URL forms, normalizes them to the canonical Rust
types, and loads all four mandatory credentials from the existing `_FILE`
secret convention. Direct values take precedence; unreadable or empty secret
files fail startup, and configuration diagnostics redact database, Redis and
all secret values. Six startup/unit vectors and strict Clippy pass. The
checked-in base and self-host manifests now carry Flow's explicit
reference-owner endpoints; these source changes are not a deployment. Beta
remains queued for one aggregate cutover after every wave-three slice lands.

Rust migration ownership now also includes the complete built-in Flow seed
surface. `contracts/flow-seed-behavior.json` freezes the Open Badge login flow,
both legacy-member and verified-badge issuance flows, the bootstrap instance,
the Marty deployment-profile link, effective protocol types, template IDs and
structured trigger events. The seed SQL stores the post-MIP custom extension
graphs directly, inserts missing records without overwriting administrator
changes, and only touches the cross-service deployment-profile table when it
exists. The isolated PostgreSQL CI vector loads every seeded definition back
through the fail-closed Rust kernel and public projection. Three migration
contract tests and strict Clippy pass; live SQL execution remains in the
configured CI database gate.

The gRPC connection plan now preserves Flow's asymmetric released trust
boundary. Typed configuration requires complete inbound and outbound workload
certificate/key/CA groups in beta and production, rejects partial groups, and
requires an explicit deployed plaintext decision for the three legacy token-
authenticated channels. The presentation-policy channel alone upgrades its
existing target to mutual TLS with private-CA trust, while organization,
credential-template and issuance continue through the shared bounded MMF
factory under the explicit compatibility flag. No service-local endpoint,
certificate loader or channel constructor is reintroduced. Six provider tests,
five startup tests, the secret-file unit vector and strict Clippy pass.

The executable dependency connection step is now implemented under
`contracts/flow-connection-behavior.json`. Startup opens a bounded PostgreSQL
pool, runs the Rust-owned schema and seed migrations under their advisory lock,
executes a live query, canonicalizes and connects the configured Redis nonce
database, requires `PING`/`PONG`, eagerly connects all four typed gRPC clients
through the shared MMF transport factory, probes all three bounded HTTP
provider adapters and all four reference-owner services,
and rejects an incomplete provider registry. Each required component becomes
healthy only after its own probe succeeds; any database, migration, Redis,
transport, HTTP, credential or registry error aborts startup before lifecycle
activation. The language-neutral connection contract test, Redis database
selection test and strict Clippy pass. Inbound gRPC security now consumes MMF's
shared workload server-TLS and exact method-authorization primitives under
`contracts/flow-grpc-security-behavior.json`. Every RPC requires the configured
service token using constant-time comparison; sensitive verification start and
application-approved calls additionally derive identity only from the verified
client certificate URI SAN parsed by `marty-crypto`, then require the exact
Auth or Applicant SPIFFE identity. A bearer value cannot replace certificate
identity, partial server credentials fail startup, and missing versus wrong
identities map to unauthenticated versus permission-denied status. Two focused
security tests, the language-neutral contract test and strict Clippy pass. The
complete application surface is now attached in the crate; the next executable
slice must bind both listeners and activate only after both are serving.

The first executable HTTP operation slice is complete under
`contracts/flow-http-read-behavior.json`. Axum now serves the public MIP 0.4.1
capability document plus tenant-authorized definition, instance, terminal
verification-result and artifact reads directly from Rust-owned PostgreSQL
records. Pagination is bounded to 500, removed lifecycle aliases stay rejected,
nonterminal result polling returns conflict, tenant permissions are checked
through the shared MMF membership policy, and every projection recursively
removes private context. Malformed stored records and missing providers fail
closed without returning storage diagnostics. Physical-document support is now
derived from the mandatory healthy downstream provider instead of duplicating
its private configuration in Flow. Three focused handler tests, the shared
behavior-vector test and strict Clippy pass. Definition and instance mutation
are subsequently complete; verification HTTP adapters, webhook, QR and DID
routes remain before the HTTP listener can be advertised as complete.

The same HTTP surface now includes the first two complete mutation paths:
tenant-authorized draft-definition deletion and instance cancellation.
Cancellation first validates the transition through the canonical Rust state
machine, then uses one PostgreSQL statement to compare-and-set any nonterminal
instance to `cancelled`, persist its completion time and append the
`flow_cancelled` history event. Concurrent or replayed cancellation returns
conflict and cannot overwrite a terminal result. The isolated PostgreSQL
behavior suite now exercises the persisted transition and replay rejection.
The authoritative reference catalog port is now complete. Application
Templates resolve from issuance with the internal API key; delivery
destinations, trust profiles and deployment profiles resolve from their owning
services with the authenticated user identity. Exact returned IDs, bounded
responses, redirects, malformed bodies, unavailable owners and non-success
statuses all fail closed. The catalog is one mandatory readiness component and
all four owners must pass health probes before activation. Beta and production
must explicitly configure the credential-template, trust-profile and
deployment-profile origins; local development alone may use defaults.
`contracts/flow-provider-behavior.json` freezes the four method/path/auth
triples, and the focused startup, provider and HTTP-adapter suites plus strict
Clippy pass.

Definition mutation parity is now attached to that catalog. Rust serves create,
PATCH, validate, dry-run test and activate in addition to the existing reads
and draft-only delete. Standard definitions preserve all twelve protocol graph
families and released defaults; custom definitions preserve extension actions,
configuration, timeouts, transitions and entry-step identity. PATCH retains
unset-versus-null behavior, cannot move a definition between tenants, increments
the version exactly once and returns the definition to draft. Draft writes
require every reference to exist and be tenant-bound but continue to allow
inactive dependencies; validation and activation require every direct and
policy-nested dependency to be active and bind each credential template's
public issuer DID to its exact organization, format, purpose, algorithm and
public signing key. System-owned delivery destinations are the sole tenant
exception. `contracts/flow-reference-validation-behavior.json` and the expanded
HTTP contract execute these rules, including one-resolution-per-template
caching and side-effect-free dry runs. The focused definition, reference and
HTTP suites plus strict Clippy pass. The remaining HTTP surface is QR
generation, native verification adapters, verifier DID publication,
application-approved webhooks and protocol-specific verification starts.

The provider-independent instance execution kernel is also complete under
`contracts/flow-instance-execution-behavior.json`. Active-definition and exact
tenant binding, initial status/history, definition-driven expiry, protocol
context, recursive private-state rejection, canonical next-step selection,
wallet-resume transitions, terminal success/failure and step-result history now
execute in Rust. Initial history preserves the released nullable prior state,
while every subsequent transition remains a typed canonical state. Direct
starts fail closed on application-approval, unknown or malformed preconditions;
only separately supplied server-authenticated evidence can satisfy the
application-approved control. Three execution vectors, persistence and atomic
repository regressions, and strict Clippy pass.

Public instance start and advance are now composed around that kernel under
`contracts/flow-instance-side-effects-behavior.json`. OID4VCI starts use only
the typed issuance provider, bind idempotency to the Flow instance (or the
existing application-flow digest), reconstruct missing per-wallet offers with
the pinned `marty-oid4vci` implementation and the complete template wallet
configuration, persist the released MIP 0.3.1 `CredentialOffer` envelope and
preserve every artifact/context field. Deployed public origins are explicit,
origin-only HTTPS configuration and fail closed. Physical-document starts
consume rather than persist raw applicant/MRZ/data-group input, then call the
typed provider for initialization and all six subsequent lifecycle operations.
Provider operation, flow and tenant identities are checked before state is
accepted. PostgreSQL inserts each new instance and optional artifact in one
transaction; advancement compares both source status and `updated_at`, so a
concurrent stale transition cannot win. Three side-effect vectors, startup,
HTTP, persistence and PostgreSQL contract suites, plus strict Clippy pass.
Manual OID4VCI QR/offer regeneration is also native: each retry has a
flow-and-attempt-bound idempotency key and one transaction expires prior active
artifacts, inserts the replacement and updates instance offer context. The
verification route set is now native. The remaining Flow gate is the other
protocol route set and actual HTTP/gRPC listener composition; no partial
executable is activated or deployed.

OID4VP presentation-query construction is now composed in Rust before route
signing and transport work. The typed credential-template provider preserves
VCT, mDoc doctype, supported formats and claim namespace/element mappings, and
reads active wallet formats from the owning service's wallet registry rather
than copying its catalog into Flow. Exact active policy/template tenant
bindings and requirement shapes are checked before the pinned
`marty-oid4vci::presentation_request` builder produces the equivalent
Presentation Exchange and DCQL artifacts. Missing templates, malformed claims,
empty wallet format catalogs and provider failures have no fallback. The
language-neutral composition contract, two focused vectors, provider
regressions and strict Clippy pass. Request-object signing, URL-query/message
composition, submission evaluation and terminal callback persistence are now
implemented by the subsequent native verification slices below.

Standard DID-bound OID4VP and SIOPv2 Request Object construction is now native
under `contracts/flow-request-object-behavior.json`. Each fetch re-resolves the
exact organization + issuer DID + `oid4vp_request_signing` +
`oauth-authz-req+jwt` + ES256 identity, builds the canonical OAuth/OID4VP or
SIOPv2 claims, delegates only the base64url signing input to the typed signing
provider and validates the returned identity before assembling compact JWS.
Flow never receives signing private key material. The request records exact
state, audience, response URI and the released MIP `PresentationRequest`
envelope. HAIP now generates a fresh native P-256 response-encryption key per
flow, advertises only its public JWK and `direct_post.jwt`/ECDH-ES/A256GCM
metadata, and persists the private JWK only through the organization- and
flow-bound signing-service envelope provider. Re-fetch reuses the bound
envelope and never serializes the private key into Flow context. Three
request-object vectors and strict Clippy pass. The unsigned URL-query profile
now composes the same native DCQL artifact with redirect-URI client identity,
direct-post state/audience binding, canonical client metadata and the same MIP
message, then enforces the released minimum/configured maximum URI bounds. It
rejects HAIP and SIOP combinations and never invokes the signing provider.
Four request-transport vectors and strict Clippy pass. The route remains
private to the Rust crate until persistence and expiry transitions are
complete. Verification-flow start composition is now native under
`contracts/flow-verification-start-behavior.json`: every start generates a
32-byte cryptographic nonce, validates an exact active tenant policy with
nonempty requirements, resolves the exact DID-bound ES256 Request Object
identity, checks optional callbacks through the shared MMF tenant registry,
and builds request-URI, signed by-value, bounded unsigned DCQL, or SIOP
authorization requests before returning one complete persistable instance.
The deployed startup contract now requires a nonempty, well-formed
`FLOW_CALLBACK_DESTINATIONS`; missing, empty, malformed, credentialed, or
unsupported destinations fail before service activation. Two focused start
vectors, startup regressions and strict Clippy pass. The HTTP start route stays
unadvertised until request retrieval expiry/CAS behavior, DC API transport and
submission/finalization are all native, preventing a partial Rust cutover from
dropping an existing verifier profile.

The configured verifier identity matrix is now native as well. Flow accepts
the released redirect-URI, decentralized-identifier and `x509_hash` client-ID
schemes plus `did:web`, canonical `did:jwk` and canonical P-256 `did:key`
derivation. DID derivation delegates to pinned `marty-didcomm`; `x509_hash`,
leaf-key matching, certificate thumbprinting and leaf-first `x5c` shaping
delegate to `marty-verification`. X.509 Request Objects omit `kid` and carry
only the validated chain. The LISSI compatibility profile retains raw DID
client identity, `client_id_scheme=did`, Presentation Exchange rather than
DCQL, no standard client metadata and an explicit HAIP incompatibility. Strict
client metadata, branding, HAIP enablement, both request-size limits and PEM or
file-backed verifier certificates are typed startup configuration; unsupported
values, missing X.509 material, insecure deployed logo URLs and out-of-range
limits fail closed. The focused request-object suite now has five vectors, the
startup suite has six vectors, and strict Clippy passes. Route exposure is now
gated on atomic retrieval/expiry, DC API transport/origin parity and complete
submission/finalization rather than verifier identity support.

Wallet Request Object retrieval is now a native, persistence-neutral kernel
under `contracts/flow-verification-request-behavior.json`. It accepts only
`awaiting_wallet` or `in_progress` snapshots, returns an explicit expired
record carrying the `request_expired` terminal history for repository CAS,
rejects URL-query flows, enforces POST-only retrieval and a nonempty
`wallet_nonce` when configured, and re-resolves the signing identity on every
fetch. Standard and LISSI retrieval share the same profiled builder. Digital
Credentials API retrieval now emits `openid4vp-v1-signed` / `dc_api.jwt`, binds
the exact configured HTTPS origins, omits redirect/state fields, creates the
native per-flow encrypted-response key, stores only its tenant/flow-bound
envelope and advertises ECDH-ES with A128GCM/A256GCM receiver support. The
public origin is the default exact DC API origin; configured comma-separated
origins are normalized, deduplicated and rejected if they are not deployed
HTTPS origins. Three retrieval vectors, six Request Object vectors, startup
regressions and strict Clippy pass. The HTTP adapter now persists either the
ready context or expiry transition with status-and-`updated_at` CAS and returns
the released `Cache-Control: no-store` and `Pragma: no-cache` response headers.

OID4VP submission evaluation and terminal composition are now native under
`contracts/flow-verification-submission-behavior.json`. The kernel binds exact
state in constant time, validates Presentation Submission shape, unwraps the
single-token DCQL transport form, and delegates cryptographic verification
only to the typed presentation-policy provider with exact nonce, audience,
trust and verifier context. The pinned ISO 18013 implementation supplies mDoc
session-transcript binding; pinned verification code validates and decrypts
HAIP JWE responses through a tenant/flow-bound key envelope. Provider failure,
empty credential evidence or any non-valid signature is retryable and consumes
neither state nor nonce. An authenticated allow completes; an authenticated
deny fails terminally and clears claims. Raw tokens and submissions are
discarded in favor of canonical SHA-256 digests. Same-payload terminal replay
returns the stable result while a different digest conflicts. The kernel emits
the released MIP 0.3.1 VerificationResult and a tenant-registered MMF callback,
requiring a minimum 32-byte delivery secret. PostgreSQL finalization now takes
the complete `FlowInstanceRecord` and atomically preserves subject, external
reference, histories, context, result and timestamps while consuming the nonce
and enqueuing the callback; organization and definition identity are immutable
CAS fences. Six language-neutral submission vectors, including the shared
HAIP interoperability JWE, the PostgreSQL contract binary and strict all-target
Clippy pass.

SIOPv2 submission is now native under
`contracts/flow-siop-submission-behavior.json` and reuses the same terminal
finalization unit rather than creating another transaction implementation. The
pinned `marty-oid4vci` verifier exclusively owns JOSE parsing, ES256/EdDSA
policy, public `sub_jwk` signature validation and RFC 7638 thumbprint binding.
Flow then enforces `iss == sub`, exact string-or-array audience membership,
constant-time nonce equality, numeric `iat`/`exp`, the released 60-second clock
skew and the rule that a token cannot predate its transaction. Success stores
only the self-attested subject, subject syntax, signing algorithm and canonical
submission digest; the raw ID token is discarded. Subject identity, both
history transitions, terminal result and nonce consumption commit through the
full-record PostgreSQL compare-and-set, with no callback for this protocol.
Same-token replay returns the stable terminal response and a different token
conflicts. Four focused behavior groups, the OID4VP regressions, PostgreSQL
contract binary and strict all-target Clippy pass. The HTTP adapters now commit
retrieval, expiry and both terminal protocols through their corresponding
compare-and-set transactions. `/v1/flows/verify` and standalone
`/v1/flows/siop` starts require authenticated `verification:execute`
membership; Request Object GET/POST, direct-post, Digital Credentials API and
SIOPv2 submission routes expose the released envelopes without a Python
fallback. Direct post rejects terminal replay, while Digital Credentials API
and SIOPv2 repeat submissions are idempotent only for the exact canonical
digest. Different terminal payloads conflict. Digital Credentials API binds
the exact HTTPS origin into `origin:{origin}` audience and native encrypted
response processing. Retryable provider failures persist and consume nothing;
expiry and terminal changes use full-record status-and-`updated_at` atomic
compare-and-set. Startup accepts an explicit `OID4VP_ISSUER_DID`, the retained
`MARTY_ISSUER_DID` alias, or a public-origin-derived `did:web` identity and
fails closed on malformed identity. The route behavior is frozen in
`contracts/flow-verification-http-behavior.json` and exercised through the
live Axum router.

Application-approved issuance planning is now native under
`contracts/flow-application-approved-behavior.json`. The reusable
Applicant-to-Flow security boundary lives once in `mmf-security` at local
commit `54b5805`: canonical Unicode JSON, dedicated purpose-bound HMAC,
producer/audience/version binding, freshness, minimized evidence, deferred
atomic replay consumption and one-winner replica races share a
transport-neutral contract. Flow no longer duplicates that cryptographic
kernel. Its native planner selects only active application-approved OID4VCI
definitions, preserves exact optional template targeting, orders flows by ID,
requires object claims and canonical manual-issuance UUIDs, and recreates both
released v1 and v2 logical offer identities. The complete definition,
applicant and claims snapshot is canonically hashed so a reused logical flow
with changed semantics conflicts. PostgreSQL now reserves the authenticated
event receipt and all selected instances in one transaction, recovers an exact
replay plan, and rejects changed event payloads or changed offer semantics.
Focused language-neutral planning, trusted-precondition, PostgreSQL contract
and strict Clippy gates pass. The HTTP adapter now authenticates before plan
reservation, consumes the shared Redis replay key only after durable planning,
recovers exact planned replays, and completes each OID4VCI offer through the
typed issuance provider. Offer completion is flow-idempotent and race-safe:
an existing active artifact is reused, while concurrent first completion uses
snapshot CAS and reloads the winner. Provider failures retain the released
per-flow partial-failure response and remain retryable through the durable
plan. The gRPC adapter now consumes this exact kernel and security evidence; no
Python fallback is permitted.

The `/oid4vp/did.json` compatibility endpoint is native under
`contracts/flow-did-http-behavior.json`. It resolves the exact configured
organization + issuer DID + `oid4vp_request_signing` +
`oauth-authz-req+jwt` + ES256 identity, publishes only the sanitized public
JWK as `JsonWebKey2020`, preserves authentication/assertion relationships and
the released DID media type, no-store and CORS headers, and fails closed when
the signing-identity provider is absent or invalid. The default organization
UUID and application-event freshness/replay settings are now typed startup
configuration; deployed environments require the dedicated 32-byte event key.

All 16 released Flow gRPC operations are now implemented by one native adapter
under `contracts/flow-grpc-behavior.json`. Legacy protobuf definition, instance,
artifact and verification DTOs translate into the same PostgreSQL records,
provider registry, graph/transition kernels, protocol side effects and atomic
mutations used by HTTP. Ordinary RPCs require constant-time service-token
authentication plus tenant membership and method-specific permission;
verification start and application approval additionally require their exact
mTLS SPIFFE identities. Application-event protobuf strings recover canonical
JSON before the shared MMF HMAC check. Starts persist their optional artifact
atomically, advances use snapshot compare-and-swap, cancellations fence terminal
state, and verification/application starts preserve their existing idempotency
units. Public projections redact private context. Streaming is tenant-bound,
supports instance and flow-type filters, uses a bounded 256-event channel and
terminates a lagging subscriber explicitly instead of silently losing events.
Health probes the live database and requires service authentication. Four
adapter unit vectors, two language-neutral contract tests, all-target compile
and strict Clippy pass.

The native Flow executable is now composed under
`contracts/flow-executable-behavior.json`. It connects and probes every required
dependency, binds both listener sockets, starts the durable callback worker and
only then activates shared MMF readiness and the standard gRPC health service.
HTTP merges all application routes with shared lifecycle/version/native-backend
diagnostics; gRPC serves the complete adapter with optional development
plaintext and required deployed mTLS. Shutdown transitions to draining, marks
gRPC not serving, gracefully closes both listeners, stops the callback worker
and then records stopped. The callback worker preserves the released bounded
retention, attempts, lease, poll, retry and batch configuration; uses
`SKIP LOCKED` fenced claims; revalidates the tenant destination for every
attempt; signs the canonical event; forbids redirects; distinguishes HTTP,
timeout and network failures; retries with bounded exponential delay;
dead-letters removed destinations; and scrubs delivered or expired payloads.
The optional PostgreSQL integration gate now drives a real loopback callback
receiver and verifies signed delivery, payload scrubbing and destination
dead-lettering in addition to the existing lease races. Executable, callback,
runtime, submission and strict Clippy gates pass locally; real PostgreSQL
delivery remains a configured Linux CI execution gate. Native container
packaging is now complete: the shared service image builds and contains
`marty-flow`, the production-equivalent Rust service image has a dedicated
non-Python `flow` target with HTTP and gRPC ports plus a native health check,
and CI builds that target as `marty-flow:ci`. The language-neutral packaging
contract verifies all three boundaries. The source cutover is now complete:
the shared image dispatches Flow only to `marty-flow`, the shared Python
migration runner no longer owns the Flow schema, and Rust startup runs the
advisory-locked schema and seed migrations. The complete `services/flow`
package and its obsolete Python-only PostgreSQL contract image are deleted,
removing 19,935 Python, migration, fixture and image-contract lines while
retaining the language-neutral contracts and native tests. The Rust
PostgreSQL integration gate now explicitly owns event-plan races, payload and
semantic conflicts, artifact idempotency, callback leases, migration and seed
behavior in CI.

Development is explicitly configured as development. Beta is explicitly
deployed and fail closed: Flow receives distinct inbound and outbound workload
certificates, presentation-policy receives its server identity, and auth,
applicant and verification receive separate client identities. A beta-only
provisioning helper creates short-lived identities with exact DNS and SPIFFE
URI SANs without printing keys; the release runner validates every required
secret, file, chain and expiry before stack mutation. The three documented
legacy downstream gRPC channels retain their explicit beta plaintext decision,
but sensitive Flow RPC authorization still derives only from verified client
certificates. Local full-suite, strict Clippy, optimized binary, packaging,
Compose and anti-reintroduction gates pass. Remaining Flow work is external CI
container/PostgreSQL execution and branch landing; no beta deployment has
occurred.

### Organization port status

The Organization whole-service port is active on its own worktree and branch
from the completed Flow cutover. The authoritative source scan freezes 62
unique HTTP method/path contracts spanning organization CRUD, membership,
join flows, API keys, preferences, lifecycle, audit, RBAC, Cedar policy sets,
onboarding and SCIM 2.0. It also freezes all 12 intended protobuf RPCs and
records the four RPCs declared by the protocol but never implemented by the
Python server (`CreateOrganization`, `UpdateOrganization`,
`ListOrganizations` and `RemoveMember`). Rust must implement the full intended
12-method surface rather than preserve that omission.

The first implementation slice establishes `marty-organization` and ports the
organization, membership, role, permission, API-key, join-code and policy-set
domain behavior plus deterministic SCIM pagination, equality-filter parsing,
error envelopes and role-name normalization. Both languages consume the same
`contracts/organization-domain-behavior.json`; the complete route, RPC and
event inventory is frozen in `contracts/organization-service-surface.json`.
Six Rust vector groups, three Python parity groups, locked tests, formatting
and strict Clippy pass. Rust migration ownership is also established over the
released `organization_service` schema: an advisory-locked, idempotent final
schema creates or validates all 11 tenant, membership, key, preference, join,
RBAC, policy and audit tables and records an independent Rust migration head.
It preserves existing Alembic installations while adding the intended API-key
`scope_type`, `deployment_profile_id`, `enabled` and `updated_at` fields that
the Python entity exposed but did not persist. A language-neutral persistence
contract and Rust source gate pass; live PostgreSQL execution is configured as
a CI gate because no local Organization database URL is present. The next
slices add the application use cases over shared MMF event publication,
authorization and audit policy, all HTTP and gRPC adapters, executable
composition, packaging, PostgreSQL acceptance and same-slice deletion of
`services/organization` after those gates pass. No beta deployment occurs
during these slices.

All nine Python persistence adapter families are now consolidated into one DRY
`PostgresOrganizationStore`. It owns organization, member, API-key,
console-preference, join-code, permission, role/member-role, policy-set and
audit storage without duplicating connection/session lifecycle. Tenant-owned
lookups bind organization IDs in SQL, membership email matching remains
case-insensitive, role replacement is transactional, assignments are
idempotent, audit filters are parameterized and bounded, persisted enum drift
fails closed, and released lowercase/DRAFT compatibility values remain
accepted deliberately. The optional live PostgreSQL contract exercises the
complete round trip and cascade behavior when
`ORGANIZATION_POSTGRES_TEST_URL` is configured. Locked unit/source tests,
strict Clippy, cross-language domain vectors and the ownership guard pass
locally; live execution remains a CI gate.

The 104-entry permission catalog is now frozen as language-neutral data and
consumed by both Python and Rust. Rust derives all eight intended system roles
from that single catalog: owner, admin, access administrator, catalog
administrator, reviewer, operator, viewer and applicant. Owner/admin retain
the complete catalog; reviewer/operator keep their exact view and action
supplements; applicant remains the sole default role and has no organization
console access. Permission IDs and new system-role IDs are deterministic,
while released database IDs are retained on reseed. Catalog and role seeding
are idempotent and included in the optional PostgreSQL round-trip gate. Four
Python parity tests, ten Rust unit/contract groups and strict Clippy pass.

Organization cache behavior now consumes the canonical production Redis
adapter in `mmf-data`; no service-local Redis client or command implementation
was added. MMF commits `b566451` and `9f9be66` provide fail-closed Redis
operations, TLS/startup health enforcement, namespace-bounded `SCAN`, complete
ordinary/sorted-set behavior and multiple keyspaces over one multiplexed
connection. `marty-organization` derives three scoped views that preserve the
mixed-deployment keys exactly: `org_membership:{user}:{organization}`,
`member_permissions:{user}:{organization}` and `org:{organization}:plan`.
The language-neutral `contracts/organization-cache-behavior.json` freezes those
keys and default-plan semantics. Rust tests prove dual membership/permission
invalidation, plan synchronization, namespace compatibility and rejection of
empty identifiers/plans; the full Organization suite and strict Clippy pass.
The optional live MMF Redis acceptance gate remains configured through
`MMF_REDIS_TEST_URL`; no endpoint is available locally, so it is compiled but
not executed here.

All 12 Organization domain-event families now have one native envelope and
audit projection under `contracts/organization-event-behavior.json`:
organization create/update, member invite/add/remove, API-key create/revoke,
and role create/update/delete/assign/remove. The surviving Python audit
publisher and Rust execute the same action, category, resource, actor,
severity, message and event-data vectors. Rust additionally projects every
event into the canonical `mmf-messaging` at-least-once envelope with exact
tenant partition, event deduplication identity, topic/routing key and bounded
retry metadata. `OrganizationEventPublisher` persists the audit record before
using the provider-neutral MMF transport and propagates audit, projection and
transport failures instead of converting an unavailable live event path into
success. Mutating application paths no longer use that non-atomic sequence:
the native `OrganizationApplication` locks updates and commits organization,
owner membership, the complete permission/role seed, owner-role assignment,
audit projection and the canonical MMF PostgreSQL outbox message in one
transaction. Existing permission IDs are resolved from the upsert before role
links are written, preserving databases seeded by Python. Acknowledgement only
occurs after the durable event is queued. Default-plan cache synchronization
runs after commit as derived state and is returned as a typed warning when it
fails, avoiding both silent drift and unsafe client retries after a successful
database commit.

`contracts/organization-application-behavior.json` now freezes create defaults,
owner membership, the 104-entry catalog, partial-update ordering,
explicit-null clearing, settings merge behavior and the open-join/public-only
invariant across Python and Rust. Native reads cover get, bounded list,
discoverable filtering and active user memberships. Twenty-two Rust tests,
all 65 surviving Python Organization tests, formatting and strict Clippy pass;
the atomic PostgreSQL acceptance test is compiled and runs when
`ORGANIZATION_POSTGRES_TEST_URL` is available. The remaining Organization
slices are member/join/API-key/preference/RBAC/policy/audit application
mutations, Cedar authorization, all HTTP and gRPC adapters, event-outbox
dispatch/readiness, executable/container packaging, acceptance gates and
same-slice deletion of the Python service. No beta deployment occurs before
those slices and the rest of wave three land.

The largest remaining Organization application family—membership and
joining—is now native as well. Invitations, acceptance, tenant-bound role
replacement, owner-role retention, owner-removal rejection, member reads and
removal, idempotent direct provisioning, pre-seeded email linking, default
role selection, Marty/demo-admin promotion, join-code consumption and direct
open joins all execute through `OrganizationApplication`. Member, role-link,
join-code-counter, audit and MMF outbox writes share one transaction; update
and code rows are locked before decisions, and membership/permission cache
invalidation is an explicit post-commit warning. The direct-provisioning
planner centralizes role deduplication and the applicant-to-admin promotion
rule rather than duplicating it across callers. Owner retention is enforced on
direct provisioning as well as ordinary role replacement.

`contracts/organization-membership-behavior.json` freezes direct-role
resolution and join-code failure precedence across Python and Rust. It also
corrects the legacy ambiguity where an exhausted code with a future expiry was
reported as expired: inactivity wins first, then actual expiration, then
exhaustion. The optional PostgreSQL acceptance gate now covers invite,
acceptance, role replacement, owner protection, removal, code/open joins and
direct provisioning while asserting one durable audit/outbox pair for every
emitted mutation. Twenty-five Rust tests, all 67 surviving Python Organization
tests, formatting and strict Clippy pass. API keys and preferences are next,
followed by RBAC/policy/audit application mutations and the adapter/runtime
cutover.

API-key and console-preference application behavior is now native. API-key
creation validates the complete MIP scope allowlist, organization versus
deployment-profile binding, positive rate limits and future expiry before
persisting every intended field. Creation and tenant-bound revocation commit
the key, audit record and MMF outbox event atomically; validation hashes the
presented secret, performs the domain's constant-time verification and rejects
disabled, revoked or expired keys. Tenant-scoped list/get operations no longer
permit a path organization to select another tenant's key. The raw secret is
retained only in the one-time creation result.

Console preferences now distinguish an omitted active-organization field from
explicit null and an explicit UUID, lock an existing preference during partial
updates and preserve the default applicant/no-active-organization behavior.
This fixes the surviving Python command's `hasattr` ambiguity, which made every
request appear to contain `last_active_org_id` and could clear it during an
unrelated view-mode update. `contracts/organization-api-preference-behavior.json`
drives both languages for key scope/binding cases and preference
omit/clear/replace semantics. Twenty-seven Rust tests, all 69 surviving Python
Organization tests, formatting and strict Clippy pass. The optional PostgreSQL
gate now also validates key creation, constant-time lookup, cross-tenant
revocation rejection, revocation, and persisted preference partial updates.
Policy-set and audit-query application behavior remains before the
adapter/runtime cutover.

Organization RBAC application behavior is now native. Custom role creation,
partial update and tenant-bound deletion; permission resolution; default-role
uniqueness and transfer; member assignment/removal; system-role deletion
protection; owner-role retention; last-role retention; and role/permission
reads all execute through `OrganizationApplication`. Each mutation locks its
decision rows and commits role, member-role, audit and canonical MMF outbox
state in one PostgreSQL transaction. Cache invalidation occurs only after
commit and reports typed warnings. Role deletion reassigns members that would
otherwise become roleless and fails closed when a required replacement is
missing or invalid.

`contracts/organization-rbac-behavior.json` freezes replacement selection,
default transfer, missing-role and self-replacement behavior across Python and
Rust. The temporary Python oracle was corrected to transfer default status
rather than deleting the only default, and its behavior remains covered until
the native adapter/runtime cutover deletes the Python service. Twenty-seven
Rust tests, all 70 surviving Python Organization tests, formatting, strict
Clippy and the ownership guard pass. The optional PostgreSQL acceptance gate
compiles RBAC create/update/assign/remove/delete behavior, system-role
protection and exactly one durable audit/outbox pair per successful mutation;
live execution still awaits `ORGANIZATION_POSTGRES_TEST_URL`. Policy-set and
audit-query application behavior is next, followed by authorization and the
adapter/runtime cutover. No beta deployment occurs before all wave-three
slices land.

Policy-set lifecycle and audit-query application behavior are now native.
`marty-organization` creates, reads, filters, partially updates, validates,
activates, archives and tenant-binds deletion of structured Cedar policy sets.
Mutations lock their tenant and policy rows; activation atomically archives
the previously active set of the same type, enforcing the domain's intended
one-active-set-per-organization/type invariant that the Python implementation
documented but did not enforce. Missing native validation fails before any
database access. Legacy Cedar text still projects into the stable structured
response shape, while malformed, duplicate, effect-mismatched, disabled-only
and schema-invalid policy documents fail closed.

The reusable implementation belongs to `mmf-security`, not the Organization
service: MMF commit `e87a538` adds one bounded `CedarPolicyValidator` for JSON
or human-readable schemas and shares strict parsing/schema validation with
the existing authorization engine. Organization consumes that API rather
than adding a second Cedar kernel. All 69 MMF security unit and integration
tests plus strict Clippy pass.

Native audit reads now preserve tenant-bound detail lookup, total counts,
bounded page/per-page and legacy limit/offset semantics, exact category,
event, resource, action and severity filters, actor substring matching,
metadata IP matching, full-text search, explicit ISO date bounds and positive
hour/day/week windows. `contracts/organization-policy-audit-behavior.json`
freezes policy validation, active-set replacement, legacy projection, audit
pagination and time-window behavior across Python and Rust. Thirty Rust tests,
all 73 surviving Python Organization tests, formatting, strict Clippy and the
ownership guard pass. The optional PostgreSQL gate compiles complete
policy-set lifecycle, active-set replacement, filtered/count-consistent audit
queries and cross-tenant detail denial; live execution still awaits
`ORGANIZATION_POSTGRES_TEST_URL`. Organization authorization and HTTP/gRPC
adapter/runtime packaging are next. No beta deployment has occurred.

Organization authorization decisions are now native and shared rather than
reimplemented in the service. MMF commit `707425d` extracts active,
tenant-bound membership authentication from permission evaluation; both paths
retain the same typed fail-closed outcomes for absent identity, missing or
cross-tenant membership, inactive membership and denied actions. Organization
projects persisted roles and effective permissions into that primitive and
adds exact gateway-forwarded API-key binding: the synthetic principal, key ID,
tenant and minimized route permission must agree, and API keys cannot satisfy
owner-only actions. Membership-only routes preserve the released behavior
without weakening permissioned routes.

`contracts/organization-authorization-behavior.json` executes the same user,
owner and API-key cases against Python and Rust, including missing identity,
inactive membership, permission mismatch, tenant mismatch and owner-only
denial. Stable application errors replace implicit `None` or permissive
fallbacks. Thirty-one Rust tests, all 74 surviving Python Organization tests,
all 69 MMF security tests, formatting and strict Clippy pass. The remaining
Organization work is the trusted HTTP/gRPC adapter boundary, runtime and
outbox composition, executable/container packaging, PostgreSQL acceptance and
same-slice Python deletion. No beta deployment has occurred.

The complete intended 12-method Organization protobuf service now executes in
Rust, including `CreateOrganization`, `UpdateOrganization`,
`ListOrganizations` and `RemoveMember`, which were declared but absent from
the Python server. Generated Tonic types remain authoritative; DTO projection,
UUID and enum validation, API-key validation, member permissions, filtered
organization totals and stable gRPC status normalization are implemented at
the adapter boundary. Every RPC requires the configured service token using a
constant-time comparison, while deployed runtime configuration will also
require mutual TLS before the server can bind. Member removal now carries and
checks the path organization in the application command, closing a latent
cross-tenant selector gap before exposing that previously missing RPC.

The frozen 12-method list is asserted against the compiled adapter and the
existing protobuf/Python surface oracle remains green. Thirty-three Rust
Organization tests, the focused six-test Python protobuf/domain oracle,
formatting and strict Clippy pass. HTTP/SCIM adapters, deployed trust-boundary
composition, runtime/outbox workers, executable/container packaging and the
final acceptance/deletion gate remain. No beta deployment has occurred.

The inbound HTTP trust boundary is now defined once before route migration.
MMF commit `fe6e6b5` owns minimum-length service-token configuration,
production-required startup failure and constant-time request authentication;
Organization gRPC and HTTP consume that shared primitive. The HTTP adapter
accepts forwarded user or API-key context only after the gateway credential is
validated, and API-key contexts additionally require a valid tenant UUID and
nonempty minimized permission. Missing, malformed and partial contexts return
typed failures before membership or domain code runs.

`contracts/organization-http-trust-behavior.json` freezes trusted user/API-key
projection and every missing/wrong credential branch. Thirty-four Rust
Organization tests, all 71 MMF security tests, formatting and strict Clippy
pass. The gateway must inject the same service credential on proxied HTTP
requests before the deployed Organization runtime can require it; that wiring
is part of the remaining executable cutover, not a fallback. No beta
deployment has occurred.

Fourteen of the 62 frozen HTTP contracts now execute through Axum:
organization create/list/discovery/mine/get/update, public and internal
lifecycle reads, public environment read/update, trusted internal settings,
console preferences and onboarding status. The adapters preserve creation
defaults and disablement, strict unknown-field rejection, explicit
omit/null/replace update semantics, membership and exact permission checks,
owner membership projection, no-store preferences, Hosted Pilot retention
projection and stable error envelopes. Organization type, join mechanism and
view-mode parsing now live in the domain and are shared with gRPC rather than
being duplicated per adapter.

Black-box Axum tests prove missing gateway credentials and malformed/private
bodies fail before storage access and preserve the released onboarding
projection. The optional `ORGANIZATION_POSTGRES_TEST_URL` gate exercises
creation, owner membership, authenticated reads, permissioned updates,
preferences, internal settings, lifecycle projection and cleanup through the
actual HTTP router. Forty Rust Organization tests, all 74 surviving Python
tests, formatting and strict Clippy pass. The remaining 48 HTTP contracts are
join/member/API-key, RBAC, policy/audit and SCIM families, followed by runtime,
outbox worker, gateway credential injection, packaging and deletion. No beta
deployment has occurred.

Twenty-five of the 62 frozen HTTP contracts now execute through the same Axum
router. The second adapter slice adds join-code admission and validation,
direct open joining, team snapshots, paginated member list/invite/role-update/
removal and paginated API-key create/list/revoke. It preserves 201 join
responses, trusted forwarded email requirements, pending-versus-active team
buckets, per-member role-alias de-duplication, sorted effective permissions,
one-time raw API-key disclosure, tenant-bound member/key mutation and the Marty
default-organization membership-removal prohibition. Gateway service
authentication and user/API-key authorization run before application storage
access, and malformed identifiers, emails, role sets, scopes and unavailable
storage fail closed through stable envelopes.

Language-neutral black-box route tests assert that the 25 native declarations
remain unique members of the frozen 62-route surface, untrusted requests stop
before database access and join admission refuses missing trusted email.
Projection tests freeze team role buckets and one-time key-secret behavior. The
optional PostgreSQL HTTP gate now also executes direct join, team snapshot,
API-key create/list/revoke and tenant-bound member removal through Axum. Forty-
two Rust Organization tests, all 74 surviving Python tests, formatting and
strict Clippy pass. The remaining 37 HTTP contracts are RBAC, policy/audit and
SCIM families, followed by runtime, outbox worker, gateway credential
injection, packaging, full PostgreSQL acceptance and same-slice Python
deletion. No beta deployment has occurred.

Thirty-five of the 62 frozen HTTP contracts now execute natively. The third
adapter slice exposes the complete intended RBAC surface: grouped permission
catalog, role list/create/get/update/delete, replace/add/remove member-role
assignments and current-member permissions. It preserves permission ID and
legacy `resource:action` key inputs, deterministic de-duplication, role member
counts, default-role behavior, response projections and 201/204 status
semantics. Every read and mutation is tenant-bound and requires its exact
`role:view`, `role:create`, `role:edit`, `role:delete` or `role:assign`
permission after gateway service authentication; missing memberships,
cross-tenant IDs, system-role deletion, owner-role removal, empty final role
sets and unknown permissions fail closed.

The shared frozen-route assertion now covers all 35 native HTTP declarations,
and black-box requests prove RBAC routes reject missing trust before storage.
The optional PostgreSQL HTTP scenario now includes grouped catalog reads,
permission-key resolution, custom-role create/update, owner permission
projection and role deletion through Axum. Forty-four Rust Organization tests,
all 74 surviving Python tests, formatting and strict Clippy pass. The remaining
27 HTTP contracts are the policy/audit and SCIM families, followed by runtime,
outbox worker, gateway credential injection, packaging, full PostgreSQL
acceptance and same-slice Python deletion. No beta deployment has occurred.

Forty-two of the 62 frozen HTTP contracts now execute natively. Because the
1,012-line Python SCIM adapter is the largest remaining deletion target, its
discovery/read half moved next: service-provider configuration, schemas,
resource types, paginated/filterable/sortable Users and Groups collections,
and tenant-bound User/Group detail. The Rust adapter reuses the canonical SCIM
parsers and pagination helpers, emits the registered core and MIP extension
URNs, preserves metadata locations and timestamps, projects effective role
membership, and returns typed SCIM `invalidFilter` and 404 envelopes.
Discovery requires the trusted gateway service credential even though it is
storage-independent; resource reads additionally require an active
organization membership.

Black-box tests freeze trust-first discovery and the expanded 42-route subset,
while language-neutral projection/filter tests cover extension keys, email,
external-ID and active-state behavior. The optional PostgreSQL HTTP scenario
now traverses SCIM User and Group collection projections through Axum. Forty-
seven Rust Organization tests, all 74 surviving Python tests, formatting and
strict Clippy pass. The remaining 20 HTTP contracts are eight SCIM User/Group
provisioning mutations and twelve policy/audit routes, followed by runtime,
outbox worker, gateway credential injection, packaging, full PostgreSQL
acceptance and same-slice Python deletion. No beta deployment has occurred.

Fifty of the 62 frozen HTTP contracts now execute natively, completing the
entire intended SCIM 2.0 surface. User POST/PUT/PATCH/DELETE preserves primary
email selection, external IDs, active/deactivated state, default or explicit
roles, PATCH operation/path behavior, uniqueness responses, extension fields,
Location headers and owner deprovisioning protection. Group
POST/PUT/PATCH/DELETE preserves display-name slugging, permission-key
resolution, member references, filtered member removal, extension metadata,
system-role immutability and SCIM status/error envelopes.

Unlike the superseded Python adapter's independent repository writes, Rust
commits SCIM User profile/status/role transitions and Group role/permission/
membership replacements in one PostgreSQL transaction with canonical audit,
outbox and cache effects. All IDs are tenant-bound and validated before
mutation. The frozen-route assertion covers all 50 native declarations, pure
behavior tests freeze payload/projection semantics, and the optional live
PostgreSQL HTTP scenario now traverses User and Group provisioning lifecycles.
Forty-nine Rust Organization tests, all 74 surviving Python tests, formatting
and strict Clippy pass. The remaining 12 HTTP contracts are nine policy-set
and three audit routes, followed by runtime, outbox worker, gateway credential
injection, packaging, full PostgreSQL acceptance and same-slice Python
deletion. No beta deployment has occurred.

All 62 frozen Organization HTTP contracts now execute through the native Axum
router. The final slice adds policy-set list/create/templates/validate/get/
update/archive/activate/delete and audit list/export/detail. Policy requests
preserve strict document shapes, omit/null/replace updates, status/type
projection, starter templates, active-set replacement and 201/204 semantics;
all Cedar decisions use the shared MMF validator and fail closed when it is
unavailable. Audit requests preserve exact `audit:view`/`audit:export`
authorization, modern and legacy pagination, category/event/resource/action/
actor/severity/search/IP/date/time-range filters, tenant-bound detail lookup,
JSON export and correctly escaped CSV export.

The router contract now asserts exact set equality—not merely subset
membership—against all 62 frozen routes. The optional PostgreSQL HTTP scenario
adds policy create/archive/activate/delete and audit list/export to the full
native lifecycle. Fifty-two Rust Organization tests, all 74 surviving Python
tests, formatting and strict Clippy pass. The remaining Organization work is
runtime and outbox-worker composition, gateway credential injection,
executable/container packaging, configured live PostgreSQL acceptance and
same-slice deletion of the superseded Python service. No beta deployment has
occurred.

The native Organization executable and its operational composition are now
implemented in commit `de0baf57`. Startup validates deployed configuration and
service credentials, connects PostgreSQL and the gateway Redis database,
loads the shared MMF Cedar validator, runs idempotent schema/outbox migration,
reconciles system roles and the configured Marty admin/reviewer memberships,
then serves the complete Axum and tonic surfaces with MMF health, readiness,
version and native-backend diagnostics. The gateway now injects its configured
service token as a trusted override only for Organization HTTP upstreams;
client headers cannot select that credential.

Durable event publication remains one shared MMF implementation rather than an
Organization worker. MMF commits `c6355b0` and `4abb2ae` add the reusable
leased PostgreSQL outbox dispatcher with fenced acknowledgement, bounded
exponential retry, dead-letter transitions, reconnect and graceful shutdown.
Organization maps its canonical event envelope to the existing event-stream
protobuf and treats an event-stream outage as observable degradation while the
transactional outbox retains delivery. Ten MMF messaging unit tests, two MMF
PostgreSQL behavior tests, the complete Organization Rust suite (including 24
crate unit tests and all language-neutral service tests), the focused gateway
credential-injection test, formatting, and strict Clippy pass. The remaining
Organization cutover work is to publish and immutably pin the MMF commits,
switch the service image/entrypoint to the Rust binary, run configured live
PostgreSQL/Redis/event-stream executable acceptance, then delete the Python
service and its Python-only dependencies in the same passing slice. No beta
deployment has occurred.

Commit `9ab00486` adds the native Organization binary to the shared service
image, dispatches `SERVICE_NAME=organization` directly to that binary, and
marks the beta overlay as a deployed environment so missing service
credentials fail closed. Twelve focused packaging/entrypoint tests pass. The
image build remains gated by publication of the MMF branch because the Marty
UI workspace still intentionally points at its clean MMF worktree; GitHub CLI
authentication is invalid and connector writes are prohibited by the current
execution policy. A PostgreSQL listener is available locally but its test
credential is not, and Docker API access is denied, so no unsafe guess or
shared-database mutation was used to manufacture live acceptance evidence.
Python deletion therefore remains pending the immutable MMF pin, image build,
and configured executable acceptance. No beta deployment has occurred.

### Auth port status

Auth is active in dependent worktree `marty-ui-rust-auth-wave3` on branch
`agent/marty-ui-rust-auth-wave3`, based on the complete Organization head so
the service can consume the same MMF platform without copying framework code.
The measured deletion target is 7,578 non-test Python lines. Commit
`bfcbbfcd` freezes all 14 HTTP routes and six gRPC methods in
`contracts/auth-behavior.json`; the contract explicitly preserves the two
retired gRPC mutation methods as `UNIMPLEMENTED`. Shared Python/Rust vectors
cover claim precedence, Keycloak realm/resource role merging, organization
claim extraction, display-name precedence, session validity and RFC 7636 PKCE
S256 output.

The first native application slices are complete. Commit `9f7b2fd6` ports the
OIDC login/registration and callback orchestration, single-use state and nonce
binding, validated-claims-only session creation, provisioning port, event
families, activity refresh, invalid-session cleanup and idempotent logout.
Commit `df1f194d` ports session and PKCE persistence against the shared MMF
cache contract, including user-session indexes, bulk user logout, exact TTL
behavior and typed fail-closed malformed-cache errors. MMF commit `db47333`
adds atomic cache consume and expiring set primitives once in `mmf-data`, with
equivalent memory and Redis implementations, instead of embedding Redis
commands in Auth.

Commit `636216f6` ports the complete Keycloak OIDC provider boundary. Bounded
no-redirect discovery, JWKS and token fetches preserve internal/external issuer
separation and trusted JWKS-origin/path validation; key rotation performs
exactly one forced refresh. Signature, algorithm, issuer, audience, authorized
party, nonce, time and `at_hash` decisions execute directly in the pinned
canonical `marty-oid4vci` kernel, and access tokens remain opaque. Commit
`0f18de11` ports JIT applicant upsert planning and organization membership
enrichment, with shared Python/Rust name vectors and observable optional
organization degradation. Commit `f6408648` ports credential-login identity
enrichment, including deterministic fallback IDs, DID extraction, Keycloak and
credential role/context merging, provisioning fallback and Canvas defaults.
Commit `a5af692b` ports Keycloak Admin user lookup/create, verified-user policy,
role and organization enrichment, native-validated RFC 8693 token exchange,
bounded transport and container URL normalization. Thirty-three Rust
behavioral tests, the focused Python oracle suites, formatting and strict
Clippy pass.

Commit `c281dec2` ports Auth persistence. Auth now owns a non-destructive,
advisory-lock-protected schema migration and strict owned/shared schema
validation; the shared `public.applicants` table remains externally owned.
The PostgreSQL repository serializes both applicant natural keys, fails closed
when account and email identify different records, preserves existing names
when later claims are incomplete, merges JIT metadata, and writes each
authentication/logout audit pair with its session-history mutation in one
transaction. Audit and session-history query behavior remains available. The
language-neutral persistence contract and optional
`AUTH_POSTGRES_TEST_URL` round trip cover migration idempotency, JIT updates,
the four event families and revocation history. No configured test database is
available locally, so the live gate compiled and skipped without claiming
external acceptance.

Commit `adf28056` ports the Canvas learner-identity and credential callback
state kernels. The callback is bound to the canonical MMF event signature,
decision digest, audience, event ID, timestamp window, pending flow, policy and
organization. Completion/failure polling, crash-safe claims, deterministic
retry session IDs and final session-cookie handoff are single-use and
replica-safe. Canvas identities preserve stable issuer/subject derivation,
fallback email and username, LTI LIS name precedence, constrained applicant
roles and tenant context. `contracts/auth-login-state-behavior.json` runs
against both Python and Rust. MMF commit `1ab07f1` adds the required expiring
atomic `set_if_absent` lease once to `mmf-data`, with memory and Redis contract
coverage, rather than embedding a service-specific Redis command. Thirty-nine
Rust Auth tests, 51 focused Python callback/Canvas tests with one optional Redis
skip, formatting and strict Clippy pass.

Commit `17172606` ports the credential callback business orchestrator on top of
that state machine. It preserves Keycloak account eligibility and optional
creation, native-validated token context, provisioning fallback, deterministic
retry sessions, denial normalization, revocation status and already-processed
idempotency. Commit `41f40038` ports all SpruceKit and LISSI wallet-link
behavior, including platform templates, Android intent packages, legacy LISSI
compatibility, DID client-ID normalization and fail-closed duplicate or
mismatched outer request parameters.

MMF commit `8b79e82` adds one bounded no-redirect outbound HTTP client to
`mmf-platform`. It validates URLs, methods, headers, timeouts and response
limits; streams bodies under the configured bound; and normalizes timeout and
transport failures. Auth consumes that shared primitive rather than adding a
service-local client. Commit `58459daf` uses it for Canvas experience-session
transport and ports Canvas session finalization, optional applicant profile
enrichment, tenant shape, client context and positive TTL enforcement.

Commit `c523851e` ports all six Auth gRPC methods from the frozen contract.
Session validation, invalidation and status use the canonical Rust application;
health remains serving; direct session minting and the retired gRPC credential
callback fail explicitly with `UNIMPLEMENTED`. Commit `62fe4864` ports trusted
UI-origin selection, post-auth redirect resolution, OIDC callback URLs and
Keycloak/handoff impersonation context. One shared fixture executes in Python
and Rust. Network-path redirects such as `//attacker.example` now fail closed
instead of retaining an open-redirect interpretation.

Commits `16aae0d0`, `c52579b7` and `16a31cfd` now expose all 14 frozen HTTP
routes through one Axum service, including the six credential-login asset,
start, poll, finalize and callback routes. Commit `18a82ba1` moves credential
page and error rendering into Rust, preserves every SpruceKit/LISSI operator
override, and compiles four shared assets from one source. Exact Python/Rust
page hashes pass, and 710 embedded Python asset lines were deleted immediately
after that gate.

Commit `b7ad9c03` ports the remaining Flow verification, Organization
provisioning, Applicant profile and event provider boundaries. Flow and
Organization channels are created only through the shared MMF gRPC factory;
Applicant requests use the bounded no-redirect MMF HTTP client; Auth events use
the canonical MMF envelope. `contracts/auth-service-transport-behavior.json`
freezes request defaults, incomplete-response rejection, organization
degradation behavior, exact Applicant headers/bounds and all four event types.

Commit `e665f9b7` establishes fail-closed Auth configuration, MMF lifecycle and
readiness, organization-scoped events, a PostgreSQL MMF outbox publisher and a
bounded event-stream gRPC transport. `contracts/auth-executable-behavior.json`
requires every database, cache, OIDC, provider, outbox, event-stream and
listener component to be healthy before activation; it explicitly forbids a
Python fallback and any per-slice beta deployment. The complete Rust Auth
suite, strict Clippy and the focused Python parity suite (71 passed, one
optional configured integration skipped) are green.

Commit `78f9e821` completes the Auth source cutover. The native executable now
connects and validates the Auth PostgreSQL schema, MMF PostgreSQL outbox, MMF
Redis session/PKCE/credential state, MMF Redis sliding-window rate limiter,
OIDC discovery/JWKS, Flow and Organization gRPC, Applicant and Canvas/issuance
HTTP health, and event-stream gRPC before readiness. Flow uses the shared MMF
workload-mTLS client when configured; production configuration additionally
requires an inbound workload server identity. Both listeners bind before
activation, the durable outbox dispatcher starts and drains with the process,
gRPC health changes with lifecycle state, and shutdown drains HTTP, gRPC and
outbox work in order.

The service image builds and installs `marty-auth`, and the entrypoint dispatches
Auth directly to that binary without a Python path. The beta Compose model now
selects the beta environment explicitly, carries the Rust-compatible PostgreSQL
URL and required identity values, preserves outbound Flow workload identity,
and renders successfully without changing the running beta deployment. The
complete pre-deletion Python oracle gate passed 95 tests with one optional
configured integration skipped; the post-cutover Rust gate passes all 76 Auth
tests, executable/packaging checks, formatting and strict Clippy. The same
change deleted 9,724 superseded lines, leaving only the four Rust-compiled
credential-login assets below `services/auth`, removed Python Auth migration
dispatch, marked Auth `native-active`, and added anti-reintroduction ownership
checks.

Auth source migration is complete. Its remaining release gates are the shared
wave-three immutable MMF pin plus configured PostgreSQL/Redis/provider and
container acceptance in the aggregate landing branch. No beta deployment has
occurred.

### Credential-template port status

Credential Template is now the largest remaining source-deletion target after
Organization when tracked Python migrations and implementation-specific tests
are included. Work is active in dedicated worktree
`marty-ui-rust-credential-template-wave3` on branch
`agent/marty-ui-rust-credential-template-wave3`, based on the completed Auth
source cutover. The first slice establishes `marty-credential-template` and
moves credential-format aliases, public and signing wire names, payload-format
defaults, issuance-protocol aliases, SD-JWT VCT and mdoc doctype requirements,
wallet inner-URI policy, wallet route rendering, and delivery-destination
tenant invariants into one Rust domain implementation.

`contracts/credential-template-domain-behavior.json` is the language-neutral
oracle for canonical, legacy and invalid format names—including the retained
VDS-NC family—registered and HTTPS VCTs, placeholder-origin rejection,
environment-specific URI schemes, encoded and inline credential offers, and
system versus organization delivery destinations. The surviving Python oracle
and Rust execute the same fixture; four tests pass in each language, and strict
Clippy passes. This parity pass caught and closed an initial VDS-NC inventory
omission before any caller or data was moved.

The persistence slice now consolidates the three Python repository families
into one `PostgresCredentialTemplateStore`. Rust owns a non-destructive,
advisory-locked and idempotent schema migration for credential templates,
wallet profiles and delivery destinations, including compatibility upgrades
for every retained column. The final schema deliberately does not resurrect
the cached issuer-profile/KMS routing columns retired in August 2026; live
`issuer_did` plus `issuer_algorithm` remain the complete template-side signing
selector. The Rust model closes two transition data-loss gaps by persisting the
domain-level `issuance_protocol` and every validity field, including
`not_before_offset_seconds`. Legacy claim rows retain Python-compatible UUIDv5
identity, type aliases and display defaults, while malformed records fail
closed. Tenant destination listings include system entries, exclude other
tenants and sort system-first by case-insensitive name without an application
side re-sort or N+1 hydration.

`contracts/credential-template-persistence-behavior.json` is the shared
language-neutral persistence oracle. `credential-template-service-surface.json`
now freezes all 24 HTTP operations and all 12 intended gRPC methods against
both Python decorators/protobuf and Rust-owned constants, preventing a partial
port from being mistaken for a complete service. The first application kernel
also owns PascalCase/reverse-domain credential-type validation, unique and
referentially sound claims, released seconds-to-days validity aliases and
rounding, canonical not-before precedence, draft-only mutation/deletion,
activation, deprecation and lossless new-version creation under
`credential-template-lifecycle-behavior.json`.

Rust now also owns all ten intended system wallet profiles and all four system
delivery destinations under `credential-template-system-catalog.json`, not
only the profiles currently used by a caller. One DRY catalog builder preserves
SpruceKit, Marty, generic OID4VCI, LISSI, disabled walt.id interoperability,
Sphereon, DC4EU, Google Credential Manager, Apple Wallet and DIDComm V2
capabilities plus both wallet and Canvas delivery modes. Startup seeding inserts
only missing IDs so operator-managed existing rows are not overwritten.

The template application layer now owns all ten template use cases behind one
repository and one fail-closed control-plane boundary: create, tenant-scoped
list/get, draft update, activate, deprecate, new version, delete, add claim and
internal active-template listing. Membership is enforced inside every public
use case. Create/update resolve the active issuer live; activation additionally
requires an active revocation profile and an accepting trust profile. Provider
failure occurs before persistence. The update plan now preserves claims,
derived attributes and display style exposed by the released request model but
previously left unwired by the Python handler.

Nine template HTTP operations are now executable through Axum: create, list,
get, update, activate, deprecate, new-version, delete and add-claim. Every route
requires the shared MMF service token plus a trusted forwarded user before the
application-level membership decision. Request DTOs reject undeclared fields,
validity aliases resolve against existing state, and responses reproduce the
public claim/privacy/TTL projection while omitting issuer algorithms, supported
formats, wallet configuration and null optionals. Black-box tests exercise
create/update/activate/delete and prove untrusted requests fail before use-case
execution.

The complete wallet-compatibility kernel now also runs in Rust under
`credential-template-wallet-compatibility.json`. All eight intended AAMVA,
ICAO, EUDI, Open Badges, enterprise and generic profiles plus unknown-format
fallbacks are retained. Organization overrides are active-only and tenant
bound, match canonical protocol aliases, sort by descending precedence with a
stable ID tie-breaker, and preserve exact unique APPEND versus component-wise
REPLACE behavior. Both languages prove the complete profile inventory from the
same fixture.

The registry application and HTTP slice now makes all 22 external operations
executable in Rust: ten template and compatibility operations, seven wallet
registry operations and five delivery-destination operations. One DRY registry
repository covers PostgreSQL wallets and destinations. Membership and explicit
wallet/destination administration remain fail-closed control-plane decisions;
system records are immutable; wallet ownership cannot be transferred; private
overrides are tenant-bound; aliases, same-device routing, capabilities and open
links use the shared Rust domain kernels. Unscoped wallet and destination lists
now return only global/system records. This closes an unsafe legacy Python
delivery-list behavior that could expose tenant entries when no organization
scope was supplied.

`credential-template-registry-behavior.json` is the shared route-level oracle
for catalog sizes, canonical formats and protocols, iOS routing, write status
codes, success bodies and tenancy rules. Rust black-box tests execute complete
wallet and destination CRUD plus compatibility and open-link behavior against
it; the surviving Python catalog and normalization oracle consumes the same
fixture, and its route suite proves the corrected unscoped destination rule.

The final two internal HTTP operations are now native as well, completing all
24 frozen routes. The issuance-context route preserves the public projection
and adds only the signing algorithm, supported formats, issuance protocol,
selective-disclosure fields, predicates, wallet configurations and full
validity rules needed by trusted issuance callers; retired cached profile,
provider, service and KMS coordinates remain absent. Dynamic OID4VCI metadata
advertises active DID-backed SD-JWT, mdoc and VC-JWT templates in their actual
production formats, skips unsupported or incomplete entries and treats the
issuer display-name lookup as optional. Unlike the legacy Python endpoint, a
repository failure now returns a dependency error instead of silently
publishing an empty successful configuration set.

`credential-template-internal-behavior.json` is the shared behavioral oracle
for the safe issuance snapshot, three advertised OID4VCI formats, skipped
formats, fail-closed repository behavior and optional display lookup. Rust
black-box and application tests and the surviving Python configuration kernel
consume the same cases.

All 12 frozen gRPC methods are now implemented by one native Tonic service over
the same template and registry applications as HTTP. The former Python adapter
implemented only get/list/configuration/wallet/health queries and deliberately
left six declared mutations absent; Rust now executes create, update, activate,
deprecate, version and delete as authenticated, tenant-authorized operations.
Every call requires the shared MMF service token, and tenant operations also
require trusted forwarded user identity. Repository/control-plane failures map
to unavailable, authorization failures map to permission denied and malformed
requests fail as invalid arguments.

The pre-v1 protobuf now carries the already-intended compliance, trust,
revocation, derived-attribute, full-validity, wallet-override and routing state,
plus an update mask so empty collections can be distinguished from omitted
fields. Removed custody selectors remain reserved and absent. The native
configuration method reuses the exact HTTP metadata kernel instead of the
legacy gRPC adapter's JWT-only approximation and empty-on-error fallback.
`credential-template-grpc-behavior.json` language-neutrally covers the complete
method inventory, authentication failures, lifecycle sequence, wire format,
wallet lookup, health and forbidden private fields.

The Rust crate now passes 29 HTTP, gRPC, application, wallet, domain, lifecycle,
catalog, surface, migration, persistence and configured-PostgreSQL contract
tests; the surviving Python oracle passes all 176 tests; formatting and strict
Clippy pass. The configured PostgreSQL tests run when
`CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL` is supplied. Remaining work is MMF
runtime/outbox composition, executable and container packaging, configured
acceptance and immediate Python deletion. No beta deployment has occurred.

The frozen contract contains 64 explicitly gateway-owned declarations: 18
well-known discovery routes, 14 internal signing-key compatibility routes,
9 organization-scoped discovery/DID routes, 6 credential metadata routes, 3
VC-API routes, 4 health/readiness routes, 5 organization composition routes,
4 retired Canvas state routes and the event-stream bridge. Rust now owns VC-API
JWT/JOSE-envelope/Data-Integrity representation adaptation, inline
OID4VCI offer parsing, issuer extraction, evaluation request construction, and
verification-result mapping. Both Python and Rust execute
`contracts/vc-api-adapter-behavior.json`; the complete existing Python VC-API
suite remains green. All three VC-API handlers are executable through the Axum
runtime. Verification delegates cryptographic decisions to the canonical
presentation-policy service. Issuance delegates transaction creation, token
redemption, nonce issuance, and credential production to the canonical
issuance service; its holder proof comes directly from the pinned
`marty-oid4vci` crate, and the adapter fails closed unless exactly one native
`ldp_vc` Data Integrity credential is returned for the requested issuer DID.
The Python VC-API module remains until the disabled Rust gateway binary passes
its complete executable/packaging cutover gate, at which point this now-ported
module is deleted in the same change.

Rust also owns the exact Marty and Canvas credential badge metadata, criteria,
well-known VCT aliases, and SVG assets. Shared fixtures compare complete JSON
bodies and byte-level asset digests in Python and Rust. Gateway-local health,
OpenID, MIP and release documents now execute in Axum. Issuance-backed root,
organization-scoped, insertion-style, appended-style, walt.id,
credential-manager, Apple Wallet, JWKS, OAuth and generic credential-type
discovery aliases are planned and normalized in Rust while the issuance
service remains the canonical metadata source.

Both public `did:web` resolution routes now execute in Axum and delegate slug
lookup and DID document persistence to the existing Rust signing-key service.
The gateway adapter preserves public-domain port encoding, exact scoped-record
integrity, safe legacy-document retargeting, empty-document compatibility,
`application/did+json`, five-minute caching and fail-closed registry errors.
`contracts/gateway-did-web-behavior.json` runs against both languages.

The 14 service-to-service signing-key compatibility operations are frozen in
`contracts/gateway-internal-signing-behavior.json`. Their dedicated API key is
checked independently in constant time and is replaced with the configured
gateway-to-service credential before proxying. List, get and delete
issuer-profile operations already execute against the canonical Rust profile
store; delete retains the legacy response envelope. Flow-key wrapping and
unwrapping now execute in the Rust signing service through one bounded OpenBao
Transit provider. The encrypted envelope is bound to the organization, flow,
schema and OID4VP response-decryption purpose; malformed key material,
provider failures and binding mismatches fail closed. The gateway replaces any
client-supplied organization field with its authenticated service scope before
forwarding. Issuer-context selection also executes in the Rust signing
service: it resolves by DID or the explicit `org_managed` default mode, requires
exactly one active profile, validates the profile/service/registry binding,
preserves profile-level X.509 material and rejects the removed private profile
selector. Organization-scoped issuer-DID resolution and both profile identity
projections now also execute in Rust. They select exactly one compatible active
profile, bind it to the registered service and DID assertion method, strip
private JWK parameters, preserve public certificate material without exposing
provider credentials, reject cross-tenant or ambiguous records, and retain the
legacy profile/public response shapes. Python and Rust execute the same
`contracts/gateway-issuer-identity-behavior.json` fixture, while Axum black-box
tests cover all three gateway adapters. All 14 operations now execute in Rust:
direct-service and DID-mediated signing, profile creation/update, and
certificate attachment joined the previously completed read, delete,
envelope, context and identity operations. Signing delegates to the canonical
KMS provider, profile writes reuse the canonical profile/document kernels,
managed OpenBao keys retain create-and-retry behavior, and certificate chains
are persisted and re-resolved without exposing custody configuration.

#### Gateway completion slices

The remaining gateway work proceeds in descending removable Python size and
dependency order. Each slice first records behavioral HTTP/provider fixtures,
runs them against Python and Rust, and deletes the superseded Python behavior
as soon as the full gate passes.

| Order | Slice | Required parity before deletion |
|---|---|---|
| 1 | Proxy trust-boundary policies | Complete: issuance/internal service credentials, trusted identity headers, special ownership/path rewrites, trusted path/query organization projection, request/response bounds, retries and public protocol exceptions pass |
| 2 | Public DTO and privacy adapters | Complete: the route-by-route audit covers organization, issuance creation/lifecycle, credential templates, trust/issuer/registry sync, presentation policies, OID4VP flow start, flow definitions/instances/results, deployment profiles/lanes, VC-API and all corresponding privacy projections |
| 3 | Cross-service composition | Complete: organization dashboard counts, runtime readiness, integration metadata, lifecycle/retention aggregation, dependency preflight, manual Hosted Pilot purge and the paginated scheduled sweep execute in Rust |
| 4 | Streaming transport | Complete: tenant-filtered event-stream gRPC subscription is exposed as bounded SSE with exact frames, disconnect cancellation, backend-failure handling, ETag bypass and cross-tenant rejection |
| 5 | Cutover and deletion | Active: full Rust and legacy behavioral suites, Redis-backed integration tests, executable/container health, immutable MMF pin, image build, Python gateway deletion and anti-reintroduction checks |

The gateway branch currently uses temporary local paths for the unpublished
MMF platform/security commits through local commit `c3a378e`. It must be
repinned to the landed MMF commit
before publication; no branch with local worktree dependencies may merge.

Distributed rate-limit and idempotency state now uses the canonical MMF Redis
adapters. Both adapters are atomic, expose health checks, preserve all four MMF
rate-limit strategies, and use owner-token idempotency leases. Gateway provider
composition permits canonical process-local adapters only in explicit
development mode; production startup and any configured Redis failure refuse
local fallback. The composed release executable is built locally and its
process-level tests prove both missing and unavailable Redis terminate startup.
CI now provisions a pinned disposable Redis instance and explicitly exercises
all four strategies plus idempotency lease ownership, in-flight repetition,
payload conflict, completion and exact replay through the production provider
composition.

The CI-only native service image now has a dedicated non-Python gateway target
and container health smoke test. The ownership manifest records the gateway as
`cutover-in-progress`; when the final dependency and public-contract gates pass,
the same deletion change flips it to `native-active`, after which the ownership
guard rejects every Python source reintroduced below `services/gateway`. The
remaining cutover blockers are publication of MMF commit `c3a378e` at an
immutable remote revision and execution of the new Redis and container gates
in CI. The public-protocol gate no longer imports the Python gateway: it freezes
all 40 exact DTO field/required sets, compares them with the pinned protocol,
rejects recursively exposed private state, and requires every gateway behavior
vector to execute in Rust. The superseded 1,306-line Python-runtime checker was
deleted. Docker cannot be executed in the current Windows
sandbox, and GitHub publication is unavailable because the configured token is
invalid and the configured local proxy cannot reach GitHub; neither condition
permits a silent local substitute.

### Delivery and deletion rules

1. Capture language-neutral HTTP, gRPC, event, storage, configuration,
   observability and provider fixtures before implementation.
2. Implement shared behavior in MMF crates first and domain behavior in the
   owning Rust service.
3. Run the same fixtures against Python and Rust until parity, including
   malformed input, unavailable dependencies, concurrency, timeout, retry and
   disconnect cases.
4. Switch packaging and deployment dispatch to Rust, verify startup and public
   behavior, then delete the Python service and implementation-specific tests
   in the same slice.
5. Guard against reintroduction of Python services and duplicated MMF behavior.
6. Land and test all wave-three slices without repeatedly updating beta. After
   every slice and cross-repository release has landed, perform one aggregate
   beta deployment and soak. Production remains unchanged.

## Implementation status (2026-08-15)

The first-wave deterministic protocol, cryptographic, policy, validation,
state-machine, wallet, licensing, DTC, and VDS-NC kernels have one canonical
Rust owner. The machine-readable inventory records all 19 governed
capabilities as `native-active`. Remaining Python and Dart files listed by the
inventory are orchestration, transport, storage, provider, DTO, UI, platform,
or deliberately thin native adapters; they do not contain a second maintained
decision kernel.

| Gate | Final state | Accepted evidence |
|---|---|---|
| Event-stream whole-service removal | Complete: `services/event_stream` is deleted and the shared image dispatches the canonical Rust executable in every stack | Executable-level public HTTP/gRPC behavior, tenant filtering, health, packaging, and regression contracts pass in CI |
| Revocation-profile whole-service removal | Complete: the Python service, status-list kernel, and Alembic ownership are deleted; the shared image dispatches the canonical Rust executable | Public issuance/status/revocation/re-verification behavior plus failure, concurrency, storage, migration, packaging, and regression contracts passed before merge |
| Phase 9 release and evidence | Complete at the approved beta boundary | Immutable Rust/UI releases, a single beta update, commit-pinned composition evidence, fail-closed checks, and the protected public lifecycle run are recorded in the [final migration evidence](rust-migrations/final-migration-evidence-2026-08-14.md) |
| Wave-two port, deletion, and aggregate acceptance | Complete at the approved beta boundary | All nine ordered workstreams, release artifacts, fail-closed rollout findings, final v1.1.194 beta deployment, and protected lifecycle acceptance are recorded in the [wave-two final evidence](rust-migrations/wave-two-final-evidence-2026-08-15.md) |

All first-wave implementation, deletion, enforcement, packaging, and beta
behavioral gates have passed. A follow-up inventory found eight initial
second-wave targets that still contain deterministic security decisions or
whole-service behavior in Python, JavaScript, or Dart. Implementation exposed
a ninth target: the remaining Python eMRTD elementary-file, DG15, and
biometric-template parsers. Completed and active workstreams are recorded
below. Production and persistent self-host configurations remain unchanged.

The notification/webhook workstream is now `native-active`: the Rust service
owns REST, gRPC, PostgreSQL migrations and persistence, Transit-bound secrets,
SSRF-resistant delivery, and the durable outbox. Language-neutral HTTP, gRPC,
HMAC, migration, concurrency, and PostgreSQL/OpenBao contracts passed before
the superseded Python service, adapters, migrations, and implementation tests
were deleted. The cutover was not deployed separately; it is active as part of
the accepted v1.1.194 aggregate beta update.

The subscription API-key workstream is implemented in
[`marty-subscriptions` PR 31](https://github.com/ElevenID/marty-subscriptions/pull/31).
The private `marty-license` crate now owns key material, format and hash
validation, scope and CIDR decisions, expiry, plan quotas, consumption costs,
minute-rate decisions, webhook secrets and signatures, and Square webhook
verification. Python retains database, Redis, HTTP, and DTO orchestration only;
the previous Python cryptographic and policy kernels were deleted after the
same language-neutral fixture passed in Rust and through the installed wheel.
The PR merged as `4c8d7f553c5c9cfe8acdbbe5d85b4278829f6cf1`.

The trust-registry synchronization workstream is implemented in
[`marty-core` PR 236](https://github.com/ElevenID/marty-core/pull/236) and
[`marty-ui` PR 546](https://github.com/ElevenID/marty-ui/pull/546). Rust now
owns the registry catalog, URL and resolved-destination policy, request plans,
strict feed and persisted-state schemas, public and remote sync tokens,
pagination, sequence checks, scheduling, atomic deltas, removals, certificate
validity, and CSCA/DSC profiles. Python retains DNS, TLS, bounded HTTP
streaming, DTO, repository, and task orchestration. The unused hard-coded
Python catalog and superseded Python state-machine, IP, URL, Pydantic, and
X.509 decision implementations were deleted after the embedded
language-neutral fixture and the existing service behavior suite passed.
The canonical and consuming PRs merged as
`780ea7c45164b6c314ac62e4a7704c030ad7c45b` and
`ed43849c4eae11be9e896bbe417b8209ed1afb11`, respectively.

## Wave two — ordered by removable non-Rust implementation

Wave two is delivered in descending order of the non-Rust implementation that
can be removed after parity. Line counts are physical source estimates used to
order work, not completion metrics and not permission to discard behavior.

| Order | Workstream | Baseline removable source | Status | Canonical destination |
|---|---|---:|---|---|
| 1 | Signing-key and KMS service | approximately 7,820 deleted Python lines | Complete on `main`: Core 0.1.57 is published and the complete Rust signing/KMS service stack, exact wheel pins, behavioral contracts, and deletion checks passed through protected merge trains | shared key/JWK/certificate decisions in `marty-core`; Rust service in `marty-ui` |
| 2 | Marty CLI and API client | 7,218 deleted handwritten JavaScript lines | Complete on `main`: native CLI and Rust/WASM browser client are compatibility-tested, packaged, and merged | native Rust workspace, executable, and browser/WASM client in `marty-cli` |
| 3 | Notification and webhook service | 7,142 deleted Python/service lines | Complete on `main`: public REST/gRPC, storage, outbox, delivery, secret-envelope, migration, and packaging contracts passed before the Python service was deleted | Rust service in `marty-ui` using the established service foundation |
| 4 | Credential attestation, evidence, governance, and VCDM decisions | 1,804 deleted Python lines in the current slices | Complete on `main`: Core decision and attestation kernels, fail-closed adapters, shared behavioral fixtures, Python implementation deletion, and complete cross-platform native-wheel, Python, Rust, WASM, PostgreSQL race, security, and packaging matrices passed | `marty-oid4vci` and `marty-verification`, consumed by `marty-credentials` |
| 5 | Passport-chip protocol and integrity kernels | more than 1,300 deleted Python lines in the current slices | Complete on `main`: Core BAC, PACE compatibility, EAC, active-authentication, ISO 9796, APDU, and integrity kernels plus Marty compatibility adapters and Python implementation deletion passed | `marty-verification::chip_io`, `marty-verification::active_authentication`, and `marty-crypto::iso9796` |
| 6 | Remaining eMRTD EF, DG15, and biometric-template parsing | approximately 1,300 deleted Python lines | Complete on `main`: bounded Rust parsers, bindings, DTO/chip-I/O adapters, exact cross-language vectors, deletion checks, and consuming CI passed | `marty-verification` eMRTD parser modules |
| 7 | Subscription API-key lifecycle | approximately 539 Python lines plus duplicated plan/webhook kernels | Complete on `main`: canonical Rust policy/cryptography, fail-closed adapters, shared Rust/Python vectors, Redis/SQL orchestration tests, and deletion checks passed | `marty-subscriptions/packages/verifier_entitlements/marty-license` |
| 8 | Trust-registry synchronization kernel | approximately 433 Python lines | Complete on `main`: canonical Rust policy/state/X.509 kernel, fail-closed adapter, startup diagnostics, exact shared vectors, service regression suite, and Python implementation deletion passed before both PRs merged | `marty-verification` trust registry plus `marty-crypto` certificate validation |
| 9 | Wallet status-list and liveness decisions | at least 378 deleted Dart kernel lines | Complete on `main`: bounded Core status decoding, Rust bridge kernels, shared behavioral fixtures, fail-closed adapters, and Dart implementation deletion passed the complete Flutter, Android, iOS configuration, generated-binding, coverage, and policy suites | `marty-status` and `marty-biometrics` through Flutter Rust Bridge |

The ordering applies to starting each workstream. A prerequisite canonical
crate PR may land before its consuming service PR, but a smaller workstream is
not substituted for an unfinished larger one merely to improve language
statistics.

### Wave-two porting requirements

This wave is a functionality-preserving port, not a feature-reduction project.
Before deleting any source, each workstream must inventory intended behavior
from public routes, schemas, CLI help and output, provider contracts, storage
semantics, configuration, error responses, observability, and tests. Existing
implementation defects are captured as explicit negative fixtures; security
corrections must retain the surrounding feature rather than remove its path.

1. **Signing-key and KMS:** preserve all service, key lifecycle, CSR,
   certificate, JWKS, DID, issuer-profile, wrapping, signing, rotation, audit,
   provider-capability, and provider-interoperability behavior. Provider SDK
   transports become Rust trait adapters. Python route, KMS, migration, and JWK
   conversion implementations are deleted after public HTTP and provider-stub
   contracts pass.
2. **CLI:** preserve command names, aliases, options, config/environment
   precedence, authentication, secret handling, API requests, stdout/stderr,
   machine-readable output, and exit codes. The current black-box HTTP-stub
   suite runs against both executables before the Node package is replaced.
3. **Notification:** preserve REST and gRPC APIs, schemas, HMAC payloads,
   destination security, subscription and webhook lifecycle, atomic outbox
   leasing, idempotency, retries, circuit breaking, secret envelopes,
   persistence, metrics, and provider delivery contracts.
4. **Credential decisions:** preserve key-attestation claims and trust policy,
   token-status validation, evidence transitions and reconciliation, canonical
   governance digests, purpose authorization, and VCDM validation. Python keeps
   external fetching, tenant composition, persistence, and API orchestration
   only when those layers do not determine the result.
5. **Passport chip:** preserve every intended BAC/PACE/EAC, active
   authentication, APDU, secure-messaging, DG15, and ISO 9796 outcome. Placeholder
   or mock cryptography is never treated as valid behavior; standards vectors
   and APDU transcripts define the replacement. A feature may be retired only
   through an explicit public-caller and contract inventory proving it was not
   intended or exposed.
6. **eMRTD data parsing:** preserve bounded BER-TLV/DER handling, EF.COM data
   group discovery, TD2/TD3 DG1 results, DG2 facial/fingerprint/iris metadata,
   quality outcomes, DG15 SPKI algorithms, RSA parameters, fingerprints, and
   existing typed Python models. Run malformed-length, truncation, oversized,
   unsupported-algorithm, and valid standards vectors directly in Rust and
   through the Python adapter before deleting the parser implementations.
7. **API keys:** preserve key formats, hashing, masking, scopes, CIDR rules,
   expiry, rotation, plan quotas, storage, and audit behavior. Redis quota
   consumption becomes atomic and unavailable enforcement fails closed in
   production-like profiles.
8. **Trust registry:** preserve bounded destination fetching, pagination,
   sequence and token handling, atomic delta application, removals, certificate
   profile checks, persistence, and synchronization scheduling. Rust owns feed,
   state-machine, and X.509 decisions; orchestration may retain HTTP and storage
   adapters.
9. **Wallet status and liveness:** preserve supported status purposes, caching,
   user-visible states, challenge steps, camera flow, and offline behavior.
   Rust owns signed status-list trust/freshness/bit decisions and canonical
   liveness challenge signing/validation. Status-check failure cannot silently
   produce a valid credential, and no embedded development secret is accepted
   as a production trust root.

Every workstream adds language-neutral fixtures that execute directly against
Rust and through the public wrapper, service, mobile bridge, or executable.
Tests that import private functions from the implementation being removed do
not satisfy the parity gate.

### Active wave-two evidence

- Signing-key/KMS implementation is split across
  [marty-core PRs 229](https://github.com/ElevenID/marty-core/pull/229) and
  [233](https://github.com/ElevenID/marty-core/pull/233), plus
  [marty-ui PRs 515](https://github.com/ElevenID/marty-ui/pull/515),
  [518](https://github.com/ElevenID/marty-ui/pull/518),
  [520](https://github.com/ElevenID/marty-ui/pull/520),
  [522](https://github.com/ElevenID/marty-ui/pull/522),
  [524](https://github.com/ElevenID/marty-ui/pull/524), and
  [527](https://github.com/ElevenID/marty-ui/pull/527). The final shared
  signing/JWK conversion and minimal-feature dependency correction merged as
  `34cf79d77161feba79934cb78700f885edf07a75` after the complete protected
  merge-group matrix passed. [Core 0.1.57](https://github.com/ElevenID/marty-core/releases/tag/v0.1.57)
  was published from `54ff554906f5fa2791b7fcb6a5965d7e8db8b0e8` and pinned by exact
  release-wheel hashes. The service foundation and five deletion slices
  merged as `4dc470150fe5816a74bf9a09c291d725a5316b02`,
  `ac15bfd9886a56babfa5e847f6481c02ab07718a`,
  `56bcaaddd0ff12c0b616bacf0891b94d9d18d54e`,
  `c0c7f53d5f8daa05f58dc4bb5e67829f766b2720`,
  `91f60663026cb1411fbc5ce362ff5863cc0a9c6c`, and
  `5b62726c380766d324a0a5417875e89b74c3e1e7`. The top-stack Rust suite
  executed 42 tests successfully, with three Redis integration tests
  intentionally ignored when no test Redis URL was configured; all 19
  release contracts and every protected PR and merge-group matrix passed.
- [marty-cli PR 14](https://github.com/ElevenID/marty-cli/pull/14) replaces the
  Node executable and browser HTTP kernel with one Rust implementation. Its
  language-neutral command vectors, native HTTP tests, Rust/WASM compatibility
  tests, release-shaped package check, unchanged UI service suite, and UI
  production bundle passed before the superseded handwritten JavaScript was
  deleted. It merged as `60e438802a83a201ebe8a7db5e31194a116dc161`.
- [marty-ui PR 529](https://github.com/ElevenID/marty-ui/pull/529) implements
  the notification/webhook service as one Rust executable and deletes 7,142
  superseded Python/service lines after public HTTP/gRPC, provider, outbox,
  persistence, migration, security, and image contracts passed. It merged as
  `3dc00a96be73c2d122b9a167ead111912944f8bc`.
- Credential policy/evidence and key-attestation work is implemented in
  [marty-core PRs 230](https://github.com/ElevenID/marty-core/pull/230) and
  [231](https://github.com/ElevenID/marty-core/pull/231), with fail-closed
  Python adapters in
  [marty-credentials PRs 182](https://github.com/ElevenID/marty-credentials/pull/182)
  and [183](https://github.com/ElevenID/marty-credentials/pull/183).
  The Core PRs merged as `918ad5e167ba4424a8fa5d8b045bf073bd640cb4`
  and `2d7419847fc01641bbe726627397280df258b5e6`. The consuming PRs
  merged as `b9e305da4c7b84471a5f0de7ee849cb36817248c` and
  `dc942c8f4a72e640579b75a2ba0c8b2cb7cf3695` after both PR matrices
  and both protected merge-group matrices passed the complete native-wheel,
  Python, Rust, WASM, PostgreSQL race, security, packaging, and
  language-neutral behavior lanes. The immutable 0.1.64 consumer release is
  prepared in [marty-credentials PR 187](https://github.com/ElevenID/marty-credentials/pull/187)
  for the final aggregate stack pin; no migration slice was deployed
  independently.
- Passport protocol/integrity work is implemented in
  [marty-core PR 232](https://github.com/ElevenID/marty-core/pull/232) and
  [Marty PR 51](https://github.com/ElevenID/Marty/pull/51). The Core PR merged
  as `eb28f3dbfe48bb5c40d883466e512ea3d8f35a2c`; the fully green
  consumer merged as `8467c7a4d82ee5f0e1bb39675bccb4dbff414cb6`.
  The remaining
  eMRTD EF/DG15/biometric parsers are implemented separately in
  [marty-core PR 235](https://github.com/ElevenID/marty-core/pull/235) and
  [Marty PR 54](https://github.com/ElevenID/Marty/pull/54). The same
  language-neutral fixture runs directly in Rust and through preserved Python
  DTOs; malformed or unavailable native paths fail closed, and the Python
  struct/ASN.1/hash implementations plus their `pyasn1` dependency are removed.
  The consuming PR merged as
  `97a0c9cba664639f162ed40a3e4eaf61803bd582`.
- [marty-subscriptions PR 31](https://github.com/ElevenID/marty-subscriptions/pull/31)
  moves the API-key lifecycle and adjacent subscription webhook cryptography
  into `marty-license`. One JSON fixture executes directly against Rust and
  through the installed PyO3 wheel; Redis cost/expiry behavior, exact quota
  boundaries, plan compatibility views, missing-native failures, and missing
  Redis enforcement are covered before the Python `hashlib`, `hmac`,
  `ipaddress`, `secrets`, and literal plan-policy implementations are removed.
- [marty-core PR 236](https://github.com/ElevenID/marty-core/pull/236) and
  [marty-ui PR 546](https://github.com/ElevenID/marty-ui/pull/546) move the
  trust-registry catalog, destination policy, request construction, feed/state
  schemas, public and remote tokens, pagination, sequences, scheduling, atomic
  deltas, removals, and certificate profiles into Rust. One embedded JSON
  fixture executes directly in Rust and through the installed `_marty_rs`
  wheel; the unchanged registry route/sync tests prove transport, TLS, SSRF,
  storage, and response compatibility before the Python kernels are removed.
  The Core and consuming PRs merged as
  `780ea7c45164b6c314ac62e4a7704c030ad7c45b` and
  `ed43849c4eae11be9e896bbe417b8209ed1afb11`.
- [marty-core PR 238](https://github.com/ElevenID/marty-core/pull/238)
  adds bounded W3C status-list decoding over the existing language-neutral
  recommendation vector, and
  [marty-authenticator PR 35](https://github.com/ElevenID/marty-authenticator/pull/35)
  moves status entry/list parsing and final bit decisions plus liveness
  challenge creation, signing, and verification into Rust. Dart retains only
  HTTP/cache, camera, gesture, and UI orchestration. The Dart Base64/GZIP/HMAC
  and random-ID kernels are deleted in the same PR, guarded against
  reintroduction. Generated bindings are current; the Flutter unit, Android,
  iOS configuration, build, and shared quality lanes pass. Maintained Dart
  line coverage is 90.47% (655/724) after excluding seven generated files,
  with production adapter, cache, compatibility, endpoint-failure, and
  unsupported-purpose behavior exercised. The consumer merged as
  `8bc37873484cacf7a0424214bb01443d4ce97ee7`. Its unrelated OID4VCI
  dependency remains on the previously validated revision because updating
  that crate would remove format-only issuance behavior; this preserves the
  public feature while keeping status-list and liveness ownership canonical
  in Rust.
- No wave-two slice updated beta independently. The commit-pinned v1.1.194
  aggregate was deployed after all workstreams landed, and protected lifecycle
  run 31916804935 accepted its real issuance, presentation, verification,
  renewal, suspension, reinstatement, revocation, and authorization behavior.
  Exact artifacts and the fail-closed rollout history are recorded in the
  [wave-two final evidence](rust-migrations/wave-two-final-evidence-2026-08-15.md).

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

The initial investigation found that `main` already rejected unknown presentation constraints and verified device challenge signatures; those fail-closed behaviors became migration baselines. It also found unsigned OIDC claim decoding, PKCE incorrectly treated as token validation, and divergent Python/Rust status-list compression semantics. Phase 0 replaced those paths with complete native validation and authoritative standards-tested Rust behavior before their callers were cut over.

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
- Run advisory-lock-protected Rust schema migrations before downstream shared migrations, then delete `status_list_manager.py`, Alembic ownership, and the superseded Python service after implementation-independent behavioral, parity, and failure gates pass.

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

**Status:** Complete at the beta deployment boundary. The final evidence
package records the deleted-code inventory, immutable artifacts, source and
dependency composition, protected behavioral lifecycle, and unchanged
production/self-host boundary.

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

Wave one used staged beta deployment. During wave two, each workstream builds,
tests, and produces immutable artifacts in CI or isolated local test lanes, but
does not repeatedly update the shared beta deployment. After all wave-two PRs
land, one commit-pinned aggregate is deployed to beta and the full smoke,
conformance, end-to-end, failure, and observability suite is run once against
that aggregate.

The final aggregate check observes normalized failure codes, native
availability, panic/crash rate, latency, memory, event lag, provider errors,
and public contract failures. Production and persistent self-hosted deployment
remain unchanged. Rollback redeploys the prior beta artifact rather than
enabling a non-Rust implementation.

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

Wave one met the following completion conditions on 2026-08-14. The complete
roadmap meets them again only after every wave-two workstream is `native-active`
and the final aggregate beta evidence is accepted:

- all unconditional workstreams have passed their deletion gates;
- every conditional DTC/VDS-NC service has been migrated or retired;
- each migrated capability has one identified Rust owner and no second Python/Dart implementation;
- required native backends fail closed and report useful health/version diagnostics;
- beta uses the Rust service images and bindings for all migrated paths;
- public and operational contracts retain feature parity;
- language-composition reporting shows the corresponding Python/Dart source and runtime dependencies removed;
- CI enforces the ownership model; and
- a production promotion package exists, based on beta evidence, for separate approval.

The wave-one evidence for these conditions is captured in
[`final-migration-evidence-2026-08-14.md`](rust-migrations/final-migration-evidence-2026-08-14.md),
and the accepted wave-two aggregate is captured in
[`wave-two-final-evidence-2026-08-15.md`](rust-migrations/wave-two-final-evidence-2026-08-15.md).
Promoting the accepted artifacts beyond beta remains explicitly out of scope.

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

## Completed wave-one dependency order

The implementation landed in the following dependency order:

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

Dependency adjustments were recorded in the implementation PR chain and
preserved the single-owner rule.

Wave two followed the removable-source order above. Its dependency chain,
deleted-source inventory, immutable aggregate, fail-closed rollout findings,
and protected beta lifecycle are commit-pinned in the wave-two final evidence.

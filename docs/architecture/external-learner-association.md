# External learner association

The storage and typed adapters in `0017_external_associations.sql` and
`external_association.rs` implement independently approved producer sources and
explicit learner consent. The protected schema owner registers migration 17 and verifies its catalog;
the read-only startup qualifier checks the actual authenticated LOGIN and all
reachable roles. The public Gateway and Core HTTP operations are wired behind explicit default-off
activation. Browser/connector integration, deployed credential qualification and
the complete public-authentication journey remain development work.

## Authority

All connector traffic uses the public Common Gateway. Only Gateway-authenticated
canonical API-key identity may enter the producer transport. The exact
`identity:attest` scope is separate from `evidence:submit`; neither a wildcard nor
an evidence grant grants identity authority. Independently authorized Core
administrators need `external-association:manage` to register and approve a source.
Creation, key replacement and expiry changes leave that source inactive.

A source pins its canonical organization key and key revision. It only permits
challenges for current, active Core bindings of the same source. Core derives the
application, subject and learner from the binding and confirmed application
ownership. The producer supplies an opaque SHA256-shaped account reference;
that reference, provider claims, email and roles never select the canonical user.

## Public transport and activation

All operations use POST with original JSON bounded to 4096 bytes. Gateway routes
have zero automatic retries and bypass the generic idempotency response cache.
The Core HTTP boundary requires the Gateway service credential and derives its
producer or user context only from the Gateway's replaced identity headers.

| Public namespace | Operations | Authentication |
| --- | --- | --- |
| `/v1/organizations/{organization_id}/external-association-sources/{resource_id}` | create, approve, revoke, replace-key, change-expiry, inspect, receipt | Session, matching tenant and allowed Origin; Core checks current `external-association:manage` |
| `/v1/identity/association-challenges/{resource_id}` | create, inspect, receipt, abandon, expire | Actual organization key with exact `identity:attest` |
| `/v1/organizations/{organization_id}/external-association-challenges/{resource_id}` | confirm, deny, relink, inspect, receipt | Captured learner session, matching tenant and allowed Origin |
| `/v1/organizations/{organization_id}/external-associations/{resource_id}` | unlink, receipt | Canonical identity owner session, matching tenant and allowed Origin |

`MARTY_EXTERNAL_ASSOCIATIONS_ENABLED` defaults to false. Enabling requires the
Gateway service credential and `ISSUANCE_EXTERNAL_ASSOCIATION_DATABASE_URL` for a
separate Core-owned restricted LOGIN. Startup verifies a different authenticated
role on the same database/server address/port, then validates its catalog and
reachable privileges. Existing unqualified Compose and Kubernetes profiles do
not bind these settings. These credentials never belong to the connector.

## Challenge and consent

The connector must generate a fresh random 32-byte code and persist the original
operation, challenge, intent and recovery pointers before dispatch. The displayed
code is canonical unpadded base64url (43 characters). Its SHA256 over the decoded
32 bytes is sent with challenge creation. Core stores the hash; the learner
transport decodes and hashes the original code before binding SQL parameters.
Codes must stay out of URLs sent to servers, logs, referrers and analytics.

A challenge lives at most five minutes and cannot outlive its source or current
application. Creation captures source, key, binding, application and ownership
revisions. Explicit consent requires the captured authenticated learner and the
original code. Core revalidates every captured authority row before and after
atomic challenge, identity, binding-edge and audit writes. A pending challenge
creates no identity relationship. Association creates no verified evidence,
approval, signing permission or issuance authority.

## Current state and recovery

Inspect and receipt recovery use distinct `kind: current` and `kind: receipt`
envelopes. Original receipts belong to the original actor, organization and
resource. Replaying an original operation never reapplies it or restores authority.
Failed or malformed mutation responses after dispatch are uncertain; recover the
original pointer instead of generating a new operation or retrying automatically.

Current inspection dynamically checks canonical authority and the active identity
and binding edge. A confirmed relationship can outlive its proof-code lifetime;
the expired code cannot confirm another operation. Producer inspection omits the
Core application, subject and identity record. Learner inspection exposes only
the captured learner's resource and matching identity summary.

## Unlink, relink and closure

Only the canonical learner can unlink an identity. Unlink deactivates all its
binding edges and increments its durable consent generation. Every challenge
captures that generation; confirmation and reads reject older generations even
after a different challenge relinks the identity.

Relink is an explicit action requiring the expected inactive identity revision
and a fresh challenge from the current generation. It activates only the newly
consented binding edge. Earlier edges and codes remain unusable. The account
reference cannot silently move to another canonical user.

The original producer may abandon a pending challenge or record its actual
expiry. Neither operation creates consent. The learner may deny a pending
challenge even after source revocation. Terminal challenges and immutable
operation records are retained; retention policy and deployed-role qualification
remain activation requirements.

## Protected schema and runtime role

The owner command applies migration 17 and verifies the exact catalog on both
migration and verification. Association, ownership and canonical binding
relations are pinned, including column collations, guard/helper bodies, indexes,
constraints, triggers, rules and PUBLIC privileges. The observation validator
keeps its original catalog for databases at 14/15 and uses an exact extended
catalog for the incoming binding foreign-key triggers installed by 17.

Runtime installs no DDL or grants. Its authenticated LOGIN must match the current
role and use `session_replication_role=origin`. Qualification rejects dangerous
attributes, predefined roles, parameter grants, database/schema creation,
function/table ownership, canonical table writes (including column INSERT),
immutable-column/journal updates and destructive table privileges. Reachable
memberships are checked even when their inheritance flag is false. The explicit
required function and mutable-column grants must also exist.

## Authenticated own-session consent

Auth's validated session response positively attests `non_impersonated_session`.
Gateway preserves the optional protobuf assertion through its production identity
provider and requires `Some(true)` for every learner association operation,
including reads, receipts and unlink, and for application-ownership confirmation.
An absent assertion from an older Auth version and any retained impersonation
context fail closed before forwarding or cache handling. Browser checks,
authentication time, roles and caller headers cannot supply this assertion.
Deploy compatible Auth and Gateway versions before enabling either feature.
Administrator proposal/revocation keep their separate current permission policy.
A local connected regression uses the actual Auth gRPC service, production
Gateway gRPC provider and Gateway router with synthetic sessions; deployed
identity-provider and canonical issuance composition still require qualification.

## Local qualification

The accumulating browser implementation exposes
`/console/identity/associations/{organization_id}/{challenge_id}`. Its first
module dependency captures the canonical `#code=` fragment in memory and removes
the query and fragment before application initialization. Both application entry
points import that dependency before their application graph. The code is never
placed in session/local storage or a login redirect; logout clears it. A learner
who needs authentication signs in in a separate tab, then explicitly checks the
original page again.

The page reads the exact application, source and binding through the public
same-origin Gateway. Confirm, deny and relink require an explicit click. The
client binds each action to the account displayed during review, checks that
account again before persistence and dispatch, and verifies it after current
inspection. An account switch requires another review. Inactive identities
require the explicit relink action and expected identity revision. The browser
uses session cookies, no bearer/API-key credentials or caller-supplied trusted
identity headers.

Before dispatch, the browser persists only the immutable original operation,
scope, reviewed actor, action and expected revisions in session storage. It
never persists the code or a cached authority response. Transport failure after
dispatch is uncertain. Reloads and the check button recover the original
receipt and separately inspect current state; they never resubmit consent.
An old successful receipt does not show a revoked connection as active.

The client calls `fetch` once per explicit consent action without application
retries. Chromium can independently replay an HTTP POST after a pre-header
connection failure. Canonical Core original-operation idempotency is therefore
required even when application retries are absent. The local Chromium fixture
observed two identical wire attempts for one application `fetch`, retaining one
original operation. It then recovered the receipt on reload without another
mutation. The fixture builds the actual page/client/helper with Vite and uses
synthetic same-origin HTTPS authority responses; it does not prove actual
Gateway authentication or Core persistence.

The browser client also supports explicit global unlink. Its original-operation
journal is scoped to organization, identity and expected revision, so a later
explicit unlink after fresh relink cannot reuse an old operation. Recovery can
start from another challenge for the same identity and actor, but separately
reads current state. An old unlink receipt does not override a later active
identity. The page explains that disconnect affects every application, removes
stale displayed authority after uncertain replies and retains only a recovery
pointer. The native Node contract at
`ui/scripts/association-unlink.contract.mjs` exercises these transport/storage
properties. The Chromium fixture also exercises explicit global unlink,
uncertain replies and reload recovery. Full Gateway/Core browser composition
remains required.

Run `ui/scripts/association-consent-browser.mjs` with the absolute path to the
existing pinned Playwright 1.59.1 module and, optionally, an existing absolute
Chromium executable. It creates and removes its own loopback HTTPS fixture,
temporary build and source entry. No installation, deployed configuration or
production credential is required.

`python3 scripts/run_application_ownership_contract.py --source-contract` uses a
disposable pinned PostgreSQL 16 instance, an actual restricted LOGIN, exact
production Rust modules and production-lock registry dependencies. It exercises
concurrent original-operation replay, privacy, current versus historical reads,
canonical revisions, code handling, unlink/relink generations, abandonment,
expiry and rollback of injected audit-time authority or edge changes. This does
not qualify deployed roles, public HTTP authentication or a browser journey.

An additional opt-in composed fixture is
`python3 scripts/test_external_association_sources.py --gateway-contract`.
It connects production Gateway routing/proxy and `ReqwestUpstream` over loopback
HTTP to production association handlers and restricted PostgreSQL, with actual
Auth gRPC and its production Gateway provider. It checks original bytes and
duplicate/unknown field rejection, producer privacy, consent, lost-reply
recovery, replay, unlink and revocation. Supporting canonical tables are reduced
fixtures; API-key and membership-provider answers and validated session inputs
are synthetic. It therefore does not qualify deployed identity authentication,
TLS, a full production database or a browser journey. A complete successful run
is required before treating this composition as qualified. Its startup checks
both host/source and build filesystem space before creating the fixture.

## Connector isolation and deferred production work

Canvas-specific behavior belongs in the independent `canvas-integration`
repository. The public Common Gateway is its sole integration point. Generic
observation and association APIs remain platform capabilities; canonical
identity, ownership, authorization and credential authority remain Core-owned.
The connector must not call private services or access Core databases.

The platform-owned `application_issuance` module supplies application clocks,
cryptographic approval seeds, and required issuer-context validation. Generic
approval and offer code consumes these primitives directly. Temporary exports
in the remaining provider adapters preserve type identity during removal; they
are not an integration API and must disappear with those adapters.

Marty no longer exposes Canvas deployment feature switches or a
`canvas_feature_flags` response. Canvas routes, Auth finalization and dedicated
UI flows are being retired from the platform; this source cleanup does not
qualify a production connector or a production cutover. Incomplete connector
features must remain disabled until their own acceptance work is complete.

TODO (deployment migration owner, before any production cutover): inventory
stored deployment profiles and remove retired `enable_canvas_*` fields from
persisted feature-flag JSON, preserving all generic settings. The request and
stored-domain schema rejects unknown fields; existing rows containing retired
fields therefore require migration before using this version. Add a reviewed
migration and exercise rollback against a representative database snapshot.
This migration is deferred production work, not a repository-split completion
gate. No production data is modified by this source change.

Ordinary application approval and offer preparation no longer dispatch to a
provider-specific adapter. The service does not wire the retired provider
reconciler. Generic evidence and observation contracts remain available.
Only platform delivery hints (`delivery` and `delivery_mode`) are accepted in
ordinary issuance integration context. Any other context is unsupported and
must not fall through into ordinary approval or reveal an existing offer.
Repository operations recheck the current application and transaction binding;
a stale caller snapshot is insufficient authority.

TODO (application migration owner): classify legacy provider-bound application
rows and migrate accepted evidence through the public Gateway contracts and
Core policy, or retire those applications. Do not clear their integration
context merely to bypass the issuance restriction. Production migration and
connector reconciliation adapters remain deferred; unsupported paths stay
disabled while source removal continues.

Credential lifecycle status transitions publish canonical status, persist the
Core state and audit record, and emit the lifecycle event without invoking a
provider mirror callback. Revocation recovery republishes canonical status.
TODO (connector owner): implement any mirror status propagation in the connector
using supported public Gateway contracts. It must not become a prerequisite
for canonical revocation or restore the platform-to-provider callback.

The canonical credential-management repository contract and its PostgreSQL
implementation contain no provider synchronization method or provider
injection option. Provider delivery errors belong to the remaining provider
adapter, pending its removal; they are not repository capabilities.

The platform no longer builds the standalone Canvas sync-worker executable.
Canvas catalog, LTI/OAuth persistence, management and mirror HTTP/PostgreSQL
adapters, and roster sync processor/worker persistence are retired from the
issuance crate. Connector-owned replacements may remain TODOs. Remaining
legacy provider domain/guard modules are transitional removal work, not
supported integration interfaces.

Platform application templates, external evidence, issued-record idempotency,
OID4VCI authorization and passport requests use the provider-independent
`canonical_json` serializer. Its sorted, ASCII-escaped compatibility output
and numeric formatting remain unchanged. The retired Canvas session claim
handler is removed from the application service; connector claims must use
supported public Gateway contracts with Core-owned authority.

The live pre-signing guard reads only the canonical application. An
application-bound transaction requires its current tenant, approved status,
exact transaction binding and supported delivery-only integration context.
Missing applications and unsupported legacy integration contexts fail closed.
Provider rollout switches, platform registrations, bindings and remote
readiness do not authorize the signing path. Transactions without applications
retain the platform's existing issuer/proof checks.

Issuance service configuration no longer defines or parses Canvas secrets,
origin allowlists, timeouts, pilot switches, LTI/OAuth settings or mirror
worker options. Remaining provider adapters cannot assemble themselves from
platform runtime configuration. Connector operators must configure the
independent connector repository; legacy platform environment entries should
be removed during deployment cleanup.

Canvas publication, status synchronization, lifecycle delivery, mirror service
and legacy-ingest implementations are removed from the issuance crate. Their
dedicated behavior/replay tests are retired with the implementation. Any
future connector implementation must use public Gateway contracts rather than
restoring platform runtime provider adapters.

Canvas review resolution, job operations, LTI evidence projection and LTI
sync-enqueue modules are retired from the platform issuance crate. Canonical
credential status transition/recovery APIs and generic external evidence
remain platform capabilities; provider review and synchronization workflows
belong in the independent connector through the public Gateway.

The retired Canvas evidence reconciliation endpoints and their PostgreSQL
adapter are removed. Generic application evidence submission, current-fact
storage, policy evaluation and ordinary approval/offer operations remain.
TODO (connector owner): implement provider recovery/reconciliation through
public observation contracts and Core policy; do not restore private
platform/binding/event-receipt queries in the application service.

Canvas candidate-approval persistence, event-status handling, OAuth HTTP and
sync-worker scheduling/lease code are also removed from the issuance crate.
Provider-specific worker replay fixtures are retired with those modules.
Remaining legacy credential projection and provider helper dependencies are
tracked removal work; they do not establish a supported connector interface.

Generic external evidence owns outbound transport through platform modules
`outbound_http_policy`, `outbound_http` and `outbound_timeout`. These modules
provide origin validation, DNS pinning, verified TLS and per-operation
budgets. They do not own provider configuration, application policy or
credential authority. Remaining provider adapters consume these same
platform primitives while their removal proceeds.

Credential finalization projects the issued credential onto the canonical
application under a row lock, requiring the approved current transaction and
supported delivery-only integration context. Explicit missing, blank or
foreign-tenant application bindings fail closed. Renewal lineage and the
current credential fence remain enforced. Finalization does not query or
update Canvas award candidates; provider claim projection belongs outside
Core through public contracts.

Renewal reservation advances canonical application transaction authority for
supported ordinary applications. Explicit blank/missing bindings and legacy
provider context are rejected. The source credential lineage, approved
application state, tenant, current transaction and current credential fences
are checked under the row lock before the binding compare-and-swap. No Canvas
marker or platform registration participates in renewal authority.

The issuance crate no longer contains Canvas award candidates, approval
adapters, platform bindings, legacy issuance guard, LTI/OAuth runtime,
readiness or management modules. Their provider-only contracts and orphaned
LTI projection test source are retired. Generic application authority checks
remain in signing, finalization and renewal. Provider-named shared response
codecs still require cleanup; they are compatibility utilities, not an
integration entry point.

Shared signing/transport response decoding now lives in `http_content_decoder`
and `http_response_*` modules, with provider-independent types. Existing
lossless text and excerpt behavior remains covered by codec and signing tests.
Unused Canvas URL-formatting, provider alias/origin helpers and Python-format
support are removed. Provider-specific timeout configuration no longer exists;
test timeout vectors exercise the shared outbound timeout owner.

Application evidence summaries expose generic facts, policy decisions and
transaction bindings without a Canvas-specific summary field. Retired provider
readiness and lifecycle mirror errors are removed from platform service and
HTTP/gRPC error contracts. Reconciliation result/receipt response models are
removed with the retired reconciliation endpoints.

Marty's Rust workspace no longer includes Canvas acceptance, worker acceptance,
demo seed or sandbox crates. The native service build and container image no
longer build/copy Canvas worker or sandbox binaries; the service entrypoint no
longer starts the Canvas worker. Connector acceptance/demo tooling belongs in
the independent repository. Remaining CI/deployment references must be retired
before integrating the complete split; mandatory platform checks stay enabled.

Manual Canvas OSS image publishing, OSS portability and hosted Canvas
qualification workflows and their deployment catalogs are retired from Marty.
Canvas sandbox/OSS/localhost bridge container sources and the sandbox
Dependabot entry are removed. The shared platform CI workflow remains enabled;
its mixed historical Canvas lanes still require reconciliation before the
complete split is ready for integration. Connector qualification is deferred
work owned by the independent repository.

Shared Compose and Oracle Kubernetes manifests no longer deploy the Canvas
worker or pass Canvas environment settings and grant-token mounts into
platform services. Dedicated Canvas Compose profiles, obsolete no-Canvas
overlay and Canvas portability schemas are retired. These are source changes;
no running workload, secret, volume or database is modified. Remaining
profile/catalog consumers must be reconciled before final integration.

Canvas-only runtime qualification steps are retired from the shared Rust CI
job: hosted/OSS parity, provider HTTPS, worker preflight, provider KMS fixtures
and full-main provider attestations. Platform CI jobs and retained Rust steps
remain. Mixed lane selection and compile/database orchestration still need
reconciliation; this intermediate branch is not ready for protected
integration until that work and its local checks are complete.

The full Rust CI lane plan is now `contracts`, `flow`, `selfhost`; the merge-group
aggregate gate requires that exact plan. Flow acceptance is explicit rather
than inherited from the retired Canvas lane. Renewal diagnostics remain.
Canvas/worker lane selection, provider compile branch and worker database
dispatch are retired. Mixed artifact/inventory/database orchestration scripts
still require reconciliation before this branch is ready for integration.

Platform artifact verification is owned by
`scripts/ci/verify-platform-test-artifacts.py`. Its flow, self-host and renewal
scopes verify the exact package/target/profile and executable location without
requiring removed Canvas targets. Worker inventory checks are retired from
this verifier. Mixed database obligation inventories remain pending cleanup.

The generic database runner no longer requires ten removed Canvas PostgreSQL
executables. Proof nonce remains an explicit exact-package/target obligation,
with positive-test-summary execution enforcement. Other platform database
suite dispatches remain. Provider preflight orchestration and broader
obligation-source inventories are still pending reconciliation.

Self-host acceptance runs through `run-selfhost-acceptance-contracts.sh`, with
its own pinned runtime-image contract. It preserves the exact seventeen-case
inventory, image identity/revision checks and execution obligation recording
without dispatching the published Canvas runner. The shared schema fixture's
legacy PostgreSQL environment variable remains a documented extraction TODO.
No live container qualification is implied by runner-source validation.

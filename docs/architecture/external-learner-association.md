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
properties; mounted UI and browser qualification for the unlink controls remains
required.

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

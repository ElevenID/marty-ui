# Portable Canvas Integration

## Supported production boundary

Marty is a standard LTI 1.3/LTI Advantage external tool for unmodified hosted
Canvas. Canvas supplies verified launch context and authoritative learning
evidence. Marty evaluates the current evidence heads and issues the canonical
Open Badge through the credential template's DID, status profile, and external
KMS configuration.

No supported production flow requires a Canvas plugin, source patch, Rails
console, direct database access, custom event producer, Live Events, or email
identity matching. Self-managed Canvas may be compatible, but it is not part of
the initial hosted-Canvas certification matrix.

## Institution setup

1. Create a disabled Canvas platform draft in the Marty organization console.
2. Copy the generated registration JSON or revocable public registration URL
   into a Canvas LTI 1.3 Developer Key as a root-account administrator.
3. Enable only the AGS and NRPS scopes required by the intended bindings.
4. Store the resulting client ID and deployment ID with
   `PUT /v1/integrations/canvas/platforms/{platform_id}/lti-installation`.
5. Install the external tool at the intended account or course scope and make
   an instructor and learner launch. Marty retains only verified capability and
   identity mappings needed by the integration.
6. If a binding reads native Canvas REST evidence, authorize named capabilities
   with
   `POST /v1/integrations/canvas/platforms/{platform_id}/oauth/authorizations`.
   Callers cannot submit arbitrary Canvas scopes.
7. Discover courses, assignments/quizzes, and modules through the connected
   OAuth grant; create typed evidence requirements and link the active Open
   Badge credential template.
8. Run `POST /v1/integrations/canvas/program-bindings/{binding_id}/validate`.
   Activation fails closed until every blocking readiness check passes.

The public registration and LTI key set are available at:

```text
GET /v1/integrations/canvas/lti/config/{registration_token}
GET /v1/integrations/canvas/lti/jwks
```

The LTI service signer is RS256 and uses the distinct
`lti_tool_signing` KMS purpose. It is never an organization credential-issuer
key. Active and retiring public keys are published together for the seven-day
rotation overlap.

Hosted Canvas does not publish an institution-local generic OpenID discovery
document for this LTI trust profile. Production uses Canvas's documented global
issuer (`canvas.instructure.com`) and SSO authorization/JWKS endpoints, while
the OAuth/LTI token endpoint remains on the institution's registered Canvas
origin. AGS and NRPS URLs are accepted only from a verified signed launch and
pagination is pinned to that service's original origin.

## Authoritative evidence contracts

| Requirement source | Supported fact | Canvas contract |
|---|---|---|
| `ags_result` | Assignment score | Exact launch-verified Marty line-item URL or Deep Linking `resourceId`; AGS Results read scope |
| `canvas_rest` | Existing assignment, Classic Quiz, or New Quiz score | Assignment Submissions API, including the assignment denominator |
| `canvas_rest` | Course completion | Learner Course Progress; background evaluation uses bulk user progress |
| `canvas_rest` | Module completion | Module lookup with `student_id` |

NRPS supplies opaque roster identities for background evaluation. It is not
issuance evidence. Numeric Canvas user IDs are accepted only from verified LTI
custom claims, or from native roster APIs and then joined to an opaque subject
through a verified learner launch. Exact SIS-identifier joins are not enabled
for the initial pilot; adding one requires a separate institution opt-in and
contract gate. Mixed AGS/REST candidates remain `identity_link_required` until
the launch join exists. Email is never used as an identity join.

Every requirement is processed independently. A successful read with no result
creates a verified negative observation; transport, authorization, rate-limit,
truncation, and parse failures leave the current head unchanged. Immutable facts
include the requirement ID, logical key, payload/source revision hashes,
observed/effective timestamps, and the superseded fact ID. Fact insertion, head
advance, policy evaluation, correction-review transition, and audit events are
committed under one application lock.

## Learner and background flow

After a verified launch, the browser receives a one-time 60-second experience
code. It exchanges the code once for a hashed, 30-minute bearer session; browser
responses do not contain raw claims, nonce, email, Canvas tokens, or internal MIP
context. Current-session operations are:

```text
POST /v1/integrations/canvas/lti/experience-sessions/exchange
GET  /v1/integrations/canvas/lti/experience-sessions/current
POST /v1/integrations/canvas/lti/experience-sessions/current/bootstrap
POST /v1/integrations/canvas/lti/experience-sessions/current/evidence-sync
```

Durable synchronization is performed by the separate PostgreSQL-backed worker,
not an in-process web loop. API synchronization returns `202` and an
organization-scoped job ID. Jobs use leases, `FOR UPDATE SKIP LOCKED`, bounded
exponential retry with Canvas `Retry-After`, and dead-letter recovery.

Background roster evaluation can create a `pending_claim` award candidate, but
it cannot sign a badge. On learner launch, current candidate observations are
materialized into the canonical application and policy is rerun. Holder binding
and KMS signing occur only in the wallet claim transaction.

## Credential custody and correction behavior

The linked credential template is the sole source of credential format, issuer
profile, signing algorithm/key reference, DID verification method, and status
profile. Canvas-triggered issuance fails closed if any of these are missing,
inconsistent, not externally KMS-backed, or fail the cached sign/verify
challenge. There is no Canvas binding-level issuer override or mDL fallback.

If corrected pre-issuance evidence changes the decision, the current policy
result applies before a claim can sign. If post-issuance evidence drifts from
permit to deny, the credential remains active and one administrator correction
review opens. An administrator may dismiss, suspend, or revoke it. Recovery of
the evidence automatically resolves an untouched open review; no evidence
change automatically suspends or revokes a credential.

Canvas Credentials is an optional secondary projection and is not a production
gate. A tenant binding may reference only an enabled, organization-owned
`canvas_credentials` secret and an operator-approved exact HTTPS API origin.
Inline tokens and tenant-selected environment-variable/file names are rejected.
`CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST` controls any non-default provider
origin. Projection metadata is sanitized before transmission and all outbound
connections use the same DNS-pinned, no-redirect transport as Canvas LMS calls.

## Deprecated compatibility contracts

These inbound compatibility routes return `410 Gone` while
`CANVAS_LEGACY_EVENT_INGEST_ENABLED=false`, which is the production default:

- `POST /v1/integrations/canvas/evidence-events`
- `POST /v1/integrations/canvas/ags/score-events`
- `POST /v1/integrations/canvas/nrps/membership-events`

Legacy webhook bindings are read-only and disabled pending administrator
migration. They are not portable evidence and cannot be created for v1.

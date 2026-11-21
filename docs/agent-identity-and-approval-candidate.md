# Agent identity administration and organization approval candidate

This slice advances M02 and M03 from the agent-trust implementation plan. It
adds executable, explicitly selected administration paths to the existing
Organization and Gateway services, a separate organization approval producer,
and console pages that use the public Gateway.

It is an integration candidate, not a declaration that all Machine Identity,
Machine Authentication Policy, delegated execution or receipt profiles are
qualified. Existing public MIP remains 0.5.0. The independent optional protocol
source lock remains at `6126da7619e057be2ff58dd38a5d50f49891d1b3`.

## Implemented scope and responsibility

| Area | Behavior in this slice | Remaining boundary |
| --- | --- | --- |
| Agent directory | Tenant inventory, attributable human administration, metadata, public-key replacement, suspension, revocation, retirement and immutable history | No managed enrollment, machine proof verification, MAP API, connection/grant aggregation or runtime orchestration |
| Organization approval | Exact grant review, explicit confirmation, independent current representation authority, withdrawal and original confirmation recovery | One configured organization, canonical UUID human grantor, organization subject/issuer and KEY binding only |
| Hosting | Opt-in Gateway routes, mandatory service authentication, separate database roles, real Auth session expiry and readiness | No public lifecycle command, START_USE, FINALIZE_USE or receipt-signing endpoint |
| Console | Directory administration and a separate exact-terms approval page | Build selection and backend selection are both required; no discovery or deployment qualification follows from a UI build |

Marty owns identity inventory, proof/authority checks, immutable grant and
consent evidence, and recovery of its own outcomes. Rifare owns logical agent
definitions, models, prompts, tasks, runs, business permissions, budgets,
reservations, provider calls and business outcomes. An inventory record or
confirmation never establishes payment authorization or business completion.

## Directory lifecycle

An authenticated human with current tenant permission can register an external
principal or a managed inventory entry. Requests cannot supply an owner,
administrator, generated identity, status, assurance result or authority flag.
The service derives the accountable owner from the organization record and
the acting administrator from the trusted authenticated request. Owner and
source provenance are retained as registration history.

External entries begin administratively `ACTIVE`; that state is eligibility for
an independent authentication/authority check. It does not authenticate the
declared issuer, subject or runtime. Managed entries begin `PROVISIONED` with
enrollment `NOT_ASSESSED`. There is no public activation or enrollment-success
switch. Both kinds retain `authority_status: NOT_ASSESSED`.

Only descriptive metadata can be edited. Tenant, principal, original owner,
source issuer/subject and runtime instance references are immutable. Each
mutation uses an expected revision, current membership and permission checks,
row locks, a new immutable historical snapshot and an attributed Organization
audit event in one transaction. The service rechecks authorization after lock
waits. API keys cannot use this administration path.

The selected key profile accepts public ES256 and Ed25519 JWKs. It uses the
existing principal-binding crate to validate key material and derive the
RFC 7638 SHA-256 fingerprint. Private/symmetric key material is rejected. The
console client rejects unknown JWK members before registration or replacement;
it never silently strips them and sends the remaining object. Each
nonterminal inventory record has exactly one current key. Replacement retains
the old key and prevents a historical fingerprint from being reactivated.
Revocation/retirement ends current keys. Current lookup denies suspended,
revoked, retired and unqualified managed entries, and rejects an old key after
replacement. A successful lookup is still not proof of possession or authority.

Suspension has no resume operation in this candidate. Revocation and retirement
are permanent lifecycle changes; history cannot be deleted or truncated.
Existing grants are never rewritten by a key change. A replacement immutable
grant binding requires a new grant and fresh approval. The console presents
access eligibility separately from runtime activity.

### Public directory routes

All paths below begin with `/v1/organizations/{organization_id}`. IDs use
canonical, non-nil UUIDs. Every route requires the caller's own authenticated
human session and current membership in the path organization.

| Method and suffix | Required permission |
| --- | --- |
| `GET /agents` | `agent-identity:view` |
| `POST /agents` | `agent-identity:create` |
| `GET /agents/{agent_id}` | `agent-identity:view` |
| `PATCH /agents/{agent_id}` | `agent-identity:update` |
| `GET /agents/{agent_id}/history` | `agent-identity:view` |
| `POST /agents/{agent_id}/suspend` | `agent-identity:suspend` |
| `POST /agents/{agent_id}/revoke` | `agent-identity:revoke` |
| `POST /agents/{agent_id}/retire` | `agent-identity:retire` |
| `POST /agents/{agent_id}/rotate-key` | `agent-identity:rotate-key` |

List/history accept bounded `limit` and `offset` only. Mutations reject unknown
or duplicated JSON fields; lifecycle operations accept `expected_revision`.
Registration accepts `kind`, `display_name`, optional `description`,
`logical_application_ref`, declared `issuer`/`subject`, `runtime_instance_ref`
and `public_key_jwk`. Metadata updates cannot change the identity's source.

Owner/admin roles receive all new permissions. Access Administrator receives
agent directory administration, but not delegated grant approval. Viewer
receives view permissions. No new API-key scope is introduced by these roles.

## Exact-terms approval and current authority

The selected profile requires a human grantor
`urn:marty:user:<canonical UUID>`, represented organization
`urn:marty:organization:<configured tenant UUID>`, the configured organization
issuer, and a KEY-bound managed delegation grant. Shared runtime SESSION
establishment and external representation-authority profiles remain separate
work. Directory registration cannot supply those missing proofs.

1. The Gateway validates the exact session cookie through Auth. It requires a
   non-impersonated session, a real future expiry from Auth and, for cookie
   mutations, a single allowed Origin. It rejects API keys and ambiguous
   cookies/security headers. The observation deadline is capped by actual
   session expiry and 30 seconds from completed authentication.
2. The Gateway authorizes current tenant/action access and reconstructs trusted
   internal headers. It sends a SHA-256 reference to the validated cookie,
   never the raw session cookie or caller-supplied identity assertions, to the
   fixed configured producer service. The internal service token is mandatory
   even in development.
3. The producer reads the exact pending grant and verifies its revision,
   immutable digest, tenant, issuer, subject, binding and human grantor. It
   independently queries the authoritative Organization database for active
   organization, active membership and the explicit `delegation-grant:approve`
   permission. Role names, owner flags and successful login do not substitute
   for that permission. The review records the exact original grant and session.
4. The console displays grantor, organization, delegate, key, scope, audiences,
   resources, validity, operation constraints, digest and prohibition of further
   delegation. Loading a review performs no confirmation. The user must select
   the explicit consent checkbox and confirm the exact terms.
5. Confirmation rechecks current authority through separate producer
   credentials. Consent and the exact review/session/confirmation binding commit
   together. An independently committed authority observation without consent
   cannot activate a grant. The confirmation response is not grant activation.

Review lifetime is at most 300 seconds (default 120). The selected confirmation
age is at most 300 seconds, and the durable consent deadline is the earlier of
that limit and the immutable grant expiry. The review exposes that bound; the
confirmation returns its original timestamps. Authority observations last at
most 15 seconds. Their deadline starts before the source query, so a delayed
query does not acquire a fresh lifetime merely by returning late.

The authority producer refreshes a bounded batch only after another current
Organization check. The runtime read provider owns no producer credentials,
rechecks Organization on every verification and does not renew assertions as a
read side effect. Source failure, inactive membership, removed permission,
withdrawal, terminal authority revocation or expired observation denies new
authority. The declared time bounds are not an instantaneous distributed
revocation or a promise to cancel a provider operation already admitted.

### Public approval routes

These paths begin with
`/v1/organizations/{organization_id}/delegation-grants/{grant_id}`.

| Method and suffix | Request | Authorization |
| --- | --- | --- |
| `POST /approval-reviews` | `grant: { id, revision, terms_digest }` matching the path | Current `delegation-grant:approve`; exact grantor |
| `POST /approval-reviews/{review_id}/confirm` | `confirmation_id`, `terms_digest`, `decision: "CONFIRM"` | Current view access; new confirmation independently requires current approve authority; exact original human/session/review |
| `POST /approval-confirmations/{confirmation_id}/withdraw` | Empty JSON object | Current view access and original human; no need to retain approve permission or the old session |

The same confirmation ID and exact binding return the original recorded result.
Changed actor/session/review/grant/digest conflicts or is denied. A confirmed
review cannot be consumed under another confirmation ID. Historical recovery
does not refresh consent or current authority and remains possible with current
read access after approval permission is lost. It still requires the original
authenticated session binding. Withdrawal can use the same human's new session.

The browser stores only the minimal original review/grant reference and
confirmation ID before sending explicit consent. A lost response or reload
offers **Check original confirmation** and reuses that exact intent. It does
not generate another confirmation automatically. If a new login prevents exact
old-session recovery, the original human can explicitly withdraw the retained
confirmation ID without creating another review or confirmation. The browser sends writes once;
Gateway retries and generic response/idempotency caches are disabled for these
routes. Responses are not cacheable. An uncertain directory mutation requires
inspection of current state before another operation.

The Gateway and console reject malformed or retargeted review terms before
showing consent. The selected organization, human grantor, KEY binding, scope,
constraint mode and time bounds must agree. A successful response with invalid
content is an uncertain write outcome, so reopening a dialog or a failed reload
does not permit another directory mutation. A successful current inventory read
is required first. The Gateway source client refuses redirects, including a
producer readiness redirect to a liveness endpoint.

## Explicit installation selection

| Component | Required selection |
| --- | --- |
| Gateway directory | `MARTY_AGENT_ADMIN_ENABLED=true` and a configured service token |
| Organization directory | `MARTY_AGENT_ADMIN_ENABLED=true` and the same authenticated service-hop configuration |
| Gateway approval | `MARTY_DELEGATION_APPROVAL_ENABLED=true`, explicit `DELEGATED_AUTHORITY_SERVICE_URL`, service token |
| Approval executable | `marty-delegation-approval`, `MARTY_DELEGATION_APPROVAL_ENABLED=true`, all source/role/profile settings below |
| Console directory build | `VITE_AGENT_ADMIN_ENABLED=true` |
| Console approval build | `VITE_DELEGATION_APPROVAL_ENABLED=true` |

Both Gateway switches default to false. Selecting a console page is not backend
authorization. Global public MIP/discovery and default deployments remain
unchanged. The optional routes appear in Gateway OpenAPI only when selected.
The configured approval producer becomes a Gateway readiness dependency and
is checked through `/ready`.

The approval executable requires four independent configured pools:

| Environment variable | Purpose |
| --- | --- |
| `DELEGATION_APPROVAL_RUNTIME_DATABASE_URL` | Read-only grant/consent/authority/review/original-result access |
| `DELEGATION_APPROVAL_CONSENT_DATABASE_URL` | Append review, confirmation, confirmation binding and withdrawal records |
| `DELEGATION_APPROVAL_AUTHORITY_DATABASE_URL` | Append independently checked authority source/assertion/observation records |
| `DELEGATION_APPROVAL_ORGANIZATION_DATABASE_URL` | Read authoritative current organization membership and permissions |

Each URL and `GRPC_SERVICE_TOKEN` can instead come from a corresponding `_FILE`.
Inline and file configuration together is rejected. The service token must be
at least 32 characters; there is no empty/development authentication fallback.
Connection strings and secrets are omitted from configuration diagnostics.

Also configure `DELEGATION_APPROVAL_ORGANIZATION_ID`,
`DELEGATION_APPROVAL_PROFILE`, `DELEGATION_APPROVAL_VERSION` and
`DELEGATION_APPROVAL_ARTIFACT_DIGEST`. These are reviewed deployment pins,
not request-selected trust and not a measurement of the running binary.
The issuer is the configured organization URI. The default listener is
`127.0.0.1:8019`; use `DELEGATION_APPROVAL_HTTP_ADDR` for an explicitly protected
service network. The public consumer connects only through Gateway.

Optional bounded settings are `DELEGATION_APPROVAL_REVIEW_TTL_SECONDS`
(default 120, maximum 300), `DELEGATION_APPROVAL_CONFIRMATION_MAX_AGE_SECONDS`
(default/maximum 300), `DELEGATION_APPROVAL_AUTHORITY_VALIDITY_SECONDS`
(default/maximum 15), and `DELEGATION_APPROVAL_AUTHORITY_REFRESH_SECONDS`
(default 5, strictly less than half the authority horizon).

Startup/readiness checks actual connected role identities, primary source state,
storage identity, required privileges, dangerous inherited/SET ROLE paths and
the new guard bindings. Evidence writers cannot rewrite each other's evidence
or their Organization authority source. Different URL strings alone do not
prove privilege separation. These checks are bounded deployment checks, not
full schema/function/artifact or network attestation.

## Migration, rollback and validation

Organization adds migration `0003_agent_directory.sql`; the prior two files
remain unchanged. Delegated Authority adds migration 0005; migrations 0001–0004
retain their bytes and recorded checksums. Read the
[delegation upgrade procedure](delegated-authority-upgrade.md) before upgrading.
There is no automatic reconstruction of missing lifecycle history.

Run `marty-delegation-approval migrate` with the separate
`DELEGATION_MIGRATION_DATABASE_URL` (or its `_FILE`) before starting the approval
producer. `verify-owned-schema` uses the runtime read credential. Normal startup
and readiness do not install schema or grant privileges. Provision the separated
roles deliberately and run the read-only preflight and runtime readiness checks.

Rollback disables new Gateway/console/producer use while preserving grant,
consent, authority, directory/key history and original results. Do not drop
history, reuse retired keys, delete uncertain confirmations or rewrite old grant
bindings. Keep authorized historical inspection and the existing revocation
path available according to the deployment's established procedure.

Validation uses actual local PostgreSQL for lifecycle, lock/revocation,
role-separation and consent/recovery behavior; Gateway boundary tests; console
component/client tests; and an application build. Full deployment, managed
proof/MAP, independent browser/issuer, shared SESSION, final-use nonce/receipt,
SDK and two-domain qualification remain separate exit gates. Rifare adoption
of delegated business execution still follows those public runtime gates.

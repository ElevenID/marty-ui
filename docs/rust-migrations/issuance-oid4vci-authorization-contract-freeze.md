# OID4VCI authorization and tenant-management contract freeze

This checkpoint freezes the next descending removable-code target without
starting its Rust implementation. The authority is `ElevenID/marty-credentials`
released Credentials v0.1.76 / protected `main` at
`aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26` (tree
`819b7458a31c75d28043a4660643b029c5ec4567`). The capture
executes the unchanged Python route composition through FastAPI's ASGI
transport with controlled native-engine and downstream revocation/Canvas
dependencies; it does not copy Python route logic into the production tree.

Authorization has two historical lifetime values that must not be conflated.
The Python route supplied 600 seconds to the Rust response engine, but discarded
that engine session expiry and persisted a new `AuthorizationSession`. Its
effective lifetime is `ISSUANCE_AUTH_SESSION_TTL_MINUTES`, defaulting to 60
minutes. Native ownership must preserve that configurable persisted lifetime.

Implementation status (2026-09-21): the change stacked on this historical
freeze implements and selects exactly the four public OID4VCI routes natively:
`authorize`, `pushed_authorization_request`, `deferred_credential`, and
`notification_endpoint`. The three tenant-management routes remain legacy and
are outside this implementation PR. This checkpoint has not deleted Python,
created a release, or deployed the candidate.

The seven selected operations account for approximately 495 Python route-body
lines:

- Public OID4VCI protocol: `authorize`, `pushed_authorization_request`,
  `deferred_credential`, and `notification_endpoint`.
- Tenant OID4VCI management: `put_oid4vci_registered_client`,
  `revoke_transaction`, and `list_credentials`.

They remain one useful deletion target because they share the issuance router,
repository, transaction/client records, and gateway selection boundary. They
are not one handler abstraction. Public OAuth behavior and authenticated tenant
management have different trust boundaries and must stay as two Rust modules
that reuse a DRY repository, tenant guard, response/error, and serialization
layer. Either component may qualify first, but no route can be claimed native
from this freeze alone.

## Executable evidence

The normative language-neutral contract is
[`contracts/issuance-oid4vci-authorization.json`](../../contracts/issuance-oid4vci-authorization.json).
The whole-response Python oracle is
[`contracts/issuance-oid4vci-authorization-python-reference.json`](../../contracts/issuance-oid4vci-authorization-python-reference.json).
It records 38 response and side-effect observations, including at least one
success and one representative authentication/error case for every route,
status, relevant headers, complete JSON or text bodies, repository calls, PAR
persistence, authorization-session persistence, and transaction-revocation
ordering.

[`scripts/capture_oid4vci_authorization_reference.py`](../../scripts/capture_oid4vci_authorization_reference.py)
replays the capture from an exact Credentials checkout. Dynamic UUIDs,
authorization codes, and timestamps are normalized; error detail, redirects,
query strings, headers, call order, and persisted effects are not. Reproduce it
with:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
py -3.12 scripts\capture_oid4vci_authorization_reference.py `
  ..\..\marty-credentials `
  --verify contracts\issuance-oid4vci-authorization-python-reference.json
```

The capture pins normalized SHA-256 hashes for the route, entity, in-memory
repository, and PostgreSQL repository sources. The contract separately pins the
reference hash, so changing either the protected source observation or its
interpretation requires an explicit review.

## Behaviors that must not disappear

- `issuer_org` from per-tenant discovery takes precedence over legacy inline
  organization selectors for both PAR and authorization.
- PAR stores the complete ten-field request object, including nulls, with a
  90-second TTL. Its opaque URI is digest-keyed and atomically single-use.
- A PAR capability is consumed before later client, redirect, or native-engine
  validation. A failed later validation does not make it replayable.
- Stored truthy PAR fields override inline query fields.
- Registered redirect URIs containing a query retain that query. Success adds
  `code`, RFC 9207 `iss`, and optional `state`; native validation errors add
  `error`, `error_description`, and optional `state`. Existing Python behavior
  uses HTTP 307.
- A successful authorization session is persisted before either redirect or
  JSON success is returned.
- Registered-client rotation validates public ES256 P-256 keys, rejects private
  key material, preserves `created_at`, changes `updated_at`, and reads the
  stored record back before returning it.
- Deferred pending or authorized transactions return 202 with `Retry-After: 5`.
- Transaction revocation publishes the canonical status-list transition before
  local credential persistence, Canvas lifecycle synchronization, and the final
  transaction update. Failure before publication leaves both local records
  unchanged; retries reconcile partial prior attempts.
- Credential listing authenticates and checks the trusted tenant before its
  repository read, preserves repository order, uses an exact case-sensitive
  status filter, and retains all seven response fields.
- Explicit errors and unhandled errors are both captured. The migration must
  not repeat the earlier class of regression where an endpoint survived but
  some of its reported errors disappeared.

## Findings requiring explicit native corrections

The capture found behavior that must be corrected rather than silently copied:

1. Deferred credential and notification only test the `Bearer ` prefix.
   `Bearer ` with an empty token passes, and any unrelated non-empty token can
   read an issued credential by transaction ID. Native code must authenticate a
   non-empty token and bind it to the owning authorization session or issuance
   transaction before parsing or lookup.
2. Notification ignores its entire body and acknowledges malformed arbitrary
   content with 204. Native code must validate supported OID4VCI notification
   events and commit their durable/auditable effect before returning 204. The
   contract pins the Final specification's required `notification_id`, three
   case-sensitive event values, optional ASCII `event_description`, idempotent
   retries, and exact invalid-request/invalid-ID errors.
3. Registered-client management accepts `organization_id` from the body even
   when `X-Organization-ID` names another tenant. Native code must apply the
   same trusted tenant guard already used by list and revoke before saving.
4. Unhandled repository failures still become `text/plain` `Internal Server
   Error`, while explicit PAR failures already use sanitized structured OAuth
   JSON. Native code should use one DRY structured, sanitized boundary per
   public protocol or management surface and retain every explicit error in the
   frozen corpus.
5. Legacy access-token rows can lack a durable expiry. Native persistence must
   apply the exact 1,800-second lifetime, use the database clock for every live
   lookup, and give pre-migration tokens only one bounded transition lifetime.
6. An exact `ALLOWED_REDIRECT_URIS` entry can bypass the legacy scheme check.
   Native code must validate scheme safety first: HTTPS everywhere except HTTP
   on exactly `localhost`, `127.0.0.1`, or `::1`, then apply the allowlist.

Each correction in the contract names the valid capability that must remain.
These are security and error-contract corrections, not permission to drop valid
wallet notification, deferred retrieval, client rotation, listing, or
revocation behavior.

## Explicit crypto follow-up outside this consumer migration

The shared DPoP verifier currently proves signature, public JWK thumbprint,
`typ`, algorithm, HTTP method, and exact target URI. It does not yet enforce a
fresh `iat`, unique/replay-protected `jti`, or access-token hash (`ath`). This
migration therefore preserves the existing DPoP boundary but does not claim
complete RFC 9449 replay protection. That hardening belongs to the separately
owned crypto lane and must update all token, credential, deferred, and
notification consumers together; this OID4VCI consumer PR must not make an
overlapping crypto change.

## Gates before implementation and deletion

The freeze is complete only when its focused tests pass and replay matches the
exact protected source. Rust implementation may then begin behind the existing
candidate split. Before routing or Python deletion, require:

1. Direct Rust HTTP tests for every frozen success, redirect, error, header,
   authentication order, tenant order, and side effect, plus each intentional
   correction.
2. Differential execution against the reference for all behavior that remains
   intentionally identical.
3. PostgreSQL contracts for PAR atomic consume/expiry, client rotation,
   authorization-session persistence, token-bound deferred lookup, listing,
   and partial/retried revocation.
4. Gateway coverage and trusted-header tests for both authentication
   components; selecting one component must not route its unqualified sibling.
5. Maintainer review specifically checking lost error responses, response
   headers, persistence effects, and redirects/query preservation.
6. Protected CI, merge, and beta-only aggregate acceptance. Production remains
   unchanged.

This checkpoint changes no Rust route, coverage selection, compose routing,
Credentials source, KMS boundary, deployment, or Python deletion.

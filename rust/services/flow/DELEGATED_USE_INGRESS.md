# Authenticated delegated-use request and proof ingress

`FlowDelegatedUseIngress` provides explicitly assembled internal request
retrieval and immutable proof submission for an original delegated Flow.
`delegated_use_flow_router` protects it with the reusable Delegated Authority
workload authenticator. The explicit default-off
[`marty-delegated-use` host](../delegated-use/README.md) installs this router with
mandatory mutual TLS. The existing general Flow executable and public Gateway
route tables do not install it.

The application requires an opaque `AuthenticatedDelegationUseContext` and an
independent current `DelegationUseIngressAuthorizer`. The concrete Organization
adapter checks separately administered `RETRIEVE_REQUEST` and `SUBMIT_PROOF`
rights for the configured tenant/deployment and its actual full MachineIdentity.
A shape-valid caller struct or challenge UUID supplies no authentication.

## Internal routes

| Method and path | Input | Successful response |
| --- | --- | --- |
| `GET /internal/v1/organizations/{organization}/delegated-use/challenges/{challenge}/request` | Canonical UUIDs; authenticated workload; no body or query | Exact retained JWS, `application/oauth-authz-req+jwt` |
| `POST /internal/v1/organizations/{organization}/delegated-use/challenges/{challenge}/proof` | Same authenticated scope; `application/octet-stream`; bounded original proof bytes | Server-generated submission ID, challenge, digest, original receive time and recovery flag |

Authentication precedes body reads; its original observation is checked again
after the bounded read. Responses/errors use `no-store`, `no-cache` and
`nosniff`. Errors expose no raw proof, signing credential or source detail.

Ordinary Flow request retrieval and the paired-wallet request-owner endpoint
reject delegated instances. Their ordinary verification behavior is unchanged.
The request retains its original Flow request/response URIs; this internal
candidate does not advertise a public wallet protocol or enable public proof
submission. Ordinary verification finalization still cannot complete delegated
Flow instances.

## Original request ownership and unresolved work

The server selects the request-signing options and HTTPS base URL. It checks the
complete original tenant, typed actor and retained Flow binding, then invokes
the existing `prepare_verification_request` owner with the frozen presentation
request. Callers supply no request claims, nonce, verifier, key or destination.

Before external signing, the application commits one immutable preparation
claim per challenge, retaining original scope, configuration digest and access
bounds. A claim without a result returns `PreparationPending` on later attempts,
including after failure, timeout, expiry, permission loss or cancellation. No
lease takeover, claim deletion or automatic signing retry is supplied.

The result JWS and request progress commit together. The current definition and
instance are locked and compared with the prepared preimage. Current access and
original bounds are rechecked, and exact stored bytes are reread before COMMIT.
A conflict preserves the unresolved claim. Later authorized retrieval returns
the exact retained JWS without another sign or a new request issuance/expiry
time. It requires the same configuration and a live original Flow.

## Proof retention and history

Fresh proof bytes and their bounded ingress authorization commit together for
the original tenant, typed actor and challenge. Current source access is checked
after the Flow lock wait, and exact stored bytes are reread before COMMIT.
Storage does not verify signatures or authorize an operation.

Repeating the exact bytes returns the original submission ID and receive time
after current access is checked. Historical recovery after finalization creates
no new submission or proof authority. A different actor/tenant/proof cannot
select that history by supplying an identifier. The existing FINALIZE_USE path
still verifies proof, current grant/consent and selected policy, then consumes
the original Flow with the receipt/result in one transaction. Rifare retains
business authorization, budgets, execution and outcomes.

## Bounds and cancellation

Authentication and each source response have at most a 30-second observation
window. Source bounds are validated before clamping to a shorter authentication
or Flow deadline. Later observations only shorten the original deadline; the
original observation floor survives clock regression.

Reads, source observations and preparation are bounded. Transactions set
five-second statement/lock limits. Definition locks precede instance locks,
matching finalization. Database clocks are checked after waits/writes; deferred
guards check original bounds at COMMIT. Only final COMMIT completion is shielded
from cancellation. A dropped caller receives no result or automatic retry.

A COMMIT can finish after the deadline following another deferred trigger or
network wait. The post-COMMIT check then returns an error and preserves any
committed original evidence. Historical recovery never renews its receive or
issuance time. These are bounded cross-owner observations, not a distributed
atomic revocation transaction.

## Schema and serving role

Forward migration 0006 adds immutable `delegated_request_claims`, exact-byte
`delegated_request_results` and `delegated_proof_ingress` linked to actual proof
rows. UPDATE, DELETE and TRUNCATE are rejected, including ordinary owner writes.
Readiness checks the migration marker, primary keys, all 25 required old/new
delegated guard bindings and exact function bodies/security/search paths.
Historical migration files and evidence remain unchanged.

The distinct nonowner LOGIN requires:

- USAGE on `flow_service`.
- SELECT on `rust_schema_versions`, `delegated_use_storage_identity`,
  `flow_definitions`, `flow_instances`, `delegated_challenge_bindings`,
  `delegated_proof_submissions`, `delegated_use_consumptions` and the three new
  ingress tables.
- INSERT on `delegated_proof_submissions` and the three new ingress tables.
- Column-only UPDATE on `flow_instances.current_step_id`, `context`,
  `step_history`, `state_history` and `updated_at`.
- EXECUTE on `flow_service.lock_delegated_ingress_definition(uuid,uuid)`.

The migration-owned helper only reads/locks the selected tenant/challenge's
definition with a fixed `pg_catalog` search path. PostgreSQL requires UPDATE
authority for FOR SHARE; this helper supplies the bounded lock without granting
definition mutation rights. Readiness checks its exact body, ownership, return
type and security mode. Other executable security-definer functions are rejected.

Readiness also rejects privileged login masking, predefined `pg_` roles,
replication/admin memberships, schema/object ownership, unrelated reads/writes,
column-only escalation, grant options and PostgreSQL 17+ MAINTAIN. It audits
actual reachable roles, including NOINHERIT paths. The source authorizer uses a
separate restricted Organization connection. The Flow writer receives no
Organization or Delegated Authority source/ledger privileges.

## Verification boundary

Focused tests use actual PostgreSQL and internal HTTP, real ES256 request and
proof/receipt signatures, role grants, row-lock waits and deferred triggers.
They cover exact recovery, no repeated signing, source loss, original bounds,
body expiry, schema/role drift and ordinary-endpoint rejection.

The cross-owner case installs the real Organization registry, access owner and
source. It revokes rights during signing and checks that new persistence and
subsequent reads fail while retained bytes remain unchanged. Its START/consent
and domain-policy inputs remain explicit fixtures. Public hosting, deployed
workload configuration, production request custody and full grant/consent/domain
composition require separate qualification.

See [retained Flow use](DELEGATED_USE.md) and the
[runtime candidate](../../../docs/delegated-use-runtime-candidate.md).

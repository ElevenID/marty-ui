# Managed key enrollment and human grant commands

This application slice advances M02 managed enrollment and P03 public lifecycle
composition after the directory/organization-approval candidate. Its two opt-in
surfaces are independently selected. Neither enables operational machine
authentication, delegated use, capability discovery, or business execution.

## What enrollment establishes

A managed directory identity can move from `PROVISIONED` to `ACTIVE` only after
an authorized human creates a server-owned challenge and the registered key
signs that exact challenge. The resulting provenance is
`managed_enrollment: KEY_CONTROL_VERIFIED`; `authority_status` and
`external_authentication` remain `NOT_ASSESSED`.

`ACTIVE` means eligible for subsequent identity checks. Key possession does not
prove an external issuer, the runtime's isolation, machine credentials,
attestation, representation authority, or permission for an external operation.
The source issuer, subject and runtime references retain their operator-declared
meaning. Enrollment is restricted to managed inventory. External principals and
ordinary holder wallets are not converted into managed machines.

The proof is the implementation-specific
`urn:marty:managed-key-enrollment:v1` profile. Its signed payload is purpose-bound
to `ENROLL_MANAGED_KEY`. It must not be reused as a Machine Authentication Policy
operation proof, consent confirmation, grant, decision receipt, or bearer token.
See the [exact proof and signer contract](../rust/crates/principal-runtime-binding/docs/managed-enrollment-proof.md).

## Operator flow

1. Register a managed identity and its public ES256/P-256 or Ed25519 key through
   the existing human administration route. The private key stays with its
   custodian. Registration leaves the identity provisioned.
2. Create an enrollment challenge for its exact current revision. Current
   `agent-identity:view` and `agent-identity:enroll` permissions are required.
3. Have the key custodian inspect the organization, agent, administrator,
   runtime, audience, policy and revisions, then sign the exact server-provided
   payload. The local signer accepts a local key file and produces only the
   compact enrollment proof; the browser/server never needs a private key.
4. Submit the proof through the same current human session. Organization
   independently checks the current permissions and locked directory state,
   verifies the signature, and atomically records the outcome, lifecycle history
   and audit evidence.
5. After a lost response, inspect the original challenge. A retained consumed
   result is historical evidence of enrollment; it does not assert the current
   key, status or authority. Use a fresh directory read for current state.

| Method and path suffix under `/v1/organizations/{organization_id}/agents/{agent_id}` | Request | Result |
| --- | --- | --- |
| `POST /enrollment-challenges` | `{ "expected_revision": 1 }` | New challenge (201), or the same valid pending challenge for the same actor/session and revision (200). |
| `POST /enrollment-challenges/{challenge_id}/complete` | `{ "proof": "<compact JWS>" }` | Immutable enrollment result (200); the same exact proof can recover the original result. |
| `GET /enrollment-challenges/{challenge_id}` | No body or query | Original human with current view permission can inspect `PENDING`, `EXPIRED`, `INVALIDATED` or `CONSUMED` state, including from a later session. |

Completion requires the original human/session binding. Reading historical
evidence from a later session does not retarget the original challenge. A
different proof, changed key/revision/policy, expired challenge, suspended
identity, or terminal lifecycle state cannot enroll the identity. There is no
unrestricted activation or suspended-identity resume operation.

Replacing a managed key invalidates pending challenges and removes enrollment
eligibility for that key. A new key requires a new proof. Existing grants keep
their original bindings and approval history; key replacement cannot rewrite
them. Revoked and retired identities remain terminal.

## Proof and transaction boundary

The retained payload binds the challenge, organization, agent, active key,
expected revision, typed RFC 7638 fingerprint, source declarations, runtime,
administrator, hashed session reference, audience, random nonce, issue/expiry
times, and the selected enrollment policy. The server owns every expected value.
The request supplies only the compact proof.

The restricted JWS header has exactly `typ`, `alg`, and `kid`. Algorithms are
ES256 and EdDSA with the Ed25519 curve. Proofs use canonical unpadded base64url,
the exact retained payload bytes, 64-byte signatures, and low-S form for ES256.
Duplicate or unknown header members, embedded replacement keys, invalid points,
wrong algorithms, altered payloads, and expired or future proofs fail closed.
The cryptographic verifier returns an opaque, non-deserializable and
non-cloneable result. It does not own replay storage or produce authorization.

Organization serializes enrollment with identity/key changes and retains
challenge consumption. The transaction checks current permissions again after
lock waits and before commit, and checks the actual database clock against the
session and challenge deadlines. A failed check rolls back the identity, outcome,
history and audit changes together. Challenge and outcome records are retained;
deleting evidence to make an old intent reusable is not a supported operation.

## Explicit installation selection

| Setting | Selection |
| --- | --- |
| Gateway and Organization directory | `MARTY_AGENT_ADMIN_ENABLED=true` |
| Gateway and Organization enrollment | `MARTY_AGENT_ENROLLMENT_ENABLED=true` |
| Organization enrollment audience | `MARTY_AGENT_ENROLLMENT_AUDIENCE`, explicitly configured URI |
| Organization enrollment policy | `MARTY_AGENT_ENROLLMENT_POLICY_PROFILE`, default `urn:marty:managed-key-enrollment-policy:v1` |
| Organization policy revision | `MARTY_AGENT_ENROLLMENT_POLICY_REVISION`, default `1` |
| Challenge lifetime | `MARTY_AGENT_ENROLLMENT_MAX_AGE_SECONDS`, default `120`, range `1..300` |
| Gateway authenticated hop | Existing `GRPC_SERVICE_TOKEN`; exact authenticated human session metadata is rebuilt by Gateway |

Enrollment requires directory administration to be selected too. Directory and
enrollment capabilities remain off by default. There is no new browser key
store, private-key upload, or automatic proof signer in the console. The existing
console still supplies directory and approval administration; these enrollment
APIs and the local signer are the explicit operator integration surface.

Organization migration `0004_managed_agent_enrollment.sql` is additive. It
introduces retained challenges, immutable outcomes and invalidations, and guards
the proof-required lifecycle transition. Organization migrations 0001–0003 retain
their original bytes. Serving performs verification; deployment owns migrations
and role provisioning. Disable the feature flags to stop new enrollment traffic;
preserve recorded evidence and enrolled lifecycle history during rollback.

## Human grant lifecycle commands

The separate `marty-delegation-commands` executable exposes the selected human
organization/KEY profile through
`POST /v1/organizations/{organization_id}/delegation-commands`. It composes
`CREATE_GRANT`, `APPROVE_GRANT`, `SUSPEND_GRANT`, `REINSTATE_GRANT`, `REVOKE_GRANT`
and `RECOVER_RESULT`. It rejects `START_USE` and `FINALIZE_USE`.

Gateway requires an own non-impersonated session, actual Auth expiry, allowed
Origin and current action permission. The host independently checks the current
Organization source. Grant creation uses the authenticated human grantor and
configured organization subject/issuer. Approval resolves the exact original
trusted human/session confirmation and independently verifies current consent
and representation authority. Supplying a confirmation UUID is not evidence.

The command writer, evidence reader and Organization reader use distinct
restricted database identities. The command executable has no consent or
representation-authority producer writer credential. New mutations recheck
source permission after acquiring their command/grant locks, without extending
the original bounded deadline. Source checks remain bounded observations across
separate owners, not a distributed atomic revocation transaction.

Each command retains its original ID, full intent digest and immutable result.
Gateway forwards original command bytes and never applies generic HTTP replay,
response caching or automatic mutation retries. After an uncertain result,
`RECOVER_RESULT` uses the original ID and expected digest with fresh view access.
A mutation-shaped resend still encounters Gateway's corresponding action check;
explicit recovery supports view-only access after the mutation right is lost.
No result found is not proof that an earlier operation has stopped.

The Gateway validates the returned original ID/digest, organization, grant
snapshot, terms digest, status and revision before returning the result. Recovered
snapshots may legitimately be expired or revoked history. Recovery does not
refresh authority or authorize a new operation.

Enable `MARTY_DELEGATION_COMMANDS_ENABLED=true` in Gateway and the separate host,
with `DELEGATED_COMMAND_SERVICE_URL` selecting the `delegated-commands` upstream.
The full credentials, adapter pins, migration commands and least-privilege SQL
are in the [command host runbook](../rust/services/delegated-authority/COMMAND_HOST.md).

## Remaining gates and ownership

Operational machine credential verification, MAP/attestation/Cedar appraisal,
external workload authentication, represented-subject SESSION establishment,
retained `START_USE` nonce admission, dedicated `FINALIZE_USE` persistence and
managed receipt signing remain separate work. Packaged public clients and
independent deployment/issuer/browser qualification are still required before
advertising the corresponding capabilities.

Marty owns the identity, grant and trust evidence described here. Rifare continues
to own agent definitions, prompts/models, orchestration, resource permissions,
budgets, reservations, provider execution and business outcomes. No Rifare
business execution behavior is enabled by either candidate. Public MIP remains
0.5.0; protocol support and discovery remain unchanged.

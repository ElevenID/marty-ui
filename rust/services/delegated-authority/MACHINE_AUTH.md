# Selected full-machine authentication gate

This is an explicit composition API around the existing Core-backed
OID4VP proof verifier. It implements the selected requirements of the pinned
Machine Authentication Policy (MAP) without defining another proof wire.
It is not installed by either human administration executable or Gateway.

The supported selection is deliberately bounded:

- A real current `MACHINE_IDENTITY` principal with `MANAGED` runtime state.
- An active MAP selecting `MACHINE_KEY` and
  `OID4VP_VERIFIABLE_PRESENTATION`, with an explicit proof age of 30–600 seconds.
- An assigned deployment, current active public JWK and its exact fingerprint,
  source identity, configured verifier audience, and registered credential IDs.
- No conflicting suspension, revocation or retirement marker in the selected
  active full-machine snapshot.
- A KEY-bound delegated grant and the same complete typed delegate.
- Every required machine credential type and every selected attestation and
  `MACHINE_AUTHORIZATION` requirement.

The current Organization agent inventory remains `SERVICE_ACCOUNT`.
Enrollment's `KEY_CONTROL_VERIFIED` state does not turn that record into a full
MachineIdentity or qualify it for this gate. The separate Organization
[full-machine registry](../organization/MACHINE_REGISTRY.md) and
`OrganizationMachineAuthenticationStateSource` now provide explicit owner-backed
registration and selection. Production composition still requires qualified
connections to that owner; inventory is never a fallback source.

## Modules and integration

The lightweight principal/runtime-binding crate provides
`machine_policy::MachineAuthenticationPolicy::from_trusted_document` and
`qualify_machine_binding`. They enforce shape and consistency of the exact
pinned MAP contract and selected machine snapshot. Parsing is not evidence that
the source is authentic. Unsupported policy selections, absent registered
credentials, inconsistent assignments, inactive machines and invalid key
lifetimes fail closed.

`machine_auth::MartyMachineOid4vpProofVerifier` supplies the complete in-process
qualification gate. Durable machine use selects
`machine_evidence::AuditedMachineOid4vpProofVerifier` as the existing
`DelegateProofVerifier` port for `DelegationUseAuthorizer`. Its concrete proof
implementation is always
`MartyOid4vpDelegateProofVerifier`, using pinned Marty Core cryptography.
An arbitrary proof-verifier implementation or a caller-authored successful
verification flag cannot replace that cryptographic step in this wrapper.

The gate first resolves current state from its configured source. It validates
the selected full machine identity, policy, key, deployment and principal
consistency. It then verifies the actual VP signature, holder, issuer, nonce,
key binding, proof lifetime and retained Flow operation through the existing
adapter. The binding configuration's authentication issuer and subject must
both equal the authenticated machine principal for this selection.

The configured authentication audience is the OID4VP verifier client ID.
It is checked through a wrapped authoritative challenge lookup and remains
distinct from the relying operation's audience. The original Flow challenge
still binds the exact tenant, grant revision, typed actor, action, resource,
operation profile and digest.

Successful `verify_machine` returns an opaque, non-deserializable,
non-cloneable `AuthenticatedMachineProof`. Its getters expose the exact scope
and provider evidence references for a qualified host to retain. Its
`into_delegate_proof` method composes with the existing authorization engine.
The ordinary trait method performs that same gate and conversion.
Neither result is a bearer capability or permission to execute a domain action.

The resulting proof evidence reference is
`urn:marty:machine-authentication:sha256:<digest>`. Its digest covers a bounded,
canonical private audit document containing the original Core proof reference,
exact scope, MAP document/digest, source observation, verified credential
IDs/types/trust selection, attestation result, selected machine authorization
policy revision/digest, completion time and earliest deadline. Thus a receipt
does not lose the machine-policy provenance when the result is converted into
the generic delegated proof type.

`evidence_document()` and `evidence_bytes()` expose that audit record to a
qualified consuming host. This reference is not a new proof envelope.
`machine_evidence::PgMachineAuthenticationEvidenceRepository` now retains those
exact bytes, their digest and JSON document in the private append-only
`machine_authentication_evidence` table. Migration 0007 is additive; migrations
0001–0006 and their existing records remain unchanged.

### Durable evidence and final use

`AuditedMachineOid4vpProofVerifier` accepts the concrete full-machine verifier
and concrete PostgreSQL repository. It verifies through Core and the selected
providers, retains the resulting opaque proof's exact audit, awaits COMMIT, and
checks the original deadline again using its trusted clock. Storage errors,
clock regression and expiry return no qualified generic proof. The repository
also checks the database clock around storage; an initially deferred database
guard checks the insertion deadline at transaction completion. An I/O delay
that outlasts that guard still cannot pass the wrapper's post-COMMIT check.
COMMIT has no cancellation timeout or automatic retry. A committed record may
therefore remain useful history even when its proof has become unusable.

`RetainedMachineAuthenticationProof` is opaque and non-deserializable. Its
conversion returns the original bounded generic proof only after durable
retention. Exact duplicate retention is idempotent and preserves the first
retention timestamp; it cannot rewrite bytes, renew evidence or extend expiry.
The audit table denies UPDATE, DELETE and TRUNCATE, including accidental writes
by its owner through ordinary SQL. Private debug output is redacted.

The audit writer is a distinct nonowner PostgreSQL identity. Readiness requires
SELECT/INSERT on the audit table, SELECT on the migration ledger and retained
machine-policy evidence, and schema USAGE. It rejects reachable administrative or
predefined PostgreSQL `pg_` roles, replication privileges, destructive privileges,
same-database source/ledger writes, unrelated table reads and executable
security-definer functions. The authenticated login must match `current_user`;
`SET ROLE` cannot hide broader login privileges. It receives no lifecycle or
use-ledger write authority. Existing
human lifecycle and consent/authority producer identities receive no audit
access. A future use writer needs SELECT on the audit table for receipt binding;
it must never inherit the audit writer's INSERT authority.

A new `MACHINE_IDENTITY` receipt cannot be appended without the retained audit.
The database guard binds tenant, complete typed actor, grant/revision,
challenge ID and nonce digest, operation/action/audience/resource, key
fingerprint, original proof verification time and the aggregate deadline. It
rejects a plain Core-only proof reference for a machine receipt and a machine
authentication reference on any other principal type. The `SERVICE_ACCOUNT`
proof path otherwise keeps its existing semantics. The retained use owner
still owns challenge replay, current grant checks and atomic receipt/result
commit.

`recover(organization_id, evidence_ref)` returns only
`HistoricalMachineAuthenticationEvidence`, scoped to the exact tenant and
reference. It rechecks the stored bytes/digest/document and timestamp binding,
and returns original history after expiry without calling a provider or
creating authentication authority. There is no conversion from historical
records into a proof and no public raw-audit route. A consuming host must
separately authorize historical inspection; regular use responses contain only
the existing receipt references and bounded outcomes.

The referenced state, credential, attestation and Cedar source evidence still
belongs to its source owner. Retaining the aggregate does not manufacture or
retain those source records, establish their trust, install a production host,
or qualify the deployment. Sources must already retain the exact records
behind their returned references.

## Required trusted providers

These are in-process verification ports, not HTTP request DTOs. The gate does
not accept raw caller fields such as `verified: true` or fabricate evidence
when a provider is unavailable.

| Provider | Obligation |
| --- | --- |
| `MachineAuthenticationStateSource` | Independently select the deployment's current MAP and load the current complete machine, public key, runtime/principal configuration, source identity and status. Its freshness covers every loaded state and assignment. |
| `MachineCredentialVerifier` | Authenticate credential signatures/issuers, selected Trust Profile, exact machine subject/key binding, validity and current revocation/status. Return the registered credential IDs and the credential types actually verified. Finding an ID or checking a self-asserted type is insufficient. |
| `MachineAttestationVerifier` | When required, authenticate an accepted attestation format under the exact verifier Trust Profile and appraise the machine identity key, runtime and original proof challenge. Its production time, result digest and freshness are checked. |
| `MachineAuthorizationVerifier` | When selected, evaluate the exact current active policy set of type `MACHINE_AUTHORIZATION`. Deny, abstain, evaluation errors, absent policy and unqualified engines fail closed. |

The credential provider is mandatory because every valid MAP requires at least
one credential type. A missing attestation or authorization provider also fails
when its requirement is selected. Optional requirements do not cause a
different provider or an enrollment result to be substituted.

Every positive provider result must return the exact derived scope: tenant,
full machine ID, deployment, typed principal, runtime, key ID/fingerprint, MAP
ID and complete-document digest, grant ID/revision, challenge ID/nonce digest,
cryptographic proof reference, action/audience/resource, operation profile and
operation digest. A result for another source, key, operation or policy cannot
be reused. The credential list is unique, registered and bounded, and must cover
every required type.

No production credential or attestation source is installed here. Synthetic
test providers exercise the composition contract; they are not issuer or
attestation qualification.

## Concrete nested JWT-VC adapter

[`machine_credentials::MartyNestedJwtVcMachineCredentialVerifier`](MACHINE_CREDENTIALS.md)
performs actual Core issuer and holder verification for exactly one registered
`MartyNestedVc2JwtV1` credential covering every required MAP type. It supports
ES256 and EdDSA with the self-certifying holder selection. Its explicit trusted
authority/status port binds the full scope, exact compact credential digest,
selected Trust Profile, issuer/key and current profile/issuer/key/credential
state. It returns a source-retained record URI into the aggregate audit and
enforces the original, source, credential and key deadlines. The live full
machine/MAP and JWT-VC authority/status owners remain qualification gates. The
existing managed SD-JWT owners are not implicitly broadened.

## Concrete MMF Cedar adapter

`machine_cedar::MmfMachineAuthorizationVerifier` implements the machine
authorization port using MMF's existing canonical Cedar engine. Its
`MachineCedarPolicySource` supplies an independently authenticated current
policy/schema pair, exact scope, typed entity graph and bounded observation.
The source must bind its policy digest to both immutable policy and schema.

The selected application mapping uses action
`urn:marty:machine:authenticate`, the machine principal, and the full machine
UUID as resource. The exact deployment, runtime, key, MAP, grant, challenge,
proof and requested operation are included in server-constructed context.
This action mapping is an application integration contract, not a newly
promoted Protocol wire definition.

Only an error-free Cedar permit is accepted. Wrong policy ID/type, draft state,
invalid revision/digest, foreign scope, stale source, entity/schema errors and
forbid/default-deny outcomes fail closed. The gate still runs the separate
delegated/domain Cedar evaluation downstream; machine authentication cannot
grant commerce permissions.

## Freshness, replay and evidence ownership

The source and provider observations are bounded to at most 30 seconds each.
The complete operation also starts with a 30-second deadline that later reads
cannot extend. The gate rereads its trusted clock after each awaited provider
and after evaluation, rejecting clock regression and expiry. The final deadline
is the earliest of the original limit, state observation, current key expiry,
OID4VP proof/challenge expiry, required credential checks, required attestation
and selected machine authorization.

A policy/key record cannot be newer than the source observation that asserts it.
Attestation cannot be produced after its observation or exceed the MAP's
maximum age. A fresh provider response cannot renew an earlier expired source
or extend an earlier evidence deadline.

These remain bounded observations across owners, not a distributed atomic
revocation transaction. A qualified host must retain the policy and evidence
provenance needed to explain its decision and revalidate at its final-use
boundary. `AuthenticatedMachineProof::ensure_current` only checks the retained
time bound; it does not refresh source state.

The underlying qualification gate is read-only and has a five-second aggregate
provider timeout. The audited wrapper additionally retains its private evidence.
Neither component consumes a nonce, inserts a replay reservation, activates a grant, creates
credentials, or executes a business operation. The retained use owner must
atomically enforce the current grant revision and challenge/replay admission.
Source freshness, provider identity, storage isolation, issuer/attestation
interoperability and public hosting remain deployment qualification gates.

## Local verification

The module tests reuse the repository's public-only independently generated
Ed25519 VP vectors and execute actual pinned Core verification. They separately
exercise the pure MAP parser/selection, current machine/key requirements,
provider absence/errors, complete evidence scope, credential coverage,
attestation and policy binding, time bounds, timeout behavior, and actual MMF
Cedar permit/forbid/schema handling. No private signing key is copied into
the static vector tests, and no private Protocol corpus is embedded.

The durable audit tests additionally generate ephemeral test-only Ed25519 keys
and current VPs so actual PostgreSQL clock checks can run. They exercise a
restricted audit writer, exact byte retention and duplicate behavior, immutable
expired recovery, all audit/receipt guards, final-use scope/deadline binding,
missing evidence, storage failure, expiry before insertion, deferred commit
expiry and I/O completing after the original deadline. Source, consent,
attestation and transport-shaped receipt fixtures are explicitly synthetic.
The SQL upgrade preflight checks schema 0008, original migration checksums,
role isolation, exact byte/digest/document constraints, audit history and new
receipt linkage without changing data.
Original pre-0007 machine receipts without this audit are counted separately as
legacy history; an upgrade never invents missing audit or renews their authority.


## Concrete source owners

The next internal composition uses the Organization
[`MachineRegistryService`](../organization/MACHINE_REGISTRY.md) and
`OrganizationMachineAuthenticationStateSource` for separately registered full
machine identity and deployment MAP assignment. It does not promote the existing
SERVICE_ACCOUNT directory or managed key-control enrollment. Current selected
identity/key/lifecycle facts are retained before returning a source observation.

The [concrete credential source](../../crates/machine-credential-source/README.md)
resolves current Trust Profile/issuer/key authority and exact originally issued
credential state from their actual owners. It preserves the selected nested
JWT-VC profile and the existing SD-JWT contract boundary. The
[audited machine-policy source](MACHINE_POLICY_SOURCE.md) reads an explicitly
administered named policy, compiles its fixed context-only schema through MMF and
retains both source and evaluation evidence. Migration 0008 rejects a new aggregate
machine audit that selects machine authorization without that retained evaluation.

The five-second provider timeout remains. Sources bound reads and locks, shield
only an already-started final evidence COMMIT from caller cancellation, and
recheck the original deadline after COMMIT. A timeout yields no positive proof,
never an automatic retry. Required attestation, protected workload authentication,
public proof ingress, current use/domain authorization and deployment role
qualification remain independent gates.

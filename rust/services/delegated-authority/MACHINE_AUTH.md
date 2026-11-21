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
MachineIdentity or qualify it for this gate. A production composition needs an
independently trusted source of the full machine model, policy assignment and
current key/deployment state. No conversion or fallback source is supplied here.

## Modules and integration

The lightweight principal/runtime-binding crate provides
`machine_policy::MachineAuthenticationPolicy::from_trusted_document` and
`qualify_machine_binding`. They enforce shape and consistency of the exact
pinned MAP contract and selected machine snapshot. Parsing is not evidence that
the source is authentic. Unsupported policy selections, absent registered
credentials, inconsistent assignments, inactive machines and invalid key
lifetimes fail closed.

`machine_auth::MartyMachineOid4vpProofVerifier` implements the existing
`DelegateProofVerifier` port and can be injected into
`DelegationUseAuthorizer`. Its concrete proof implementation is always
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
qualified consuming host. This reference is not a new proof envelope or a
storage API. Hashing the record does not durably store it; the host must retain
the record and referenced source evidence before advertising this composition.

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

The gate is read-only and has a five-second aggregate provider timeout. It never
consumes a nonce, inserts a replay reservation, activates a grant, creates
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
these tests, and no private Protocol corpus is embedded.

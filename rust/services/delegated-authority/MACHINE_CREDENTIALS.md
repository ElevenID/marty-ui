# Selected machine JWT credential verification

`MartyNestedJwtVcMachineCredentialVerifier` supplies actual issuer and holder
cryptography to the `MachineCredentialVerifier` port in
[`MartyMachineOid4vpProofVerifier`](MACHINE_AUTH.md). It uses the accepted pinned
Core implementation. The separate
[`marty-machine-credential-source`](../../crates/machine-credential-source/README.md)
crate now supplies an explicit concrete composition of the actual Trust Profile
and Issuance PostgreSQL owners with retained source evidence. Neither library
installs a production credential authority or full-machine host.

## Implemented selection

This is one deliberately bounded selection:

| Boundary | Accepted behavior |
| --- | --- |
| Machine path | Current full `MACHINE_IDENTITY`, managed runtime, registered current `MACHINE_KEY`, and the selected MAP's OID4VP presentation path. The enclosing machine verifier owns source qualification. |
| Securing profile | Core `MartyNestedVc2JwtV1`, selected by the adapter, with one nested issuer JWT VC in the original JWT VP. No profile detection or fallback. |
| Credential count | Exactly one credential whose authenticated types satisfy **every** MAP-required credential type. A MAP requiring separate credentials needs a different qualified adapter. |
| Credential types | A unique array of at most 32 bounded type names, including `VerifiableCredential`, consistent with the enclosing machine gate. |
| Issuer algorithm | ES256 or EdDSA, with an explicit protected `kid` and an independently selected public issuer key. |
| Credential identifier | Exact canonical lower-case `urn:uuid:<uuid>`, present in the current machine's registered UUID list. Aliases, unknown IDs and nil IDs fail closed. |
| Holder and subject | Core authenticates the original VP, its self-certifying holder identity and exact credential subject. The actual public signer key must also match the current machine key. |
| Challenge and audience | Original Flow-owned nonce from the preceding proof result and the qualified binding's verifier audience. The relying operation's audience remains separately scoped. |
| Issuer authority | Current selected Trust Profile, issuer authorization, issuer key and credential status, supplied by the configured trusted source. Issuer authorization must cover every signed non-base credential type. |
| Lifetime | Earliest source deadline, original 30-second observation window, original proof deadline, actual VP expiration and MAP proof-age bound, signed credential expiration/date bound, and registered machine-key expiration. |

Core's profiled verifier performs both issuer signature verification and
subject/holder key binding. The adapter first verifies the original holder VP
and its current key before consulting the source on the inner credential's
untrusted selectors. It then verifies the complete profiled presentation again
after the source await, at a newly read clock instant. There is no success flag
that can replace either signature.

The adapter revalidates the complete `MachineAuthenticationScope` against the
qualified binding, selected policy, original proof digest and operation. Its
source response must echo the entire selection exactly, including all scope
fields, selected Trust Profile, securing profile, registered credential UUID,
original compact credential digest, issuer, key ID and algorithm. A changed
tenant, runtime, grant revision, nonce digest, proof, policy or operation cannot
reuse an observation.

## Trusted authority/status port

`MachineJwtVcAuthoritySource::resolve_current` is an internal source interface,
not an HTTP contract and not a caller request body. `MachineJwtVcSelection`
contains **untrusted lookup hints** from the compact issuer credential. A future
owner adapter must use configured, authenticated authorities; it must not turn
an issuer, `kid` or other hint into an arbitrary network fetch.

`ResolvedMachineJwtVcAuthority` represents a current source record. All four
statuses—Trust Profile, issuer authorization, issuer key and credential—must be
`Active`. `Unknown`, `Suspended`, `Revoked` and `Expired` fail closed. A missing
source, malformed key, private key member, ambiguous public JWK, wrong key
identity, missing type authorization, invalid policy revision/digest, failed
lookup or timeout also fails closed.

The source's observation and deadline must cover all four authoritative states
together. The maximum window is 30 seconds from `observed_at`; no source can
extend that window. The adapter rejects future observations, empty or stale
windows and overlong deadlines. It reads the clock after the source await and
after cryptography, rejecting expiry or clock regression without renewing any
earlier timestamp.

The source is responsible for durably retaining its exact authority/status
record under `evidence_ref`, including the exact scope, token digest, issuer/key
selection, Trust Profile revision/digest, statuses and validity interval. The
credential result carries that source-owned reference into the aggregate
machine-authentication audit. It does not manufacture a hash-only credential
evidence artifact whose underlying record is absent. The aggregate audit does
not contain raw bearer presentations, credentials or private source documents.

## Composition

An authenticated internal host may construct this provider with a qualified
authority source and pass it into the existing machine verifier's credential
slot:

```rust
let credentials = Arc::new(
    MartyNestedJwtVcMachineCredentialVerifier::new(credential_authority_source),
);
let machine = MartyMachineOid4vpProofVerifier::new(
    flow_challenge_store,
    full_machine_and_map_source,
    Some(credentials),
    selected_attestation_provider,
    selected_machine_authorization_provider,
);
```

The constructor does not prove that any source is deployed or qualified.
Required attestation and `MACHINE_AUTHORIZATION` evaluation remain mandatory
when selected by the MAP. Delegated/domain authorization, durable aggregate
audit retention, atomic final-use challenge consumption and current grant
revision checks remain separate existing gates.

## Qualification still required

The existing Organization inventory contains `SERVICE_ACCOUNT` registrations;
it is not the authoritative current full-machine/MAP registry required by this
path. This change neither promotes those registrations nor adds an invented
full-machine source endpoint.

The existing authenticated managed SD-JWT channels retain their existing scope.
The concrete nested-profile source uses separately named internal owner APIs,
explicit nested-type grants and a separate Trust Profile revision namespace.
Its Issuance owner binds the exact compact artifact to the original committed
issuance transaction and current lifecycle; its source commits exact private
evidence before returning. No managed SD-JWT HTTP contract is widened.

A live deployment still requires authenticated, qualified owner connections,
the selected host and actual workload authentication. The source's local
PostgreSQL/crypto tests establish implementation behavior; administrative test
fixtures and HTTP success do not establish production owner qualification.

There is no public route, default executable, inventory promotion or protocol
capability advertisement added by this module. Broader credential bundles,
other securing profiles, non-self-certifying subjects, additional issuer
algorithms or alternate credential ID mappings require explicit separate
selection and qualification.

## Verification

`machine_credentials_tests.rs` generates ephemeral P-256 and Ed25519 issuer and
holder keys at test execution. No private test keys or private Protocol corpus
are embedded. Positive tests exercise both algorithms and the entire enclosing
machine authentication gate with **synthetic** full-machine and authority
source records.

The regression cases include a valid holder presentation carrying a forged
issuer credential, actual wrong holder signatures/current keys, wrong original
nonce/verifier audience, every scope/selection field, all non-active source
states, issuer key identity and private/duplicate JWK rejection, required
credential types, registered UUID/subject binding, malformed or ambiguous
credentials, profile confusion, duplicate JSON members, signed credential/date
expiry, source freshness, clock regression and expiry while verification is in
progress. Positive deadline tests prove the shortest signed/source/machine
bound is preserved.

Focused check from `rust/`:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 \
  cargo test --locked --offline -p marty-delegated-authority --lib machine_credentials
```

These are real cryptographic and composition tests backed by source fixtures.
They do not claim live full-machine or issuer/status-owner qualification.

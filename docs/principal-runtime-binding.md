# Principal and runtime binding consumer foundation

`marty-principal-runtime-binding` is an internal Rust consumer of the optional
Marty principal/runtime-binding v1 profile at protocol revision
`6126da7619e057be2ff58dd38a5d50f49891d1b3` (protocol PR #38).
It advances the M02 foundation: strict parsing, typed fingerprints, and binding
consistency against independently supplied configuration and state.

The consistency foundation alone does not complete agent administration or
operational authentication. Its parsing/consistency functions add no public route,
Gateway authentication mode, discovery capability, or runtime qualification claim. The existing global protocol/API
version and unsupported MachineIdentity/MAP/ADR product statuses are unchanged.

## Follow-on enrollment proof module

The `managed_enrollment` module now separately verifies a versioned signed
challenge for managed enrollment key control. Its opaque, non-cloneable proof
result must be consumed by the Organization service's retained challenge
transaction. This does not change the consistency-only semantics of
`validate_binding` or promote the resulting identity to an operational MAP
appraisal or delegated authorization. The exact signature, source, freshness and
local signer contracts are documented in
[managed-enrollment-proof](../rust/crates/principal-runtime-binding/docs/managed-enrollment-proof.md).
The [application enrollment candidate](managed-agent-enrollment-candidate.md)
owns the optional HTTP/lifecycle integration.

## Relationship to existing Marty identities

The gateway currently authenticates browser sessions and organization API keys.
API-key scope checks, organization membership, resource ownership, and existing
tenant resolution remain in their current services. A bearer API key is not a
proof key. Its database secret hash must never be reused as a JWK thumbprint.
A browser session does not by itself establish a represented-subject session
bound to a separate agent principal, runtime, and key.

The new crate keeps the protocol's typed `SERVICE_ACCOUNT`, `MACHINE_IDENTITY`,
and `EXTERNAL` principals distinct from runtime instances and descriptive agent
definition/run references. It does not introduce a sixth protocol primitive or
rewrite the API-key, user, or session models. External runtimes cannot supply a
managed MachineIdentity just to satisfy a shape requirement. Ordinary customer
wallets do not need stable machine enrollment.

The existing `marty-service-runtime::workload` module extracts URI SANs from the
actual Tonic TLS transport and applies an exact RPC workload policy. A future
adapter may reuse that seam, but still needs verified certificate/key material,
an explicit per-instance runtime mapping, and authoritative machine state. URI
SANs, API-key forwarding headers, Agent Cards, and caller-supplied runtime labels
cannot independently establish those bindings.

## API and trust contract

Only the bounded parsing functions create the input wrappers:

| Function | Parsed input; no trust is established by parsing |
| --- | --- |
| `parse_binding_record` | Normalized authentication-adapter result |
| `parse_configuration` | Private, organization-scoped profile configuration |
| `parse_machine_snapshot` | Current managed MachineIdentity snapshot |
| `parse_session_evidence` | Independently established represented-subject tuple |
| `parse_thumbprint` | Explicit hash basis, encoding, and digest |

All documents are limited to 65,536 bytes and 32 nested levels. Decoding rejects
duplicate fields at every depth, fractional/nonfinite numbers, invalid UTF-8 or
Unicode, trailing data, wrong scalar types, unknown fields, explicit null where
the contract requires omission, and unsupported versions. DTO construction
follows strict decoding. No URI is fetched, and no dynamic schema/key lookup is
performed. URI validation does not normalize identifiers before comparison.

`TrustedBindingInputs::new(authorized_organization_id, &configuration)` takes the
tenant already established by the consuming service's authentication and
authorization processing. Optional `.with_machine(...)` and `.with_session(...)`
attach independently resolved state. The word **trusted** describes a caller
obligation; it is not a cryptographic assertion made by the constructor. Loading
all these values from one untrusted request defeats the binding checks.

`validate_binding(&record, inputs)` returns an opaque
`ValidatedPrincipalBinding` or a static, privacy-safe error. The output has
private fields, redacted `Debug`, and no `Deserialize` implementation. Its
read-only accessors expose the exact tenant, typed principal, issuer/subject,
audience, configured deployment, runtime, typed key, and optional subject-session
identifiers. It is a consistency result, not an authenticated principal,
authorization decision, grant, or bearer capability. Do not persist it as live
authority or create an HTTP endpoint that accepts it as caller-authored JSON.

There are deliberately no automatic conversions from gateway API-key identities,
human sessions, or request headers into the validated result. Integration with
the delegated-authority command layer requires an explicit trusted caller/proof
interface and remains a separate step.

## Enforced consistency

The authenticated tenant must match the record and independently loaded
configuration. Principal type and identifier, issuer/subject, allowed audience,
runtime kind/instance, selected algorithm, and typed key must agree exactly.
Descriptive agent/run references do not change the authenticated principal.

For managed runtimes, the current machine's organization and identity must match
the configuration. A non-null deployment assignment must match the configured
deployment profile; a missing/null assignment adds no deployment assurance.
An ACTIVE machine has exactly one ACTIVE key. The selected key ID, explicit
stored fingerprint encoding, and compatible algorithm must match it. A ROTATING
candidate cannot authenticate. Machine key material, when supplied, is validated
as a public key even when the chosen fingerprint basis is a full certificate.

The selected algorithm must exactly equal the configured algorithm. Core
MachineIdentity records may use either `EdDSA` or `Ed25519` for the same Ed25519
key family; this does not permit silently changing the selected configured
algorithm. The restricted reference consumer supports P-256/ES256 and Ed25519
public JWKs. It does not remove other algorithms from Marty or protocol core.

Shared runtimes require independent represented-subject evidence. The exact
tuple includes represented subject, session reference, establishment evidence,
acting principal, runtime instance, and typed proof key. It must agree with the
current record as well as the independently supplied expected tuple. Changing
the runtime mapping, principal, or key requires newly established session
evidence; an old tuple cannot silently move to the replacement. Even non-shared
runtimes cannot self-assert a supplied subject-session tuple.

## Fingerprint handling

`TypedThumbprint` preserves the distinction between:

- `JWK_RFC7638_SHA256`: SHA-256 of the RFC 7638 canonical public JWK members.
- `X509_CERTIFICATE_DER_SHA256`: SHA-256 of the complete DER certificate.

Supported representations are canonical unpadded base64url of exactly 32 bytes,
`sha256:` plus 64 lowercase hexadecimal digits, and `sha256:` plus canonical
base64url. Padding, whitespace, wrong length, nonzero unused base64 bits, and
uppercase hexadecimal fail. Equality requires the same basis and digest bytes.
Re-encoding changes only representation; it never re-hashes the digest.

`jwk_thumbprint_to_digest` converts an already verified RFC 7638 SHA-256 `jkt`
to the existing DelegationGrant hexadecimal representation. The caller must have
established the JWK basis from verified source semantics. A generic machine
fingerprint cannot be passed merely because it has the expected string length.
`TypedThumbprint::delegation_key_thumbprint` rejects a certificate basis.

`jwk_sha256_thumbprint` performs restricted public-key shape checking and
fingerprinting using existing `p256`, `sha2`, and base64 dependencies. It accepts
only the required RFC 7638 members plus checked public metadata. It rejects
private members, unknown fields, invalid P-256 points, incompatible algorithm
metadata, and malformed coordinates. It does not verify signatures or possession.
Certificate parsing/trust remains with the selected existing cryptographic
adapter; this crate cannot infer a certificate-to-JWK relationship from hashes.

## Required runtime processing still outside this crate

Before and at use, a consuming runtime must independently:

1. Authenticate the actual issuer/workload proof, signature, audience, algorithm,
   private-key possession, and exact source-to-runtime/key association. Use
   authenticated TLS evidence or a separately qualified OAuth/proof adapter;
   never replace it with caller headers or a `verified: true` flag.
2. Load authorized tenant configuration, current machine status/key lifecycle,
   and currently valid represented-subject session evidence from authoritative
   sources within declared freshness bounds. Validate key/certificate validity
   periods, session expiry, revocation, and any required attestation appraisal.
3. Enforce proof replay protection and any transport-specific requirements. The
   existing issuance DPoP verifier does not by itself qualify a generic agent
   authentication boundary. DPoP does not bind a business request body.
4. Resolve and evaluate current delegated authority, exact operation binding,
   policy, approval, and domain/resource authorization. A successfully bound
   session is not consent or grant approval.
5. Retain the selected runtime and evidence qualification tuple before enabling
   public capability discovery or execution. The two-domain qualification gate
   remains separate from this local library's conformance tests.

Machine timestamps are checked for RFC 3339 shape only. No clock is consulted.
An old snapshot that still says ACTIVE is not evidence of current authority.
This is deliberate parity with the protocol's offline consistency reference,
not an assertion that expired keys or stale sessions are usable. Workload
identity, issuer signatures, and session proof do not establish the isolation or
security of an external execution host.

## Local verification

From `rust/`, after the pinned workspace dependencies have been prepared:

```sh
cargo test --locked -p marty-principal-runtime-binding
```

The default suite includes locally authored external inventory-reader, managed
document-worker, and shared support-session examples, fingerprint vectors,
mutation regressions, and a compile-fail doctest showing that the opaque result
cannot be deserialized. Each example has a different freshly generated public
Ed25519 key; the managed example also has a generated P-256 rotation candidate.
Only public key material was exported. Expected RFC 7638 fingerprints were
computed independently with Python's JSON and SHA-256 implementations.

Fixture provenance records the local authorship, generation method, file hashes,
and protocol compatibility target. The target revision identifies the contract,
not the source of the example bytes. No private Protocol fixture snapshot,
private key, or live identity data is bundled. The exact upstream corpus remains
available only through the separately configured checkout test below.

Run the complete protocol corpus explicitly against an independently verified
checkout at the pinned revision:

```sh
MARTY_PRINCIPAL_BINDING_PROTOCOL_ROOT=/path/to/marty-protocol \
  cargo test --locked -p marty-principal-runtime-binding \
  complete_pinned_protocol_binding_corpus -- --ignored --exact
```

This additional test is marked ignored by default because the private source
checkout is not bundled. A missing configured checkout is a failing explicit
gate, not a simulated pass. Verify the checkout against the optional-protocol
consumer lock before running it. All tests run locally; none dispatch GitHub
Actions or imply native dependency, deployed runtime, independent interoperability,
or public capability qualification.

## References

- [Pinned principal/runtime profile](https://github.com/ElevenID/marty-protocol/blob/6126da7619e057be2ff58dd38a5d50f49891d1b3/protocol/principal-runtime-binding/SPECIFICATION.md)
- [RFC 7638: JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
- [RFC 9449: DPoP](https://www.rfc-editor.org/rfc/rfc9449.html)

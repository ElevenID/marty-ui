# Native SD-JWT query, subject and holder evidence

## Scope

This W05 increment produces a typed authentication record for one governed
issuer's holder-bound SD-JWT satisfying one frozen DCQL credential query. It
extends [policy and request binding](policy-bound-verification.md) without
changing the reviewed Core, SD-JWT or MMF fork revisions.

The record is deliberately partial. It is not
`AuthenticatedOid4vpEvidenceV1`, does not assert durable replay consumption,
does not establish issuer authorization for a credential type, and cannot
authorize issuance. Authoritative trust/status evidence and an issuance-owned
continuation remain required before the prerequisite-to-issuance workflow is
complete.

## Supported profile

The existing workload-authenticated transport must carry the exact saved DCQL
query, nonce, verifier client ID and response. The selected profile requires:

- One active saved policy with one required `SD_JWT_VC` requirement and no
  alternative requirements or derived/predicate claims.
- One DCQL credential whose ID equals the saved requirement ID, format is
  `dc+sd-jwt`, and metadata contains one exact VCT URI.
- Literal top-level scalar claim paths matching the policy producer's selected
  required claims. If no claim is required, all requested claims are selected.
  Explicitly empty claim arrays, duplicate paths/IDs and unsupported extensions
  are rejected.
- Exactly one response key and one token. Duplicate JSON response keys, extra
  responses, format substitutions and a token different from the selected
  request token are rejected before authentication.
- Normal client-ID OID4VP audience binding and a nonce of at least 32 bytes.
  Digital Credentials API origin-based audience binding requires its own
  adapter and is outside this profile.
- A governed public Ed25519 or P-256 issuer key. The issuer algorithm is chosen
  from that governed key; supported holder algorithms are separately limited
  to EdDSA and ES256.
- An authenticated issuer JWT with protected `typ: dc+sd-jwt`, exact VCT,
  a bounded issuer-scoped subject, an issuance time and a live expiry. The
  issuer-signed `cnf.jwk` must be the unambiguous public holder key.

The VC profile's non-disclosable fields (`iss`, `nbf`, `exp`, `cnf`, `vct`,
`vct#integrity`, `aka_vcts` and `status`) must agree exactly between the
authenticated issuer payload and reconstructed claims. This check prevents the
generic SD-JWT verifier from accepting selectively disclosed security metadata
under this stricter VC profile. `sub` and `iat` may be selectively disclosed.
Requiring an expiry is a local restriction of this bounded profile.

Other credential formats, Presentation Exchange and calls without typed
transport retain their existing behavior. They do not acquire this guarantee.

## Authentication and correspondence

`SdJwtDcqlRequest` has private fields and is prepared from the saved policy and
typed workload transport. Its verifier calls Core's policy-aware SD-JWT
verification with both expected nonce and audience. Only that call can produce
`AuthenticatedSdJwtQueryEvidence`; neither type has a public JSON constructor.

The prepared request and authenticated record bind the organization, complete
saved policy identity, template, query ID/digest, exact selected response-token
digest, nonce, audience, VCT, selected claim names and observation time. They
also retain the effective trust-profile ID privately. The saved requirement's
profile overrides the saved policy default; caller context cannot replace it.
A cached native result or public projection under a different profile is
rejected. Returned issuer
provenance must match the actual profile and organization used for that
evaluation. This does not freeze the profile's contents or establish that its
issuer/type relationship is authorized by an issuance policy.

A private digest binds the adjacent policy claim values to the authenticated
selection. Both the native orchestration boundary and the final production
projection reject genuine evidence attached to a different request, policy,
token or set of claims. The projection attaches the record only to the unique
matching credential result, never to an arbitrary result selected by order.

After awaited trust and status work, the orchestrator rereads its clock and
rechecks the authenticated credential validity window. It also rechecks the
authenticated KB-JWT `iat` using the pinned Core verifier's five-minute maximum
age and sixty-second future-skew window, including fractional NumericDate
values. Optional authenticated KB-JWT `nbf` and `exp` also retain strict live
validity bounds at both observations. Expired credentials, stale holder proofs
and a backwards observation clock cannot acquire a refreshed `checked_at` value.

## Minimal public record

The serialized contract is `marty.sd-jwt-dcql-query-evidence/v1`. It contains
policy and query identity, digests of the exact selected token/nonce/audience,
issuer ID, a domain-separated issuer-scoped subject digest, the holder key's
RFC 7638 thumbprint, VCT, issuer algorithm, matched claim names and final
observation time.

It omits the raw subject, credential, disclosures, holder public key, nonce,
audience and claim values. The internal selected-claims digest, trust-profile
identity and validity/freshness fields are serialization-skipped. The record
has private fields and no deserializer, so caller JSON cannot manufacture or
promote it. It travels in the existing credential-result JSON; no new protocol
descriptor or wire field is needed. Existing Flow callback evidence digests
cover the resulting credential records.

The record may accompany a denied policy decision. For example, successful
query and holder authentication does not satisfy a policy requiring durable
replay consumption. No replay pass is inferred from a nonce comparison.

## Review and regression coverage

Real signed issuer and holder fixtures exercise selective disclosure and the
actual native kernel, policy evaluator and wire projection. Coverage includes
signature/issuer/holder substitution, missing or incorrect protected type,
nonce and audience mismatch, malformed or ambiguous queries/responses, caller
JSON promotion, cached native evidence, changed policy claims, crossed policy
and request identity, selected trust-profile correspondence, credential expiry
and holder-proof staleness during awaited evaluation, and non-disclosable VC
metadata. The compile-fail example checks the absence of a JSON constructor.

Two independent source audits are required for this PR. Exact local test
counts, reviewed publication head and hosted gates are recorded in PR 1845 and
the [development checkpoint](fork-protocol-development-checkpoint-2026-11-07.md).

## Related CI corrections

The preceding published head exposed three independent integration failures:

1. Auth's Flow dev dependency violated the registered service-dependency
   boundary. The exact production callback serializer now lives in the shared
   OID4VP contract crate and accepts the existing MMF digest function. Auth
   tests retain independent DTO/HMAC verification, including a frozen legacy
   canonical-event and HMAC vector.
2. The Envoy descriptor contract still expected the hash preceding the
   reviewed policy-revision fields. Its expected hash now matches the generated
   descriptor; RPC, route and field assertions remain intact.
3. Canvas renewal's historical-schema fixture lacked the native authorization
   expiry columns. It now runs the existing native extension migration in its
   isolated scenario database before seeding through the normal repository.

These fixes do not relax the dependency rule, alter production migrations or
bypass live signing authorization. Actual PostgreSQL assertions remain a
separate gate from compilation and tests that return early without a database.

## Next implementation boundary

Complete the canonical evidence producer with authoritative issuer/type
trust, status and durable replay outcomes for this selected profile. Then bind
that evidence to one tenant, issuing template and exact dataset through an
issuance-owned single-use continuation with expiry. Revalidate and consume
that continuation under the existing atomic signing claim before enabling the
prerequisite-to-issuance workflow.

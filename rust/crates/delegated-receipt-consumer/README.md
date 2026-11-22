# Independent delegated receipt consumer

This crate verifies supplied Delegated Decision Receipt v1 compact JWS bytes
without a Marty service, database, Core API, signing service, or network client.
It has only ordinary workspace serialization, clock-value, URL-shape, hashing,
and public-key cryptography dependencies. It is an application consumer candidate
with `publish = false`; it does not promote public transport, discovery, Protocol
qualification, or deployment support.

Every successful result has `EVIDENCE_ONLY` semantics. A receipt records one
issuer's signed identity/authority decision for an exact request. It does not
establish merchant permission, payment, reservation, business execution,
idempotency, present revocation state, or successful resolution of evidence
references. Those remain the relying application's responsibilities.

## Trust and input contract

The caller supplies four independent inputs:

1. A `PinnedReceiptKey`: tenant UUID, complete typed receipt issuer, exact DID
   verification-method ID, selected algorithm, and minimal public JWK. The
   configured key must independently be trusted for delegated decision receipts.
   The receipt cannot establish its own key purpose or trust authority.
2. A `ReceiptContext`: the tenant, exact grant ID/revision/terms digest, typed
   actor and subject, complete KEY or SESSION binding, complete operation tuple,
   original nonce, context time bounds, expected status issuer/state, and selected
   policy. The operation tuple includes action, resource, audience, request
   profile, and request digest. The relying domain computes its expected request
   digest under its selected request profile before obtaining the receipt.
3. A `RetainedReceiptBinding`: receipt reference, digest, decision, original
   recorded time and original authorization expiry obtained from an independently
   authenticated `FINAL_USE` result. The digest is SHA-256 of the exact original
   compact-JWS bytes, including their original JSON and signature encoding.
4. An explicit observation time. Fresh verification additionally requires an
   explicit `FreshnessPolicy`; the crate never reads a clock or adds clock skew.

Do not derive these expectations from the unverified receipt. Parsing an HTTP
response does not authenticate it. A transport adapter must independently bind
the response to the requested tenant, typed caller and original command/digest,
require the expected `FINAL_USE`/`EVIDENCE_ONLY` response, and enforce current read
authorization for recovery. This crate does not perform those transport steps.

The signed receipt contains the nonce `evaluation.challenge`, but does not contain
the command ID, Flow challenge UUID, or proof-submission UUID. This crate never
claims that its signature directly authenticates those external identifiers.
Their correlation belongs to the independently authenticated retained result and
the caller's original workflow context.

## API

```rust,ignore
use marty_delegated_receipt_consumer::{
    verify_fresh, verify_historical, Algorithm, FreshnessPolicy,
    PinnedReceiptKey, ReceiptExpectation,
};

// All these values come from independently trusted application configuration,
// the original request/challenge, and an authenticated retained-result response.
let key = PinnedReceiptKey::new(
    organization_id,
    receipt_issuer,
    Algorithm::Es256,
    verification_method_id,
    &minimal_public_jwk_json,
)?;
let expected = ReceiptExpectation::new(original_context, retained_result)?;
let policy = FreshnessPolicy::new(30, 30)?;

let evidence = verify_fresh(&compact_jws, &key, &expected, supplied_now, policy)?;
assert_eq!(evidence.semantics(), "EVIDENCE_ONLY");
// Independently authorize, deduplicate and commit the business operation.

// A separate type represents an original result inspected later. Its expiry,
// decision, receipt identity and digest remain unchanged even after expiry.
let history = verify_historical(&compact_jws, &key, &expected, later_time)?;
```

`verify_fresh` returns a sealed `FreshReceiptEvidence` only after signature,
correspondence, retained digest and freshness checks. A signed `DENY` returns
`DecisionDenied`; it is never fresh positive evidence. Even a successful `PERMIT`
is signed evidence and is not a business permission object.

`FreshReceiptEvidence::fresh_until()` exposes the exclusive effective freshness
deadline, including the caller's observation-age cap. It can be earlier than
`expires_at()`, which always preserves the original signed expiry. The object
records verification at `verified_at()`; it does not read the clock again or
assert that authority remains unchanged after that instant.

`verify_historical` returns a separate sealed `HistoricalReceiptEvidence` for
either signed decision. It accepts expiry at the supplied observation time,
while preserving all intrinsic timelines, exact bindings, original timestamps
and receipt digest. It never extends a deadline or converts history to fresh
evidence. It rejects an observation time earlier than issuance or recording.
Neither result type implements `Deserialize`, exposes a public constructor, or
offers a permission/execution method. Both expose the signed decision, exact
receipt reference/digest, original dates, attested evidence references and policy.

The verifier is stateless. Repeating verification of the same receipt does not
consume an idempotency key, reserve a resource, prevent a duplicate external side
effect, or create a new receipt. The relying application's operation transaction
must enforce its own replay and business idempotency rules.

### Dynamic signed claims and optional pins

Approval, authority, proof and status references can be created during
finalization. Requiring callers to independently know those generated values
would encourage unsafe extraction of expectations from the submitted receipt.
The verifier instead validates their URI spelling and exposes them as signed
issuer assertions through `evidence_references()`.

Callers that already obtained references independently can add exact pins using
`with_evidence_reference_pins(EvidenceReferencePins { ... })`. A selected policy
ID is required; `PolicyExpectation.version_digest` is an optional independent
version pin. The signed version digest is always validated and exposed.

Domain evidence is accepted only when the caller explicitly selected its
evaluator, profile and document digest through `DomainEvidenceContext`. The
optional evidence reference can be pinned independently. Its nested grant and
operation must equal the enclosing evaluation; its decision and deadlines must
agree with the receipt. An unexpected, missing or substituted domain evaluation
fails. Validating these assertions does not independently execute the domain
policy or fetch its evidence document.

## Verification rules

- Compact input is at most 100,000 bytes with exactly three nonempty canonical,
  unpadded base64url segments. Decoded protected headers are bounded to 1,024
  bytes; payloads to 75,000 bytes. JSON depth and node limits apply during parsing.
- Duplicate members, unknown fields, nulls, arrays, booleans, floating-point or
  unsafe integers, malformed UTF-8 and trailing JSON are rejected. UUIDs use
  their nonnil canonical lowercase spelling; revisions are 1 through 2^53−1.
- Protected headers contain exactly `alg`, `kid` and
  `typ = mip-delegated-decision+jws`. `alg` and `kid` must match the independent
  key pin. Embedded keys, discovery URLs, detached payloads and JOSE extensions
  cannot select trust.
- Supported keys are ES256 with EC/P-256 coordinates and EdDSA with a strong,
  canonical Ed25519 public key. Only minimal public JWK fields are accepted;
  private material and optional discovery/algorithm metadata are rejected.
  Signatures are raw 64-byte JOSE signatures. Ed25519 uses strict verification.
- Signature verification authenticates the original protected and payload
  segment bytes. ECDSA may normalize a temporary signature value for verification;
  it never rewrites receipt bytes or their retained digest.
- All URI comparisons preserve the original string. There is no URI
  normalization, percent-decoding, DID resolution, reference fetching or trust
  inferred from an identifier prefix.
- Receipt and evaluation profile constants are exact. All nested object schemas
  are closed. This selected consumer follows the producer's completed-evaluation
  subset: status must refer to the same complete grant and remain `ACTIVE`, and
  any present domain evidence must say `PERMIT`, including for a signed overall
  `DENY`. Other grant/domain denials are producer errors without a completed
  receipt. Broader Protocol decision combinations are not qualified here.
  Expected actor/subject types remain part of equality.
- UTC timestamps use a four-digit year, uppercase `T`/`Z`, up to nine fractional
  digits and ordinary seconds. Offset aliases, expanded years and leap seconds
  are rejected. Proof and status observations precede evaluation; evaluation
  precedes issuance; expiry is after issuance and bounded by proof/status and
  selected domain evidence. The intrinsic maximum receipt lifetime is 600 seconds.
- The independently supplied context bounds constrain proof/evaluation and
  receipt expiry. Retained recording must be within the original receipt window;
  the retained decision and authorization expiry must equal the signed values.
- Fresh verification requires `issued_at <= now < expires_at`. Its selected
  lifetime cap and maximum age of proof/status/domain observations are each
  explicitly bounded to 1–600 seconds. Historical results have no conversion to
  fresh results; callers must supply a trusted current instant to the fresh API.

## Validation scope

The standalone tests use application-authored synthetic keys and signed vectors
for both algorithms. They cover exact context substitutions, original-byte
digest binding, signed denial, expiry/history separation, optional reference and
policy pins, domain correspondence, timestamp relationships, strict encoding,
malformed public trust, and sealed result construction.

Producer and host interoperability tests may depend on this crate as a test
consumer. This crate does not depend on those services, their database models,
private Core APIs, signing-grant implementation, or transport fixtures. Synthetic
verification does not qualify live provider custody, TLS, public delivery,
Protocol conformance, or Rifare business execution.

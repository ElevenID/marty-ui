# Managed key enrollment proof, local profile version 1

`urn:marty:managed-key-enrollment:v1` is a Marty implementation profile for a
single managed enrollment key-possession challenge. It is not a new protocol
core flow or a complete Machine Authentication Policy (MAP) appraisal. The
protocol consumer remains pinned to revision
`6126da7619e057be2ff58dd38a5d50f49891d1b3`.

The pinned MAP permits `SIGNED_CHALLENGE` but does not define this wire envelope.
This local profile therefore defines its own purpose, protected JWS type,
payload, algorithm selection, freshness and host integration requirements.
It establishes only possession of the independently registered enrollment key
for the exact retained challenge. It does not verify machine credentials,
workload deployment, issuer authentication, X.509 chains, attestation, Cedar
policy, operational MAP completion, delegation, or permission to use a resource.
An ACTIVE directory status records eligibility; authority and operational MAP
remain separately assessed. This module does not change discovery, public MIP
fields or the deployment's default-off feature switches.

## Trust and replay boundary

The Organization host creates `EnrollmentChallengeParameters` exclusively from
its own authenticated administrator session, directory row, current key,
configuration, fresh cryptographic nonce and clock. No HTTP JSON object,
`verified: true`, API-key context, arbitrary forwarding header, or existing
consistency-only principal binding can create a `VerifiedEnrollmentProof`.

The host retains the entire `.document()` before exposing a challenge. Completion
loads that retained document and current public JWK from the database. The
constructor and `from_trusted_document` validate shape, not source authenticity;
the latter must never load an expected challenge from the caller's request.
`verify_enrollment_proof` verifies the submitted compact JWS against those
independent inputs and a trusted fresh clock.

The returned proof is opaque, has no `Clone`, `Serialize` or `Deserialize`
implementation and exposes privacy-safe metadata/digests. Debug and errors do
not contain submitted proofs, nonce, subject, session identifiers or key bytes.
The host consumes the proof by value while locking the challenge and current
directory/key rows. It must atomically recheck the exact challenge digest,
administrator and session authorization, eligible status, current key and
revision, call `ensure_current` with its commit clock, append the result and make
the challenge single-use. Rotation, lifecycle invalidation and expiry must
prevent a stale completion. Same-request idempotent recovery is the host's
retained historical result, not a second authorization.

This library deliberately has no process-local replay cache. The same signed
challenge can pass cryptographic verification twice; only the host transaction
provides durable single-use behavior across workers and restarts. The signature
cannot be reused for another retained nonce, challenge, tenant, agent, key,
revision, administrator, session, source identity, runtime, audience or policy.

## Compact JWS envelope

The proof is exactly three nonempty segments:

```text
BASE64URL(protected-header).BASE64URL(exact-payload).BASE64URL(signature)
```

Each segment is canonical unpadded base64url. Padding, whitespace, alternate
trailing bits, extra segments and invalid alphabet characters fail closed.
The whole compact proof is at most 16,384 bytes; the decoded protected header is
at most 1,024 bytes; the decoded payload is at most 8,192 bytes. Signature length
is exactly 64 bytes for both supported algorithms. The JWS signing input is the
first two original encoded segments, including the separating period.

The protected header has exactly three required, non-null string fields:

| Field | Required value |
| --- | --- |
| `typ` | `marty-managed-enrollment+jws` |
| `alg` | `ES256` or `EdDSA`, exactly the challenge's selected value |
| `kid` | Exact canonical lowercase UUID string of the challenge's `key_id` |

Header JSON rejects duplicate names and unknown fields. Embedded `jwk`, `jku`,
`x5u`, `crit`, `b64`, algorithm aliases, `none` and MAC algorithms are not allowed.
Header member ordering and insignificant JSON whitespace are not prescribed;
the actual supplied protected header is always signed and verified.

`ES256` means P-256 ECDSA with SHA-256 and the 64-byte `r || s` JWS encoding.
Scalars must be valid and nonzero. This local version additionally requires the
low-S representation: `s <= n / 2`. Mathematically valid high-S signatures,
ASN.1 DER and truncated signatures are rejected. A signer must normalize S.

`EdDSA` in this selected local profile means only pure Ed25519 with SHA-512 as
specified by Ed25519, not Ed448, a prehash variant or generic algorithm
negotiation. The verifier requires a canonical compressed public point,
rejects small-order public keys, and uses Dalek `verify_strict` to reject scalar
and R-point malleability and small-order R. These are the fixed implementation
choices for this pinned profile, not a claim to implement every current JOSE
algorithm registry or policy update.

The public JWK is separately loaded by the host. The existing public-only JWK
parser accepts EC/P-256 or OKP/Ed25519 and rejects private/symmetric components,
unsupported curves, invalid coordinates, duplicate/unknown fields and invalid
metadata. Optional JWK `kid`, `alg`, `use: sig` and `key_ops: [verify]` remain
metadata; they are not substituted for the challenge's explicit `key_id`.
The RFC 7638 SHA-256 thumbprint includes only the required public members.
It must match the retained typed fingerprint and selected algorithm exactly.

## Exact signed payload

The challenge payload is the following closed object. Every field is required;
there are no optional/null fields or extension points in version 1.

| Field | Type and constraint |
| --- | --- |
| `profile` | `urn:marty:managed-key-enrollment:v1` |
| `purpose` | `ENROLL_MANAGED_KEY` |
| `challenge_id` | Non-nil canonical lowercase UUID |
| `organization_id` | Non-nil canonical lowercase UUID |
| `agent_id` | Non-nil canonical lowercase UUID |
| `key_id` | Non-nil canonical lowercase UUID of the current retained key |
| `administrator_id` | Non-nil canonical lowercase UUID of the authenticated initiating human |
| `expected_revision` | Integer 1 through 9,007,199,254,740,990; leaves a JSON-safe next revision |
| `key_algorithm` | Exactly `ES256` or `EdDSA` |
| `key_thumbprint` | Closed object described below |
| `runtime_instance_ref` | Exact absolute URI, maximum 1,024 ASCII characters, no wildcard |
| `issuer` | Exact absolute URI, maximum 1,024 ASCII characters, no wildcard |
| `subject` | 1–512 Unicode characters, no control characters |
| `session_ref` | `urn:marty:session:sha256:` followed by 64 lowercase hex digits; never a raw session token |
| `audience` | Exact deployment-selected absolute URI, maximum 1,024 ASCII characters, no wildcard |
| `nonce` | Canonical base64url of 32 fresh cryptographically random bytes |
| `iat` | Integer UTC epoch seconds, 0 through 253,402,300,799 |
| `exp` | Integer UTC epoch seconds in the same range, strictly greater than `iat` |
| `policy` | Closed deployment-selected policy object described below |

The host must generate an unpredictable nonce. The constructor rejects an
all-zero value as an accidental-default check; it cannot prove that supplied
nonce bytes came from a cryptographic random generator.

`key_thumbprint` has exactly `basis: JWK_RFC7638_SHA256`,
`encoding: BASE64URL_SHA256` and `value`, the canonical unpadded base64url
encoding of 32 fingerprint bytes. Other accepted internal fingerprint
representations are re-encoded at challenge construction without re-hashing.

`policy` has exactly these fields:

| Field | Constraint |
| --- | --- |
| `profile` | Deployment-selected absolute URI, maximum 1,024 ASCII characters, no wildcard |
| `revision` | Integer 1 through 9,007,199,254,740,991 |
| `allowed_algorithms` | Nonempty unique array in canonical order `ES256`, then `EdDSA`; includes the selected key algorithm |
| `max_age_seconds` | Integer 1 through 300; `exp - iat` must not exceed it |

URI parsing checks syntax only. It does not normalize, dereference or infer
authority from a trust-domain prefix. All comparisons retain exact strings.

The library serializes payload objects with recursively sorted ASCII member
names, compact separators, UTF-8 JSON strings and integer decimal numbers.
Arrays preserve their defined order. It emits no insignificant whitespace and
no fractional/exponent numbers. This is the restricted local serializer, not
a general-purpose JSON canonicalization implementation for arbitrary values.

Clients must sign the exact bytes from `.payload()` or the exact encoded segment
from `.payload_b64url()`. Verification compares decoded payload bytes to the
retained exact bytes. A differently spaced, reordered or escaped representation
of the same JSON values fails, as do duplicate, unknown or null fields.
`from_trusted_document` accepts JSONB's member ordering and whitespace changes,
strictly validates duplicate/unknown/type/numeric fields, reconstructs the
canonical payload, and requires canonical field values and array order.

## Clock and digest semantics

The verifier requires `iat <= now < exp`, including the clock's subsecond value.
There is no implicit clock-skew tolerance. Exact expiry is expired.
`VerifiedEnrollmentProof::ensure_current(now)` also rejects a clock earlier
than the original verification time. The host must use a fresh transaction
clock at the final state transition; request time alone is insufficient.

All returned digests are lowercase `sha256:<64 hex>`:

- `challenge.digest()` / `proof.payload_digest()` hash the exact canonical
  payload bytes only.
- `policy.digest()` / `proof.policy_digest()` hash the canonical closed policy
  JSON bytes only.
- `proof.proof_digest()` hashes the actual full compact JWS bytes, including the
  protected-header and signature segments.
- `proof.key_thumbprint()` preserves the independent RFC 7638 hash basis and
  32 public-key fingerprint bytes.

No digest represents a private key or raw human session credential. Retained
records should store the challenge and digest/result evidence, not log proof
strings or private signing material.

## Local key-custodian signer

The repository utility `scripts/sign_managed_enrollment.mjs` runs with Node 24
and built-in modules only. It imports a local unencrypted PKCS8 PEM, verifies the
exported Organization challenge's closed structure, canonical payload and
digest, checks the current local clock, derives the public JWK fingerprint and
algorithm from the key, signs locally, normalizes ES256 to low S and prints only
the compact proof. It makes no network call and does not send the private key
to a browser or service. The key remains in its caller-owned local file.

Invoke it with independently reviewed expected organization, agent,
administrator, audience, runtime, enrollment policy URI/revision and current
directory revision. Optional `--session-ref`, `--issuer` and `--subject` pin the
remaining source/session fields. Those fields are always in the signed payload
and rechecked by the completion host, even when the key custodian does not add
the optional local pins. Do not copy expected values blindly from an untrusted
request; the flags record the key custodian's reviewed intent.

```sh
node scripts/sign_managed_enrollment.mjs \
  --challenge exported-challenge.json --key local-key.pk8.pem \
  --organization 11111111-1111-4111-8111-111111111111 \
  --agent 22222222-2222-4222-8222-222222222222 \
  --administrator 33333333-3333-4333-8333-333333333333 \
  --audience urn:example:organization:managed-enrollment \
  --runtime urn:example:runtime:instance \
  --policy urn:example:enrollment-policy:v1 --policy-revision 1 \
  --expected-revision 7
```

This utility accepts the exported outer Organization challenge DTO, not just
the inner payload. Its `signing_payload`, `challenge_digest`, identifying fields
and expiry must agree with the inner challenge. Only a compact proof should be
submitted through the authenticated enrollment completion API. The CLI does not
enroll an agent or make any lifecycle transition itself. It has no clock
override flag; expired exports require a newly issued server challenge.

## Verification evidence

The Rust integration tests exercise actual signatures for both algorithms,
wrong keys and algorithm confusion, each retained binding field, high-S ECDSA,
malformed Ed25519 points/scalars, closed and duplicate JSON, canonical base64,
clock boundaries, numeric limits, policy restrictions, context replay and
privacy-safe diagnostics. Compile-fail tests check that a verified proof cannot
be deserialized or cloned. Existing binding semantics and the separately run
pinned protocol corpus remain intact.

Node tests generate temporary synthetic keys and verify the CLI's local intent
and key restrictions. Committed Node-generated public interoperability vectors
are verified independently by Rust. Their fixture metadata identifies the
generator and runtime; no private keys are retained in those artifacts.

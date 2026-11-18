# Native signing response adoption

This slice adopts the existing signing diagnostic owner into the native HTTP
signer, issuer resolver and proof-policy resolver. It does not change routes,
Core revisions, cryptographic operations, KMS policy or deployment configuration.
Qualification is local; it is not deployed-route or beta acceptance evidence.

## Shared ownership and observed behavior

`signing_http_response.rs` owns error response bytes, existing content decoding,
the existing lossless response JSON arena, and independent response-text decoding.
`signing_error_detail.rs` owns selection and the 500-codepoint diagnostic prefix;
the operation prefix is outside that bound. JSON is attempted before text, and
text decoding still runs when a parsed JSON diagnostic is selected. Formatting
finishes before truncation. This is not a response-memory bound or redaction.

The shared `python_value` formatter accepts borrowed scalar or lossless arena
views, preserves dictionary order and non-scalar text, and uses iterative
traversal. Truthiness is a separate cheap borrowed operation; it does not
materialize keys, strings, children or number representations.

Caller identity is independent of the endpoint URL: credential issuance and
proof policy use Context; LTI and readiness use Resolve; signing uses Sign.
Context/Resolve preserve the 404 optional branch, and 401 uses the fixed service
API-key rejection without diagnostic decoding. Responses below 400 continue the
existing success parsers without following redirects. Existing strict success,
identity, algorithm, verification-method, signature and private-selector checks
remain in their original owners.

The typed remote failure carries lossless diagnostic text. Debug and Display do
not expose it. Explicit consumers choose their established projection:

| Consumer | Projection |
| --- | --- |
| Credential HTTP | Scalar diagnostic JSON 503; unpaired surrogate plain 500 |
| Proof-policy HTTP | Runtime failure fixed JSON 503; unexpected decoder/JSON failure plain 500 |
| Native LTI JWKS and deep linking | Existing fixed JSON 503 privacy mask for every signing failure |
| Readiness | Failure is false; failed resolution performs no downstream signing |
| Credential gRPC | Existing issuer/signing prefix and unavailable for scalar diagnostic; non-scalar internal error |
| Approval | Signing unavailable; issuer resolution readiness drift |

Native LTI's outer fixed mask intentionally differs from the controlled Python
class-wrapper observations in the reference. Those observations are not evidence
that a native privacy mask should expose remote details.

The repository failure-reason argument is projected explicitly rather than using
safe Display implicitly. Scalar diagnostics retain the previous issuer/signing
prefix. Unpaired surrogates and NUL receive a static text-representability marker;
the original typed cause remains intact for HTTP/gRPC. **The current PostgreSQL
adapter ignores this reason argument and updates status only.** The tests' reason
recorder and NUL rejection are controlled port behavior, not a claim that this
slice restores stored PostgreSQL diagnostics or repairs a production NUL write.
No SQL or schema change is included.

## Evidence and limits

The original 45 diagnostic and six operation observations remain unchanged in
`canvas-worker-privacy-reference.json`. Additional observations remain unchanged
in `signing-response-python-reference.json`; their pinned signing source is
Credentials `d418ac0df283625f43b0c011fb1c72fd7d3013a9`, blob
`5e84cfdcbdf289ec0059eb39dd54c4a5c79c5b3a`, SHA-256
`c412284956f3cb41a9dbd8840a1f67ff4df97f3db1990109499d5b37b704d253`.
See [reference scope](signing-response-reference.md).

The local test graph includes owned loopback HTTP peers, all three production
adapters, native tenant/LTI routers, both readiness entry points, full diagnostic
and request assertions, 3xx success validation, compression, and explicit outward
projections. The frozen reference artifact itself is read with the lossless arena;
it is not converted through scalar JSON to discard surrogate observations.

Fifteen portable additional detail observations are compared, including depth
2048. The captured depth-10000 RecursionError belongs to the recorded Python
interpreter/configuration; no universal depth-10000 threshold is invented in Rust.
Success DTOs retain their existing scalar parsers: this is not a claim of complete
lossless success-envelope parity. Content decompression/read failures use a closed
static failure category, not exact Python decompressor exception-message parity.
The native status short circuits precede body draining; the captured complete-body
401/404 observations do not establish HTTPX non-streaming transport-failure phase
parity for incomplete or compression-invalid bodies at those statuses.

`credential_signing_behavior` additionally composes actual native credential HTTP
admission, claim handling and `HttpCredentialBuilder` with actual remote error
responses. Repository, proof, issuer and lifecycle ports remain controlled. Three
scalar/NUL/surrogate cases assert the public body, one remote POST, a failed claim,
retained reservation and no credential finalization. This is not actual PostgreSQL
or cryptographic signing proof. The new actual-builder scenario removes only the
controlled fixture's conflicting explicit subject so the unchanged Core preparer
can use ordinary subject claims; the original format corpus is unchanged.

During qualification, the tenant fixture initially omitted the issuer DID that
the actual discovery planner requires before requesting proof policy. The final
fixture includes this independent precondition; no runtime or expected response
was changed to accommodate that test setup failure.

## Local qualification

On this slice, the final locked/offline Rust 1.95.0 run passed 398 library tests
and 87 tests across eight integration targets: `signing_error_detail_contract`
(15, including all original 45+6 observations), `credential_signing_behavior` (4),
`credential_admission_behavior` (1), `issuance-behavior` (24),
`canvas_lti_deep_linking_behavior` (10), `canvas_lti_experience_behavior` (17),
`canvas_award_candidate_approval_behavior` (4) and `http_behavior` (12).
Strict Clippy for issuance `--lib --tests -- -D warnings` passed in 39.34 seconds.
All nine inert Python reference guards passed in 0.08 seconds. Issuance package
format checking and `git diff --check` passed. The aggregate `cargo fmt --all`
invocation exceeded Windows command-line length; the package-specific format
check completed normally and was not waived.

The HTTP fixtures join their exact owned servers on normal completion and retain
abort ownership on panic/timeout. This slice created no Docker containers or
external deployments. These results do not replace configured full-system gates
or the aggregate beta-only acceptance run.

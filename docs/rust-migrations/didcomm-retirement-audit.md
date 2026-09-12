# DIDComm Python retirement audit

Reference: Credentials commit `87eae30788924921a42848425d315e2f33f7ae41`;
UI inspection at `31b07a20ad4118ca6283464e6ae0856dadab6272`.
This audit is not routing, release, deployment or KMS acceptance.

## Reproducible response evidence

`contracts/didcomm-projector-python-reference.json` records eight complete
HTTP/gRPC service response pairs and four isolated idempotency-guard cases.
Run `python scripts/capture_didcomm_projector_reference.py <credentials-checkout>`
with Python 3.12, reference dependencies and the observed marty-rs 0.1.60 binding.
Five exact Git source blobs are checked before importing the unchanged reference.
The actual native offer builder is used; only delivery, issuer base URL and
transaction inputs are controlled. Credential strings and IDs are synthetic.

The corpus deliberately retains `pre_auth_code` and encoded offer strings: these
are complete service DTOs, not evidence that gateway redaction has passed.
Recovered cases are existing-snapshot inputs to projectors, not executed database
recovery. Idempotency checks execute the original source-hashed `If` nodes alone;
fallthrough proves neither admission nor successful issuance. Execute the complete
reference replay separately with
`python scripts/capture_didcomm_projector_reference.py <credentials-checkout> --check`.
This is explicit qualification evidence, not a default CI gate.
`tests/test_didcomm_projector_reference.py` uses only repository-local fixtures and
guards: it requires neither another checkout nor a native binding, and has no
skipped substitute for actual reference execution.

## Callers and governed differences

Credentials `services/issuance/infrastructure/api/routes.py:3172` automatically
pushes during HTTP response projection; `:5508` implements explicit delivery.
Both call `_didcomm_sign_and_deliver` at `:5116`.
`services/issuance/infrastructure/adapters/grpc_adapter.py:225` instead builds
OID4VCI offers for every wallet, without pushing, including DIDComm variants.
Its fresh/recovered paths call that projector at `:680` and `:426`.

The source contract already governs the intended difference:
`contracts/issuance-initiation.json` records legacy gRPC as `openid-offer-only`
and the native Rust target as `same-delivery-semantics-as-http`. Native gRPC push
must therefore be qualified as the intended change, not mislabeled identical
legacy behavior. Flow's `rust/services/flow/src/grpc_providers.rs:522` calls this
gRPC method independently of gateway HTTP routing. A direct HTTP cutover does
not migrate Flow. Both legacy adapters reject DIDComm initiation with an
idempotency key; this rejection remains captured, not normalized away.

## Canonical peer support follow-ups

An executed local marty-rs 0.1.60 probe used the synthetic X25519 multibase key
`z6LSd1FDxqS6PDoWwxco3fnM3DGEuXyse6pr7uRRYamJDqit` (recipient secret `[7; 32]`).
Full peer2 service JSON with `id`, `type: DIDCommMessaging`, and
`serviceEndpoint: https://wallet.example/inbox` passed resolve, endpoint extraction,
pack, real anoncrypt encryption/decryption, and unpack/thread binding. The native
`embedded_peer2_resolves_inline_service_and_encrypts_without_network` test covers
this same accepted representation and actual crypto path.

Outstanding existing canonical defects, not demonstrated native-only losses:

- **DIDCOMM-PEER-001:** standard `did:peer:0z...` fails because Core
  `ec307b6.../marty-didcomm/src/did_resolver.rs:527` prepends another `z`.
  Removing the input prefix resolves but leaves verification IDs outside the
  peer DID; it also supplies no delivery service. Fix and qualify canonical
  method-0 binding separately; do not advertise successful peer0 delivery.
- **DIDCOMM-PEER-002:** peer2 abbreviated service JSON
  `{"t":"dm","s":"https://wallet.example/inbox"}` resolves with zero services
  and an empty endpoint in the old binding. Core `did_resolver.rs:595` only parses
  full `ServiceEntry` and silently drops this representation. Canonical expansion
  and invalid-service behavior remain to implement/test, without a duplicate UI
  resolver. This old defect must not indefinitely block no-loss Rust selection.

Probe provenance: installed `marty-rs 0.1.60`, module `marty_rs._marty_rs`, Windows
native module SHA-256
`94b41c5125e580edb1809a101561c3bfa5c1fb0839e24a8596ffdf7bdc5fa44b`.
Local installed metadata and this digest are not immutable release attestation.

## Deletion boundary and next slice

Credentials `rust_integration.py:74` requires all seven DIDComm symbols at startup
(`main.py:342`). Decrypt (`:1229`) and unpack (`:894`) wrappers had no production
callers in the inspected Credentials/UI sources; the frozen service surface has
delivery, not an inbox. Preserve canonical Rust decrypt/unpack capabilities while
retiring unused Python wrappers/requirements after explicit caller/test review.
Prepared encryption remains reachable through both HTTP callers. The unprepared
`didcomm_encrypt_delivery` path appears test-only; transfer its controls before
removing it. Shared UI `services/common/did_resolution.py` needs its own caller
audit and must not be removed merely because issuance delivery moved.

After direct selection, the next consumer slice is full automatic HTTP initiation
admission/reservation/projector qualification, including mixed non-DIDComm wallets,
holder fallback and fresh/recovered behavior. Select only its allow-listed route;
do not replace the entire issuance service or all gRPC methods. Then qualify the
governed Flow/gRPC push target. Preserve anoncrypt and true authcrypt without
fallback. **DIDCOMM-KMS-001 remains explicitly deferred**; migrating custody from
Python memory to Rust memory is not KMS-only custody.

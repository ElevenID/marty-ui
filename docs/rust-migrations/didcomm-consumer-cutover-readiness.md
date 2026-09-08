# DIDComm Rust consumer cutover readiness

Status, 2026-09-08: reconciliation and qualification in progress. No DIDComm
consumer cutover or reachable Python deletion is established by this document.
Production is unchanged. This is a migration of observable behavior into the
existing native owner, not a second cryptographic implementation.

## Explicit scope

The user directed Rust migration before KMS correction. Credentials PR #273
merged the outstanding `DIDCOMM-KMS-001` note at
`501977d0759ccad42b3e55488e65151c3934ef39`, in
`docs/rust-migrations/didcomm-kms-outstanding.md`. KMS backend design, provisioning
and opaque key-agreement corrections are outside this slice. Both anoncrypt and
sender-authenticated authcrypt remain; failure must not select a weaker mode.
Retained native local-key compatibility is not KMS-only custody.

## One native delivery owner, multiple consumers

| Reachable Credentials Python path | Native owner | Required evidence |
| --- | --- | --- |
| `routes.py::didcomm_deliver` | `initiation_didcomm_http.rs` and `NativeInitiationDidcommDelivery` | Authenticated direct HTTP, trusted tenant, state, full receipt and failure responses |
| `routes.py::_issuance_response_from_transaction` calling `_didcomm_sign_and_deliver` | `initiation_response.rs::InitiationOfferProjector` | Fresh/recovered issuance, actual successful-delivery status, holder fallback, wallet URI mapping, failure and repeat behavior |
| Endpoint validation and encryption/transport helpers used by both paths | `initiation_didcomm.rs` plus canonical Core | Actual two-mode delivery, frozen preparation, TLS/network policy, side-effect ordering and retry fencing |
| `rust_integration.py` wrappers and startup capability requirements | Native configuration and linked Core capabilities | Remove Python startup requirements only with all remaining callers |

Native `main.rs` constructs one delivery instance and shares it with direct HTTP
and automatic offer projection. The same projector is supplied to the gRPC
platform. Repairs must remain in these shared owners.

## Qualified reconciliation and limits

Policy Unicode-length parity, trusted tenant checking, eight public prerequisite
error responses, real authcrypt roundtrip/no-fallback and embedded resolver
controls are qualified locally. The combined `4d8b5728b` tree passed 28 DIDComm
unit tests and five HTTP tests with strict scoped Clippy. Fixtures explicitly
identify unchanged Python source and controlled dependencies. They are not
independent-wallet or PostgreSQL acceptance.

The automatic response audit found that Python reports `issued` after successful
delivery while the original native projector reports the reservation's old
status. A narrow shared-projector repair is being qualified separately.
Seven actual Python observations also expose two differences that must not be
silently called equivalent: Python maps a failed HTTP transport receipt to an
endpoint URI, and multiple DIDComm wallet entries can repeat signing/transport.
Preserve native pending-failure URI and no-resend safeguards while reconciling
their public contract explicitly. Do not restore duplicate sends to match a
legacy observation.

Direct unsupported-state response specificity remains to be reconciled without
placing an eligibility rejection before native delivered replay or
projection-only recovery. Missing/foreign transaction responses must not require
an unscoped lookup. Peer method 0 and abbreviated peer service encoding remain
unqualified, distinct from the tested peer2 full service representation.

## Gates before Python retirement

1. Qualify direct and automatic delivery through the shared actual native owner,
   including whole response fields, true crypto, durable finalization, failure,
   concurrent ownership, projection-only recovery and stable no-resend replay.
2. Exercise actual gateway-to-native direct and initiation routes with a legacy
   trap. Preserve management-key injection, trusted tenant and error projection.
   `ISSUANCE_NATIVE_SERVICE_URL` alone does not switch the direct DIDComm route:
   its gateway ownership is still the `issuance` service.
3. Review issuance-wide routing and image/migration ownership. Compose profiles,
   the beta image plan and Kubernetes still select external Python issuance;
   do not switch the entire service based solely on DIDComm evidence.
4. Remove superseded Python delivery callers, helpers and startup capability
   requirements together only after those gates pass. Retain language-neutral
   reference evidence. Audit shared resolver wrappers separately; UI
   `services/common/did_resolution.py` still consumes backend resolution.
5. Land reviewed exact-head CI, qualify immutable artifacts, then include the
   result in the aggregate beta-only deployment and acceptance soak.

KMS deferral is not a reason to stop this consumer work. It also does not qualify
a release pin whose selected feature set removes required authcrypt behavior.

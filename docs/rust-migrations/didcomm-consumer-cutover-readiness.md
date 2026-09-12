# DIDComm Rust consumer cutover readiness

Status, 2026-09-12: reconciliation and qualification in progress. No DIDComm
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
status. Reviewed integration `29beef466` repairs that shared projector without
adding a second receipt flag or mutating the reservation: only pending/authorized
responses become issued after successful durable delivery. Existing issued,
revoked, expired, failed and signing statuses remain unchanged on delivered
replay. The selected author tree passed 47 initiation tests, nine gRPC tests,
17 HTTP/delivery integration tests and strict package Clippy. An actual native
delivery owner with controlled ports proves single-send multi-wallet/repeated
projection and failure non-promotion; this is not an actual PostgreSQL or wallet
acceptance test. Its regression first reproduced pending versus issued.
The combined `29beef466` tree subsequently passed all 372 issuance unit tests,
eight DIDComm/initiation HTTP and legacy-fence integration tests, and strict
package Clippy with all test targets. Only documentation changed during that run.
Seven actual Python observations also expose two differences that must not be
silently called equivalent: Python maps a failed HTTP transport receipt to an
endpoint URI, and multiple DIDComm wallet entries can repeat signing/transport.
Preserve native pending-failure URI and no-resend safeguards while reconciling
their public contract explicitly. Do not restore duplicate sends to match a
legacy observation.

Direct unsupported-state response specificity is repaired by reviewed source
`40b06fcc8` (integration `9b4a8b67a`). Five freshly executed unchanged Python
observations preserve issued/409 and signing, failed, expired, revoked/400 with
their exact public details. The native owner carries the closed status from its
existing post-dispatch eligibility check; delivered replay, projection recovery,
busy, unknown and holder-binding failures keep precedence. Qualification passed
375 issuance library tests, six direct HTTP tests, two initiation HTTP tests and
strict package Clippy. The reproducible capture verifies the original route blob.
Missing/foreign transaction responses must not require
an unscoped lookup. Peer method 0 and abbreviated peer service encoding remain
unqualified, distinct from the tested peer2 full service representation.

## Gates before Python retirement

### Operator TLS trust parity

The source-hashed executable capture in `scripts/capture_didcomm_tls_reference.py`
and `contracts/didcomm-tls-python-reference.json` records Python's per-delivery
trust loading. Missing/malformed CA files fail with the exact public 503 detail
after controlled signing/encryption, before any HTTP client is created. Python
has already saved issuer context once but has not finalized the credential.
Real SSL contexts accept multiple PEM certificates and observe same-path file
replacement while retaining certificate and hostname verification.

Native transport now retains the configured path, not cached certificate bytes.
Each actual attempt reloads the bundle; missing/malformed trust cannot abort
unrelated service startup or silently use default roots alone. The native
durable state intentionally differs from Python: a credential/envelope is staged
before transport, and a failed trust load must persist `transport_retryable`
before returning the captured 503. Recovery reuses that exact staged envelope
without reallocating or signing; a failed marker write retains the claim fence.
Delivered receipt replay does not reopen trust material or send again.

Operator CA input is restricted to regular files and at most 1 MiB. Metadata is
checked before and after opening; this rejects existing special files such as
FIFOs, but the byte bound is not a filesystem I/O deadline or a defense against
a malicious operator concurrently replacing deployment-controlled paths. The
configured path itself follows normal startup configuration precedence; file
contents are reloaded per attempt. No public request selects CA files.

Qualification includes isolated executable health with missing/malformed CA and
zero database connection, native/gateway two-mode missing-to-valid recovery,
and a separate real TLS transport test that replaces valid root A with B,
rejects A, accepts B, and then accepts both roots from a bundle. Directory,
empty, oversized and mixed malformed PEM inputs fail before connection. These
are controlled loopback peers, not independent wallets or KMS custody evidence.

Composition now has a configured local gate, not a new cryptographic kernel. Existing
`credential_postgres_contract.rs` exercises real repository/lifecycle durability
with literal credential/JWE strings. The test named `didcomm_delivery_atomicity`
uses an in-memory legacy repository to prove zero sends without durable claims;
it is not PostgreSQL atomicity evidence. HTTP contract tests use controlled
delivery ports, and crypto roundtrips are separately qualified.

`didcomm_native_composes_crypto_https_and_published_durability` passed nine
configured cases using the owned `PublishedDatabase` and actual published
migrations: four anoncrypt/authcrypt × direct/automatic successes, two wallet
HTTP-503 cases, two untrusted-TLS cases and one mismatched authcrypt sender key.
It composes the real native repository, lifecycle, envelope, endpoint validator
and HTTPS transport. Captured success and HTTP-503 envelopes decrypt through
canonical Core. Positive gates check complete public responses, protocol and
attachment fields, allocated/signed/persisted credential linkage, durable
delivery/audit metadata and equal whole-row JSON after both entrypoint replays.
HTTP-503 and TLS failures retain durable uncertainty with no repeat POST,
allocation or signing; a wrong sender key leaves all seeded state unchanged and
performs no allocation, signing or POST, including automatic retries.

Signing, issuer context and the local DID/status peers are explicitly controlled;
this is not an independent wallet, frozen Python composition, packaged-process
or gateway cutover proof. Automatic cases call the real projector with a controlled
reservation; they do not qualify fresh automatic initiation HTTP/admission replay.
The bounded Python wallet fixture reuses the existing
certificate helper without changing the worker fixture's GET/DELETE contract.
Its 38 real TLS/framing/deadline tests passed; the root combined wallet and CI
registration suite passed 204 tests. Rust startup now verifies canonical ownership
without passing Windows verbatim paths to OpenSSL; a real subprocess/TLS control
covers the startup failure found during composition. The nine-case gate and five
support controls passed together in 6.58 seconds after strengthening review gaps.
The combined state-parity/composition tree then passed all 377 issuance unit
tests, six direct HTTP tests, two initiation HTTP tests and strict package Clippy
with all test targets. All 19 workspace packages passed the formatting check.
The subsequent recovery gate expands native composition to thirteen cases.
For each encryption mode, a controlled barrier holds the real PostgreSQL claim
while a second request observes signing/400 with no extra side effects. A scoped
event-insert fault also proves transported-state recovery by the automatic
projector: one event after repair, unchanged message/credential identity and no
second POST, allocation or signing. The fault objects are removed and their
absence checked. This does not assert that every concurrency interleaving was
exercised; the stale-read busy/409 path remains separate unit evidence.

## Direct gateway candidate qualification

`didcomm_gateway_candidate_preserves_real_delivery_without_legacy_fallback`
executes eleven cases through the real gateway router/proxy and HTTP upstream
into the same native delivery graph, published-schema PostgreSQL and HTTPS wallet.
Only the exact direct POST owner is changed in candidate route tables; all other
route fields and routes remain identical. An actual legacy HTTP trap is exercised
once as a baseline, and candidate traffic never reaches it, including when the
native listener is stopped. That unreachable control qualifies routing and
server-error status, not exact transport-error body parity.

The gate preserves distinct caller and management keys, trusted tenant injection,
forged-header removal, complete authorization and native-error envelopes, five
frozen Python eligibility errors, private-selector rejection, both crypto modes,
durable failures and recovery/replay. Denied requests reach neither upstream.
Gateway identities, signer and DID/status peers remain controlled; the gateway
router runs in-process, not as a packaged ingress binary. Automatic projection
is exercised for recovery/replay, not fresh initiation HTTP or Flow admission.

The combined configured run passed eight test functions (thirteen native cases,
eleven gateway cases and six support controls) in 36.35 seconds. Strict issuance
Clippy with all test targets passed, all nineteen workspace packages passed
formatting, and the CI/preflight registration suite passed 166 tests. The new
gateway gate is mandatory in the full published-contract runner. These are local
results, not exact-head hosted qualification or deployed consumer selection.

Direct cutover still needs native startup/configuration parity. Beta native
issuance lacks the legacy resolver settings; authcrypt and conformance overlays
currently mount policy and CA only into legacy issuance. The native transport
also loads its CA at startup rather than per delivery, changing invalid-file and
rotation behavior. Correct these without broad key mounts, weaker defaults or a
KMS redesign. Production route ownership and reachable Python remain unchanged.

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

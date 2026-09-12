# DIDComm Rust consumer cutover readiness

Status, 2026-09-12: direct-route native source selection is locally qualified;
automatic initiation and Flow consumer migration remain in progress. No deployed
DIDComm cutover or reachable Python deletion is established by this document.
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

## Latest direct-route checkpoint

Reviewed source `ff7d3462f`, integrated as `d4a8cae53`, selects only
`POST /v1/issuance/didcomm/deliver` through the existing native allow-list.
Both gateway route tables now use that embedded selection without test rewrites;
the negative legacy control changes exactly one owner. Initiation, Flow/gRPC,
sibling paths and other methods remain on their existing routes. Native coverage
is 64 HTTP operations with 67 remaining; the frozen total of 131 is unchanged.

The selected-route tree passed 108 gateway tests, all 379 issuance library tests,
six direct HTTP and two initiation HTTP tests, nine configured target tests
(fifteen native/thirteen gateway cases plus transport/support controls), actual
bad-CA executable startup, strict gateway/issuance Clippy and nineteen-package
formatting. The final configured run took 43.40 seconds; all eight exact-owned
containers from the two root runs were independently verified absent. An initial
full-suite failure caught a missing typed coverage selector; it was corrected
and the complete issuance and composed gates rerun successfully. Eighty-two
coverage/CI guards also passed. These are local results, not hosted CI or release
acceptance.

Reviewed source `417fbd974`, integrated as `fca0d17db`, pairs explicit beta
authcrypt selection and validates the actual final Compose model before image
mutations and again before maintenance. The integrated selector/configuration
suite passed 307 tests. No policy contents were read by that gate, and no
deployment occurred. Current PR #814 remains draft and its older exact-head
runtime run is allowed to finish before pushing this batch.

The clean combined integration `3afeb32af` subsequently passed all 3,135 root and
retained service Python tests, with three explicit skips, in 205.47 seconds.
Its actual read-only Compose gate also passed independently. This does not
replace the upcoming exact-head hosted run or aggregate beta acceptance.

## Fresh automatic HTTP checkpoint

Reviewed source `f14da5255`, integrated as `0d50538d2`, adds actual native HTTP
admission through `InitiationService`, PostgreSQL reservation and the same
delivery owner/Core/HTTPS graph. Three fresh successes cover anoncrypt, authcrypt
and mixed ordinary-wallet offers. A keyed-push rejection precedes seed generation,
reservation, signing, allocation and transport. Complete service DTOs, default
expiry, durable binding and subsequent projector/direct replay are asserted.
The final author run passed ten configured target tests in 47.84 seconds, retaining
all fifteen native and thirteen gateway cases, and strict Clippy in 6.11 seconds.
All eight exact-owned Docker objects across both author runs were verified absent.
The new test is registered as mandatory in the published-contract CI runner.

Clock, labeled synthetic seed values, signer and control-plane ports are controlled.
This is not secure random generation, packaged gateway, independent-wallet or
Flow qualification. Unkeyed HTTP initiation is not represented as idempotent
replay: subsequent replay explicitly uses the committed reservation. Holder
fallback and genuine existing-reservation admission recovery remain next gates.

Rust offer-TTL repair `2579307e2` uses the existing shared Python-compatible
integer configuration type and one configured initiation owner. The eighteen-case
unchanged Python capture covers default/custom values, zero/negative values,
integer spelling, invalid input and expiry overflow. Beta binding `ef027ff22`
forwards the exact legacy expression; actual read-only Compose checks and 41
configuration/selector/reference tests passed. See the
[TTL evidence and limits](initiation-offer-ttl-parity.md). Neither change selects
automatic routing or changes Core/KMS.

Root requalification of combined `0d50538d2` passed 383 issuance library tests,
three initiation HTTP tests, six direct HTTP tests and ten explicitly configured
composition tests (47.55 seconds). Strict issuance library/test Clippy passed
in 23.66 seconds; all nineteen workspace packages passed formatting. All six
exact-owned test containers were independently verified absent. The mandatory
registration/configuration/reference regression suite passed 120 tests. These
results include the integrated TTL repair, unlike the earlier 3,135-test Python
checkpoint, and still do not claim hosted CI or deployment acceptance.

Reviewed source `cc8e0406e`, integrated as `7e349c652`, expands the same fresh
HTTP gate to nine unkeyed cases: explicit holder, subject fallback, missing holder
and wallet refusal in both modes, plus mixed ordinary-wallet success. Explicit
and mixed-wallet keyed requests are rejected before reservation/delivery. Missing
holder leaves no credential, delivery or event rows. A refused HTTPS POST leaves
durable unknown delivery state; direct retry and reloaded projector replay do not
send, allocate or sign again. The first HTTP response remains pending, while a
reloaded issued transaction projects issued status with a pending delivery URI.
That observed distinction is asserted, not hidden by rewriting the reservation;
it is not a claim that Python's transport-failure URI behavior is identical.
The focused fresh gate passed in 5.82 seconds and the combined ten configured
target tests in 47.61 seconds, with strict Clippy in 6.44 seconds. All eight
exact-owned containers across those runs were verified absent. Genuine keyed
admission recovery and the initiation gateway/Flow consumers remain separate.

Reviewed source `214531581` (integration `fb6d266c8`) now executes ordinary-wallet
keyed HTTP creation, exact recovery and changed-request conflict through the real
PostgreSQL lookup. It asserts the frozen request/key hashes, complete response,
unchanged durable row and zero additional template/clock/seed/issuer work. Recovery
precedes changed negative/oversized TTL configuration. The exact new gate passed
in 3.38 seconds; the author's eleven configured target tests passed in 50.67 seconds
and strict Clippy in 27.45 seconds. Two earlier combined invocations failed existing
wallet startup because Python/OpenSSL fixture configuration was incomplete; the
correct environment passed without weakening source assertions. All 26 exact-owned
containers across those runs were verified absent. This ordinary-wallet gate
deliberately panics if DIDComm delivery is requested: historical keyed DIDComm
delivery/recovery remains to qualify with the actual shared delivery graph.

## Fresh initiation gateway candidate

Reviewed source `2c4d4ff7e` (integration `c5a390593`) runs the same nine fresh
scenarios through actual `POST /v1/issuance` gateway admission, its preserved
`/v1/issuance/initiate` rewrite, real upstream HTTP and the shared native
PostgreSQL/Core/HTTPS graph. Only that route's candidate owner differs from the
embedded legacy selection. Both route tables retain every other route/policy.
Identity and template/signing-identity preflight ports are controlled; the
issuance upstream is never replaced with a canned response.

Each scenario exercises a real legacy trap baseline and checks denials before
even ancillary preflights, exact public JSON media type and eight-field response,
and exactly one template/signing-identity preflight per accepted attempt. The
native nine-field DTO is independently checked; only its top-level internal
`pre_auth_code` is removed, not the protocol-required grant in encoded offers.
A genuine native 401 caused by a deliberately wrong injected management key
preserves the complete MIP service-error envelope with zero issuance effects.
Stopping the native listener produces a server error and no legacy fallback.

The exact gateway gate passed in 24.44 seconds; all twelve configured DIDComm
target tests passed in 73.99 seconds, with strict Clippy in 6.53 seconds and all
nineteen-package formatting checks. All ten exact-owned containers across both
runs were independently verified absent. Keyed rejection and direct/projector
repetition in the shared fixture still call the native service, not the gateway:
this gate does not claim gateway idempotency forwarding or HTTP replay semantics.
It is not packaged-ingress, independent-wallet or deployed acceptance. Automatic
initiation selection remains unchanged pending the remaining historical recovery
and consumer gates; production and KMS are untouched.

The root's combined integration `c5a390593` subsequently passed all thirteen
configured target tests in 77.22 seconds, including ordinary keyed recovery and
the new gateway gate together. Strict target Clippy passed in 6.76 seconds;
all ten exact-owned containers were independently verified absent. Mandatory
CI-registration guards passed 79 tests. The older hosted head `184509745` also
completed its Rust Service Tests job successfully in run `34701797735`; that
run still failed the two separately repaired security/release-contract jobs.
This is not exact-head hosted acceptance of the newer local integration.

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

Reviewed configuration source `671cd18ba` (integration `db9fcf058`) now forwards
the legacy resolver/default-private-IP settings to beta native issuance and adds
explicit native-only policy/CA overlays. Full Compose rendering and synthetic
binding checks pass, including rejection of legacy authcrypt without native
policy pairing. The reviewed deployment runner now enforces that guard as noted
above; an optional overlay alone would not prevent a downgrade. See the
[configuration boundary](didcomm-native-configuration.md).

Reviewed TLS source `d9740b515` (integration `af6e54d44`) closes CA startup/reload
parity as described above: fifteen native and thirteen gateway composition cases,
actual trust rotation/bundle controls, six HTTP tests, real executable health
with invalid trust, all 378 library tests and strict Clippy passed. No KMS change
is included. The subsequently qualified single-route selection is recorded above;
this document does not establish a merged or deployed cutover.

The [retirement audit](didcomm-retirement-audit.md) and source `25f14fb3a`
(integration `627d977d3`) preserve eight full HTTP/gRPC response pairs and four
isolated idempotency guards. Exact unchanged-source capture matched; fifteen
repository-only tests passed separately. Python automatic HTTP is a delivery
caller; old gRPC is offer-only, with an explicitly governed native push target.
Neither snapshot projection nor isolated rejection is full admission evidence.
Existing peer0/abbreviated-peer2 defects are documented canonical follow-ups,
not demonstrated migration regressions; working full peer2 has old/new evidence.

1. Qualify explicitly historical keyed DIDComm admission snapshots with actual
   delivery/recovery without weakening fresh DIDComm rejection. Ordinary-wallet
   keyed success/recovery/conflict is qualified above; direct/projector repetition
   is not a substitute for executing DIDComm admission recovery. Keep actual
   persisted Issued+Delivered state distinct from a stale in-memory Failed snapshot.
2. Retain the direct gateway gate and qualify the initiation route with a legacy
   trap before selecting it. Preserve management-key injection, trusted tenant and
   error projection. Qualify Flow/gRPC separately against its governed push target.
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

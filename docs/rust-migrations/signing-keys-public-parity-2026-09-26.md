# Signing Keys public-route parity audit — 2026-09-26

The Gateway's `contracts/gateway-routes.json` declares 37 method/path pairs
under `/v1/signing-keys`. The beta Compose stack runs the Rust
`marty-signing-keys` binary. Source inspection of its Axum router found 24
declared pairs without a matching public method/route. This is a static audit,
not a runtime acceptance result. Keep the Gateway declarations; do not treat
their presence or green Gateway tests as proof that the upstream implements
them. Do not retire any remaining Python consumer or claim lossless migration
until the pairs below have language-neutral behavior fixtures, Rust handlers,
and public-through-Gateway tests.

| Group | Missing declared methods and paths |
| --- | --- |
| Key and holder lifecycle | `POST /v1/signing-keys`; `GET`, `PATCH`, `DELETE /v1/signing-keys/{key_id}`; `GET`, `POST /v1/signing-keys/holder-keys` |
| Service certificate and signing | `GET`, `PUT /v1/signing-keys/services/{service_id}/certificate`; `POST /v1/signing-keys/services/{service_id}/certificate-csr`; `POST /v1/signing-keys/services/{service_id}/sign`; `GET /v1/signing-keys/services/{service_id}/verify-current`; `POST /v1/signing-keys/services/{service_id}/rotate` |
| Service publication and observability | `GET /v1/signing-keys/services/{service_id}/audit-log`; `GET /v1/signing-keys/services/{service_id}/mdoc-x5c`; `POST /v1/signing-keys/services/{service_id}/publish-did-vm`; `POST /v1/signing-keys/services/{service_id}/publish-jwks`; `POST /v1/signing-keys/services/vdsnc/register` |
| Discovery, policy, and DID | `GET /v1/signing-keys/compliance/keys-summary`; `GET /v1/signing-keys/config/certificate-expiry-alerts`; `POST /v1/signing-keys/config/resolve`; `GET /v1/signing-keys/did-document`; `GET /v1/signing-keys/jwks`; `PUT /v1/signing-keys/issuer-identities/didcomm-key-agreement`; `POST /v1/signing-keys/issuer-identities/resolve` |

The pre-Rust Python service CSR endpoint was also a real declared public
route, although its KMS branch returned structured 501
`kms_csr_generation_unavailable`; it never emitted a signed KMS CSR. The new
issuer-scoped Rust CSR operation is separate and more capable, but does not
erase that public-route/error contract. The managed-service UI now directs
operators to the issuer-scoped operation. Dedicated-service CSR behavior and
the other missing adapters still require review and implementation.

Port in groups, using the last Python implementation and live consumer
requests as behavioral evidence. Keep all key references and signing secrets
inside Rust service/KMS boundaries. For each group, add a test that traverses
the authenticated Gateway route and asserts the corresponding Rust handler,
not merely Gateway route-table membership. Re-run the audit after each merge.

The service certificate/CSR group is frozen first in
`contracts/signing-service-certificate-behavior.json`, including its legacy
success and error shapes and the stricter managed-service custody rule.

## Local integration progress (not merged or beta-accepted)

This review branch has Rust `GET`/`PUT` service-certificate and `POST`
service-CSR handlers. The managed shared service is rejected in favor of the
issuer identity route. Registered-service certificate uploads are matched to
the current KMS public key, and CSRs are signed by that KMS key and verified
before release. The console asks for the country and organization explicitly.
These three pairs are no longer absent from the local router. An opt-in
live Rust-route test for registered-service CSR passed against isolated Redis
and OpenBao on 2026-09-26; the disposable containers and their test key were
removed afterward. Authenticated through-Gateway tests and live certificate
upload/read tests are still required before cutover acceptance. A fourth
local adapter now restores `GET /config/certificate-expiry-alerts` using the
existing Rust alert kernel and the stored service-certificate override, with
its response frozen in `contracts/signing-certificate-alerts-behavior.json`.
The local `GET /jwks` adapter now exposes only public verification fields from
the tenant's stored JWKS and strips legacy custody coordinates. Its behavior
is frozen in `contracts/signing-public-jwks-behavior.json`. The neighboring
`GET /did-document` adapter now preserves public DID relationships and
service entries while removing custody fields from stored data; its fallback
uses the configured public authority and the trusted organization scope.
`contracts/signing-public-did-document-behavior.json` freezes that behavior.
The `POST /issuer-identities/resolve` adapter now uses the same exact active
profile tuple and internal DID resolver as signing, then returns only the
public identity projection and a custody-free JWK. Its request and response
are frozen in `contracts/signing-public-issuer-resolution-behavior.json`.
The `GET /services/{service_id}/mdoc-x5c` adapter now selects the same stored
certificate override as the service-certificate read path, checks it against
the current KMS public key, and returns only the public X.509 chain and COSE
header hints. Its intentional omission of the legacy public key-reference
field is recorded in `contracts/signing-mdoc-x5c-behavior.json`. Its isolated
Redis/mock-KMS route test passed for a matching certificate and rejected a
cross-tenant read; this is not a through-Gateway or beta acceptance test.
The `GET /services/{service_id}/verify-current` adapter restores the legacy
check names while deriving supported algorithms from the current KMS public
key and registered service policy, including ES384, ES512, PS256, and EdDSA.
Its response contains no public key or custody coordinates; the behavior is
frozen in `contracts/signing-service-verify-current-behavior.json`.
The `POST /services/{service_id}/publish-jwks` adapter fetches the current
KMS public key, requires any attached certificate to match it, upserts the
tenant JWKS, and updates service discovery metadata. It rejects caller key
selection and returns only the public JWK projection. The contract is
`contracts/signing-service-publish-jwks-behavior.json`. An isolated
Redis/mock-KMS test passed for publication, public readback, and discovery
metadata; this is not through-Gateway or beta acceptance.
The paired `POST /services/{service_id}/publish-did-vm` adapter uses the same
current KMS key and certificate binding check, then publishes a public
assertion method to the tenant DID document and records discovery only after
the document is stored. Its request permits `did_id`, `org_slug`, and
`fragment`, but no caller KMS locator; the behavior is frozen in
`contracts/signing-service-publish-did-vm-behavior.json`. An isolated
Redis/mock-KMS route test passed for publish/readback, assertion relationship,
certificate chain, and discovery metadata; this is not a through-Gateway or
beta acceptance result.
The `GET` and `POST /holder-keys` adapters preserve the tenant's legacy Redis
keyspace, default purpose, record ID, replacement, and exact device filter.
They accept and return only public verification fields; legacy private JWK
parameters are redacted on read, and new private/custody fields are rejected
before storage. `contracts/signing-holder-keys-behavior.json` freezes the
behavior, and a disposable-Redis route test passed. The wallet-supplied public
key does not create or import a signing key in KMS. This is not a
through-Gateway or beta acceptance result.
The `GET /services/{service_id}/audit-log` and `GET /compliance/keys-summary`
adapters retain the released Python service's structured 501 MIP errors. The
audit route still distinguishes a missing tenant service (404) from a
registered service whose event store does not exist (501), and both routes
carry an opaque message ID and the MIP version header. Their behavior is
frozen in `contracts/signing-observability-unavailable-behavior.json` and
verified against isolated Redis. These adapters do not implement audit-event
storage or compliance metrics; no synthetic events or totals are returned.
The `PUT /issuer-identities/didcomm-key-agreement` adapter now requires one
active tenant-scoped issuer identity, an exact public-only X25519 JWK, and a
local managed `did:web` issuer before publishing the fixed
`didcomm-authcrypt-x25519` method into `keyAgreement`. Its released public
response and rejection rules are frozen in
`contracts/signing-issuer-didcomm-key-agreement-behavior.json`. This is only
publication of caller-supplied public material; it does not create, import,
read, or hold a private key. Opaque KMS-backed DIDComm key agreement remains
the separately tracked `DIDCOMM-KMS-001` follow-up, not a claim made by this
adapter. An isolated-Redis Rust-route test passed for publication, private-JWK
rejection, tenant isolation, absent and ambiguous profiles, and public-only
stored output. Authenticated through-Gateway acceptance remains before cutover.
The `POST /services/{service_id}/sign` adapter now delegates to the same Rust
KMS signing and purpose-isolation kernel as the internal service route. It
retains the released payload selection and signature response shape, frozen in
`contracts/signing-public-service-sign-behavior.json` and the existing
`contracts/gateway-signing-authorization-behavior.json`. The reviewer-required
security tightening on this public route rejects a caller-selected KMS key
reference unless it is the tenant service's default, a registered alias,
purpose-bound in its registry, or bound by an active tenant issuer profile;
arbitrary unregistered KMS names are not a public capability. The internal
signing kernel's existing compatibility behavior is unchanged. No
private key material enters this route. An isolated Redis/OpenBao route test
passed for a real KMS-held signature and the unregistered-key, tenant,
private-field, and empty-payload denials. Authenticated through-Gateway
acceptance is still required before cutover.
Thus 7 declared pairs remain without local public handlers. These new
adapters still need authenticated through-Gateway runtime tests. The
24-pair table above remains the protected-main audit baseline.

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

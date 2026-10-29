# Issuance regression ownership

The three retired Credentials contract copies are historical migration
references, not inputs to this runtime. Maintained behavior belongs here:

| Retired Credentials reference | Current executable owner |
| --- | --- |
| `issuance-canvas-lti-foundation.json` | `contracts/issuance-canvas-lti-foundation.json` and issuance's Canvas LTI behavior suites |
| `physical-passport-provider-reference.json` | `passport_bureau.rs`, `passport_signer.rs`, `passport_provider_ingress.rs` tests and `contracts/issuance-physical-passport-native.json` |
| `physical-passport-python-route-reference.json` | `passport_http.rs`, `passport_postgres_contract.rs` and the native passport contract |

The native LTI contract preserves all 16 forbidden private-key fields from the
retired copy. `private_key_aliases_never_reach_signing_or_public_jwks` exercises
active-key resolution, signing refusal before provider calls, and filtering of
retiring assertion methods for populated, empty and null members. The shared
metadata policy keeps its separate null semantics; no KMS-provider policy is
changed here. Existing session-cache and non-JSON exchange requirements remain.

Passport coverage retains all nine operations, strict request validation,
sanitized projections, bureau status mapping and auth/payload/poll/batch behavior.
Named existing checks include `frozen_nine_routes_are_registered_without_enabling_database_or_providers`,
`application_validation_matches_frozen_python_responses`,
`quality_validation_matches_frozen_python_responses`,
`bureau_http_preserves_auth_payload_status_and_private_error_boundary`,
`batch_submission_preserves_python_envelope_and_input_order`, and
`passport_jobs_survive_restart_without_cross_tenant_reads`. The PostgreSQL suite
exercises encrypted artifacts, tenant rejection, webhook-to-job effects, restart,
quality/activation and scrubbing; it requires its disposable database.

Historical self-signed/external signer modes, local artifact keys and absent
route authorization are not supported compatibility requirements. Native tests
reject those modes and require managed issuer/DSC/CSCA profiles, KMS artifacts
and tenant principals. Keep live provider integration, custody, deployment/drain,
unreadable legacy-artifact recovery and physical-booklet qualification with their
owners; deleting reference JSON does not establish any of those capabilities.
Existing contract source hashes and upstream paths describe immutable migration
provenance, not a dependency on current Credentials files. No code/test imports
those three retired files across repositories.

## Retired activation receipts

The one-time DIDComm and retention image checkers, their historical-only tests,
and the `release_gate` receipt in `didcomm-native-consumer-ownership.json` are
retired. They validated Credentials 0.1.78 at commit
`efd5da1e2d41419ce93721f98d314c7b911e6b5e`, before Python issuance retirement;
that image is absent from the current stack lock. Their implementations and
receipt remain recoverable in UI commit `5499531d5630f09d6ab7f44a20d6e827ce9a6c81`.

The DIDComm contract still checks selected native owners, readiness and no
cryptographic mode downgrade through `test_didcomm_native_consumer_ownership.py`.
Current release validation belongs to the stack lock, release manifests and
existing release checks, rather than an exact old Python image. Native retention
must retain tenant-owned issuance events and qualified schema migrations; the
old image receipt did not prove current runtime behavior. DIDCOMM-KMS-001 and
live callback/provider qualification remain open with their existing owners.

## Per-offer lifetime shortening

The authorized organization application issue request accepts an optional JSON
`offer_ttl_seconds` unsigned integer. Omission keeps the configured issuance default.
The issuer accepts at least 60 seconds and at most that configured default, calculates
expiry from its own clock, and rejects invalid or overflowing values. This option
cannot extend an offer, change process configuration, or grant issue authority.

Applicant keeps the chosen lifetime with the issuance attempt. The authenticated
application event, Flow offer semantics, and issuer idempotency request all bind the
value; a retry cannot silently change an existing offer's lifetime. The optional gRPC
field is additive. Applicant, Flow, and issuer must all support this path before a
short-lifetime test can qualify; an older server retaining the default is a test
failure, never evidence of expiry. Natural-expiry tests wait for the actual server
410 and cached-code denial, then create a fresh owned recovery offer.

Custom lifetimes are admitted before a new applicant attempt is persisted or its
Flow event is sent. Applicant reuses its authenticated native issuer client for
`/internal/compat/issuance/offer-lifetime/validate`. This internal route has the
same initiation management authority and uses the same configured expiry kernel
and issuer clock without creating a transaction, offer or signing operation.
Applicant requires the exact tenant/lifetime echo; invalid, malformed or
unavailable validation leaves the application unchanged so a corrected request can
succeed. Already validated reservations retain their exact lifetime on retry and
are not re-admitted against a later default. Requests omitting the option retain
the original behavior and require no new validation dependency.

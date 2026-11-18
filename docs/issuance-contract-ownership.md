# Issuance regression ownership

The three retired Credentials contract copies are historical migration
references, not inputs to this runtime. Maintained behavior belongs here:

| Retired Credentials reference | Current executable owner |
| --- | --- |
| `issuance-canvas-lti-foundation.json` | Historical provider migration evidence; no current platform LTI runtime. Provider protocol ownership belongs to [canvas-integration](https://github.com/ElevenID/canvas-integration). |
| `physical-passport-provider-reference.json` | `passport_bureau.rs`, `passport_signer.rs`, `passport_provider_ingress.rs` tests and `contracts/issuance-physical-passport-native.json` |
| `physical-passport-python-route-reference.json` | `passport_http.rs`, `passport_postgres_contract.rs` and the native passport contract |

## Provider retirement references

The [external connector boundary](architecture/external-connector-boundary.md)
supersedes the earlier UI-owned Canvas/LTI migration plan. Provider protocol,
credentials, callbacks and storage belong to the connector; the public Common
Gateway is its only platform interface. Core retains canonical identity,
ownership, evidence, approval and signing. Old parity observations do not
authorize restoring removed provider APIs or workers.

| Retained reference | Current purpose |
| --- | --- |
| `issuance-canvas-mirror.json` | `tests/test_base_native_issuance_compose.py` checks that all six historical provider routes are absent. |
| `issuance-canvas-operations.json` | Native `executable_smoke.rs` rejects retired CLI entrypoints before authority or configuration reads. |
| `issuance-canvas-lti-foundation.json`, `issuance-canvas-oauth-lifecycle.json`, `issuance-canvas-management.json` | Frozen migration observations and cross-references, not executable platform protocol owners. |
| `issuance-canvas-sync-worker.json`, `issuance-canvas-worker-process-signals.json` | Historical worker behavior/provenance; no supported platform worker. |
| `fixtures/canvas_review_recovery_claim.py` | Historical schema source named in `issuance-runtime-surface.json`; not a migration to apply to the current baseline. |

These observations remain unchanged. Some have no direct filename consumer;
that alone does not establish that provenance or dynamic inventory references
are disposable. The unreferenced test-child CA override
`fixtures/canvas_worker_test_trust.py` is retired; its last source remains in
[the pre-cleanup tree](https://github.com/ElevenID/marty-ui/blob/958615920f7b9d10829e175f1e275cf2ea579e22/contracts/fixtures/canvas_worker_test_trust.py).
It has no current transport consumer and is not a deployment trust mechanism.

Keep negative route/authority tests, byte-pinned codec oracles and generic
credential safeguards. Do not relabel old provider behavior as a current
capability or regenerate frozen observations from the new implementation.

## Retained native issuance owners

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

# Canvas gateway coverage audit — 2026-09-08

This is a coverage inventory, not a smaller replacement acceptance contract.
Corpus names, request counts, route selections and exact differential replays
are different measures. Production gateway ownership is unchanged. No gateway
route cutover, Python deletion or deployment is established by this document.

## Evidence boundary

The tested `574cb4895` candidate controls (integrated at `4d8b5728b`) live in
[canvas_operations_gateway_replay.rs](../../rust/services/issuance/tests/support/canvas_operations_gateway_replay.rs).
They compose the actual gateway router/proxy and bounded HTTP client with the
actual issuance executable and owned PostgreSQL. Identity and membership ports
are controlled; this is not execution of the gateway binary or its production
identity dependencies. The registered gate is
`operations_gateway_candidate_preserves_trusted_actor_and_frozen_routes`.

Both real runtime and proxy route tables are used. Candidate construction changes
only the eight operation service selections; methods, paths, authentication and
other policy fields must remain identical. The published-table control makes
eight requests to a separately served legacy trap, with zero native effects.
The candidate gate counts 42 native requests and zero legacy requests: one
against an actual rollout-disabled process, 38 enabled requests, and
three additional tenant controls. Four additional public auth/tenant denials
make no upstream call. This does not mean 42 frozen cases. The seven-entry
`NON_MANUAL_CASES` list supplies
one request for each nonmanual route, not an exhaustive replay inventory.

The new registered
`operations_gateway_candidate_preserves_review_lifecycle` helper in
[canvas_gateway_lifecycle_replay.rs](../../rust/services/issuance/tests/support/canvas_gateway_lifecycle_replay.rs)
has independent source-review clearance and passed a configured owned-PostgreSQL
execution in 9.83 seconds. The existing gateway candidate also passed in 5.35
seconds. Hosted and integrated-head qualification remain separate requirements.
The lifecycle wrapper uses the same status-provider fixture owner as the direct
actual-main gate, including its application/delivery seed and corrected review
migration; bare recovery-schema preparation alone does not seed these records.
It reuses the actual-process owner in
[canvas_status_runtime_contract.rs](../../rust/services/issuance/tests/support/canvas_status_runtime_contract.rs),
not a copied lifecycle service graph. It requires ten requests, nine native
forwards and zero legacy forwards. Its legacy endpoint is a distinct owned,
unserved reservation, not another executed legacy-trap test.

## Base operations: 46 names, 40 represented, six remaining

The authority is [canvas-operations-oracle.json](../../contracts/canvas-operations-oracle.json)
with [its scenarios](../../contracts/canvas-operations-scenarios.json).
The following **40 distinct corpus names are represented by source-derived
checks**, not 40 exact unadapted replays. The oversized-note expansion passed
configured PostgreSQL qualification in 7.84 seconds, retaining the previous
41 native requests and eight legacy-route controls. Thirteen pure controls and
strict scoped Clippy passed; the shared gateway lifecycle regression passed in
5.67 seconds. All four owned containers were verified absent after cleanup.

| Coverage form | Corpus names | Boundary |
| --- | --- | --- |
| Seven positive response/job-state comparisons | `jobs_list`, `candidates_list`, `reviews_list`, `job_get`, `retry_dead_letter`, `resolve_dead_letter`, `enqueue` | Frozen response fields and selected durable snapshots; validated timestamp/generated-ID substitutions. Gateway supplies trusted authentication and tenant query. |
| Trusted dismissal and repeat conflict | `review_dismiss`, `review_dismiss_again` | Session/API identities deliberately change expected actor fields and the second review ID. Duplicate responses use an explicit public MIP projection. Raw unrelated rows and resolution audit are checked. |
| Foreign/missing object hiding | `job_foreign`, `job_missing`, `review_foreign` | Authorized foreign tenant query reaches native 404 rather than an outer 403. A synthetic missing-review counterpart reuses `review_foreign`; it is not a fifteenth frozen name. |
| Public validation errors | `jobs_invalid_status`, `review_invalid_action` | Explicit public 422 envelopes, not unchanged direct Python error bodies. |
| Oversized manual-review note | `review_note_limit` | Shared unchanged body recipe sends all 2001 note characters. Complete frozen Pydantic detail checked before explicit public MIP projection; raw state unchanged, one native forward. Unsupported media recipes fail explicitly before dispatch. |
| Filtering and unmatched bindings | `jobs_filtered`, `jobs_unmatched_binding`, `candidates_filtered`, `candidates_unmatched_binding`, `reviews_filtered`, `reviews_unmatched_binding` | Exact frozen DTOs before mutations; full raw state unchanged and one native forward per request. |
| Additional list validation | `jobs_zero_limit`, `jobs_excess_limit`, `candidates_invalid_status`, `candidates_zero_limit`, `candidates_excess_limit`, `reviews_invalid_status`, `reviews_zero_limit`, `reviews_excess_limit` | Frozen status strings/complete bound arrays checked before explicit public MIP projection; raw state unchanged. |
| Rollout, foreign tenant and repeated job transitions | `retry_rollout_closed`, `retry_foreign`, `retry_again`, `resolve_queued`, `resolve_again`, `enqueue_foreign` | Real disabled startup and frozen transition ordering; explicit public MIP errors and exact unchanged raw state. Foreign cases use an authenticated foreign principal, not untrusted tenant headers. |
| Duplicate enqueue | `enqueue_duplicate` | Frozen existing-job response and snapshot; only the matched target's two nondecreasing timestamps and request-source metadata may refresh. All jobs and unrelated raw rows remain exact. Mutation controls reject extra effects. |
| Public authentication/tenant adaptations | `missing_management_key`, `wrong_management_key`, `missing_tenant`, `foreign_query` | Seven controls: missing/invalid public identity yields exact 401 MIP; omitted client tenant uses session/API tenant for two frozen successful reads; an authenticated org-less identity reaches native 400; exact foreign query yields session/API-specific pre-proxy 403. Direct-service frozen 401/400/404 obligations remain distinct and unchanged. |

Six earlier auth/RBAC denials also check zero upstream calls and unchanged raw
state. Neither they nor the seven new controls are unchanged direct-service
replays. The remaining **six base names** are:

| Required family | Names still outside the represented base-name set |
| --- | --- |
| Manual review, effects and recovery (6) | `review_suspend`, `review_revoke`, `review_failed`, `review_recovered_failure`, `review_recovered_success`, `review_concurrent` |

New lifecycle outcomes do not silently mark the six base manual-review names
as complete: those scenarios have their own setup, ordering, effects and recovery
observations. The corrected recovery corpus
[canvas-operations-recovery-oracle.json](../../contracts/canvas-operations-recovery-oracle.json)
also has 46 names. It is not 46 additional gateway tests, and the recorded legacy
recovery defect must not replace the corrected required behavior. Preserve the
official migration and corrected recovery authority described in
[canvas-review-resolution.md](canvas-review-resolution.md).

## Lifecycle: 17 full cases, four outcome projections

[canvas-review-lifecycle-oracle.json](../../contracts/canvas-review-lifecycle-oracle.json)
contains 17 observations. The new gateway helper adapts four outcome projections:
`suspend_delivered`, `revoke_delivered`, `mirror_failure`, `publication_failure`.
It retains the real publisher/mirror requests, claim span, credential/review
projections, trusted actor persistence and duplicate guards of the shared
actual-main fixture. The configured local gateway execution passed; this does
not establish the thirteen remaining full cases or qualify a production cutover.

Its held-publication competing 409 is analogous to
`concurrent_at_publication`; it does **not** replay that entire frozen scenario.
Accordingly, **13 full lifecycle cases remain**:

| Required family | Full cases not supplied by the four outcome projections |
| --- | --- |
| Delivery modes (4) | `no_delivery`, `pending_delivery`, `failed_delivery`, `wallet_delivery` |
| Mirror/binding/platform gates (4) | `mirror_gate_disabled`, `binding_missing`, `binding_disabled`, `platform_disabled` |
| Existing terminal credential state (2) | `suspend_revoked`, `revoke_revoked` |
| Cancellation and full concurrency (3) | `cancel_at_publication`, `cancel_at_mirror`, `concurrent_at_publication` |

## Supplementary direct corpora are not gateway proof

| Corpus | Observations | Existing direct gate |
| --- | ---: | --- |
| [Operations input](../../contracts/canvas-operations-input-oracle.json) | 75 | `operations_inputs_match_frozen_published_python` |
| [Review input](../../contracts/canvas-review-input-oracle.json) | 45 | `review_inputs_match_published_python` |
| [Enqueue input](../../contracts/canvas-enqueue-input-oracle.json) | 28 | `enqueue_inputs_match_frozen_published_python` |

These cover additional numeric/status parsing, duplicate-query and precedence
rules, malformed JSON/media types, note/actor input boundaries and enqueue
validation. Their direct native/Python evidence must remain; counts cannot be
credited to the public gateway without executing that boundary and checking its
explicit public contract. Nor are they interchangeable with the base 46 or
lifecycle 17 observations.

## Concrete completion gates and adaptation hazards

1. Cover remaining supplementary read/filter/limit and job/enqueue inputs
   without recounting the represented base names. Reuse the existing seed,
   snapshot, owned-process and candidate-router owners. Keep the exact eight
   route-selection assertion independent of the growing replay list. Compare
   full DTOs, null/omitted fields, safe error/result projections and durable
   state; a successful status alone is insufficient.
2. Preserve the deliberate auth/tenant construction path: the default gateway
   `tenant_path` appends exactly one approved tenant and rejects existing/encoded
   duplicates. Only the dedicated negative/fallback controls use untouched paths
   and closed expected-header modes. Do not relax this default for further
   precedence inputs or conflate trusted fallback with missing-tenant rejection.
3. Preserve request bytes and input controls. The current gateway request helper
   serializes `body` as JSON with a fixed content type; unlike the direct helper,
   it does not interpret `note_length`, `raw_body`, `omit_headers` or alternate
   media types. Merely adding those scenario names would not execute their
   intended inputs. Never forward the direct management key as public identity.
4. Finish the remaining lifecycle and corrected recovery scenarios through the
   shared actual-process fixture. Its explicit `RealHttpPublisher` capabilities
   must continue to include all four cases and the active-claim hold independent
   of transport. Prove pending recovery/failure and claim/audit atomicity with
   the corrected schema, not only successful suspend/revoke.
5. Keep public expectations independently specified from frozen expected data,
   never from actual responses. MMF projects string/object `detail` to
   `service_error` and preserves `detail.code` under `details.code`; its current
   array-detail projection loses the direct validation array. That difference
   must remain explicit, not be described as full direct-error parity. Validate
   generated message IDs as UUIDs and substitute only the declared sentinel;
   do not strip other fields. Trusted actors may alter only reviewed expected
   success fields, not observed rows or failed-publication null actors.
6. Do not equate client disconnect or aborting the gateway HTTP future with
   cancellation of the issuance handler. The two cancellation scenarios need
   a source-backed process/handler boundary and observed effects, not a renamed
   direct in-process cancellation test. Retain bounded peers, kill/reap and
   owned database cleanup on failures as well as success.
7. Only after the required public-route evidence is complete should the exact
   eight production selections change. Preserve a deliberate legacy-selection
   negative control and all non-selection authentication/policy fields; do not
   weaken the existing assertion by automatically accepting either destination.
   Fresh configured hosted tests and intended consumer/artifact compatibility
   must establish that no remaining caller needs the Python implementation.
   Delete superseded Python immediately after those removal gates pass; the
   aggregate beta deployment and acceptance soak remain separate final gates.

This audit neither deletes tests to reduce CI nor requires inventing an
unbounded failure matrix. The enumerated corpora and normative operations
[contract](../../contracts/issuance-canvas-operations.json) remain the concrete
coverage authority; new evidence must identify exactly which boundary it proves.

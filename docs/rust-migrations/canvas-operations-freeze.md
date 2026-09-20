# Canvas operations: published HTTP/database baseline

Status: Python behavior captured; four [native read candidates](canvas-operations-reads.md)
implemented but unrouted. The follow-up [job candidate](canvas-job-operations.md)
adds three writes; the [manual resolver candidate](canvas-review-resolution.md)
adds the eighth operation. Extended input/lifecycle and full cutover qualification remain.
This does not qualify worker cutover, Python deletion or production deployment.

The separate operations router owns eight reachable APIs for application
enqueue, job history/get/retry/resolve, unsigned candidates, correction-review
listing and dismiss/suspend/revoke. These are not the already migrated 31 Canvas
management routes. The existing gateway native allowlist keeps them on Python.

`contracts/issuance-canvas-operations.json` records their intended behavior and
the blocking legacy recovery defect. `canvas-operations-scenarios.json` drives
46 cases across all eight routes. The published image runs the real FastAPI
router and management-key dependency, service logic, PostgreSQL repository and
official migrations. Only repository injection and external credential
suspend/revoke callables are test ports; authentication is not bypassed.
The existing published-schema runner and issued-review seed are reused through
explicit read-only fixture mounts on exact-owned disposable databases.

Two independent runs produced identical `canvas-operations-oracle.json` before
any native operations implementation. This baseline includes complete response
bodies/content types/statuses, selected durable state, audit counts, and calls
to controlled lifecycle ports. Generated UUID identities are consistently
aliased; timestamp strings must be timezone-aware ISO values, but are replaced
with presence markers. Null/omitted fields are retained. Exact timestamp values,
deployed middleware and real external lifecycle effects are not qualified.

Cases cover management-key errors, trusted-tenant errors and foreign probes,
list/status/limit validation and binding filtering, response privacy, dead-letter
retry/resolve and duplicate conflicts, actor priority and note normalization,
all three manual actions, failed handler release, recovery during handler,
competing manual resolution with one winning side-effect call, and idempotent
enqueue. Named preparation stages reset only synthetic reviews between manual
variants; this is not a claim that production history may be deleted.
Credential and issuance-transaction rows remain exactly unchanged throughout
the run because lifecycle effects are controlled ports. All HTTP calls are
in-process; no production service or credentials are used.

## Blocking published defect: recovery claim rejected by schema

In `review_recovered_failure`, the handler observes an active claim, records
recovered evidence state, then fails. Python releases the manual claim and
attempts an internal `evidence_recovered` claim. Its published database
constraint permits only `dismiss`, `suspend` and `revoke`, so recovery fails:
the review remains open/recovery-pending and no resolution audit event is added.
The frozen database constraint definition and durable outcome record this.
The in-memory unit test expects resolution and does not exercise that schema.

This is a historical negative control, NOT behavior the Rust port should copy.
The worker's existing normative contract requires recovery to resolve with an
audit event after a failed manual handler. Restore that capability with an
official forward migration and corresponding model/repository regression
coverage; do not rewrite the published migration or loosen tenant/claim fences.
Verify actual corrected PostgreSQL recovery, rollback and competing-claim
behavior before accepting a deliberate difference from this baseline.
Credentials PR #266 merged that forward-only migration and real-database
regression coverage; aggregate adoption and qualification are still required.
Keep this historical golden unchanged when adopting the repair.

## Next implementation and acceptance gates

Use the existing Rust issuance crate and its shared scheduler/target, candidate,
policy-review, credential lifecycle, auth and gateway owners. Freeze additional
boundary vectors where this baseline is insufficient: 500-row filtering-window
behavior, full status/state and malformed-input matrices, absent/foreign
resources, transaction/audit failures, claim/finalize races, and real lifecycle
adapter effects. Do not treat these 46 cases as exhaustive feature proof.
Then replay the same HTTP/state scenarios against Rust, with the repaired legacy
defect explicitly distinguished, and route all intended consumers only after
the whole-worker and beta acceptance/deletion gates pass.

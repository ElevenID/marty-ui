# Native Canvas correction-review resolution (candidate)

All eight Canvas operations now have candidate handlers in the existing Rust
issuance crate. The eighth implements manual dismiss/suspend/revoke, note/action
validation, actor-header priority, durable claims, failure release, pending
recovery and atomic review/audit finalization. None is newly registered in the
live issuance router or gateway. Reachable Python and deployment consumers remain.

## Shared owners and state boundaries

`CanvasReviewResolver` uses the evidence processor's existing application-lock
SQL before claiming an open tenant-owned review. Claim token and action both
fence finalization. The processor's existing audit insertion helper executes in
the same transaction as review finalization. Audit failure rolls that transaction
back without discarding the already committed claim, preserving published behavior.

The real lifecycle implementation delegates directly to
`CredentialManagementService::transition`, including its tenant checks, credential
state policy, publisher, PostgreSQL persistence, Canvas synchronization and events.
Existing lifecycle HTTP error mapping is reused. A controlled transition port is
used only by differential tests, matching the published oracle's external boundary.
There is no second credential state machine or audit writer.

On lifecycle failure, the resolver releases only its own active token. If released,
pending evidence recovery is attempted; recovery errors are logged without replacing
the original lifecycle error. Actor/notes are normalized for finalization, while
the lifecycle reason retains the original nonempty note. Dismissal requires no
lifecycle handler; suspend/revoke check tenant credential and handler availability
before acquiring a claim.

## Corrected official schema, with provenance

Credentials #266 merged the recovery constraint fix as
`51f0a758a076777cb18a30b1db3f89c74ac23e01`. The latest published component remains
v0.1.72 (2026-08-31), predating that fix. For tests only, the exact official
migration is vendored under `contracts/fixtures/canvas_review_recovery_claim.py`
and mounted read-only at its original path inside the pinned published image.
The existing service migration entry point executes it; no handwritten alternate
migration or version-table stamping is introduced.

`canvas-review-recovery-migration.json` binds repository, commit, original path,
Git blob `96cdaabd80fee1a21322e27c767d7bc3bc00d5c6`, SHA256
`b2bde4ce51071bcd8c33f044c66c9bf963243c13a5dec6bfcea951086aee5361`,
parent `merge_issuance_heads` and revision `canvas_review_recovery_claim`.
The probe verifies both content hashes and the parent, and both probe and native
harness verify the resulting head/provenance. Old-schema tests remain unchanged.
This verifies the source overlay, NOT a newly published component or deployed schema.
The aggregate still needs provenance-bound adoption of the official fix.

## Qualification evidence

- Two independent corrected-schema captures of all46 published HTTP/state cases
  agree before implementing the native resolver. New golden:
  `canvas-operations-recovery-oracle.json`, blob
  `a7ac869ce8ca3c993479c2824b8660611af73e4a`. The original published46-case
  golden remains the historical negative control, unmodified.
- All46 corrected cases pass through native Axum, comparing full normalized
  HTTP responses, job/target/review snapshots, audit counts and lifecycle calls.
  No manual cases are omitted. Credential/transaction rows remain unchanged in
  this replay because external lifecycle effects are controlled on both sides.
  Failed-handler recovery now resolves the review with one audit while preserving
  the request's original500; concurrent manual resolution invokes lifecycle once.
- Additional real-schema tests verify audit failure rollback, stale-token and
  changed-action fences, and waiting on the processor's application lock before
  claiming. A PostgreSQL lock wait is observed before releasing the test lock.
- A separate test uses the real credential service and PostgreSQL repository:
  suspend/revoke persist actual credential state, preserve the original reason,
  synchronize Canvas and emit lifecycle events. A controlled publisher verifies
  the durable claim is active before publication. Suspending a revoked credential
  retains the existing400 response and releases the review claim without auditing
  success. This is not real signing/provider acceptance.
- All12 configured schema tests pass locally (67.60s),260 library tests pass
  (4.96s), all-target Clippy passes (24.83s),20 workflow/image tests pass (0.76s),
  and Ruff/fmt/diff checks pass. CI explicitly registers both new schema tests.
  Full hosted qualification is still required for this candidate.

## Remaining gates before any cutover

An additional45-case manual-request corpus was captured independently twice from
the pinned published service on the corrected official schema before changing the
candidate parser. The native negative control reproduced the empty-body mismatch.
All45 now replay through native HTTP with complete response and selected database
state comparison, including no lifecycle calls for these dismissal/input cases.
It covers empty/null/scalar/array bodies, action/note errors, malformed syntax,
JSON/vendor/absent/non-JSON content types, authentication precedence, tenant scope,
actor header priority/whitespace, and the2000/2001-character note boundary.
The original46-case goldens remain unchanged. The shared published capture/replay
owners are reused rather than introducing another lifecycle or audit simulation.

JSON syntax decoding precedes management authentication; model validation follows
it. Non-JSON input is treated as text. A private diagnostic renderer translates
serde's syntax errors to published character offsets/messages; serde remains the
parser, with no runtime Python. Nine frozen malformed-request observations also
run as a library test. This corpus does not establish arbitrary Unicode/encoding,
every malformed numeric/string form, nonstandard JSON constants, or all media-type
parameter behavior; extend the reference where broader gates expose differences.

The46+45 cases are not exhaustive request or concurrency proof.
Verify transport size policy without silently narrowing the Python interface.
Qualify lifecycle dependency/publication failures, cancellation between claim
and finalization, additional worker/recovery races and actual remote effects.
Exact timestamp/wire equality and broader issuance/worker/provider gates remain.

Then migrate all intended consumers, delete superseded Python after gates,
reconcile remaining dirty branches without losing other-worker features, finish
CSCA monitoring follow-up and demo/device/wallet acceptance, and perform one
aggregate beta-only deployment and governed soak. Production remains unchanged.

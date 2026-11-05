# Official conformance before stack publication

Product CD prepares and attests the exact five-role manifest from its durable
digest transaction before version-tag promotion. It calls the shared official
suite at the immutable accepted integration-main source pinned in `cd.yml`,
including the product's shared KMS-only setup. All seven lanes must collect
complete evidence, and the independent Rust gate must qualify it before promotion.

The no-write release claim checks that the literal harness pin is an ancestor
of integration `main`, and matches the caller's `harness_revision`. Pin the
accepted merge commit after integration, rather than a squash-merged PR head
whose branch can be deleted. Candidate run 39873517844 could not resolve the
old PR-head reusable workflow; restoring its original branch allowed run
39874228600 to start. That ref remains preserved for reproducibility of the older source.
The accepted merge commit has the identical Git tree to the reviewed PR head.

Native conformance startup uses the shared release validator in Rust-only mode
both before and after manifest attestation. It requires the five current KMS
image roles and rejects retired Python issuance components. Candidate run
39874228600 built and passed its five image/runtime gates, but all seven official
lanes stopped before assertions because this startup check still selected the
legacy manifest policy. The corrected preflight passes against that actual
candidate, including real GitHub manifest attestation and its committed native
capability floor. This read-only check is not an official protocol pass; the
failed lane summaries remain failed and a fresh candidate execution is required.

Candidate run 39886188606 completed KMS-only bootstrap and all five image/runtime
gates, but its seven official lanes failed native startup before protocol
assertions. The run step did not supply GitHub authentication for manifest
attestation. The same immutable manifest passes the native release preflight
with authenticated `gh attestation verify`; this is not a protocol qualification.

The shared harness supplies its read-only job token only to trusted native
startup and strips all GitHub authentication aliases before invoking upstream
suite processes. The common subprocess environment helper enforces this boundary
for both the lane runner and the stack adapter. Native preflight failures report
the failing stage and exit code without exposing command output or credentials.
A fresh exact-source candidate must pass all seven official suites; the failed
run and its summaries remain unchanged.

Candidate run 39902897491 passed authenticated native preflight and KMS-only
bootstrap, but all seven lanes stopped before assertions because the Envoy
issuance bridge retained a source build without a released image binding.
The GHCR overlay now selects the same immutable services artifact for that
bridge, preserving its keyless entrypoint and scoped KMS configuration.
Released startup rejects any remaining source build in the rendered graph,
and the isolated executable probe checks both issuance and bridge linkage.
These startup checks do not establish a protocol pass.

Local execution then exposed a second startup defect: Compose restarted
`openbao-init` after the disposable KMS bootstrap had completed. The production
initializer correctly refused the already-initialized Raft state. Native resume
now verifies the exact project, service, image and successful completion of both
bootstrap jobs, plus the running healthy OpenBao container. It explicitly starts
the selected runtime graph with `--no-deps`, preserving migration and health
ordering while leaving those verified bootstrap services untouched. Missing,
foreign, failed or unhealthy custody prevents startup. Fresh runs still execute
the original strict ceremony; its fresh-state guard is unchanged.

The reusable suite verifies product `cd.yml` provenance, exact protected-main
source, independent manifest digest and all five KMS image roles. It does not
require a public release or modify the ordinary reviewed release pin. Its
sanitized summaries explicitly identify an unpublished candidate.

The shared Rust `validate-official-suite` verifier requires seven distinct lane
summaries bound to one source, manifest, harness and originating release-run
attempt. Missing, mismatched, failed, skipped JUnit, pre-activation and empty
evidence fail closed. OIDF permits only explicitly declared optional skips;
every selected module must finish. Local/native runtime overlays cannot qualify
the release image even when their functional checks pass.

The reusable product call explicitly collects raw evidence; its successful job
means collection completed, not that every official result was `PASSED`.
Standalone and scheduled suite calls still enforce their original raw exits.
The independent candidate gate rejects genuine protocol/process failures and
incomplete plans. Complete `REVIEW` cases can instead produce an immutable
`official-review-input-<run-id>` artifact before the qualification step waits
for at most 60 minutes for the exact protected-main disposition. It contains
only the exact candidate manifest,
sanitized summaries, origin attempt and canonical `review-request.json`.
Raw exports, API readbacks and screenshot pixels must remain private.
The shared harness encrypts the actual images and unchanged exports to the
public `OFFICIAL_REVIEW_RECIPIENT` repository variable before upload. Only the
ciphertext and public-safe delivery receipt are stored as
`official-review-private-<lane>-<run-id>-<origin-attempt>`. The decryption identity
stays with the operator's secure local credentials; product signing keys remain
in remote KMS custody. Follow the integration harness's `conformance/README.md`
to open the exact packet against its frozen public summary. The viewer verifies
all bytes and image bindings before writing images/HTML; it does not write raw
plaintext exports or approve cases. Every actual image still needs review; a
hash alone is not an accepted disposition.

After reviewing every pending case, submit a normal reviewed change at
`release/official-reviews/<run-id>-<origin-attempt>.json`. That record uses
`marty.official-review-disposition/v1`, the exact SHA-256 of `review-request.json`
(with the `sha256:` prefix), the same numeric run ID/origin attempt, a reviewer
with kind `human` or `delegated_codex` and `github_login`, an overall `verdict`,
and a `cases` array. Every case copies its exact `lane` and `module` object from
`pending`, adding its own `verdict`. All verdicts must be `accepted`; omitted,
duplicated, rejected, changed-image or foreign cases fail. A pending template,
an arbitrary local file, or an artifact-supplied approval is not authorization.
Do not identify delegated Codex review as human review.

The workflow resolves protected `main` through the authenticated GitHub API and
reads the record only at that immutable commit. It does not trust a candidate
branch, alternate host/ref or a self-reported approval flag. The resulting gate
receipt binds the accepted main commit, record/request digests and reviewed
case count. Original stock `REVIEW` results and exports stay unchanged. This is
review disposition for the selected interoperability evidence, not paid OIDF
certification or demo editorial/publication approval.

The release stays on its original run and attempt 1 while the record passes
normal protected-branch review and merge. Only an authenticated absence at an
immutable protected-main commit is a waiting state. Authentication, transport,
malformed evidence, rejection, unrelated source drift and the fixed 60-minute
deadline fail closed. The validator builds once and the seven-lane packet is
frozen once; waiting does not recollect protocols or rewrite evidence.

The candidate source and review commit are separate identities. Every commit
between them may change only `release/official-reviews/<run-id>-1.json`. The
record must be absent at the candidate source and an ordinary non-executable
file at the accepted main commit. Unrelated changes later reverted, another
review file, a symlink, incomplete history or a non-descendant are refused.
The exact accepted main commit is checked again before every public promotion
and release write. A subsequent main commit stops this candidate; it never
silently refreshes the accepted authorization.

A failed or expired run must not be retried to manufacture another producer
attempt. The workflow rejects later attempts and the historical `resume_run_id`
and `resume_artifact` inputs before building. Retain the original evidence and
claimed coordinates. Any recovery needs a separately reviewed source and a fresh
unused claim; do not reuse the failed version or relabel existing signatures.

The digest of the allowlisted receipt becomes required
`official_interoperability` transaction evidence. The frozen public summaries
and authenticated disposition inputs are retained alongside that receipt.

Publication copies the exact tested manifest bytes and checks their independent
producer digest. It does not regenerate a potentially different manifest.
There is no conditional bypass or continue-on-error path through qualification.
Old five-gate transactions cannot qualify or resume under this new policy;
they remain historical evidence and must not be rewritten as passing it.

Source checks and synthetic unit controls do not establish an official pass.
Local feedback also found that the old conformance composition mixed a workload
CA with plaintext control-plane targets. Conformance now layers the existing
beta workload configuration before the protocol and isolation overlays, reusing
its remote KMS TLS identities, authenticated Redis and gRPC bindings. The native
selection extends only the neutral executable definition so it cannot overwrite
those deployed bindings with development settings. Both issuance owners must
retain the scoped HTTPS control-plane targets and public CA. The shared harness
generates disposable Redis and device credentials alongside its other run inputs.

The adapter and product gate must complete protected integration and a real
candidate execution before claiming release qualification. Keep beta runtime,
disposable conformance stacks, demo acceptance and editorial review distinct.

## Bounded publication and independent tag handoff

After all qualification gates pass, the publisher promotes the five exact image
digests in their existing order and signs the original release files. It verifies
and seals all 32 public assets, including all 13 Cosign bundles and all five
complete publication-provenance sidecars, into
`stack-release-publication-inputs-<run-id>-1`. The v2 checkpoint and unchanged
official gate receipt bind the candidate, claim, original run, accepted main,
exact asset sizes and hashes, the explicit tag-handoff contract, and a fixed
15-minute deadline. This checkpoint is evidence, not a published release or
installer admission.

### Create-only reservation contract

The operator dispatches `.github/workflows/release-tag-handoff.yml` on protected
`main`. Its default inspect mode is read-only. The qualified-tag mode validates
the live original publisher's waiting step, successful prerequisite jobs,
authenticated artifacts, all original cryptographic proofs and unchanged review
authority. It uses its existing scoped ephemeral job token for metadata and
ref operations. It does not build, sign, publish a release, handle private review
images, or update main.

The contract is `marty.create-only-annotated-tag/v1`. First the operator acquires
`v-release-intent-<major>.<minor>.<patch>`, an annotated ownership tag binding the
production version, original CD, claim, checkpoint, source, admitted main and
one original operator. It requires a confirmed HTTP 201 and exact readback.
Any existing owner blocks another invocation, even if the production tag remains
absent or the apparent owner matches.

Only then may it create the production annotated object targeting the original
source and binding that ownership. It makes one REST create-reference request
for the absent production tag, requiring HTTP 201 and the exact ref/object
identity. There is no update, force, lightweight intermediate tag, overwrite
fallback, or automatic retry. Each intent is durably recorded before its request
and consumed even when the response is lost. If ownership acquisition was never
confirmed and its ref remains absent, a new acquisition cannot replay an earlier
production write: the earlier invocation could not have reached that operation.
Confirmed ownership remains the durable barrier to any later production attempt.

This is an explicit revision of the earlier atomic main/tag requirement:
`ref_creation_scope=absent_tag_only` and
`main_check_scope=before_after_observation`. All existing main, review-only
history, visible rules, original run, candidate, cryptographic and deadline
checks remain. They are observations around separate operations; they do not
prove main's value at the tag-write instant or detect a main/policy change that
is restored between reads. The supported Marty consumers treat the tag as a
reservation until the operator and publisher authenticate the complete evidence.
Third-party tag watchers can still see it before a release exists. The receipt states
`tag_alone_authorizes_publication=false`.

A concurrent main advance or a lost response can leave an immutable, unused tag
and consume the version. Any observed authority change stops admission. Preserve
that state and its original failure evidence; never delete or retarget the tag,
adopt an unknown write, retry the original mutation, or reuse the coordinate.
The exact guarantee change, observed GitHub failure and approval requirements
are described in [the reservation contract](release-tag-reservation-contract.md).
Normal branch protection, merge-queue requirements and workflow permissions
remain in force. Activate this revision only after explicit owner approval and
normal protected integration.

### Evidence and publisher admission

The exclusive private audit journal retains REST mutation intent, outcome and
safe response metadata before successful admission. The
`marty.release-tag-operator-observations/v3` record keeps the retained native
negative probe distinct from the new create-only ref operation. The artifact
member keeps the name `operator-api-receipt.json`. The successful
`marty.release-tag-handoff-result/v2` is emitted only after exact annotated-tag
readback and all unchanged-main/context/rules checks pass.

The original publisher waits for the exact annotated ownership and production
tags and the actual
successful operator workflow, authenticating its original bound result artifact.
Matching tag text alone is insufficient. It emits
`marty.release-tag-admission/v2` with the same explicit reservation contract.
A failed or cancelled operator, collision, changed main, invalid receipt or
elapsed deadline stops admission. An uncertain write permits investigation and
readback only; a matching readback cannot convert it to successful mutation
evidence.

Immediately before release creation or candidate sealing, the original publisher
revalidates its checkpoint and compares all 32 workspace files to the sealed
bytes, then checks accepted protected-main authority again. The original
deadline is rechecked after API/registry reads. Old checkpoint/result/admission
schemas cannot be reinterpreted as this contract.

The separate v2 publisher authenticates original CD success and the new policy
digest, both exact annotated tags, operator result, review authority, image identities
and original asset bytes. Publication policy v3 binds this tag contract; the
external `publication_contract=v2`, candidate schema v2, fixed 24-hour candidate
lifetime and at-most-15-minute publisher authorization remain unchanged.
An unqualified reservation is not an admitted candidate, an owned release, a
published installer, or permission to resume a failed original CD attempt.
After release creation, all 32 downloaded files must match the original sealed
bytes and pass their original proof checks. Separate registry, workflow, Git
and publication operations are not one global atomic transaction.

### Fresh scoped capability qualification

Before consuming a stable claim, qualify the revised operator against the actual
repository with a new original `qualify-capability` run on protected main.
The experiment uses a unique non-semver
`v-release-capability-<operator-run-id>-1` audit tag and a real distinct ancestor
whose workflow files are identical. Do not manufacture an ancestor or change the
tag target to satisfy this prerequisite.

The negative probe retains its native two-ref request: ancestor-to-same-ancestor
main plus absent-to-audit-tag, while discovery binds actual current main.
Require either the exact stale-ref refusal or the exact recorded GitHub GH013
main-policy refusal, both refs refused, unchanged main and absent tag on
independent readback. This proves only the reported refusal under the observed
protection; it does not establish the former atomic positive capability.

Before writing, require the same active repository-owned merge-queue ruleset
applying exactly to main, with no excluded refs or additional conditions, and
`current_user_can_bypass: "never"` for the actual workflow credential.
An omitted `bypass_actors` inventory remains absent and is recorded
`not_disclosed`; an explicit empty list is `observed_empty`. Null, malformed,
nonempty or non-`never` values remain non-qualifying. This describes the current
credential and visible policy, not an undisclosed global bypass inventory.
GitHub [defines the current actor field](https://github.blog/changelog/2023-06-27-repository-rules-public-beta-updates/)
and [documents the bypass inventory's access requirement](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset).

After rechecking the full context, main and visible rules, the positive phase
creates the absent annotated `v-release-capability-intent-<run>-1` ownership ref,
then its bound audit ref, through the revised REST operation. Require confirmed
ownership before the audit mutation, exact responses and object/message/ref readbacks, unchanged observed
main and rules, and the original deadline. The v5 capability result states the
reservation contract and observation scopes. It cannot be relabeled as v4 atomic
capability. Keep both the ownership and audit tags and their original receipts. Local collision
and failure-injection tests do not justify an extra live mutation or retry.

### Historical atomic evidence stays historical

In run 41894878943 the corrected stale no-op was rejected by GitHub policy before
the stale-lock layer; no positive transaction was sent. Run 41925744279 stopped
before recorded REST or Git mutation because v3 incorrectly demanded a globally
visible empty bypass inventory. The actual read-only workflow-token inspection
41791774863 omitted that inventory and explicitly reported `never`; its
unchanged packet remains in
`tests/fixtures/release-tag-inspection-41791774863.json`.

After the separately reviewed v4 visibility correction, original run
[41943309794/1](https://github.com/ElevenID/marty-ui/actions/runs/41943309794)
reached the positive current-main no-op transaction. GitHub rejected that command
with GH013 merge-queue and pull-request requirements and refused the tag
atomically. Independent replay confirmed correct request construction and
parsing. Main remained unchanged and the audit ref was absent. The original
result remains refused, and the native parser continues to reject this positive
response. The [reservation contract](release-tag-reservation-contract.md)
records original artifact identities and hashes.

The previous ordinary-Git route omitted the no-op main command; GraphQL rejected
the annotated target. Neither is an admitted fallback. The actual native failure
does not justify accepting `ng` as success, expanding credentials, weakening
protections, or changing historical evidence.

Arrange access to the existing private review identity and enough time for normal
review/merge before claiming a version. The fixed 60-minute review and 15-minute
tag bounds do not extend because a queue is slow. Private full-production UI
packaging follows authenticated stable publication separately; production pages
do not establish completed billing-runtime behavior.

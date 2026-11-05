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
`stack-release-publication-inputs-<run-id>-1`. The separate request and unchanged
official gate receipt bind the candidate, claim, original run, accepted main,
exact asset sizes and hashes, and a fixed 15-minute tag-handoff deadline. This
checkpoint is evidence, not a published release or installer admission.

The operator dispatches `.github/workflows/release-tag-handoff.yml` on protected
`main`. Its default inspect mode is read-only. The qualified-tag mode validates
the live original publisher's waiting step, successful prerequisite jobs,
authenticated artifacts, all original cryptographic proofs and unchanged review
authority. It uses its own scoped ephemeral job token for GitHub metadata and
ref operations; it does not build, sign, publish a release or handle private
review images.

The tag object targets the original candidate source. One native Git
`receive-pack` transaction explicitly sends both the expected-current-to-same
main command and the absent-to-annotated-object tag command. Discovery must
advertise `atomic`, `report-status`, `side-band-64k` and the exact admitted main;
the target tag must be absent. The request includes Git's required empty pack
because REST has already created and verified the annotated object. Ordinary
Git push cannot supply this compare: its sender omits an unchanged-main command,
even when requested with a matching lease. The earlier GraphQL `updateRefs`
route rejected the annotated object type and is not a fallback. Never use an
unconditional tag creation, lightweight intermediate tag or protection bypass.
The wire and atomic contracts are documented in
[Git's pack protocol](https://git-scm.com/docs/gitprotocol-pack.html) and
[protocol capabilities](https://git-scm.com/docs/gitprotocol-capabilities).

The transport uses the same workflow token and permissions over canonical
GitHub HTTPS. A short-lived isolated worker receives the credential through
bounded private stdin; the parent enforces the remaining absolute deadline.
It does not follow redirects or retry an unknown write. Each consumed intent
is preserved in an exclusive private audit file before dispatch. The
`marty.release-tag-operator-observations/v2` record keeps REST mutations and
native Git transactions distinct, retaining the bounded packet bytes, safe
HTTP metadata, command hashes, status reports and diagnostics. Its artifact
member retains the existing `operator-api-receipt.json` name. The generic
successful handoff result keeps its closed v1 candidate bindings; it is emitted
only after the native transaction and unchanged-main/rules/tag readbacks pass.

The publisher waits for both the exact annotated tag and the actual successful
operator workflow, authenticating its bound result artifact. Matching tag text
alone is insufficient. A failed/cancelled operator, conflicting tag, changed
main, invalid receipt or elapsed deadline stops publication. An uncertain write
outcome permits readback only; never blindly replay a mutation or delete/rewrite
an immutable tag. Atomicity covers the two refs, not registry state, workflow
cancellation or later release publication; those remain independently checked.

Immediately before creating the release, the publisher revalidates the original
checkpoint and compares all 32 workspace files to its sealed bytes, then checks
the accepted protected-main authority again. The original deadline is rechecked
after those API/registry reads, so late admission cannot start release creation.
An existing release is a collision
on this first-attempt-only path. After creation, all 32 downloaded release files
must match the sealed checkpoint and pass their original proof checks.

Before consuming another claim, qualify this exact operator workflow and token
against the real repository protections. Its capability mode uses a unique,
non-semver `v-release-capability-<operator-run-id>-1` audit tag and a genuine
ancestor with identical workflow files. The stale-main negative transaction
asserts the ancestor as both old and new main, modelling a formerly admitted
no-op after main advanced. Its separate `observed_main_oid` binds discovery to
current main; the request never proposes an ancestor-to-current
branch update. Before writing, the operator requires an active repository-owned
merge-queue ruleset applying exactly to main, with no additional conditions,
excluded refs, and GitHub's explicit `current_user_can_bypass: "never"` for the
workflow credential making the request. This proves the credential's own
authority; it does not assert that no other actor has bypass rights. GitHub
[defines that field for the requesting actor](https://github.blog/changelog/2023-06-27-repository-rules-public-beta-updates/)
and [withholds `bypass_actors` without ruleset write access](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset).
An omitted inventory stays absent in the raw snapshot and is recorded as
`not_disclosed`, never converted to an empty list. An explicit empty list is
recorded as `observed_empty`. Explicit null, malformed or nonempty inventories
remain non-qualifying, as do missing or non-`never` current-credential capability.
No additional credential, permission or ruleset change is introduced.

The negative transaction must
return either the exact main/current/expected stale-lock diagnostic with both
refs atomically refused, or GitHub's exact main-policy GH013 diagnostic for
the merge queue and pull request, with main refused for rule violations and
the run-bound tag refused by the atomic transaction. The latter is recorded as
`confirmed_main_policy_refusal`; it is not proof of Git's stale-lock layer.
Both refs must remain unchanged on independent readback, and the complete
operator context and visible ruleset snapshot, including the requesting
credential's capability and inventory visibility, must still match before the
positive transaction. This is not an assertion that an undisclosed global
inventory remained unchanged. Concurrent changes to main remain subject to the
original native atomic comparison and independent readbacks. A generic atomic
failure, other GH013 diagnostic, or policy
refusal on a positive or production transaction is insufficient.

The paired current-main transaction must report both refs successful and
create the exact annotated audit tag without moving main. The v4 capability
result retains the distinct negative evidence and protecting ruleset IDs, and
explicitly scopes its protection observations to `current_workflow_credential`.
Each observation records the exact `never` capability and `not_disclosed` or
`observed_empty` inventory visibility. The unchanged raw API snapshot and all
bounded wire evidence remain available. Recheck the same visible rules afterward.
The parser counts and ignores only the observed standalone progress
NUL packet; raw packets remain intact. NULs within text or status and unsupported
control bytes are refused.
Decoded refusals are preserved before admission. No negative result alone is
successful qualification, and historical failed runs remain failed. In run
41894878943 the corrected stale no-op was rejected by GitHub policy before
the stale-lock layer; the positive transaction was never sent. A fresh paired
qualification is required after this correction. Run 41925744279 stopped before
any recorded REST mutation or Git transaction, with only a `HandoffError` in its
old refusal receipt. The v3 preflight incorrectly required a globally visible
empty inventory: actual workflow-token inspection 41791774863 omitted that field
while explicitly reporting `never`. Its unchanged public packet is retained as
`tests/fixtures/release-tag-inspection-41791774863.json` (artifact 13303856131;
original ZIP SHA-256 `09a5d46952b0ab6fcda60279765cd58bc0f5e1389510cbec3705af321915067e`).
That packet reproduces the preflight refusal locally; it is read-only inspection
evidence, not live capability success. New refusals report fixed internal
`refusal_stage` and `refusal_reason` codes without exception messages, credentials,
API payloads or redirected URLs. Original failure evidence remains unchanged.

Local bare-Git tests establish protocol behavior, and do
not replace this actual GitHub qualification under the existing protections. Permission,
type, transport or generic errors are not successful capability proof. Keep
the immutable audit receipt and tag; do not weaken protections or obtain a
broader credential to force success.

Arrange access to the existing private review identity and enough time for normal
review/merge before claiming a version. The 60-minute review and 15-minute tag
bounds do not extend because a queue is slow. Final publication reads back all
32 exact files and their proofs. Private full-production UI packaging follows
authenticated stable publication separately; production pages do not establish
completed billing-runtime behavior.

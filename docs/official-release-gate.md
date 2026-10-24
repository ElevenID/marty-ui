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
`official-review-input-<run-id>` artifact before the qualification step fails
closed awaiting disposition. It contains only the exact candidate manifest,
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

Retry only the failed `official-gate-evidence` job after the record reaches
protected main. It restores the same frozen seven-lane evidence and originating
attempt, revalidates all bytes and reads the latest main record. No app image or
protocol replay is needed for that review-only retry. An expired/ambiguous
snapshot, changed candidate, changed evidence, or a newer lane run fails closed;
start a new qualification run instead of falling back to an older approval.
A rejection on current main cannot fall back to an older accepted record.

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

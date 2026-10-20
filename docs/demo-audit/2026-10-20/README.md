# Marty / ElevenID demo functionality audit — pass 2

**Date:** 2026-10-20 UTC. **Status:** local fixes verified; full scenario qualification pending.

This pass continues the [first audit](../2026-10-19/README.md). It adds six confirmed findings and fixes four issues that were left open in that report. The tracker now records 20 findings fixed locally, one open finding, and one follow-up risk. D12's recording-free execution remains unsupported; its failure now occurs before setup with a specific explanation. Full authenticated scenario qualification remains separate from this engineering audit.

The machine-readable record is [audit-tracker.json](audit-tracker.json). Exact test commands, results, baseline reproductions, and fixture boundaries are in [verification.json](verification.json). The built public UI browser results are in [browser-report.json](browser-report.json).

## New findings

| ID | Severity | Failure and consequence | Change |
|---|---|---|---|
| DA-017 | Medium | An obsolete manifest request could finish after navigation and replace the current release with old content or an old error. | Bind resource state to the current request and ignore successful or failed completions after cancellation. Hide prior-release state during the render before the next request effect runs. |
| DA-018 | Low | A chapter position from one demo carried into the next recording. A new video could start partway through. | Keep seek position inside the detail component keyed by the exact recording. A different recording starts at zero and requires fresh consent. Seeking within one recording preserves consent. |
| DA-019 | High | The Canvas/provider-switch verifier accepted the wrong signed credential type. A missing legacy template field made its substring fallback match every string. | Require the selected template's exact VCT before consuming an offer, then compare exact VCT equality after signature verification. |
| DA-020 | High | Employee/passport preflight withdrew pre-existing applications matching a template without establishing ownership. | Treat existing applications as explicit conflicts, inspect all pages, and avoid preflight withdrawal. |
| DA-021 | Medium | Shared setup could validate and activate a pre-existing draft configuration. | Activate only a resource created by the run. Reject existing drafts and foreign-organization responses; retain existing active-configuration reuse subject to the consumers' configuration checks. |
| DA-022 | High | A created application could be lost from cleanup when submission or passport evidence validation failed. Reviewer-lock response loss and missing failure reports obscured partial progress. | Retain the application ID immediately with its run, applicant, organization, and template bindings; account for uncertain mutations and reviewer locks; validate cleanup results; write the final failure report after cleanup. |

The UI regressions were reproduced before their fixes: both stale-request outcomes and the chapter carry-over failed. The credential-exchange regressions also failed before repair: an unrelated type, a missing type, a misleading substring, and a missing expected type did not fail at the required boundary. The repaired exchange tests use real ES256 signatures and matching holder keys with scripted network responses. They do not substitute a mocked signature verifier for the check.

## Previously open findings addressed

### DA-015: exact ownership in employee and passport audits

The shared helper previously selected the newest credential matching a template and a timestamp. Another run's newer record could therefore be selected and later revoked during cleanup.

The revised path follows the public contracts already present in the Rust services:

1. Record the created application with the run ID, applicant, organization, application template, and credential template.
2. Resolve its issuance transaction by exact `application_id` from the public transaction inventory. The application's own `id` is not a transaction ID, and its DTO omits the internal issuance transaction field.
3. Select the issued credential only when `application_id`, `flow_execution_id`, organization, and template agree. Rust projects `flow_execution_id` from the source transaction ID.
4. Re-establish these relationships before cleanup mutates a resource. Reject ambiguous or inconsistent inventories and confirm the returned lifecycle state after mutation.

Newer unrelated records are ignored. Conflicting identity data, multiple possible matches, a response without the required state, and unresolved mutations prevent successful cleanup. A pending offer without an issued record remains incomplete: withdrawing its application does not establish that the offer has been cancelled.

### DA-011: the legacy six-scene narrated demo

The previous harness could finish scenes despite missing controls, swallowed errors, stale routes, or absent business results. It also passed Locator objects to a helper that expected selector strings and selected an arbitrary pending application for approval.

The revised harness uses current console routes, requires one active linked template, fills the current dynamic application form, captures the submitted application ID, and binds administrative review to that exact application and applicant. It requires observable submission and approval results. Its final scene requires both an issued/credentialed application and a claimed state.

This closes the false-success behavior; it does not supply a new wallet implementation. The last scene intentionally fails when real wallet redemption has not happened. Six scenes were parsed by Playwright, and focused local helper tests cover the failure boundaries. The full seeded journey was not run against a backend.

### DA-012: the legacy Canvas recording

Required checkpoints now fail the run when they return false, return no successful result, or throw. A page header or narration alone is insufficient: the relevant badge, destination, administrative readiness controls, or verification setup dialog must be present.

The report distinguishes required checkpoints from narration. It records the first failure, attempts session finalization, retains finalization errors, and leaves `completed_at` empty for unsuccessful runs. Configuration refusal occurs before artifact cleanup. The legacy script's pre-existing fixed output-directory behavior remains; it should be run in a dedicated recording workspace.

Its report explicitly identifies a legacy Canvas sandbox walkthrough and sets `qualifies_as_real_oss_portability: false`. Showing a sandbox badge, provenance lookup, or policy dialog does not prove provider delivery, external key custody, or a wallet presentation.

### DA-013: D10 functional execution without video

The organization audit now honors `RECORD_VIDEO=0` even when its ordinary command includes `--record-video`. It executes the same audit actions, behavior assertions, and cleanup. It exports the required trace without screenshots, DOM snapshots, or source snapshots, creates no video context, and reports `NOT_CAPTURED` with no recording.

The trace remains mandatory in the recorder contract. Ordinary recorded execution retains its video and trace requirements. Entry-point fixtures reproduced the previous flag override failure and verify all three relevant environment modes.

## Remaining work and limits

**DA-014 remains open.** D12's protected receipt requires negative-run videos and privacy scans bound to those exact videos. A reviewed recording-free receipt contract is still needed. The recorder configuration, direct qualification API, and standalone passport driver now refuse the unsupported mode before their setup or side-effect boundaries. No evidence requirement was made optional to make the mode pass.

**DA-016 remains a follow-up.** The shared test-wallet reset and revocation-profile ownership boundary is not qualified for concurrent use. Wallet processes should be isolated for runs before attempting a shared environment concurrency qualification. The legacy Canvas recorder also retains its pre-existing fixed artifact directory behavior.

The checked-in latest catalog remains **14 DRAFT scenarios with 60 NOT_RUN assertions**. No manifest assertion or publication state was upgraded by these changes. All 20 current and historical public scenario pages rendered in the local production browser check; that is UI evidence, not evidence that their authenticated flows completed.

The following still require a disposable, source/deployment-bound target environment: authenticated issuance and negative lanes; real external KMS switching; real Canvas OSS portability; Android and independent wallets; Windows/native and offline verification; D11 webhook scope/signature/duplicate cases; and D12 signed and denied simulator callbacks. The passport scenario continues to make no physical booklet verification claim.

## Verification and Git delivery

This pass passed **201 named local tests and 29 public browser checks**:

| Check group | Passed | Boundary |
|---|---:|---|
| Demo route and video player | 17 | React navigation and deferred service fixtures |
| Exact signed credential type | 20 | Real local signatures and holder keys; scripted exchange |
| Shared ownership and consumer regressions | 66 | Exact identity, conflict, partial-failure, and cleanup fixtures, including lifecycle/provider consumers |
| Legacy narrated journey helpers | 10 | Missing controls, exact application identity, and final claimed state |
| Legacy Canvas recorder | 18 | Required checkpoints, failure reports, and finalization |
| D10 Python driver | 32 | Entrypoint mode fixtures and release checks |
| D12 gate and privacy | 8 | Local evidence/guard checks and synthetic browser masking |
| Recorder configuration and functional contracts | 30 | Shipped definitions through injected qualification drivers |
| Built public catalog browser | 29 | 20 scenario routes, responsive layouts, consent, and manifest recovery |

TypeScript and the production build passed. Playwright discovered all six legacy narrated scenes; discovery is not execution.

This pass reruns the checks listed in [verification.json](verification.json). The first pass's Rust, lifecycle, QR, and other results remain historical evidence unless explicitly listed as rerun here. The production build kept prerendering enabled and passed with the existing large-chunk warning. The browser check used installed Chrome for Testing 155; external Google Fonts requests failed certificate validation, so layout used fallback fonts.

The download contains two alternative patch series for each changed repository:

- `pass2-patches/`: apply after the first audit's patches.
- `patches/`: apply both passes together from the original audited upstream base.

Do not apply both alternatives to one branch. Each series is checked using `git am --3way` in a disposable baseline worktree, with exact final-tree equality recorded in the package. The public `marty-ui` bundle preserves genuine Git ancestry and the original commit IDs.

The private recorder fixes were developed against 129 exact upstream source blobs, not a full authenticated Git clone. The recorder's synthetic local baseline is excluded from every patch series; no recorder bundle is provided. Its application checks establish exact selected-source compatibility, while application to the full private upstream checkout remains unverified. See `UPSTREAM_SNAPSHOT.json`, `BASELINES.json`, and both application-verification records in the download.

The `Marty` compatibility repository has no changes. Source links in the tracker point to the original audited revisions; local implementation commits are supplied in the patch package rather than represented as already-published GitHub commits.

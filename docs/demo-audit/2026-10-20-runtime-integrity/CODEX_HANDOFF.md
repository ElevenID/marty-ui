# Codex worker handoff — Marty / ElevenID demo audit

## Objective

Continue developing and auditing the Marty / ElevenID demos. Every demonstration should use a real production feature path and a clear scenario. Match the lifecycle presentation standard: voice, subtitles, measured crop/zoom and disclosed cursor actions. Prefer Rust for domain logic and shared, DRY implementations for UI and recording adapters. Track the work with Git and provide reviewable commits and downloadable changes.

This handoff includes completed source repairs and local verification. It does **not** claim that all demos are production-ready. The remaining catalog is 19 recording configurations, 14 DRAFT scenarios, 66 NOT_RUN assertions and 61 UNBOUND presentation beats. No current qualification flag was upgraded.

## Start from the supplied Git state

1. Read the package root `APPLY.md` and `BASELINES.json`, then inspect the destination repositories, their current branches, worktrees and any applicable `AGENTS.md` instructions. Preserve existing user edits.
2. Select one UI lineage: main UI or the lifecycle branch. Do not apply both. Use the lifecycle alternative when continuing the user's lifecycle work. Choose either its cumulative series from the original reference or its incremental series from the previous delivered integration.
3. Select the matching recorder cumulative or incremental series. Apply core/native carryover patches only if those previously delivered changes are absent.
4. Use the appropriate verified bundle or `git am --3way` series in a clean review branch/worktree. Check the resulting tree against `BASELINES.json` / `application-verification.json` before development. Replayed commit IDs may differ while trees match.
5. Read the current runtime audit, gap tracker and verification index. Continue from these repairs; do not restart the audit or rerun all historical tests.

### Repositories and starting points

| Repository / lineage | Previous delivered state for incremental application | Role |
| --- | --- | --- |
| `ElevenID/marty-ui`, main | `653cd9f5d5b8b4f079410d1eb02a94a6705d06ad` | Rust services, React UI and functional demo drivers |
| `ElevenID/marty-ui`, lifecycle alternative | `4007290d32d772ff44d376cd28a8e51470b6b8f1` | Same repairs integrated while preserving other lifecycle work |
| `ElevenID/marty-demo-recorder` | Source-equivalent prior head `8d8bf8673f9a1162a4f7a788c1f2e8349a3f8a25` | Recorder, media composition and scenario contracts |
| `ElevenID/marty-core` | Carried unchanged at `adbc29d2511dead6082618b1b05e7d91e089feb1` | Isolated Rust demo wallet sessions |
| `ElevenID/marty-verifier` | Carried unchanged at `25d2bf22e296dfd726a0295c414efee143db0105` | Durable native offline reporting acknowledgement |

The package's final heads and trees are authoritative. The table above lists **starting/carryover states**, not the final UI or recorder head. The separate Python Marty repository remains unchanged at reference `c6823c6316fc0f3be051133986236913ac4dcfee`.

Four bundles preserve genuine UI/core/native ancestry. The recorder is supplied as change patches against its verified complete source: all 453 blobs and modes match actual private upstream `64c9bc986185b53bdcb1dd3d383787ad94fe931a`, tree `4e6089f470c9e1a1ca5a704a4587c233acb2e12c`. Its private upstream commit history was not imported. Do not import or recreate an audit reconstruction baseline as if it were upstream history; no recorder bundle is supplied.

## Completed in this continuation

| Area | Completed behavior | Source checkpoint |
| --- | --- | --- |
| Withdrawal | Shared Rust guard rejects withdrawal when approval, issuance or retained uncertainty needs reconciliation; denied requests do not persist. | UI `0a2b100` |
| Claim contract | Native claim accepts empty body / `{}`, rejects unsupported options, advertises actual capabilities and retains pending offer reuse. Exact late completion and stale NoActiveFlow handling preserve current state. | UI `e67364c` |
| Reissue reconciliation | The transaction ID observed by an async read is compared under the store lock before any mutation. Old revoked/issued responses cannot overwrite replacement offers. | UI `23331ae` |
| Claim interface | Scoped catalogue/request handling, shared pending acquisition, read-only receipt polling, raw GET normalization, truthful email draft wording, and unsupported destination/Canvas options removed. | UI `b02894b` |
| Wallet opening | One shared guarded opener for mobile and actual desktop invite/QR. Close, unmount, scope/wallet/offer changes and confirmed receipt invalidate delayed navigation. | UI `0943e11` |
| Canvas return | Read-only evidence refresh on close/focus/visible return, with coalescing and stale-result cleanup. Only confirmed claimed status shows completion. | UI `c971c40` |
| Owned retirement and D05 recovery | Confirm exact credential revocation and preserve application history; use transaction detail for unused proof; reissue the same D05 application with a freshly validated retired-transaction ledger and new offer binding. | UI `b5d0821` |
| Canvas assertion integrity | Imported portability cases remain prerequisites. Preflight and action boundaries reject their promotion to current-run assertions. Source/control mapping corrected. | Recorder `a124bae`, `ed60078` |
| Media | Shared native portrait validation, strict source/event pointer measurements and one integer frame timeline, checked against encoded output. | Recorder `cfcd351` |
| D05 recorder linkage | Two support configurations pin the new driver's exact bytes; current runbook updated. | Recorder `5f99d6a` |

Do not regress the Rust claim contract by reintroducing holder delivery destination or optional Canvas mirroring controls without implementing their actual backend behavior. Those capabilities remain unsupported on this route. Likewise, application withdrawal is not proof of transaction cancellation or credential revocation.

## Next development priority: complete the real D07/D08 recorder adapter

The largest known source gap is **PG-15: OPEN_SOURCE_AND_LIVE_EVIDENCE**. A stock Canvas environment alone will not fix it. The existing product controls and Rust evidence, policy, approval and review paths are present, but the generic recorder does not connect the full scenario.

Read `marty-demo-recorder/docs/canvas-capture-source-gaps.md` first. Reuse the actual source in `marty-ui/tests/scripts/run-canvas-oss-standard-contract.js`, including `launchLearnerResource`, `triggerLearnerSync` and `receiveAndVerifyCredential`, while respecting the distinction between a protocol client and visible native wallet operation.

Implement the work in focused commits:

1. **Bind the real launch and current application.** Observe LTI bootstrap, click `canvas-lti-continue`, and retain the exact returned application ID. Bind the evidence-sync enqueue/job and terminal evidence heads to that application. The assignment popup must have actual capture coverage; do not merely disable popup checks.
2. **Connect approval, wallet receipt and verification.** Preserve evidence that the pending award is unsigned; perform actual scoped approval before Claim is available. Operate the intended wallet through a supported path, retain the matching transaction/credential receipt and use the canonical verifier. Opening a claim dialog is not successful receipt, and protocol redemption alone must not be described as native wallet UI capture.
3. **Execute fresh negative and recovery operations.** Reuse the stock contract's governed synthetic grade correction and policy recovery. For D08, bind the post-issuance correction review, unchanged issued credential status and review resolution to the exact application/credential. Do not inherit outcomes from a prior portability report.
4. **Produce current runtime evidence.** Register the real run-owned fixtures and observed service operations with the recorder's existing evidence contract. Bind those operations to the scenario, source revision and captured media. Keep `CANVAS_CURRENT_RUN_EVIDENCE_REQUIRED` until a real producer can satisfy the current assertion; receipt-shaped JSON or an environment override is not a repair.

Acceptance requires a runnable source path, focused failure/recovery tests and, when the governed environment is available, actual current positive and negative execution. If deployment, fixtures or a native device are unavailable, finish the authorized source work and record the exact remaining prerequisite. Keep runtime assertions NOT_RUN rather than substituting a synthetic success.

## Then complete presentation and production qualification

Use `docs/lifecycle-presentation-profile.md`, `docs/editorial-pointer-evidence.md` and `demos/lifecycle-alignment.json` in the recorder. For each actual recording, measure source crop geometry and click/response timing, generate the intended narration and subtitles, compose to the normalized frame timeline, then watch and listen to the exact master.

New editorial pointer evidence requires the versioned source filename/hash/dimensions and exact event measurements. Its verification is `SOURCE_AND_MEASUREMENT_IDENTITY_ONLY`; it does not independently prove an OS click or business outcome. Retain the editorial reconstruction disclosure. Historical hash-only files need reviewed rebinding before new compositions.

The included 7.04-second, 176-frame media fixture contains generated shapes and a sine tone. It proves the tested composition behavior, not human voice quality, product functionality or native capture.

Other retained requirements include matching deployment revisions, governed short-TTL D05 fixtures, pinned independent native wallet profiles, D09 coordinated migration/service/native acknowledgement deployment, D10 actual external KMS execution and D12 physical-booklet/native hardware scope. Native automatic server retirement remains NOT_PERFORMED.

## Validation already completed

| Final scope | Passed |
| --- | ---: |
| Rust applicant application/HTTP/issuance/domain | 42 |
| Claim dialog | 19 |
| Actual invitation and QR components | 12 |
| Canvas application return | 15 |
| Shared resource helper | 33 |
| D01 passport clearance driver | 9 |
| D04 employee access driver | 8 |
| D05 support driver | 24 |
| Recorder media across eight files | 54 |
| Canvas prerequisite guard | 15 |
| Recorder configuration | 11 |

All listed final scopes have zero failures/skips. Two additional local D05 driver pin/schema checks passed. Production `tsc -p tsconfig.build.json --noEmit` passed. The 31-case final UI command contains the 19 parent and 12 child cases; earlier child executions are not additional unique cases. The final 42 Rust cases include the earlier 31/38 gates. Do not add those overlapping executions into inflated coverage totals.

These are controlled local source/HTTP/media tests. No full application bundle build, broad test-source TypeScript pass, Docker/native GUI build or new live production capture is claimed. Earlier broad TypeScript diagnostics remain documented. Two helper log filenames label D01/D04 in reverse; their commands and explicit scenario IDs establish the correct 9/8 counts above, and raw log bytes were preserved.

Run only the tests needed for each concrete new risk. The production UI configuration is the appropriate typing gate. Do not spend the next development pass rerunning every historical regression or rewriting existing test evidence.

## Working and handoff expectations

Preserve user changes and the chosen lifecycle lineage. Keep domain decisions in Rust and reuse existing service paths and shared adapters. Make small commits with the reason, resulting behavior, relevant tests and limits. Preserve evidence hashes and identify historical checkpoints honestly. Record the actual applied checkout revisions for capture/driver pins; patch replay may change commit IDs.

No push, deployment, publication, external message or live shared-resource mutation has been performed in this handoff. Continue authorized local development. Obtain the actual missing environment/authorization before operations that require it; do not invent credentials, approval or release results.

At the next handoff, provide the new commit IDs, changed areas, focused verification, remaining source/environment work and an updated applicable Git package. Keep the current catalog unqualified until its real evidence and master-review requirements are met.

# Local marty-ui worktree cleanup inventory — 2026-09-07

## Scope and evidence freshness

This is a **marty-ui repository-only** audit, not workspace-wide cleanup. The
shared Git directory is `marty-workspace/marty-ui/.git`. The final read-only
checkpoint was `2026-09-07T09:21:45Z`. No fetch, switch, reset, merge, commit,
worktree removal, branch deletion, deployment, or configuration change was made.
This document is the only audit file added.

All comparisons use cached `origin/main`:
`f5c4da685f5723a7614649c883bfaa540dd153f1` (#815). Its local reflog last records
`fetch --no-tags origin main: fast-forward` at
`2026-09-05T23:06:57-06:00`. This does **not** establish the current GitHub branch
tip, PR state, remote branch existence, or current owner activity. Refresh that
evidence in the later authorized cleanup workflow before acting.

Commands used were local `git worktree list --porcelain`, status with optional
locks disabled, `for-each-ref`, `rev-list --left-right --count`, `merge-base
--is-ancestor`, `cherry`, reflog/log metadata, and filename/tree comparisons.
No secret values or crypto implementation contents were inspected.

## Counts and protected ownership

- **11 worktrees:** three attached local branches and eight detached checkpoints.
- **All 11 were Git-clean at the initial scan.** At the final checkpoint, the
  active Canvas worktree had the parent's new modification to
  `scripts/test_canvas_worker_compose_render.py`. This is ongoing owned work,
  not an abandoned dirty branch; adding this audit creates another owned file.
- **Three local branches:** `main`, `feat/canvas-review-resolution-v1`, and
  `security/kms-boundary-hardening-v1`.
- **48 cached non-main remote-tracking branches**, excluding symbolic
  `origin/HEAD`. One is an ancestor of cached main; 28 have only patch-equivalent
  non-merge commits according to `git cherry`; 19 have unmatched individual
  patches. Squash equivalence below explains several of those 19, so this is
  not a count of 19 unfinished features.

Paths below are relative to `marty-workspace`. Counts are **ahead / behind**
cached `origin/main`, not merge recommendations.

| Worktree | Local tip | Ahead / behind | Disposition |
| --- | --- | --- | --- |
| `marty-ui` (`main`) | `97bf86a38` | 2 / 31 | **DO NOT DELETE/RESET.** Local crypto work is merged here but not in cached upstream. |
| `_codex-worktrees/marty-ui-canvas-review-resolution-v1` | `f8670830b` | 118 / 0 | **DO NOT DELETE.** Parent owns active PR #814, its CI, and current edits. Cached branch upstream matches this tip. The 118 commits are not marked merged. |
| `_codex-worktrees/marty-ui-kms-security-v1` | `827ab777b` | 1 / 33 | **DO NOT DELETE/MERGE/EDIT.** Separate crypto-worker ownership; coordinate its clean handoff first. |
| `_codex-release-activate-113` | `3bf4cc05d` | 0 / 37 | Historical ancestor; retention/activity review required. |
| `_codex-release-activate-114` | `24f5d5dc0` | 0 / 35 | Historical ancestor; ignored release artifacts present. |
| `_codex-release-activate-115` | `1866528ab` | 0 / 31 | Historical ancestor; ignored release artifacts present. |
| `_codex-release-activate-116` | `89c66b07a` | 0 / 26 | Historical ancestor; ignored release artifacts present. |
| `_codex-release-activate-117` | `4596afaca` | 0 / 20 | Historical ancestor; ignored release artifacts present. |
| `_codex-worktrees/marty-ui-ci-cache-v2` | `cf7930956` | 4 / 1 | Entire tree equals #815's `f5c4da685`; not four missing changes. |
| `_codex-worktrees/marty-ui-ci-next-v1` | `dac18d03e` | 8 / 3 | Entire tree equals #807's `e5c619010`; not eight missing changes. |
| `_codex-worktrees/marty-ui-timing-refresh-v1` | `cbb59f4cf` | 1 / 13 | Sole patch is equivalent on main (`git cherry` reports `-`); #803 is `94c8fc02b`. |

The local-main divergence is substantive: `827ab777b` adds the KMS-reference
trust/BYOK work, followed by merge `97bf86a38`. Its three paths remain different
from cached main: `TrustApiAdapter.jsx`, `TrustApiAdapter.test.ts`, and
`ports/types.js` under `ui/src/components/trust/`. These paths have no current
diff in PR #814 against cached main. Preserve both local references and ask the
crypto owner to review provenance, tests, and integration; a fast-forward-only
main update cannot resolve the two local commits.

## Feature preservation and squash evidence

The UI/demo work reviewed here is not an abandoned dirty implementation:

| Cached ref | Evidence of integration | Capability to retain |
| --- | --- | --- |
| `fix/demo-production-csp-v1` (`2613d89a8`) | Single patch is equivalent on main; #791 `0db570ebf`. | Consented demos and edge analytics under production CSP; keep `ui/nginx.prod.conf` and the CSP regression checks. |
| `fix/ui-native-wasm-csp` (`78d2c5d4d`) | Single patch is equivalent on main; #782 `f20f3e0f5`. | Rust UI WebAssembly loading under CSP. |
| `feat/beta-evidence-transport-v1` (`1c6cadfd8`) | Single patch is equivalent on main; #792 `136a11bfe`. | Lossless Rust evidence bundles, provenance, and their CLI tests. |
| `fix/canvas-worker-renewal-progress-v1` | Entire tip tree equals #799 `9a7b0ad01`. | Worker renewal/heartbeat behavior and the UI inventory test's awaited loaded rows. |

The current PR #814 comparison contains 364 changed paths but no paths under
`ui/`, or paths matching the reviewed demo/recording filename patterns. That is
a scoped filename observation, not a claim that its backend work cannot affect
UI behavior. Its features and pending qualification remain owned by the parent.

Additional **whole-tree equality** checks confirm these cached refs match their
integrated snapshots:

| Cached ref | Equal integrated tree |
| --- | --- |
| `feat/canvas-worker-lossless-config-v1` | #795 `354374618` |
| `fix/lifecycle-private-qualification-v1` | #793 `b1088c997` |
| `release/beta-acceptance-1.1.215` | #783 `1866528ab` |
| `release/beta-acceptance-217-v1` | #794 `4596afaca` |
| `test/canvas-operations-oracle-v1` | #811 `aac7d9377` |

Two historical refs merit a narrow final review instead of blind merging:

- `feat/canvas-job-operations-v1` has 21 of its 23 original changed paths exactly
  matching #813 `04e2ea2c7`; the remaining paths are `.github/workflows/ci.yml`
  and `tests/test_ci_workflow_performance.py`, which changed with intervening CI
  work. Compare those two integration changes before retiring the cached ref.
- `fix/token-exchange-json-storage-v1` matches #785 `895218b40` on all four
  original changed paths. Its Rust implementation and contract-test files also
  still match cached current main; documentation has evolved. Preserve that
  behavior and verify history/owner completion before deleting its remote ref.

Eight cached automation/dependency branches remain separate review candidates:
the monthly Node-toolchain refresh; GitHub Actions group; browser-test
`eventsource`; UI `i18next`, `@mui/x-date-pickers`, and development-tool groups;
Canvas-sandbox `uvicorn`; and the general Python-dependency group. Each has one
unmatched cached patch. Check live PR status and run relevant UI/demo, lockfile,
browser, and retained-Python compatibility gates; do not bulk merge or discard
these updates based on this local inventory.

## Required checks before any later removal

**Git-clean does not mean disposable.** The canonical `marty-ui` checkout has
ignored runtime environment files, `tests/artifacts/`, `tests/demo-recordings/`,
and demo reports. Release worktrees 114–117 also contain ignored
`tests/artifacts/`. Ignored-entry counts were not artifact inventories, byte
counts, or evidence that all data is reproducible. No ignored payloads or
environment values were opened.

1. Obtain each owner's explicit clean-checkpoint/retention confirmation, including
   the parent and crypto-worker exclusions above; verify no worker resumed.
2. Check current CI jobs, recording processes, terminals, Docker bind mounts,
   Compose source paths, and release/rollback references before removing even a
   historical release checkout. This audit did not inspect live process/mount
   ownership and does not authorize changing deployment state.
3. Inventory ignored release evidence and recordings in a scoped follow-up.
   Preserve required provenance and recordings in an approved durable location;
   handle local environment files as secrets, never copy them into Git or logs.
4. Refresh main/PR/branch evidence through the authorized workflow, repeat clean
   status and equivalence checks immediately before action, and retain a
   recoverable reference for anything not conclusively integrated.
5. Review/removal of the eight historical worktrees is a separate authorized
   operation, not an action performed here. Do not use broad recursive deletion,
   force resets, or branch-name matching as a substitute for these checks.

Recommended order: finish the parent-owned PR #814 gates; obtain the crypto
owner's main-divergence handoff; review historical checkpoint activity/artifact
retention; then resolve remaining cached-ref and dependency PR questions.

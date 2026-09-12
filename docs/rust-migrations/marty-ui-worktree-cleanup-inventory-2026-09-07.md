# Local marty-ui worktree cleanup inventory — 2026-09-07

## UI preservation and compatibility hold — 2026-09-08

The later native consumer work reuses the existing lease-expiry worktree on
`feat/canvas-worker-native-consumer-cutover-v1`, based on `14de48dce`.
The superseded `feat/canvas-worker-native-lease-expiry-v1` branch name was
deleted normally only after its exact tip
`662edbc15d008f7fcd1868c52958aa0416644816` was verified as an ancestor of both
the local and pushed PR branch. No worktree files or commits were removed;
the implementation remains recoverable through those retained histories.
This narrow cleanup does not release the unique UI/security references below.

The independent read-only follow-up found local `main` clean: no staged,
unstaged or ordinary untracked changes at
`97bf86a3824ac7e79fb4ff662f4c86c002fa716d`. It retains **two local commits and is
31 commits behind cached `origin/main`**, not a freshly fetched remote. The
comparison uses cached `f5c4da685f5723a7614649c883bfaa540dd153f1`, whose recorded
fetch is `2026-09-05T23:06:57-06:00`. PR checkpoint
`afc8bd754e84104c45ae48e7cc8297125cd7f579` contains that cached main but not local
`97bf86a38`. The older cleanup counts and Canvas/CI heads below are historical;
this bounded update does not re-inventory worktrees or refresh hosted CI.

Unique commit `827ab777bbc11fbf8024ab26889d31a71529df15` is retained by both
`main` and `security/kms-boundary-hardening-v1`; the audit found no other local
reference containing it. Local main merges that commit with
`1866528ab859ea7007ca34671ad80a62131fd79d`. Its unmatched patch changes only:

- `ui/src/components/trust/adapters/api/TrustApiAdapter.jsx`
- `ui/src/components/trust/adapters/api/TrustApiAdapter.test.ts` (new)
- `ui/src/components/trust/ports/types.js`

This is feature work to preserve, not disposable cleanup: the adapter rejects
truthy `privateKeyPem`, requires a trimmed `keyReference`, and sends
`key_reference` instead of `private_key_pem`. Three mocked-fetch unit controls
are present; their existence does not establish backend compatibility or a
passing current test run. No demo files occur in this local-only patch.

**Hold integration and reference deletion pending trust/crypto owner review.**
The adapter's `/v1/organizations/{org}/trust-config/byok` endpoint has no
established matching `key_reference` request contract in the inspected current
Rust routes or relevant frozen gateway/organization/trust contracts. Generic
gateway organization ownership does not establish that an actual deployed
request returns 404. No deployed endpoint was tested. The mock adapter ignores
the input; `TrustProvider` exposes the operation but the audit found no active
UI caller. Existing issuer onboarding uses public certificates plus
`keyLocation.kmsArn`, not a demonstrated translation into this adapter's
`keyReference` contract.

First obtain owner-approved endpoint/schema evidence and an actual authenticated
backend request-contract test proving `key_reference` acceptance, tenant binding
and certificate semantics. Only after that capability proof and ownership
handoff should a separately attributed three-file port and expanded adapter
unit tests proceed. Preserve rejection of private-key material
and existing onboarding/demo features; do not invent an API or remove a feature
to make the patch merge. Clean status is neither owner release nor permission
to reset, delete, deploy or integrate these references.

## Earlier cleanup checkpoint — 2026-09-08 (historical)

Current local inventory is **eight worktrees and four branches**. The reviewed
body reference and application REST repair are composed into retained native
body replay head `fd65082f9424d1fb402cd52d566ffdf2de7581c5`. PR #814 remains at
`2d864723f` while its hosted full CI runs. Neither statement claims a main merge,
whole-worker qualification, feature deletion or deployment.

Three superseded worktrees and their local branch names were removed normally
after independent audit and parent revalidation. Every tip is an ancestor of
retained `fd65082f9` and was additionally archived before removal:

| Removed worktree suffix | Preserved exact head | Archive suffix | Generated caches discarded |
| --- | --- | --- | ---: |
| `marty-ui-canvas-timeout-replay-v1` | `cf5182ef73678b5e0d47cacf23c1f5b38150cd5d` | `timeout-reference` | 19 |
| `marty-ui-canvas-body-timeout-reference-v1` | `acbf9609b2e5ffbc2bc8dd1e2687776fbe49550c` | `body-reference` | 31 |
| `marty-ui-canvas-operation-timeout-repair-v1` | `2d864723f74831d4338e1686c242b1bad534a4b9` | `operation-repair` | 0 |

Worktree paths were below workspace `_codex-worktrees/`; archive refs are under
`refs/archive/worktree-cleanup-20260908/`. Clean tracked/untracked status, exact
heads, ancestor retention, ignored-file inventories and resolved paths were
verified. No live process references or matching mount sources among 206
running/stopped containers were found. Target directories and descendants had
no reparse points. The existing workspace parents carry a non-name-surrogate
Microsoft directory reparse tag, not a link target; the entire ancestor chain
is not described as reparse-free. No force or recursive shell deletion was used.

Only the 50 audited Python/pytest/Ruff cache files were discarded. Source and
history remain recoverable from the retained branch and archive refs. External
raw captures and generated executable evidence remain under `_codex-tmp`.

Remaining branches are `main`, `security/kms-boundary-hardening-v1`,
`feat/canvas-review-resolution-v1`, and `feat/canvas-worker-native-body-replay-v1`.
Keep the two active Canvas worktrees, the main/crypto worktrees and all four
release checkouts 114–117 with their backups and recordings. Crypto ownership
and approved archival/recoverability remain unresolved cleanup requirements.
No claim is made that all repositories are clean or all branches are merged.

## Earlier update — 2026-09-08 (historical, superseded above)

This update supersedes the counts, heads, current ownership and cleanup status
in the dated historical audit below. Scope remains this repository only. The
parent verified live GitHub main at
`f5c4da685f5723a7614649c883bfaa540dd153f1`, matching cached `origin/main`.
No fetch was performed. The read-only audit was followed by the parent-owned
cleanup recorded below.

The removal checkpoint left **eight worktrees and four local branches**, after the
parent removed the separately audited detached deadline-validation checkout and
the four cache-only checkouts below. At their pre-removal audit, all eight
historical checkouts had no tracked modifications or ordinary untracked files,
but all retained ignored files. That is not a claim that
the entire workspace is clean or that ignored files are disposable.

A subsequent clean worktree, `_codex-worktrees/marty-ui-canvas-body-timeout-reference-v1`,
was created at `395cab656` on `feat/canvas-worker-body-timeout-reference-v1` for
parallel streamed-body fixture preparation. Current totals are therefore **nine
worktrees and five local branches**. This is active reference work to preserve,
not an abandoned checkout; no body-worker capture is qualified yet.

Retain both earlier active Canvas branches:

- `feat/canvas-review-resolution-v1` at
  `f0b60073093a89567e43a6fd6452100b2ddc67ec` matches its cached upstream. PR #814
  remains draft; its runtime CI is still in progress at the parent's checkpoint.
- `feat/canvas-worker-timeout-replay-v1` at
  `395cab656f9a3c3063651a2a6c52657b4cdc7884` was clean before this owned inventory
  update and retains three local commits beyond `f0`: `c17f1e1fa`, `e3009a4f5`,
  and `395cab656`. No upstream is
  configured. This is feature-preserving test/qualification work to land, not
  an abandoned branch to discard.

Metadata-only exclusions remain: local `main` at `97bf86a38` is ahead 2/behind
31 relative to cached main; `security/kms-boundary-hardening-v1` at `827ab777b`
is ahead 1/behind 33. Their work contents were not inspected. Preserve the
separate crypto owner's references and obtain its handoff before integration.

### Material release artifacts: preserve checkouts 114–117

These tracked-clean checkouts contain ignored `tests/artifacts/` trees:

| Worktree | Retained head / merged provenance | Ignored artifact files |
| --- | --- | --- |
| `_codex-release-activate-114` | `24f5d5dc0` / #779 | 114 |
| `_codex-release-activate-115` | `1866528ab` / #783 | 95 |
| `_codex-release-activate-116` | `89c66b07a` / #788 | 64 |
| `_codex-release-activate-117` | `4596afaca` / #794 | 207 |

All four heads are ancestors of retained Canvas/main history. Their ignored
files are nevertheless material: filenames include PostgreSQL dumps, OpenBao
archives, Redis/applicant backups, deployment/recovery manifests, signed
transactions and SBOMs. Checkouts 116 and 117 retain KMS-switching `.webm`
recordings; 117 also retains hosted lifecycle evidence. Only filenames and
counts were inspected, never backup, credential, environment or log contents.
Do not remove these worktrees until approved private archival, recoverability,
recording retention and live deployment/rollback references are verified.
No claim is made that these files are duplicated elsewhere.

### Four removed cache-only checkouts, with preserved history

All paths below are relative to `marty-workspace`. The ignored directory names
and recursive regular-file counts were checked with read-only access sufficient
to resolve the initial pytest-cache ACL warnings.

| Removed worktree | Source/provenance evidence | Generated caches discarded after audit |
| --- | --- | --- |
| `_codex-release-activate-113` | Head `3bf4cc05d` is merged #777 and an ancestor of retained main/Canvas refs | `.pytest_cache/`: 4; `scripts/__pycache__/`: 2; `tests/__pycache__/`: 3 (9 total) |
| `_codex-worktrees/marty-ui-ci-cache-v2` | Head `cf7930956` is #815's original head; its whole tree equals merged main `f5c4da685` | `.pytest_cache/`: 4; `.ruff_cache/`: 4; `scripts/ci/__pycache__/`: 1; `tests/__pycache__/`: 7 (16 total) |
| `_codex-worktrees/marty-ui-ci-next-v1` | Head `dac18d03e` is #807's original head; its whole tree equals merge `e5c619010` | `.pytest_cache/`: 5; `tests/__pycache__/`: 4 (9 total) |
| `_codex-worktrees/marty-ui-timing-refresh-v1` | Head `cbb59f4cf` is #803's original head; its sole patch is equivalent on retained main | `.pytest_cache/`: 4; `tests/__pycache__/`: 1 (5 total) |

Current read-only GitHub PR metadata independently confirms:

- [#777](https://github.com/ElevenID/marty-ui/pull/777) is merged at
  `2026-09-04T21:43:51Z`; merge commit
  `3bf4cc05d719161a0dc026351ca6f4f12075179a`, original PR head
  `57cb7b38dadc5ebff0143b1836cc8d74fa77bc37`.
- [#815](https://github.com/ElevenID/marty-ui/pull/815) is merged at
  `2026-09-06T04:49:01Z`; original head
  `cf7930956809a68959f69b2a1e59a8fd7a2e3349` and merge `f5c4da685` share tree
  `e8f2e09a394cacb29a13596519a815c0fa2f5b43`.
- [#807](https://github.com/ElevenID/marty-ui/pull/807) is merged at
  `2026-09-05T21:19:19Z`; original head
  `dac18d03e65f1f9502efdc36815896778bed2fd0` and merge
  `e5c61901015a7e4ebb30e1ce4bee9ba75500f7b2` share tree
  `9bc996817132c3ba47933aea65c32563e1947f30`.
- [#803](https://github.com/ElevenID/marty-ui/pull/803) is merged at
  `2026-09-05T16:01:52Z`; original head
  `cbb59f4cf5e66baf8b675c21e0bbedce4a749c7c`, merge
  `94c8fc02b85854c290a18eb5b6f06756cb7fd7e9`. `git cherry` reports its patch
  equivalent; the affected paths are the timing-refresh workflow and its test.

PR head metadata records provenance; it does not prove a corresponding remote
branch still exists. Whole-tree/patch equivalence means no missing final source
feature was found in these checkouts. Before removing them, the parent found no
other process command line referencing their exact paths and no matching bind
mount or Compose source label among 210 inspected running/stopped containers.
A tracked documentation/script/workflow search found audit references only.
The parent rechecked exact resolved targets, unchanged heads, clean ordinary
status, all 39 ignored files against the audited cache directories/counts, and
absence of reparse points. Normal `git worktree remove` succeeded for all four;
no force or recursive shell deletion was used, and all four paths are absent.

Every original checkout commit was retained before removal in local Git refs
under `refs/archive/worktree-cleanup-20260908/`:

- `release-113`: `3bf4cc05d719161a0dc026351ca6f4f12075179a`
- `ci-cache-v2`: `cf7930956809a68959f69b2a1e59a8fd7a2e3349`
- `ci-next-v1`: `dac18d03e65f1f9502efdc36815896778bed2fd0`
- `timing-refresh-v1`: `cbb59f4cf5e66baf8b675c21e0bbedce4a749c7c`

These are local archive refs, not new branches or release tags. They preserve
intermediate history as well as final source, and can be passed to
`git worktree add --detach <new-path> <archive-ref>` to recreate a checkout.
The 39 deleted cache files are regenerable; no backup, recording, runtime
configuration, feature source, branch or tag was discarded. Release checkouts
114–117 and both crypto-owned local references remain untouched.

## Historical audit — 2026-09-07 (superseded where stated above)

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

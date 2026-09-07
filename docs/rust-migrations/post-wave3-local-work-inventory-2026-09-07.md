# Post-Wave-3 local work inventory - 2026-09-07

This bounded read-only audit identifies work to preserve, reconcile or retire.
It does not establish global workspace cleanliness, authorize deletion, or prove
that every feature is merged. No fetch, branch mutation, source change, merge,
deployment or deletion was performed by the audit. Secret contents and source
diff contents were not inspected.

All paths below are relative to
`C:/Users/maree/OneDrive/Glthub/marty-workspace`. Ahead/behind counts compare
the observed checkout with **cached `origin/main`**, not freshly fetched GitHub
state. Counts and clean statuses are snapshots, not owner-liveness evidence.
Squash history can produce apparent divergence without unique code.

## 1. Preserve work before reconciling branches

| Path and branch | Observed state | Required next action |
| --- | --- | --- |
| `marty-authenticator`, `main` | Ahead 3 / behind 1; modified `lib/model/version.g.dart` | Explain and preserve generated-file change; reconcile wallet bridge, biometric-provider lifecycle/initialization errors and policy sync work with protected main. |
| `artifacts/dry-merge-authenticator`, `refactor/dry-merge-ready` | Clean; ahead 8 / behind 1, head `e514399` | Review wallet UTF-8 manifest repair, shared discovery/request APIs, authorization tests and generator/dependency alignment; land or prove equivalent without losing behavior. |
| `artifacts/dry-authenticator-sync`, `refactor/authenticator-core-alignment` | Separate Git checkout; clean; ahead 1 / behind 29, head `91b58e7`; absent from primary authenticator worktree registration | Reconcile explicitly; primary worktree enumeration alone does not cover this checkout. |
| `_codex-worktrees/marty-credentials-sdjwt-pin-2799-v1`, `chore/sd-jwt-pin-2799-v1` | Ahead 0 / behind 14; modified `Cargo.toml` and `Cargo.lock` | Establish dependency-work owner and intended pin; retain both edits until compared and tested. |
| `worktrees/marty-core-credentials-native`, detached `dce4fb9` | Ahead 0 / behind 53; modified `Cargo.lock` | Reconcile the lockfile edit before treating this ancestor checkout as disposable. |
| `worktrees/marty-demo-recorder-governance-lock` | Source snapshot with `demos`, `publication`, `schemas`, `scripts`, `src`, `test` and other source files, but no `.git` metadata | Preserve and compare with canonical recorder history and evidence. Git cannot prove this snapshot merged. |

## 2. Coordinate divergent implementation work with its owners

| Path / branch | Cached divergence and relevant work |
| --- | --- |
| `marty-ui`, `main` | Clean; ahead 2 / behind 31. Local commits concern the KMS trust boundary. |
| `marty-credentials`, `main` | Clean; ahead 8 / behind 8. Shared Python adapters, credential-offer formatting and KMS/security work. |
| `artifacts/dry-merge-credentials`, `refactor/dry-merge-ready` | Clean; ahead 4 / behind 4. Shared adapter and reviewed-core alignment. |
| `artifacts/rust-quality-credentials`, `refactor/rust-quality-next` | Clean; ahead 8 / behind 3. Exception compatibility, typed JWK admission, shared signing/normalization and diagnostics. |
| `marty-core`, `main` | Ahead 43 / behind 7; modified tracked `marty-verification/python/marty_verification_py/__pycache__/__init__.cpython-313.pyc`. |
| `artifacts/dry-high-priority-core`, `refactor/dry-high-priority` | Clean; ahead 20 / behind 7. |
| `artifacts/dry-merge-core`, `refactor/dry-merge-ready` | Clean; ahead 13 / behind 7. |
| `artifacts/rust-quality-core`, `refactor/rust-quality-next` | Clean; ahead 8 / behind 5. |

These commit counts do not prove that the corresponding features are absent
from protected main. Determine exact patch/tree equivalence, PR outcomes and
behavioral coverage before choosing a landing or retirement action.

Crypto ownership is active. During the audit,
`_codex-worktrees/audit-crypto-20260906-marty-core` changed branch label from
`security/crypto-boundaries-v2` to `security/audit-followups-20260906` at head
`9291ade`. Leave it and the related `security/kms-boundary-hardening-v1`
worktrees in core, credentials and UI untouched pending owner coordination.
Do not fold crypto work into migration cleanup or discard local main divergence.

The parent-owned `_codex-worktrees/marty-ui-canvas-review-resolution-v1`
is also active. Following the audit's initial clean snapshot at `d059995bd`,
the next resources-unavailable capture introduced intentional edits to
`canvas_published_schema_contract.rs`, `canvas_published_database.rs` and
`prepare_canvas_published_schema.py`. Those edits are implementation WIP, not
abandoned work. This inventory is not a declaration that that worktree is clean.

## 3. Verify operational roles before retiring equivalent or ancestor worktrees

| Path | Evidence available | Remaining check |
| --- | --- | --- |
| `_codex-worktrees/marty-ui-ci-cache-v2`, detached `cf7930956` | Exact tree match with cached UI `origin/main`, despite ahead 4 / behind 1 | Confirm current owner, merged PR/evidence and no runtime/artifact role. |
| `_codex-worktrees/marty-credentials-canvas-privacy-v1`, detached `0b62d22` | Exact tree match with cached credentials `origin/main`, despite ahead 2 / behind 1 | Preserve any qualification/evidence role; confirm owner checkpoint. |
| `_codex-worktrees/marty-ui-timing-refresh-v1`, detached `cbb59f4cf` | Commit is patch-equivalent to cached main | Check evidence and owner role before retirement. |
| `_codex-release-activate-113` through `_codex-release-activate-117` | Clean; each has zero commits ahead of cached UI main | Check deployment, immutable release evidence and rollback dependencies. |
| `worktrees/marty-demo-membership-badge-review` | No `.git`; only `node_modules` at top level | Confirm no owner/tool dependency before removing disposable installation data. |
| `_codex-worktrees/marty-ui-verification-candidate-empty-layer-v1` | Empty directory; no `.git` | Confirm no owner reference before removal. |

Exact tree or patch equivalence is **not deletion approval** and does not prove
that worktree-local artifacts, recordings or operational roles are dispensable.
Retirement requires current path validation, owner checks and preservation of
required evidence.

Do not yet classify `_codex-worktrees/marty-ui-ci-next-v1`, detached
`dac18d03e`, as equivalent: it is clean but ahead 8 / behind 3 and its complete
tree differs from cached main. Its CI work relates to merged PR #807, but
individual patch comparison did not establish squash equivalence.

## Feature and acceptance boundaries

`marty-demo-recorder/main` is clean and matches cached `origin/main` at
`7858b58` (`feat(recorder): wire private Rust deployment evidence intake (#41)`).
UI history contains landed demo/UI preservation changes and CSCA lifecycle,
renewal and managed P-521 repairs. No separate pending CSCA branch was found in
the inspected UI branch list. This does not close the CSCA lifecycle-manager
follow-up, device-wallet behavior, all-demo acceptance or the beta soak.

Prioritize preservation and owner reconciliation above branch-count reduction.
After that, use clean worktrees to review, test and land any genuinely missing
features, favoring shared Rust implementations. Delete superseded code only
after its behavioral gates pass. Keep production unchanged.

## Audit scope and uncertainties

Inspected all 11 registered UI worktrees and all 7 credentials worktrees;
recorder primary; authenticator primary and relevant DRY checkouts; and the
core worktree registry plus eight selected primary/crypto/DRY/native checkouts.
Directory names identified the unregistered demo snapshots above. The audit
did not inspect every core branch or unrelated repository.

Two credentials checkouts emitted permission warnings for pytest-cache
directories, qualifying their otherwise clean Git status. No unreadable cache
was removed. Remote PR state, release evidence and current owner intentions
must be verified separately before taking cleanup actions.

## Focused follow-up: unregistered recorder governance snapshot

Compared `worktrees/marty-demo-recorder-governance-lock` with the clean canonical
`marty-demo-recorder` at `7858b5843306fbb08e441340f702d9ac3f3f4e21`. Scope was
43 files: JavaScript/JSON/PowerShell source under `src`, `scripts`, `test` and
`schemas`, plus `package.json`, `package-lock.json` and `governance.lock.yaml`.
No secret files, installed dependencies, build/media/recording artifacts or raw
data were inspected. Demo configuration/publication snapshots outside this
scope remain unqualified for retirement.

Hash/name comparison found **no snapshot-only file in this selected set**:
21 files match canonical bytes, five differ only in line endings and 17 have
content differences. More importantly, **42 of the 43 files match historical
commit `15cf3315f9f33120f20e638a0e11634cc8e790f1`** after normalizing line endings
and terminal newlines. That commit (`docs: pin commercial governance contract
(#7)`) is a verified ancestor of current canonical HEAD. The only non-matching
historical file is `package-lock.json`.

Selected source review found retained or expanded behavior, not unique unlanded
UI/demo-creation/governance source in the snapshot:

- Publication policy, automated publication, rebound attestation and governance
  lock contents are retained; the latter differs only in line endings.
- Recorder hook loading and template resolution moved into shared `scenario.js`;
  browser recording remains alongside native Tauri and external qualification.
- Android deep-link, accessibility-tap and text-assertion operations remain;
  current code adds stronger device/profile binding and additional actions.
- Composition retains its original call arguments and device capture while
  adding multiple-device inputs, narration, editing and disclosure support.
- Current release binding adds exact deployment/source/image checks; Canvas
  portability adds correction/review scenarios. Media duration now prefers the
  video stream's duration over container duration, with the reverse fallback.
- All 58 single-quoted test names extracted from the snapshot's ten test files
  still occur in their corresponding canonical files. This is a preservation
  signal, not a claim that the tests ran or that behavior is fully equivalent.

The snapshot lockfile contains 130 package entries versus 117 at the historical
commit, with different dependency nesting and some version resolutions. The
package manifest itself matches that historical commit. This does not establish
why the lockfile changed, which dependency state is preferable, or that either
state is security-qualified. Do not overwrite the canonical lockfile with it.

Next action: retain the snapshot pending owner confirmation, reconcile its
lockfile intent separately, and check the excluded demo/publication/evidence
files before retirement. No missing implementation was identified in the
selected source set that warrants a new port or merge. This bounded result is
not blanket feature-parity proof, acceptance evidence or deletion approval.

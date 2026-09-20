# Feature-preserving branch cleanup — 2026-09-06

## Current follow-up — 2026-09-20

PR #814 merged through the protected queue as
`ec7780f390b4ae123cf6d0bdf0f5d139000ab544`. A fetch of protected
`origin/main` proved that its landed tree and the reviewed candidate tree are
both `eeaa080d5ddc342b1e70fdf3680e7d838712289c`. Each of the nine gated
worktrees was then rechecked for an empty porcelain status and a path beneath
the intended `_codex-worktrees` root. The #814 source worktree and all eight
historical mapped worktrees were removed, followed by their nine superseded
local branch names.

A post-cleanup `git worktree list` reports exactly four `marty-ui` worktrees
and four local branches: local `main`, Application Template PR #826, internal-
Application PR #827, and separately owned
`security/kms-boundary-hardening-v1`. All four were clean at the checkpoint.
PR #826 was then rebased onto protected `main` with an identical complete tree,
and PR #827 was restacked on that head with an identical complete tree. Local
`main` and the KMS branch remain otherwise untouched because their preserved
KMS work is outside this migration landing. The separate workspace-wide
inventory still records five dirty worktrees owned by the crypto/SD-JWT effort;
none is a `marty-ui` worktree and none is authorized for cleanup here.

The dated sections below are retained as historical audit evidence. Their
then-current counts are not the present inventory.

## Current follow-up — 2026-09-08

The superseded timeout, body-reference and operation-repair worktrees and their
three local branch names are now retired. All commits are ancestors of retained
`fd65082f9424d1fb402cd52d566ffdf2de7581c5` and have additional local archive refs.
Only 50 verified generated cache files were discarded after clean-status, path,
ancestry and live-use checks; no source feature or retained capture was lost.
The [current inventory](marty-ui-worktree-cleanup-inventory-2026-09-07.md) records
the exact tips, archive names and retention boundaries.

Current counts are eight worktrees and four local branches: active PR #814,
native body replay, main and crypto. Release checkouts 114–117 remain intact.
The new native replay is locally tested but awaits hosted qualification; its
ancestors being consolidated does not mean they are merged into main. This is
not all-repository cleanup completion or deployment approval.

## Earlier follow-up — 2026-09-08 (historical)

The three detached CI/timing checkouts below and release checkout 113 have now
been removed after source-equivalence, ignored-cache and live-use checks. All
four original commits remain in local `refs/archive/worktree-cleanup-20260908/`
refs; no intermediate history or feature was lost. Only 39 generated cache
files were discarded. See the [current inventory](marty-ui-worktree-cleanup-inventory-2026-09-07.md)
for exact archive refs, checks and retained release backups/recordings.

The removal checkpoint left eight worktrees and four local branches. Both Canvas branches retain
their unlanded qualification work; local main and the separate crypto branch
remain unchanged. A subsequent clean body-timeout reference worktree/branch was
created at `395cab656` for parallel fixture preparation, bringing current totals
to nine worktrees and five local branches. That active work must be preserved.
This is still not an all-repository cleanup completion claim.

## Historical branch-name retirement — 2026-09-06

Scope: local `marty-ui` Git branch inventory only. This is not an all-repository
cleanup completion claim. No source files, ignored files, demo evidence, release
worktrees, tags or commits were deleted.

The following worktrees were verified clean at the exact PR heads. GitHub reports
their PRs merged, and their remote branch names no longer exist. Because the PRs
were squash-merged, their original tips are not ancestors of local main. Each
worktree was therefore detached at its exact existing tip before retiring only
the obsolete local branch name. All original commits and files remain available.

| Retired local name | Merged PR | Preserved worktree and detached tip |
| --- | --- | --- |
| `perf/ci-cache-reuse-v2` | [#815](https://github.com/ElevenID/marty-ui/pull/815) | `_codex-worktrees/marty-ui-ci-cache-v2`, `cf7930956809a68959f69b2a1e59a8fd7a2e3349` |
| `perf/ci-rust-cache-and-timings-v1` | [#807](https://github.com/ElevenID/marty-ui/pull/807) | `_codex-worktrees/marty-ui-ci-next-v1`, `dac18d03e65f1f9502efdc36815896778bed2fd0` |
| `fix/ci-timing-refresh-no-artifacts-v1` | [#803](https://github.com/ElevenID/marty-ui/pull/803) | `_codex-worktrees/marty-ui-timing-refresh-v1`, `cbb59f4cf5e66baf8b675c21e0bbedce4a749c7c` |

Remaining local branch names are `main`, the active
`feat/canvas-review-resolution-v1`, and the other worker's
`security/kms-boundary-hardening-v1`. The crypto branch and its files were not
modified or inspected for private reproductions. Five detached release-activation
worktrees remain retained as release/deployment evidence.

Local main was clean at `97bf86a3824ac7e79fb4ff662f4c86c002fa716d` when inspected.
This does not assert current beta health or fresh protected-main acceptance.
Other repositories, feature-bearing work, release evidence and final migration
branch retirement still require their own review before cleanup. A retired name
can be recreated at its preserved detached tip if needed.

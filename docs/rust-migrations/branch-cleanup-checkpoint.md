# Feature-preserving branch cleanup — 2026-09-06

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

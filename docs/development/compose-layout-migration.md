# Compose layout migration

## Implemented first deployment batch

Starting from `d23538d7c7a7c20e06cd202fd81b6505eecd82a7`, move two local-only
root overlays into `deploy/compose/development/` without changing their YAML:

| Former root filename | Caller updated in this batch |
| --- | --- |
| `docker-compose.worktree-dev.yml` | `scripts/dev/worktree_stack.py` |
| `docker-compose.passport-supported-disposable-watch.yml` | `scripts/passport_local_watch.py` |

The [Compose index](../../deploy/compose/README.md) links to the canonical files.
The helper interfaces, first/base Compose files, merge order, port values,
project identity, environment handling, and teardown semantics are unchanged.
No compatibility copies or symlinks remain at the old paths. This deployment
batch is independent of the earlier documentation-only organization PR.

## Audited boundaries

**Relative paths.** `worktree_stack.compose_command` explicitly selects the
repository project directory. `passport_supported_infra_rehearsal._compose_args`
selects the root-level disposable base first and supplies an explicit environment
file. The local watcher appends its overlay after that base/surface pair. Keep
those rules when adding future overlays; do not rebase the watcher's build
context or source bind to `deploy/compose/development`.

**Published self-host bundle.** The
[self-host bundle descriptor](../../deploy-config/bundles/selfhost.json) selects
assets and render inputs explicitly. Neither moved overlay nor either local
launcher is listed. Its production/OpenBao/render inputs and asset paths are
unchanged in this batch. This is an inspected descriptor boundary, not a new
built-bundle or installation qualification result.

**CI selection.** `scripts/ci/affected_components.sh` explicitly recognizes root
Compose files, but also selects the full suite for unknown paths. The new
`deploy/compose/` paths therefore retain conservative selection. No workflow,
required-check setting, or matrix narrowing is needed for this move.

**YAML discovery.** The existing conformance duplicate-key test scans only root
Compose files. The new layout test additionally scans nested `.yml` and `.yaml`
files under `deploy/compose/`, including mappings containing Compose tags.
Root-only environment-discovery loops in `test_compose_memory_limits.py` and
`test_beta_passport_selector.py` need review before their own rendered inputs
move. The moved watcher has no interpolation variables; the worktree helper
supplies its `WT_*` variables itself.

Indexed filename searches identified the two callers above. They are not a
complete checkout-wide or cross-repository reachability proof. Subsequent batches
must repeat source and consumer searches against their exact current base.

## Validation scope

The selected source blobs were verified against GitHub blob hashes before
editing. Only the two caller path literals change; the overlay blobs are reused.
Existing worktree tests and the new layout tests are runnable with:

```sh
python -m pytest -q tests/test_worktree_stack.py tests/test_development_compose_layout.py
```

The Docker-enabled layout tests render the real overlays against synthetic base
services at both the old and new locations. They perform no pulls, container
starts, credentials provisioning, or production operations. A skipped Docker
test is not a passing render comparison. Full source-stack rendering and a live
disposable smoke test remain required before claiming deployment acceptance.

## Remaining deployment batches

| Group | Dependencies to migrate and validate together |
| --- | --- |
| Conformance/local-native profiles | `scripts/conformance_stack.py`, policy and isolation tests, exact binary/image bindings, and documentation. Preserve base-file ordering and isolation-last behavior. |
| Development/base/UI profiles | `Makefile`, shell/PowerShell helpers, workflow path selection, Docker contexts, environment discovery, and cross-repository consumers. |
| Self-host and installer definitions | `deploy-config/bundles/selfhost.json`, Rust deployment-catalog/selfhost-bundle crates, package/nightly generators, native operator inputs, and installer contract tests. Preserve emitted bundle filenames separately from source filenames. |
| Snapshot fixtures | Native-owner regression scripts, pinned snapshot hashes, and CI obligation manifests. Do not regenerate expected models merely because source files moved. |

Keep each batch reviewable and run before/after model comparisons for its
supported combinations. Production and installer paths must not move until the
packager distinguishes source paths from emitted asset paths and the published
layout is verified unchanged. No release dispatch, new infrastructure, or
upstream-fork reorganization is part of this work.

# Compose source organization

This directory groups Compose source files by purpose. It is not a new installer
or a replacement for the published bundle layout. The initial `development/`
files are local-only overlays, not standalone stacks or protected evidence.

## Development overlays

| Overlay | Supported caller |
| --- | --- |
| [Worktree port isolation](development/docker-compose.worktree-dev.yml) | [scripts/dev/worktree_stack.py](../../scripts/dev/worktree_stack.py) |
| [Disposable passport Rust watcher](development/docker-compose.passport-supported-disposable-watch.yml) | [scripts/passport_local_watch.py](../../scripts/passport_local_watch.py) |

Run the existing helpers; their command-line interfaces are unchanged. For the
worktree helper, the repository-root command remains:

```sh
python scripts/dev/worktree_stack.py config
```

This validates configuration without starting containers. The passport watcher
still requires its existing release-matched disposable plan and manifest; moving
its overlay does not remove those checks or make it a customer installer.

The worktree helper starts only PostgreSQL and Redis. Compose still interpolates
the full base file, so the helper supplies deliberately unusable application-only
image, managed-key endpoint, and secret-file values for rendering. It creates no
certificate or token files and imports no other stack's service credentials.
Starting application services requires their normal managed-key configuration.

On Linux, both helpers preserve an existing rootless Docker daemon at the current user's
`/run/user/<uid>/docker.sock`, after checking the private runtime directory and
socket ownership. Remote Docker hosts and context overrides are discarded. The
selected endpoint stays fixed for the process and is rechecked before Docker
calls; a missing, unsafe, or replaced rootless socket fails closed. Hosts without
a rootless selection retain the existing local `/var/run/docker.sock` default.
The worktree helper keeps its existing Docker Desktop lookup on Windows while
discarding ambient host/context overrides. The helpers never start a daemon.

## Path and ordering contract

Do not pass these overlays as the first or only Compose file. All relative build
contexts and bind sources remain relative to the repository root:

- The worktree helper retains `--project-directory <repository>` and the
  root-level base and development profile before its relocated overlay.
- The passport helper retains the root-level disposable base as its first
  `-f` argument, its selected surface, and its explicit environment file. The
  watcher overlay remains last for startup, replacement, and teardown.

Docker [resolves relative paths from the first Compose file unless a project
  directory overrides it](https://docs.docker.com/reference/cli/docker/compose/).
Changing only an overlay's location does not justify rebasing `context: .` or
`.:/workspace:ro` to its new folder.

There are no root-level copies or symlink aliases for the relocated files.
Other Compose definitions remain at their established paths until their callers,
packaging contracts, and rendered models are migrated together.

## Validation

[Layout tests](../../tests/test_development_compose_layout.py) check canonical
locations, caller paths, and duplicate YAML mapping keys throughout this tree.
Docker-enabled tests compare the real overlays at old and new locations against
synthetic base services, from outside a checkout whose name contains spaces.
They check watcher build/bind paths and worktree isolation. These are bounded
path-resolution tests, not a complete product deployment or installer rehearsal.

See the [migration audit](../../docs/development/compose-layout-migration.md)
for the remaining work and release-layout constraints.

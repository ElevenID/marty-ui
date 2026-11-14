# Compose source organization

This directory groups Compose source files by purpose. It is not a new installer
or a replacement for the published bundle layout. The initial `development/`
files are local-only overlays, not standalone stacks or protected evidence.

## Development overlays

| Overlay | Supported caller |
| --- | --- |
| [Worktree port isolation](development/docker-compose.worktree-dev.yml) | [scripts/dev/worktree_stack.py](../../scripts/dev/worktree_stack.py) |
| [Disposable passport Rust watcher](development/docker-compose.passport-supported-disposable-watch.yml) | [scripts/passport_local_watch.py](../../scripts/passport_local_watch.py) |

Run the supported helpers. For the worktree helper, the repository-root command
remains:

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

### Prepare the disposable passport watcher

Prepare its local dependency image before obtaining or consuming the disposable
plan's lease:

```sh
python scripts/passport_local_watch.py --prepare \
  --private-forks-token-file /absolute/private/passport-reader
```

The reader file must be a current-user-owned regular file, mode `0600`, in an
owned mode-`0700` directory outside the checkout, without symlinks or writable
ancestors. It needs the existing Contents-read access to the three private forks
described in [Native build access](../../docs/private-native-builds.md). The
launcher checks the file before preparation. Only the short-lived fetch
container receives it, as a read-only bind at the canonical helper's secret
path. The credential is never a build argument, image environment variable,
builder input, or application mount.

An existing authorized Cargo cache can supply the same locked Git sources when
a reader file is unavailable. Create a private parent directory outside the
checkout, then export the exact objects and prepare from that directory:

```sh
python scripts/passport_watch_git_seed.py \
  --cargo-home /absolute/authorized/cargo \
  --output /absolute/private/watch-seed-inputs/source-seed
python scripts/passport_local_watch.py --prepare \
  --git-source-seed /absolute/private/watch-seed-inputs/source-seed
```

The output parent must already be owned by the current user and mode `0700`,
with canonical paths and safe ancestors. The exporter reads only the supplied
cache's Git objects and shallow boundaries through fresh configuration-free
views. It creates new minimal bare databases, a complete file inventory, and a
manifest bound to the original lockfile, every locked Git revision/tree, and the
RDF gitlink derived from the locked SSI tree. Original Git configuration, hooks,
credentials, alternates and replacement refs are excluded. A partial-clone cache
is usable only if all required objects are already present; it is never hydrated
from a remote during export. Missing objects fail closed. The bounded seed is
at most 128 MiB and 8192 data files; its directories are mode `0700` and files
mode `0600`, without symlinks or hardlinks. Keep it private when transferring it
through an authorized route; it contains private dependency source.

`--git-source-seed` and `--private-forks-token-file` are mutually exclusive.
The launcher validates and privately copies a seed before Docker receives it.
Only the bounded fetch container mounts that copy, read-only. Imports use fresh
Git views with no input configuration. Git network transports and credential
helpers are disabled while Cargo fetches public crates.io packages against the
unchanged lockfile checksums. The separate offline phase verifies resolution,
all locked Git checkout contents and the nested RDF checkout before writing
seed markers. The original input directory is preserved; only owned staging is
removed. Neither preparation mode changes Cargo URLs or the lockfile.

Preparation uses the existing daemon's default local builder and discards
ambient builder-routing overrides. Probe, fetch and offline verification run in
three ordinary rootless containers, each with one CPU, 2 GiB RAM, no swap and at most
128 processes. Preparation inspects each container before starting it and checks
its actual cgroup values before fetching. All three have a read-only filesystem,
dropped capabilities and a bounded temporary filesystem. The pinned Rust image
already contains the required tools; preparation installs no packages.
The first container checks these tools and limits without a reader, network or
writable cache before the fetch container is created.

With a reader file, the canonical private-fork helper performs the locked fetch.
With a Git seed, Cargo fetches the public registry using the imported objects.
Neither path compiles.
A separate network-disabled container, without the reader mount, proves the
exact workspace can fetch offline. Each receives only a read-only snapshot of
tracked Rust files and the required helpers/recipe, excluding local Git, Cargo,
environment, build and log state. Stage new Cargo manifests before preparation;
missing or redirected inputs fail closed. The final image recipe copies only
the verified registry/Git caches and executes no `RUN` instructions: rootless
BuildKit can discard per-step resource limits. Newly created preparation
containers and private source/cache directories are removed after use; a private
diagnostic log remains. The resulting local image contains private dependency
sources; do not push it or export its build cache.

Ordinary startup still requires the release-matched plan and manifest, the
existing source-matched native model policy, managed signer/certificate checks,
and project ownership. The launcher checks the prepared image before staging
inputs and uses its immutable image ID with `--no-build`. Missing or stale
preparation fails before application startup. Source-reader environment values
are discarded before policy or runtime commands.

The image seeds this project's initially empty registry and Git volumes.
Compilation runs offline, with one Cargo job, one CPU, 4 GiB RAM, and no swap;
these caps do not establish that the complete stack fits a particular host.
Migration retains its private network. Ordinary Rust edits remain watchable.
Changes to Cargo manifests, the lockfile, or the preparation recipe require
preparation and a fresh disposable project: existing volumes obscure a rebuilt
image's seed and are never silently replaced. Seed markers and volume labels
reject mismatches, including dependency changes before a watched rebuild.
The existing `--resume --stop` path remains available for an old or expired
project without requiring a prepared image.

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

# Installer bootstrap

The GitHub-hosted bootstrap selects a release, authenticates its deployment
operator and launches that operator. The new-install boundary requires a
nonroot Linux amd64 process with no-new-privileges and an already-running,
user-owned rootless Docker daemon. macOS, Windows and other architectures are
not supported.

**Provisioning is currently held.** This source can authenticate the selected
operator and inspect the rootless prerequisite, then refuses before persistent
installation state or Docker resource creation. It is not yet the working
one-line stack trial for outside testers. The on-target storage canary and its
recovery path must be connected before that trial is published.

The development invocation puts the entire download-and-script pipeline under
no-new-privileges and propagates download errors:

```sh
/usr/bin/setpriv --no-new-privs -- bash -o pipefail -c 'curl -fsSL https://raw.githubusercontent.com/ElevenID/marty-ui/main/install.sh | sh -s -- --channel nightly'
```

Use `--channel stable` for stable releases, or `--version TAG` for an exact
version. These selectors are mutually exclusive. `--install-dir ABSOLUTE_PATH`
and `--yes` are forwarded to the verified operator. `--help` works without
Docker or platform detection.

The exact-tag candidate command has the same boundary. Both tag placeholders
must name a newly published nightly containing this implementation; historical
nightlies can contain the older rootful path:

```sh
/usr/bin/setpriv --no-new-privs -- bash -o pipefail -c 'curl -fsSL https://github.com/ElevenID/marty-ui/releases/download/vX.Y.Z-nightly.YYYYMMDD.RUN_ID/install.sh | sh -s -- --candidate-test vX.Y.Z-nightly.YYYYMMDD.RUN_ID'
```

The initial script is fetched over HTTPS and executes before its own bytes can
be independently verified. It authenticates the signed inventory and operator
before executing that operator. The current storage hold stops before the
remaining payload preparation and provisioning stages. Candidate scope grants
neither installer admission nor Ready status. Normal `--version` and `--channel`
paths continue to require signed admission.

No source checkout, organization credentials or separate download package is
needed for this command shape. Use disposable identities and data on a fresh
disposable VM. Once the trial is enabled, the operator will print its private
random installation path under HOME; `--install-dir` remains an optional absolute
override. Send the first failing stage, exit status, OS/architecture, RAM/disk,
Docker/Compose versions and redacted error text to the person who invited you,
or [issue #1350](https://github.com/ElevenID/marty-ui/issues/1350). Do not share
secret values or raw credential diagnostics.

## Requirements and release availability

Run as a regular Linux amd64 user with trusted preinstalled `setpriv`, Bash,
curl, Docker client and Compose plugin. The daemon must already be rootless and
accessible only through that user's `/run/user/<uid>/docker.sock`. Explicit
context overrides, foreign sockets, rootful daemons and userns-remap mode are
refused. The installer does not use sudo, install OS packages, start a daemon,
configure subordinate IDs or change host CA trust. Any earlier runtime or host
policy setup is a separate prerequisite. It does not remove the user's unrelated
group memberships or claim to sandbox all their existing authority.

The bootstrap uses private temporary verification-tool and Docker-config files,
then downloads pinned verification tools. It requires no repository checkout or
build toolchain. Provisioning, when enabled, will create private state and owned
Docker resources; ordinary uninstall retains recoverable data and images. The
current rootless boundary stops before those persistent changes.

Normal version/channel installation requires signed admission and an
authenticated operator. Channel selection also requires valid signed channel
metadata. Experimental candidate selection instead requires an exact signed
nightly inventory and authenticated operator; it grants no admission. Invalid
required metadata refuses execution. Artifact publication alone does not
establish deployment readiness or channel availability.

## Platform adapters

`install.sh` keeps release selection and authentication shared. Its closed
platform selector maps Linux `x86_64` and `amd64` host names to `linux/amd64`.
Every other OS/architecture pair stops before prerequisite checks, Docker calls,
temporary staging or downloads.

Each adapter selects its host preflight, checksum implementation, operator asset,
admission platform, verification-tool URLs, literal SHA-256 pins, size limits and
archive member together. Host strings and environment variables cannot supply
download URLs or trust anchors. Adding another platform requires its matching
operator and release metadata, reviewed tool pins, host adapter and executable
bootstrap tests. A future native Windows entry point would need a PowerShell
adapter; this POSIX shell script does not claim Windows support.

## Deployment operations

### Applicant state ownership

The applicant implementation runs the service as the image's UID/GID 10001.
Its rootless host mapping remains subject to the storage gate above.
The installer keeps the installation and parent state directories private to
the host operator. It provisions only the applicant child directory for the
service's exact nonzero supplemental group and checks that owner, group, and
mode again before application startup. The applicant store is written through
a group-readable temporary file and atomic rename, so the installer can still
read its state for backup and recovery.

Do not apply the new Compose model directly to an existing installation whose
applicant directory or JSON store was created by the former root-running
container. The installer does not adopt an existing directory, and this change
does not include an automatic self-host upgrade. A separate reviewed migration
must first stop the exact owned applicant writer, prove there are no other
volume consumers, take and verify a complete backup, reject links or unexpected
entries, bind the original file hash and ownership, change only the exact
applicant directory and store to the selected owner/group and bounded modes,
then verify unchanged bytes and a real UID 10001 read/write/restart. If any
precondition or readback fails, preserve the backup and stopped installation
for explicit recovery. Do not recursively change the installation or state
parent permissions.

### Inspecting removal

For an installation with a fully recorded runtime, or the specifically proven
pre-application cleanup boundary, inspect the scoped ordinary-uninstall actions:

```sh
/absolute/install-dir/marty-deploy uninstall plan --install-dir /absolute/install-dir
```

The JSON preview lists each verified container ID and the network ID that
ordinary uninstall would remove. It identifies the installation directory,
including its state, credentials, backups and evidence, and any Redis socket
volume as retained. Images are also retained. The preview writes no cleanup
receipt or installation file and issues no Docker mutation. It is a point-in-time
inspection; a later uninstall repeats ownership and scope checks and may refuse
if resources changed. It also summarizes the known host storage roots by
category, file and directory count, and observed bytes without printing child
filenames or file contents. This inventory is not an atomic snapshot, omits
unknown top-level artifacts and external backup locations, and cannot authorize
deletion. If a known root cannot be fully inspected because it is inaccessible
or contains an unsafe entry, the preview marks the host summary unavailable;
it still reports the independently verified Docker actions. Unsupported partial
provisioning is refused. Purge is not yet supported,
and neither ordinary uninstall nor this preview claims secure erasure or media
sanitization.

The bootstrap's boundary is verified operator dispatch. The operator owns
existing-installation detection, configuration, deployment changes and exit
status. The bootstrap does not attempt to repair deployments or implement
upgrade migrations. Selecting `--version` chooses an operator release; it is not
an automatic upgrade of an existing installation.

Explicit updates, diagnostics and supported repairs belong to the deployment
tool. Future bootstrap options should expose those operations only after the
verified operator supports them. Re-running the bootstrap must not be documented
as a supported update or repair procedure without that deployment contract.

## Deployment validation

After application startup, the deployment operator automatically runs read-only
validation and prints a `PASS`, `FAIL` or `SKIP` summary. It checks the recorded
containers and migration initializers, the bound local HTTPS certificate, gateway
health, the gateway's configured required services, credential issuer metadata
and authorization metadata. Public readiness uses the existing `/health/ready`
ingress route. Validation has a 90-second operation budget; HTTP requests have
shorter timeouts and bounded response bodies.

To repeat these checks with the operator retained by an installation:

```sh
/absolute/install-dir/marty-deploy validate --install-dir /absolute/install-dir
```

This command writes JSON to stdout and a readable summary to stderr. Each run
saves a separate private `evidence/validation-<uuid>.json` report beneath the
installation directory, including failed runs. A required check that fails,
cannot be observed, or changes during inspection returns a nonzero exit status.
An unsafe installation or report destination is refused. Prior reports are never
overwritten. The existing repository command `marty-deploy validate --repo-root
PATH` continues to validate the deployment catalog.

Validation uses only the installation's recorded Docker Engine, owned resources,
local HTTPS origin and verified certificate material. It does not restart or
repair services, alter host CA trust, create test credentials, or remove data.
When the before and after service inspections agree, the validation report also
includes `container_security_posture` for each observed service. This redacted
summary comes from Docker inspect after the installer verifies the container's
recorded identity and configuration. It records configured user class, privileged
mode, read-only root filesystem, `no-new-privileges`, capability changes, and
counts of devices, writable entries in Docker inspect `Mounts`, and published
ports. The writable count excludes tmpfs and other writable paths absent from
`Mounts`. A `null` service entry
means that service was missing; a `null` top-level value means the inspection
could not be held stable. It does not inspect kernel-effective UID or capabilities
inside a running process and is not a container-hardening qualification.
The credential journey is explicitly reported as `SKIP`: login and actual
issue/present/verify/revoke/deny tests require isolated test fixtures and remain
in the separate disposable qualification runner. Authorization metadata checks
do not establish that user login or credential issuance works.

A passing report means the listed read-only deployment checks passed at that
time; it is not an atomic snapshot or a release qualification. The current
operator still reports `installation_ready: false` and retains its existing
trust-onboarding and installed-journey completion gate, including when these
checks pass. Automatic validation does not turn an incomplete installation into
a successful installation. The bootstrap propagates the operator's exit status.

# Installer bootstrap

The GitHub-hosted bootstrap selects a release, authenticates its deployment
operator and launches that operator. The new-install boundary requires a
nonroot Linux amd64 process with no-new-privileges and an already-running,
user-owned rootless Docker daemon. macOS, Windows and other architectures are
not supported.

For a first installation on your own Linux machine, start with the
[Linux installer tester quickstart](linux-installer-tester.md). It covers host
preparation, `--check-host`, `--check-compatibility`, exact signed candidate selection, pending ACME
orders, HTTPS trust, and feedback. The current external test entry is
`--candidate-test EXACT_NIGHTLY_TAG`; normal channel/version admission remains
held. This page describes the bootstrap and deployment boundaries in detail.

Unsigned Compose development qualification passed on an 8 GiB rootless host:
fresh installation, migrations, two ordinary restarts, the credential
issue/present/revoke/deny journey, final audit, and normal shutdown with data and
disk retained. Setup executions and existing signing identities were unchanged.
This does not qualify a published signed installer or admit normal installation.
Built-in read-only `validate` still reports the optional journey as `SKIP` and
`installation_ready: false`; the separate disposable runner supplies the passing
functional result. The results do not establish 3 GiB or production load capacity,
rendered UI, or external wallet interoperability. See the
[qualification summary](compose-installer.md#current-qualification-window) and
[development canary](installer-development-canary.md).

The read-only validator checks the application entry document, its local entry
module, declared module preloads and stylesheets, and the emitted runtime origins as well as API
readiness and issuer metadata. If an IP entry alias is configured, it repeats
the page checks with that exact IP authority and certificate identity, rejects
session cookies, and requires the alias to reject session, issuer and console
API routes. Requests use the retained ingress leaf, verified trust source and
bound local listener; redirects, proxy placeholders, source-tree HTML, and
HTML returned in place of JavaScript do not pass. These bounded HTTP checks do
not execute JavaScript, establish public network reachability, or replace the
required fresh-browser test. The report states both limitations explicitly.

## Select an exact signed candidate

Run the bootstrap as the regular installation owner under no-new-privileges.
Both tag placeholders below must name the same published nightly containing
this implementation; historical nightlies can contain the older rootful path.
The invocation puts the entire download-and-script pipeline under
no-new-privileges and propagates download errors:

```sh
/usr/bin/setpriv --no-new-privs -- bash -o pipefail -c 'curl -fsSL https://github.com/ElevenID/marty-ui/releases/download/vX.Y.Z-nightly.YYYYMMDD.RUN_ID/install.sh | sh -s -- --candidate-test vX.Y.Z-nightly.YYYYMMDD.RUN_ID'
```

The quickstart downloads that same release's bootstrap first, so you can inspect
it and run `--check-host` before provisioning. That check performs the bootstrap's
Linux, process-privilege, tool, and rootless Docker checks, then exits before
verification-tool or release downloads and operator dispatch. It does not
validate Compose, resource capacity, signed payloads, or an installation.

Next, use the same exact release selector with `--check-compatibility`. This
authenticates the selected inventory/admission and operator, then runs the
operator's existing rootless Docker and Compose preflight. Its Compose version
requirement comes from the native deployment catalog; a newer plugin can be
unsupported. The check exits before reserving an installation port or creating
persistent state and reports the selected release, observed tool versions,
required Compose version, and `installation_ready: false`. It makes no capacity,
remaining-payload, image, or application-readiness claim. Do not combine it with
`--check-host`, `--yes`, or installation input paths.

`--candidate-test`, `--channel nightly|stable`, and `--version TAG` are mutually
exclusive release selectors. The latter two require separate signed admission;
a published nightly alone does not make them available. `--install-dir
ABSOLUTE_PATH` and `--yes` are forwarded to the verified operator. Review the
host-impact confirmation before using `--yes`. `--hosting-file ABSOLUTE_PATH`
selects a versioned local, direct, or external-proxy hosting configuration;
without it the default remains private localhost. Hosting does not require
`--foundation-file`, and managed OpenBao remains the default. See
[hosting, optional Cloudflare, and browser access](installer-hosting.md) for
the strict schema, signed candidate command, and frontend/backend trust rules.
For an explicitly selected ACME staging environment, pass the public staging
CA file with `--acme-staging-roots ABSOLUTE_PATH`. The verified operator validates
and retains that trust input; production ACME refuses this override. See
[ACME hosting setup](installer-acme-host.md) for the complete staging contract.
`--help` works without Docker, platform detection, or downloads.

The initial script is fetched over HTTPS and executes before its own bytes can
be independently verified. It authenticates the signed inventory and operator
before executing that operator. The operator may write private state and
evidence before it verifies remaining payloads; payload verification precedes
Docker runtime provisioning. The candidate records a durable canary pull intent
before image acquisition, verifies the image and exact helper containers, and
tests a reversible ownership transition before generating runtime credentials.
Failure preserves the installation and evidence without automatic purge.
Candidate scope grants neither installer admission nor Ready status. Normal
`--version` and `--channel` paths continue to require signed admission and
remain held before installation state or Docker resource creation.

No source checkout, organization credentials or separate download package is
needed for this command shape. Use disposable identities and data on a fresh
disposable VM. The operator prints its private
random installation path under HOME; `--install-dir` remains an optional absolute
override. Send the first failing stage, exit status, OS/architecture, RAM/disk,
Docker/Compose versions and redacted error text to the person who invited you,
or [issue #1350](https://github.com/ElevenID/marty-ui/issues/1350). Do not share
secret values or raw credential diagnostics.

An ACME-pending invocation can exit zero with `application_started: false`.
Inspect the reported outcome and retained polling deadlines; use the retained
operator's `acme status` and, when permitted, `acme continue` under
no-new-privileges. Preserve the existing installation instead of running a new
bootstrap to resume an order. After actual startup, use `status`, `doctor`,
`trust-info`, and `validate`, then check the browser separately. The
[tester guide](linux-installer-tester.md#4-inspect-the-result-and-finish-pending-acme)
connects these steps to the canonical hosting and lifecycle operations.

## Application policy and optional credentials

`--settings-file ABSOLUTE_PATH` selects a private, typed JSON policy for a fresh
installation. Registration defaults to enabled for managed Keycloak. Email
verification, password reset, social login and integrations require their
documented dependencies; optional credentials are imported from private files
and remain bound through ACME continuation and credential generations.
See the [complete settings, defaults and credential matrix](installer-application-settings.md),
including the distinction between Keycloak SMTP and unavailable application
notification email, external-provider ownership and unsupported combinations.

## Requirements and release availability

Run as a regular Linux amd64 user with trusted preinstalled `setpriv`, Bash,
curl, Docker client and Compose plugin. The daemon must already be rootless.
The installer connects only through that user's `/run/user/<uid>/docker.sock`. Explicit
context overrides, foreign sockets, rootful daemons and userns-remap mode are
refused. The installer does not use sudo, install OS packages, start a daemon,
configure subordinate IDs or change host CA trust. Any earlier runtime or host
policy setup is a separate prerequisite. It does not remove the user's unrelated
group memberships or claim to sandbox all their existing authority.

Follow the [host preparation steps](linux-installer-tester.md#1-prepare-the-linux-host)
before entering the no-new-privileges installer process. The rootless runtime
requires cgroup v2, the systemd cgroup driver, and Docker memory-limit support.
Use the 8 GiB test target and at least 20 GiB free on Docker's data filesystem;
these are test resources, not a production capacity claim.

The bootstrap uses private temporary verification-tool and Docker-config files,
then downloads pinned verification tools. It requires no repository checkout or
build toolchain. Candidate provisioning may pull images, create a private canary
and owned Docker resources, and retain private state; ordinary uninstall retains
recoverable data, credentials, images and the Redis volume. There is no automatic
purge. Use a disposable VM snapshot and reset it after collecting feedback.

If the canary stops while its child is foreign-owned, preserve the installation
and invoke the retained verified operator's **recovery-only** command under
no-new-privileges, using its printed absolute installation path and the verified
absolute Docker executable path (shown here as `/usr/bin/docker`):

```sh
/usr/bin/setpriv --no-new-privs -- /absolute/retained/installation/marty-deploy restore-rootless-canary --installation /absolute/retained/installation --docker-bin /usr/bin/docker
```

Recovery rechecks recorded identities and may restore host traversal or record
an exact-ID abort; it never resumes provisioning, grants Ready or removes the
retained installation. An interrupted one-shot retry can require manual review.

Normal version/channel installation requires signed admission and an
authenticated operator. Channel selection also requires valid signed channel
metadata. Experimental candidate selection instead requires an exact signed
nightly inventory and authenticated operator; it grants no admission. Invalid
required metadata refuses execution. Artifact publication alone does not
establish deployment readiness or channel availability.

## Controller observations and resource profiles

The controller's incomplete checkpoint records its resource profile separately
from functional qualification and load characterization. The default
`rootless-startup-8gib` profile requires at least 7 GiB of measured guest-visible
and Docker RAM and 20 GiB free on Docker's data filesystem. The separately named
`rootless-functional-recovery-8gib` contract uses the same resource floors and
requires every functional, negative and recovery assertion; it is not permanently
tied to the historical 32 GiB profile. The explicit `qualification-32gib` and
legacy v1 reports retain their previous meaning. None of these resource guards
establishes startup success, throughput or a supported load limit.

The signed acceptance-only entry now uses the same nonroot/rootless boundary and
can bind exact configured DNS/IP hosting through a versioned authorization. It
retains all nine authenticated proof-file digests and uses the existing storage
canary. A controller can target an independently prepared AWS guest directly over
pinned SSH, including a host with recorded caches or unrelated stacks. QEMU is
optional. See [signed rootless acceptance](installer-signed-rootless-acceptance.md)
for the exact input custody, profiles and evidence versions.

Current trust observations use the configured HTTPS origin, the separately
bound local probe address, the certificate's public-ingress or backend scope,
and the selected generation's evidence. A local probe verifies TLS and OIDC
discovery using the configured authority while connecting to the recorded local
listener. It does not observe public reachability, browser trust or login.
The checkpoint leaves installation readiness, functional qualification and load
characterization false. Full installed browser/recovery/root-retirement proof
writers and native adapters are still missing, and the qualified report producer
refuses with those named blockers. Normal `Ready` completion remains held.

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

The [Windows Docker Desktop recovery](windows-compose-recovery.md) and
[candidate product/credential transition](windows-renewal-activation.md)
commands operate an already retained installation. They do not provide a fresh
Windows installer or extend this bootstrap's platform support. A Windows host
needs a separately prepared Linux amd64 environment to use this bootstrap.

## Deployment operations

For customer-managed unattended boot and read-only scheduled checks, see
[systemd lifecycle controls](installer-lifecycle.md). The generated user units
use the retained operator and preserve manual stop intent. Unit installation is
not a claim of reboot, credential-expiry, or public-browser qualification.

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
The credential journey remains `SKIP` in this read-only command because actual
issue/present/verify/revoke/deny checks require isolated fixtures. The separate
disposable runner passed that bounded sequence; its result does not change this
command's `SKIP` or promote the installation to ready. See the
[qualification limits](compose-installer.md#functional-readiness-and-qualification-boundaries).
Authorization metadata checks alone do not establish that login or issuance works.

A passing report means the listed read-only deployment checks passed at that
time; it is not an atomic snapshot or a release qualification. The current
operator still reports `installation_ready: false` and retains its existing
trust-onboarding and installed-journey completion gate, including when these
checks pass. Automatic validation does not turn an incomplete installation into
a successful installation. The bootstrap propagates the operator's exit status.

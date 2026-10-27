# Installer bootstrap

The GitHub-hosted bootstrap selects a release, authenticates its deployment
operator and launches that operator. Linux amd64 is the initial supported
platform. macOS, Windows and other architectures are not supported yet.

```sh
curl -fsSL https://raw.githubusercontent.com/ElevenID/marty-ui/main/install.sh | sh -s -- --channel nightly
```

Use `--channel stable` for stable releases, or `--version TAG` for an exact
version. These selectors are mutually exclusive. `--install-dir ABSOLUTE_PATH`
and `--yes` are forwarded to the verified operator. `--help` works without
Docker or platform detection.

For an explicitly unqualified nightly installation trial, use the exact tag:

```sh
curl -fsSL https://raw.githubusercontent.com/ElevenID/marty-ui/main/install.sh | sh -s -- --candidate-test vX.Y.Z-nightly.YYYYMMDD.RUN_ID --install-dir /absolute/disposable/path
```

`--candidate-test` authenticates the nightly inventory, operator, and payloads
from the same release run. It records a separate candidate-test scope and never
creates installer admission or marks the installation Ready. Current runtime
provisioning can return a nonzero result after creating owned resources; preserve
the printed installation path and diagnostics for review. Use only a disposable
Linux amd64 host and disposable identities. The normal `--version` and
`--channel` paths continue to require signed admission.

## Requirements and release availability

Run as a regular Docker-enabled Linux amd64 user. Docker Engine must be locally
accessible through a Unix socket, with its Compose plugin available. Rootless
Docker, user namespace remapping and remote Docker contexts are currently
unsupported. The bootstrap checks its standard command-line prerequisites and
downloads pinned verification tools itself; it does not require a repository
checkout or a build toolchain.

The selected version must have published signed admission metadata and an
authenticated operator artifact. Nightly and stable channel selection also
requires valid signed channel metadata. Missing, expired, mismatched or invalid
metadata causes refusal before the operator executes. A completed artifact build
alone does not establish channel availability. Artifact production and deployment
readiness are owned by their respective release and deployment workflows.

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

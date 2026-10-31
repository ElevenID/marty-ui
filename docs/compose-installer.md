# Compose installer

The Compose installer replacement passed scoped unsigned development qualification.
See the [qualification summary](#current-qualification-window) for coverage and
release limits. Normal installation still requires signed admission.

## Deployment model

The authenticated installer performs host checks, collects private installation
inputs, verifies the release, and invokes Docker Compose. Compose owns service
configuration, dependency scheduling, image pulling, container creation, health
waiting, logs, and ordinary project shutdown/removal. Rust retains the credential
and ownership boundaries, release authentication, scoped resource checks, and
product-specific HTTPS validation.

There is one Compose path. The custom application topological sorter,
configuration rewriting engine, per-service start loop, and ordinary health
poller are removed. Kubernetes and other deployment paths are outside this
replacement.

The deployment package includes these authenticated source files:

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | Published application topology and pinned images. |
| `docker-compose.selfhost.openbao.yml` | Existing KMS components and provisioning operations. |
| `deploy-config/compose/selfhost-installer/compose.bootstrap.yml` | Explicit installer setup jobs and bootstrap configuration. |
| `deploy-config/compose/selfhost-installer/compose.installer.yml` | Installer service policy, dependencies, scoped storage, and loopback ingress. |
| `deploy-config/compose/selfhost-installer/compose.runtime.yml` | Ordinary runtime selection with completed setup dependencies removed. |

Compose resolves the final model through `config`. The installer inspects that
model and its service hashes; it executes the verified source files, not a
rewritten JSON deployment. Generated files contain installation values, private
paths, and credential-generation selection. Included deployment files must be
inside the authenticated package; mutable remote includes are unsupported.

## Host and toolchain

The target is Linux amd64 with an ordinary user, rootless Docker, cgroup v2,
systemd resource controls, and an explicitly bound per-user daemon socket.
Process privilege, socket identity, Docker/Compose executable custody, and memory
control checks remain mandatory.

The selected Compose baseline is **5.6.1**, matching the existing AWS test host,
which runs rootless Docker Engine **29.9.2** on Ubuntu 24.04 amd64 with two vCPUs
and 8 GiB RAM.
The version check permits its distribution build suffix but rejects a different
semantic version, including a newer patch, until qualified. The baseline uses
long-form dependency conditions, profiles, anchors, `!reset`/`!override`, native
configuration hashes, `up --wait`, and explicit setup-job exit status. The
qualified build passed the real Compose baseline parser fixture. Parsing alone
does not establish daemon execution or full application qualification.

Private inputs remain in the installation's owned directories. File-backed
Compose secrets are files, not an encrypted vault; the existing file-type, mode,
owner, link, and retained-directory checks still apply. Narrow bind mounts remain
where credential custody or component storage requires them. Compatible new data
uses installation-scoped named volumes; this change does not migrate old data.

## Trust boundary

The shell authenticates the downloaded operator before executing it. The native
preparation stage uses the existing pinned Cosign and GitHub attestation tools
and requires the expected ElevenID publisher workflow, repository/source/ref,
GitHub Actions issuer, run/attempt, hosted-runner restriction, and provenance
policy. Release admission, expiry, candidate authorization, operator identity,
payload limits, complete file inventory, and approved image digests remain
separate checks.

Successful verification may be reused only inside one acquisition transaction,
bound to the exact artifact/proof bytes and complete policy. Private-file custody
and pinned tools are checked again on a cache hit. Failures are never cached, and
there is no persisted "already verified" flag. Ordinary lifecycle operations use
the retained authenticated inputs without repeating heavyweight verification for
every service. See [verification transaction](installer-verification-transaction.md)
for the exact bindings and regression scope.

Digest pinning alone is not publisher authentication. Compose does not enforce
image signatures. The existing independent image-provenance requirements remain
in force; this replacement does not introduce a new OCI-policy shortcut. The
resolved model and observed resources must remain bound to approved immutable
images, the installation, private inputs, project, and daemon.

## Initialization and ordinary runtime

First installation has a few explicit barriers for KMS, credentials, and TLS.
Existing provisioning implementations execute through selected Compose jobs.
Long-form `depends_on` conditions express service health and successful job
completion; a failed prerequisite must prevent its dependent from starting.
Presentation Policy also requires Organization health before its initial TLS connection.

A setup job records exclusive intent before running. It uses attached Compose
execution with explicit `--exit-code-from`; long-running service groups use
bounded `up --wait`. Setup completion also requires the existing sensitive-output
checks and a retained terminal container identity. `restart: "no"` is not an
exactly-once guarantee: prior intent, uncertain completion, or a previous setup
execution must never cause automatic credential minting or ownership changes.

The public `start` command applies the runtime layer, omits setup/initialization
profiles, and explicitly selects retained ordinary services. It uses native
`compose start --wait`; it does not create replacement containers or replay setup.
On ordinary restart, the runtime layer removes the `issuance-native` dependency
on `issuance-migrations` and the other completed-job dependencies. It retains
non-setup health dependencies and requires live unsealed KMS health for the 22
runtime KMS consumers. Notification also waits for PostgreSQL health. The
real-bundle parser checks the full maintenance union, including OpenBao and its
unseal worker, and compares complete remaining service and dependency sets.
The qualified bundle parser passed these assertions before provisioning.
Retained setup IDs, execution timestamps, and completion observations remain bound across ordinary stop/start cycles. Do not enable every
profile or manually restart retained setup containers. Public command wiring is
implemented; repeated invocation is qualified separately with the retained
operator, as recorded in the qualification summary below.

## Registering existing AWS keys

After organization and operator authentication are established, the retained
operator can attach existing AWS keys through the same KMS registration API as
the console:

```sh
marty-deploy kms register --install-dir /absolute/private/installation \
  --organization-id ORGANIZATION_UUID \
  --registration-file /absolute/private/aws-registration.json \
  --api-key-file /absolute/private/operator-api-key
```

Both input files must be owned regular files with mode `0600` in owned
directories with mode `0700`. The organization API key needs `keys:write`.
The registration file contains a `services` array; each item has `id`, `name`, `service_type: "aws-kms"`,
`region`, `auth_mode: "iam_role"`, an immutable `key_reference` ARN, `algorithms`
and `key_purposes`. An optional `default_service_id` selects one of those entries.
Optional `resolution_checks` entries specify `credential_format`, `key_purpose`,
`algorithm`, `expected_service_id` and `expected_key_reference` for saved routing
checks.
Workload IAM credentials belong to the running Signing Keys service.

The command validates each registration, preserves other providers and bindings,
uses the registry revision to reject concurrent edits, and verifies the saved
configuration. It does not replace a differently configured service with the
same ID or retry an uncertain write. Provider keys are not created, rotated or
deleted. The HTTPS certificate is pinned before the API key is sent.
This command requires an existing installation and operator credential; it does
not establish AWS-only installation readiness or remove the OpenBao dependency.

## Inspection, shutdown, and removal

Use the retained installer helper with the installation's absolute private path:

```sh
marty-deploy status --install-dir /absolute/private/installation
marty-deploy doctor --install-dir /absolute/private/installation
marty-deploy logs --install-dir /absolute/private/installation --service gateway --tail 100
marty-deploy trust-info --install-dir /absolute/private/installation
marty-deploy validate --install-dir /absolute/private/installation
marty-deploy uninstall plan --install-dir /absolute/private/installation
```

`status` reads journal history; `doctor` observes the bound runtime. Logs are
bounded and filtered for credentials, and remain private diagnostic information.
Compose health and exported certificates do not establish complete application
journeys or installation of trust in the host/browser.

To stop the bound project and later resume its existing runtime containers:

```sh
marty-deploy stop --install-dir /absolute/private/installation
marty-deploy start --install-dir /absolute/private/installation
```

Each action writes a separately numbered intent and result. A failed or missing
result blocks further mutation; an earlier successful operation does not erase
that uncertainty. Successful `uninstall` prevents subsequent ordinary start.

`stop --install-dir ...` uses scoped Compose stop. `uninstall --install-dir ...`
uses scoped Compose down after checking the saved configuration, exact resource
identities, and unexpected resources or consumers. Ordinary shutdown has a
60-second grace period and follows Docker's stop semantics. Active or uncertain
credential/ownership setup cannot enter ordinary shutdown.

Default uninstall retains named data volumes, host data, credentials, backups,
recovery material, diagnostic evidence, and images. It does not use global prune,
unrestricted orphan removal, host-directory deletion, or shared-image removal.
Destructive purge is not exposed by this replacement. Resource removal is not
secure erasure, and external resources require separate accounting.

A failed or interrupted Compose client does not prove daemon work stopped. Keep
the installation and operation evidence, inspect current daemon state, and avoid
automatic retries or deletion while the outcome is uncertain.

A narrow cleanup path is implemented for a finite failure of the initial
`application-up` operation. Before application startup, the installer saves the
complete maintenance model and input bindings; the actual startup intent and
result bind that plan. Cleanup admission requires a normally returned nonzero
client exit in the supported range 1–125, before the wait deadline, with validated
resource observations. Every configured role must be present with its exact
owned identity, and every setup job must have completed successfully with its
retained execution timestamps. Current observations must still match those
bindings and pass the ordinary project and consumer checks.

For an admitted failed-runtime scope, `uninstall plan`, `stop`, and `uninstall`
use that saved removal scope and retain the data listed above. This path cannot
pull images, run setup, run `up`, or authorize ordinary `start`; a successful
cleanup receipt cannot turn the failed installation into a successful runtime
session. Cleanup is an explicit operator action; its synthetic qualification is
recorded separately in the qualification summary below.

Unknown or interrupted outcomes, client timeouts or signals, failed or active
setup, changed identities, and incomplete service topologies remain preserved
for separate recovery. A missing successful session alone does not authorize
cleanup, and resources are never adopted by name.

## Qualification and maintenance accounting

### Current qualification window

Unsigned development qualification passed on an 8 GiB rootless host using pinned
published components. Application storage was fresh; the OS, Docker installation,
and image cache were retained. The scoped results are:

- **Build and orchestration:** 177 successful test executions across 27 invocations,
  the real Compose parser, and three live synthetic gates passed. Synthetic checks
  covered failed dependencies, uncertain setup, cleanup, and neighboring resources.
- **Installation and migrations:** fresh startup and required HTTPS checks passed.
  Complete migration values matched before restarts, after restarts, and after the
  credential journey, with unchanged schema and setup execution.
- **Restart:** two normal stop/start cycles passed without rerunning setup;
  observed restart and OOM counts remained zero.
- **Credential journey:** all 11 checks passed, including issuance, accepted
  presentation, revocation, and denial after revocation. The pinned assertions
  were unchanged, and both existing signing identities remained unchanged.
- **Shutdown:** normal platform and VM stops passed, with application data,
  diagnostic evidence, and disk retained.

### Functional readiness and qualification boundaries

The separate disposable journey establishes this bounded functional result.
Built-in read-only `validate` still reports its optional credential journey as
`SKIP` and `installation_ready: false`. A published signed installer requires
separate qualification; required repository CI and review still apply.

This does not qualify a 3 GiB deployment, production load capacity, rendered UI,
external ingress/browser trust, public-only DID resolution, independent wallet
JWT signature verification, unsupported schema validation, or full key-custody
attestation. The development launcher's 4 GiB available-memory floor is a safety
margin, not a measured production minimum.

### Measured maintenance reduction

Production orchestration Rust plus installer YAML decreased from 10,727 to 8,070
lines (**24.8%**); direct Docker lifecycle invocation sites decreased from 41 to 9.
The retained sites implement the rootless storage canary. These source counts
are separate from runtime coverage and exclude documentation.

## Reproducing the development gates

Use the [audited installer-only build procedure](installer-development-canary.md#audited-development-build-and-focused-tests)
with the existing pinned Rust builder, one build job, and the musl target. The
Compose replacement's isolated workspace contains five installer crates:
`deployment-catalog`, `managed-key-reference`, `selfhost-identity`,
`openbao-http`, and `selfhost-bundle`, plus their existing pinned dependencies.
Resolve the development metadata offline, audit dependency versions, checksums,
features, and source revisions, then compile with `--offline --locked`.
Canonical repository manifests and the release lockfile remain unchanged; the
isolated development lock does not qualify the canonical release build. Record
source and executable hashes, use Cargo's exact reported test executables, and
retain the helper's unsigned `unknown:unreleased` identity.

First run the focused installer tests, the development-layer integrity test,
and the `selfhost-bundle` `installer_layers` integration target. Then run the
real Compose feature-baseline parser, which invokes only version/config:

```sh
MARTY_INSTALLER_COMPOSE_EXECUTABLE=/absolute/path/to/reviewed/docker-compose \
  setpriv --no-new-privs -- /absolute/path/to/installer-compose-native-tests \
  --ignored --exact native_filtering_merge_and_restart_layer_semantics \
  --test-threads=1
```

For the [synthetic engine tests](../rust/crates/deployment-catalog/src/installer_compose_engine_tests.rs),
set all four inputs explicitly:

| Environment variable | Required value |
| --- | --- |
| `MARTY_INSTALLER_COMPOSE_FIXTURE_IMAGE` | Reviewed, already-cached shell-capable image with an immutable `@sha256:` digest. |
| `MARTY_INSTALLER_TEST_ENGINE_ID` | Independently recorded identity of the existing rootless daemon. |
| `MARTY_INSTALLER_TEST_DOCKER` | Absolute trusted Docker executable path. |
| `MARTY_INSTALLER_COMPOSE_FIXTURE_PARENT` | Existing dedicated canonical private directory outside existing installations. |

Run one exact test at a time as the ordinary user under no-new-privileges. Use
this command with each of the three exact names below; stop on failure and
preserve its printed fixture scope before attempting any recovery:

```sh
setpriv --no-new-privs -- /absolute/path/to/deployment-catalog-tests \
  --ignored --exact \
  installer_compose_engine_tests::actual_native_health_jobs_restart_and_neighbor_preservation \
  --nocapture --test-threads=1
```

- `installer_compose_engine_tests::actual_native_health_jobs_restart_and_neighbor_preservation`
- `installer_compose_engine_tests::actual_failed_dependency_and_uncertain_intent_do_not_run_dependents_or_repeat`
- `installer_compose_engine_tests::actual_finite_runtime_failure_allows_only_bound_data_preserving_cleanup`

The [actual-component development harness](../rust/crates/deployment-catalog/src/installer_compose_development_tests.rs)
is independently opt-in and requires these thirteen inputs. Paths and daemon
identifiers belong in private run records; executable hashes must match the
reviewed build and tool records.

| Environment variable(s) | Required value |
| --- | --- |
| `MARTY_DEV_COMPOSE_OPT_IN` | `I_ACCEPT_UNSIGNED_DEVELOPMENT_COMPOSE` |
| `MARTY_DEV_COMPOSE_PARENT` | Dedicated canonical owned mode-0700 development parent. |
| `MARTY_DEV_COMPOSE_FIXTURES` | Private published inventory, image lock, bundle ZIP, and their signature/provenance sidecars. |
| `MARTY_DEV_COMPOSE_TOOLS`, `MARTY_DEV_COMPOSE_GH` | Private pinned verifier-tools directory and trusted GitHub CLI executable. |
| `MARTY_DEV_COMPOSE_DOCKER`, `MARTY_DEV_COMPOSE_ENGINE_ID` | Trusted Docker executable and the exact existing rootless daemon identity. |
| `MARTY_DEV_COMPOSE_HELPER`, `MARTY_DEV_COMPOSE_HELPER_SHA256` | Static unsigned AMD64 helper and its independently reviewed SHA-256. |
| `MARTY_DEV_COMPOSE_NATIVE_TESTS`, `MARTY_DEV_COMPOSE_NATIVE_TESTS_SHA256` | Native-parser integration-test executable and its reviewed SHA-256. |
| `MARTY_DEV_COMPOSE_EXECUTABLE`, `MARTY_DEV_COMPOSE_EXECUTABLE_SHA256` | Pinned standalone Compose executable and its reviewed SHA-256. |

```sh
setpriv --no-new-privs -- /absolute/path/to/deployment-catalog-tests \
  --ignored --exact \
  installer_compose_development_tests::actual_pinned_marty_components_with_unsigned_compose_layers \
  --nocapture --test-threads=1
```

This harness authenticates the original published fixtures, creates a separate
explicitly unsigned package with the three local layers, and runs the actual
layer parser before creating runtime containers. It then invokes the existing
ownership canary, writes the fresh-state receipt, and invokes the installer
runtime, retaining all resources and evidence.
It does not authorize automatic failure cleanup or grant installation/release
readiness. Run only after the focused and synthetic gates pass, with the existing
VM safeguards intact, sufficient disk/memory, and time reserved for observation
and safe shutdown.

### Current Signing Keys image in a fresh development run

The default-off `installer-development` Cargo feature enables one local
`signing-keys` image in this harness. Build the operator, library tests, and native
parser tests with that feature and without `MARTY_DEPLOY_SOURCE_SHA` or
`MARTY_DEPLOY_RELEASE_TAG`. The operator must report
`unknown:unsigned-installer-development`. An isolated workspace must also retain
the canonical `rust/services/signing-keys/Dockerfile` for its compiled hash check.

Build that Dockerfile from a clean pinned checkout for `linux/amd64`, with
`CARGO_BUILD_JOBS=1`, `MARTY_UI_SHA=<commit>` and
`MARTY_RELEASE_VERSION=unsigned-installer-development-<commit>`. Use the local
tag `docker.io/elevenid/marty-ui-installer-development:installer-development-signing-keys-<commit>`,
gzip OCI output, `--provenance=false --sbom=false`, and a metadata file with
`BUILDX_METADATA_PROVENANCE=max`. Keep all outputs outside the checkout.
`scripts/prepare_installer_development_signing_image.py` binds the clean source,
native build metadata and archive using the existing bounded OCI inspector.

Set `MARTY_DEV_COMPOSE_SIGNING_IMAGE_ARTIFACT`,
`MARTY_DEV_COMPOSE_SIGNING_IMAGE_ARTIFACT_SHA256`,
`MARTY_DEV_COMPOSE_SIGNING_IMAGE_SOURCE` and
`MARTY_DEV_COMPOSE_SIGNING_IMAGE_ARCHIVE` to the resulting receipt, its SHA-256,
the pinned commit and that exact archive. The fresh harness imports the archive
and binds its native image ID for subsequent lifecycle and KMS commands.
Bootstrap images and the authenticated fixture inventory retain their original
bindings. Default release builds reject this unsigned scope.

Native Compose behavior references: [startup ordering](https://docs.docker.com/compose/how-tos/startup-order/),
[profiles](https://docs.docker.com/compose/how-tos/profiles/),
[merge rules](https://docs.docker.com/reference/compose-file/merge/),
[up](https://docs.docker.com/reference/cli/docker/compose/up/), and
[down](https://docs.docker.com/reference/cli/docker/compose/down/).

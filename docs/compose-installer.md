# Compose installer

**Development status:** this is the integrated replacement for the single-host
Compose installer. The recovered `native009` build passed formatting,
compilation, and 176 focused and native-parser tests across 25 test invocations.
Complete-tree maintenance counts are recorded below. Full synthetic lifecycle
acceptance and actual pinned Marty runtime qualification remain **PENDING**.
Its exact source snapshot is verified. Subsequent lint and frozen-contract
fixture corrections are separate changes covered by the required PR CI gate.
An unsigned development run does not qualify a signed release; this replacement
is not yet ready to merge on the recorded evidence.

The first `native007` synthetic run exposed truncated IDs in Compose's default
status output. The driver now requests `ps --no-trunc`, retains exact full-ID
comparisons, and has a passing regression in `native008`. The second synthetic
attempt then reached database and credential bootstrap but failed application
session construction: the synthetic fixture did not explicitly select its
runtime profile for native configuration hashing. Source correction `011` adds
that profile to the fixture's application/start selections and adds stage
diagnostics; it does not enable setup profiles on ordinary restart.

Both failed attempts received separately guarded fixture-only stop/down,
retaining data and diagnostics and leaving the 214-container baseline and 178
original evidence files unchanged. The second recovery retained both fixture
data volumes and did not rerun setup. These recoveries are not acceptance passes.
The `native009` result was recovered after the browser connection resumed.
All 35 non-documentation files in the first submitted commit matched the
compiled source snapshot and its provenance; all four artifact hashes and 25
test results were rechecked. The protected 214-container and 178-file baselines
were verified again before an ordinary VM stop. AWS confirmed the instance
stopped with its disk retained on 2026-10-30 at 19:35 UTC. The existing six-hour
automatic stop was unchanged. A third synthetic attempt and actual Marty
component execution were not launched after the recovery-margin cutoff.

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
`native009` build passed the real Compose baseline parser fixture. Parsing does
not establish daemon execution or full application qualification.

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

A setup job records exclusive intent before running. It uses attached Compose
execution with explicit `--exit-code-from`; long-running service groups use
bounded `up --wait`. Setup completion also requires the existing sensitive-output
checks and a retained terminal container identity. `restart: "no"` is not an
exactly-once guarantee: prior intent, uncertain completion, or a previous setup
execution must never cause automatic credential minting or ownership changes.

The public `start` command applies the runtime layer, omits setup/initialization
profiles, and explicitly selects retained ordinary services. It uses native
`compose start --wait`; it does not create replacement containers or replay setup.
The runtime layer removes completed-job dependencies while retaining runtime
health dependencies. Retained setup IDs, execution timestamps, and completion
observations remain bound across ordinary stop/start cycles. Do not enable every
profile or manually restart retained setup containers. Public command wiring is
implemented; integrated qualification of repeated invocation is **PENDING**.

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
session. Cleanup is an explicit operator action, with qualification **PENDING**.

Unknown or interrupted outcomes, client timeouts or signals, failed or active
setup, changed identities, and incomplete service topologies remain preserved
for separate recovery. A missing successful session alone does not authorize
cleanup, and resources are never adopted by name.

## Qualification and maintenance accounting

Acceptance must separately record: authenticated configuration and tamper
rejection; setup failure and restart behavior; actual rootless security settings;
partial-failure diagnostics and data-preserving cleanup; neighboring-project
preservation; and real pinned Marty startup/HTTPS behavior on the 8 GiB target.
Synthetic services establish orchestration behavior only. Resource capacity or a
correctly invoked component failure is an external blocker, not a passed test.
Published signed-release qualification follows merge and release publication.

The recorded results below describe the `native009` development build, completed
2026-10-30 at 19:03:33 UTC on the toolchain above. Its artifact receipt SHA-256 is
`a043b5f7dde5f24f650d284c956cd1aeb4a693bad9189c1fbef7b20715f576e9`.
The recovered inspection SHA-256 is
`7a6c78c200077bc5ebe6f78a14a9db870bfbc41c4bcbe5504829f37c4638595a`.
This build binds the first submitted source commit
`25f3cdbf1ce32ee512a421d1429fbec4d2de6c6f`, excluding documentation differences.
Later CI corrections remove unused legacy helpers, retain live evidence-reader
regressions, document intentional provisioning argument boundaries, and update
the frozen selfhost asset list. They are newer than the VM build; canonical
repository CI must validate each subsequent PR head separately.
Replace each remaining **PENDING** entry only after recording its exact build,
engine, result, and preserved-evidence bindings. The successful build left all
214 previously recorded containers and all 178 files in the original
failed-installation evidence inventory unchanged; the compiler container was
removed normally.

| Gate | Required observation | Recorded result |
| --- | --- | --- |
| Focused installer, verification, packaging, and development-harness tests | The affected operator and test targets compile; selected policy, receipt, lifecycle, packaging, and development-isolation regressions pass. | **PASS** — `native009`: 176 tests across 25 invocations; 169 tests in 22 unit groups, one development-layer integrity test, five packaging tests, and the native baseline parser fixture below; zero failures. |
| Native parser: selected Compose feature baseline | The real Compose executable resolves profiles, complete bind overrides, `!reset`, native dependencies, literal interpolation values, and runtime setup exclusion in the controlled fixture. | **PASS** — included in the 176-test `native009` result; no daemon mutation. |
| Synthetic: `actual_native_health_jobs_restart_and_neighbor_preservation` | Native health/completion ordering, two stop/start cycles through the production Compose driver with unchanged setup executions, retained data, and an unchanged neighboring project. | **PENDING** — attempts `synthetic001` and `synthetic002` failed as described above; corrections are present, but a passing rerun is not established. |
| Synthetic: `actual_failed_dependency_and_uncertain_intent_do_not_run_dependents_or_repeat` | Failed prerequisite blocks its dependent; an uncertain setup intent prevents repeat execution; failure evidence remains retained. | **PENDING** |
| Synthetic: `actual_finite_runtime_failure_allows_only_bound_data_preserving_cleanup` | A finite runtime health failure admits only scoped stop/down; pull, setup, up, and start remain refused; data and neighbor are preserved. | **PENDING** |
| Native parser: real installer and runtime layers | The separately authenticated fixture bundle plus unsigned local layers retain required dependencies, exclude setup on ordinary start, and satisfy the installer policy before any new runtime container is created. | **PENDING** |
| Actual pinned Marty components on the existing 8 GiB rootless VM | Authenticated fixture inventory, explicit unsigned development classification, successful orchestration and required HTTPS checks, and unchanged prior installation evidence. | **PENDING** |

The three synthetic gates use fresh private scopes and one explicitly approved,
already-cached immutable fixture image. Their results describe orchestration
behavior. The actual-component gate uses the published immutable Marty fixtures
and a separately marked unsigned local package; it does not claim host trust,
installed application journeys, or signed-release readiness.

### Reproducing the development gates

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
ownership canary and installer runtime, retaining all resources and evidence.
It does not authorize automatic failure cleanup or grant installation/release
readiness. Run only after the focused and synthetic gates pass, with the existing
VM safeguards intact, sufficient disk/memory, and time reserved for observation
and safe shutdown.

### Measured maintenance reduction

The final submitted-source inventory compares base commit
`5c5e1fe88a8053df9a79a8fc596867844b136f7b`, whose tree is
`85eb1ff3bc11d095c34980b39fef82e0098c5c51`, with the exact 49-path publication
delta. The local recount used the complete pinned Git-tree inventory and
independently verified every required base blob against its Git object ID.
The report records the counter and per-file SHA-256 values; its SHA-256 is
`f734fb5172e30821c7692de206a65ddcedc2094e0c5bbdada15686b472db2c4a`.
Both call-site inventories have zero unresolved entries and
`callsite_review_complete: true`.

This complete source inventory includes the subsequent CI corrections. It is
separate from the recovered `native009` build result. Documentation and the
frozen CLI fixture JSON are outside the Rust/YAML inventory and do not alter
these totals; their changed paths remain explicitly accounted for.

| Counted scope | Before | Replacement | Change |
| --- | ---: | ---: | ---: |
| Complete installer Rust inventory, files | 61 | 58 | -3 |
| Complete installer Rust inventory, production lines | 26,172 | 22,556 | -3,616 |
| Complete installer Rust inventory, test lines | 17,287 | 14,601 | -2,686 |
| Complete installer Rust inventory, total lines | 43,459 | 37,157 | -6,302 |
| Orchestration subset, files | 22 | 18 | -4 |
| Orchestration subset, production Rust lines | 10,727 | 7,402 | -3,325 |
| Orchestration subset, test lines | 6,357 | 3,056 | -3,301 |
| Orchestration subset, total Rust lines | 17,084 | 10,458 | -6,626 |
| Installer Compose configuration | 0 files / 0 lines | 3 files / 636 lines | +636 lines |
| Production orchestration Rust plus installer YAML | 10,727 lines | 8,038 lines | -2,689 lines / -25.1% |
| Reviewed direct Docker lifecycle invocation sites | 41 | 9 | -32 |

The complete Rust inventory includes every tracked `installer_*` module in
`deployment-catalog`, including unchanged shared helpers, matching installer
integration tests, and the selfhost-bundle installer-layer test. Physical lines
include comments, blank lines, and string contents. Dedicated test files and
lexically delimited `cfg(test)` items are counted separately from production
Rust. Installer Compose YAML is separate. The explicitly enumerated
orchestration subset overlaps the complete inventory; these rows must not be
added together.

The orchestration subset covers application startup and environment, Compose
execution and plugin binding, doctor, generation host/binding, ingress, jobs,
Keycloak, logs, OpenBao, renewal, runtime execution, TLS, trust, uninstall, and
validation, including the obsolete application graph/model/observation/start
and ingress-model files in the base. The dormant Compose-specific purge-volume
module and its registration were also removed after confirming it had no
external callers. The retained nine direct Docker lifecycle sites belong to
the rootless storage canary, whose explicit ownership experiment remains
separate from ordinary Compose scheduling.

Direct-call counts describe reviewed source invocation sites below Compose,
including image pulls and completion waits. They are not execution or service
counts. Native Compose dispatch and the common timeout forwarding wrapper are
excluded. The removed purge wrapper contributes one baseline site for its
volume-removal caller. Each report entry retains its path, line, invocation,
and indirect-call review basis. Missing Git objects or working files abort the
report rather than counting as zero.

CLI registration, bundle metadata, frozen CLI expectations, development/build
scripts, and documentation
are reviewed separately outside this line-count inventory. The replacement does
not move the old scheduler into these files. Test-line reductions describe
removed implementation-specific tests, not a measured increase in coverage.
These maintenance counts establish source reduction only; runtime behavior and
acceptance coverage require the separate evidence above.

Native Compose behavior references: [startup ordering](https://docs.docker.com/compose/how-tos/startup-order/),
[profiles](https://docs.docker.com/compose/how-tos/profiles/),
[merge rules](https://docs.docker.com/reference/compose-file/merge/),
[up](https://docs.docker.com/reference/cli/docker/compose/up/), and
[down](https://docs.docker.com/reference/cli/docker/compose/down/).

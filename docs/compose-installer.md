# Compose installer

**Development status at October 30, 2026, 6:04 PM MDT:**
the `native014` unsigned installer build passed **177 test executions across 27 invocations**,
and all three live synthetic tests passed. The separate authenticated-bundle
parser, fresh application storage proof, actual Compose provisioning, and required
HTTPS validation also **PASS**. The fresh scope contains 39 containers; the
216 retained baseline containers and 178 original files are unchanged.
The initial migration/schema audit also **PASS**: 12 ledgers / 29 version rows,
four native verifiers, three migration jobs, and zero observed restarts or OOMs.
Two ordinary stop/start cycles also **PASS**, with unchanged setup execution,
zero container restarts or OOMs, and successful HTTPS validation after each cycle.
The post-restart migration audit also **PASS**, with the same ledgers, schema
catalog, and unchanged setup. The journey-v3 runner then passed UI asset, login,
refresh, PKCE, seeded-organization, and managed-profile checks, but its credential
template request received HTTP 422 because the pinned client supplied an
unsupported `schema_uri` field. The v4 runner omitted that exact field and
reused existing managed profiles, but again received a definite HTTP 422 on
credential-template creation. Complete pinned-contract review and a read-only
observation of the exact disposable profile identified a missing setup step:
the compliance profile remained `DRAFT`, while template creation requires it to
be active. The bounded v5 setup adapter is implemented, with **42 local guard
tests passing**. It permits activation only of its newly created disposable
profile through the supported API and reuses the existing managed signing
profiles. It has not been staged or run on AWS. The browser connection was
unavailable at the 6:04 PM MDT check; the last VM observation remains the
5:52 PM MDT read-only profile check. The full credential journey, final migration
comparison, normal platform stop, and current-window EC2 stop remain unverified.

The earlier native013 fresh startup and initial migration audit passed, but its
first ordinary restart failed stability: Event Stream and Notification each
recorded six restarts, with no OOM. Native014 contains the reviewed live KMS
readiness correction; both native014 ordinary restart cycles passed the strict
zero-restart and zero-OOM checks.

### Earlier development window

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

### Installer corrections from qualification

The `native011` actual-component attempt passed installation configuration but
failed runtime configuration before creating new application containers:
`issuance-native` still depended on the excluded `issuance-migrations` setup job.
The runtime layer now removes that completed-job dependency. First installation
still requires the migration job to finish successfully. The real-bundle parser
regression derives all setup roles from the resolved phase labels and checks
that ordinary runtime retains every other service and every non-setup dependency.
The corrected `native012` real-bundle parser passed before provisioning.

Native012 then exposed an eager TLS dependency: presentation-policy attempted
to connect to Organization before its TLS endpoint was available and restarted
four times before becoming healthy. All four restarts preceded the passing
startup/HTTPS validation; the later audit rejected their recorded restart count.
No OOM was observed. The installer layer now
requires Organization health alongside KMS completion before presentation-policy
starts. The native parser asserts this edge, and its all-service runtime-map
comparison protects that non-setup dependency during ordinary restart. The
native013 fresh startup and required HTTPS checks passed. Its strict initial
migration and stability audit is recorded separately below.

Native013's first ordinary restart then exposed a separate KMS readiness gap.
Event Stream failed eager TLS key metadata requests, and Notification reported
OpenBao webhook-secret requests returning HTTP 503. A completed KMS setup job
cannot establish readiness after OpenBao restarts: its API health check permits
a sealed state so that explicit setup can run. Native014 adds the live
`openbao-unseal: service_healthy` prerequisite to all 22 runtime roles whose
completed KMS setup dependency is removed. Notification also gains a direct
PostgreSQL health prerequisite for its startup connection. All 42 per-value
setup dependency resets and other existing runtime dependencies are retained.

The real-bundle parser now checks the full retained maintenance union: the base
application, OpenBao, bootstrap, installer, and runtime layers. It compares every
remaining service and dependency, excludes setup roles, and asserts the strict
unsealed status probe. Five additional private parser-only environment values
supply the bootstrap layer's required inputs. The fresh-application installer
layer is unchanged from native013. The native014 build and focused native
feature parser passed. Its separate authenticated-bundle parser, fresh
application startup, and required HTTPS validation also passed. Migration,
restart, and functional qualification remain separately recorded gates.

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
On ordinary restart, the runtime layer removes the `issuance-native` dependency
on `issuance-migrations` and the other completed-job dependencies. It retains
non-setup health dependencies and requires live unsealed KMS health for the 22
runtime KMS consumers. Notification also waits for PostgreSQL health. The
real-bundle parser checks the full maintenance union, including OpenBao and its
unseal worker, and compares complete remaining service and dependency sets.
The actual native014 bundle parser passed these assertions before provisioning.
Retained setup IDs, execution timestamps, and completion observations remain bound across ordinary stop/start cycles. Do not enable every
profile or manually restart retained setup containers. Public command wiring is
implemented; repeated invocation is qualified separately with the retained
operator, as recorded in the current qualification table below.

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
recorded separately in the current qualification table below.

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

### Historical build record

The `native009` development build completed on 2026-10-30 at 19:03:33 UTC on the
toolchain above: 176 tests passed across 25 invocations. Its artifact receipt
SHA-256 is
`a043b5f7dde5f24f650d284c956cd1aeb4a693bad9189c1fbef7b20715f576e9`.
The recovered inspection SHA-256 is
`7a6c78c200077bc5ebe6f78a14a9db870bfbc41c4bcbe5504829f37c4638595a`.
This build binds the first submitted source commit
`25f3cdbf1ce32ee512a421d1429fbec4d2de6c6f`, excluding documentation differences.
Later CI corrections remove unused legacy helpers and a test fixture constant,
retain live evidence-reader regressions, document intentional provisioning
argument boundaries, and update the frozen selfhost asset list. They are newer
than the VM build; canonical repository CI must validate each subsequent PR head
separately. CLI integration assertions now cover the native Compose session and
maintenance-history reports, including a direct doctor error-redaction check.
Each result remains bound to its exact build, engine, observation, and
preserved evidence. That historical successful build left all
214 previously recorded containers and all 178 files in the original
failed-installation evidence inventory unchanged; the compiler container was
removed normally.

### Current qualification window

The application fixtures are the authenticated published package
`v1.1.263-nightly.20261029.40946723707`, with Marty source revision
`225818494f4ba716e75df7225d6c43d71b038879` in `ElevenID/marty-ui`. The functional
runner uses `ElevenID/marty-integration-tests` at pinned integration revision
`5b3ec6a802a5e13201be8883741889405a86d146`. The installer
changes are built locally and remain explicitly unsigned; service images are
reused without rebuilding.

Native012's required HTTPS checks passed after startup, but its later stability
preflight failed. That historical startup result does not establish migration or
platform readiness. Native013 passed startup in a new application scope; the
separate initial migration/stability audit also passed. The first ordinary
stop/start cycle subsequently failed stability, so neither the second cycle nor
the functional journey was executed. The initial audit is a completed observation
of the fresh installation, not proof of restart stability.

Native014 completed its own build on 2026-10-30 at 22:39:13.624215 UTC.
The copied, VM, and local source hashes matched all four reviewed files;
formatting did not change them. Normal compiler cleanup preserved the original
214 containers and 178 files. The test-execution total was summed from the 27 observed
invocation summaries; it is not a distinct-test inventory. Earlier source builds
are not combined with this count.

| Gate | Native013 record | Native014 observed results |
| --- | --- | --- |
| Focused build, packaging/CLI tests, and native feature parser | **PASS** — 177 test executions / 27 invocations. | **PASS** — 177 test executions / 27 invocations; compiler removed normally. |
| Three live synthetic gates | **PASS** — original 214 containers and 178 files unchanged. | **PASS** — all three tests exited zero; original 214 containers and 178 files unchanged; two new fixture containers inactive. |
| Authenticated-bundle install/runtime parser | **PASS** — Organization health prerequisite included. | **PASS** — full retained maintenance union and runtime readiness assertions. |
| Fresh pre-provision storage and actual startup/HTTPS | **PASS** — seven absent paths; 39 new containers; 12 successful setup jobs, including three migrations. | **PASS** — fresh application storage, 39 new containers, required HTTPS checks, and restored canary traversal; 216 prior containers and 178 original files unchanged. |
| Initial migration/schema audit | **PASS** — 12 ledgers / 29 rows, four native verifiers, three migration jobs, stable catalog, and pinned private-key scans; zero runtime restarts/OOMs during that audit. | **PASS** — 12 ledgers / 29 rows, four native verifiers, three migration jobs, stable 1,226-column catalog, unchanged setup executions, and pinned private-key scans; zero restarts/OOMs. |
| Two ordinary operator stop/start cycles | **FAIL** — first cycle recorded six Event Stream and six Notification restarts; no OOM. Second cycle not executed. | **PASS** — both cycles, ten operator calls exited zero, 12 setup job identities/execution timestamps unchanged, zero restarts/OOMs, and successful HTTPS validation after each cycle. |
| Post-restart migration/schema audit | **NOT EXECUTED** after the failed first cycle. | **PASS** — same 12 ledgers / 29 rows, four native verifiers, three migration jobs, 1,226-column catalog hash, unchanged setup, and zero restarts/OOMs. |
| Installed functional journey | **NOT EXECUTED** after restart stability failed. | **INCOMPLETE** — v3/v4 passed seven preliminary checks but received definite credential-template HTTP 422 responses. The exact v4 profile remained DRAFT. V5 has 42 passing local guard tests but is not staged or run on AWS; earlier failures are retained. |
| Final migration comparison | **NOT EXECUTED** | **NOT STARTED** — AWS execution is blocked by the unavailable browser connection. |
| Final platform and VM disposition for the current window | Earlier stop records are historical. | **UNOBSERVED** — no final stop claim; last VM observation was 5:52 PM MDT. |

| Native014 evidence | SHA-256 |
| --- | --- |
| Build completion | `bb5ea205974d4e83d97c130f9e33e20ef2c74803bc423c6bb1c0840a1d202b01` |
| Artifact receipt | `180798b73afd0e9f26aab43a033ea6cc568c4e31f60060d81a6a789ab6e2b6e3` |
| Unsigned helper | `06146904cccc132a67e724b14a448e8029625b04a7e7f5d73a2ba2d90b2167a9` |
| Copied-source preparation | `182b37c7455e02b5156483b032af8fe7b8cc0ab75b3a985f85087eece6c5726a` |
| Compiler cleanup | `4efeb19ba9d0f0a69dc89172ca45a7235cf9139ac5a4edf3822d5eb611aa468e` |
| Synthetic launch intent | `3f329f364f10a7c34bc33fdcd125cde7096890e4469fe5a33a9496aa9bdb5972` |
| Synthetic launch receipt | `3ec5b0ca4d416280577bfc1c0a4cc8f2c4ad6ead75a829928b98e63ab85e175a` |
| Completed synthetic result | `a44a1d8e29169f41c40adae71bc75b20dd3342f7ae3f60f8fa438fecd01ef0ce` |
| Inactive successor baseline (216 containers) | `65cc59431ce613b35fd218f444cf7a1eb1207ee9c6ca6bef76d8022a7ef69b3d` |
| Actual authenticated-bundle parser | `fbc4d049abfde4f671000bb78f83d149fdeab63ff0b107d4a35760c7dd4c7d1c` |
| Pre-provision fresh-state proof | `f117b9ff018ddb7ee97f338e41609e74638c4a0164fb8595cc4773143a05e0a7` |
| Actual startup and required validation | `0d4c10fae4e78a85b1c0bd953a8d0a8ebc26d2df00a403bd4182cc7e053424ea` |
| Bound Compose session | `c87783330998eba904b42145eaa38e4a7b361273eec501019e46bcab263e8b66` |
| Initial migration/schema audit | `159463a2fecbf5da0dd3b63f54112f0c50a869fbf2a26e9c647e87db21bc44ef` |
| Initial stable schema-column catalog | `6e73764ce2b7869612fcc9c79e6c1b8a86ae00d53a37c58bce448f9aab2aea44` |
| Two ordinary restart cycles | `7b0b76b82b28ce1534126bd49f72775ce7436aeab14f217d4f9ba468c35d4f13` |
| Identical setup snapshots after both cycles | `d4a78f730dd78cb2483b46dab3923df3c4af57353d7b7db4eb137d13ffb3dbf2` |
| Post-restart migration/schema audit | `d4af0f4ab668722fa0ad5133ebdba633dffc609bd36ad8a381f00c35c37ef31f` |
| Retained journey-v2 failure | `28a43c0d484999e1e71cefa9122b6c317eb8f356ef636600efb129d357fb0ece` |
| Retained journey-v3 failure | `0cd20abaced4b6fa95453668590ef2f7187f801bdcc34090e85c5da288e95fcf` |
| Retained journey-v4 failure | `28e617ecefe0d71a5d9c899e9c42be0160f00c1118181ea9371e4520818ff25b` |
| Pinned credential-template contract diagnostic | `bce28b606550922b48cd317652d4c8eb35329a7470cb4e859c8d03c8ab9b4164` |
| Complete v4 template payload/default audit | `903466ba5b3d6f267629b7101679d62da251bfe8d5c8591a8fee5fb7e16c8d38` |
| Read-only exact v4 compliance-profile observation | `30b3de4ba59ca01f6f2e134d87081490020405e80de819a257c052689ca6d3e8` |
| V5 qualification wrapper, not run on AWS | `6602e3ec675bfc0ea25c1532d7c773ea2f755db432e6e08bae99addc3d5145da` |
| V5 local guard-test result, 42 passing tests | `649b99aa8a583a38fa8bd538c6085a6daf7af23d62095b84a4f2dcf87fb1fb2f` |
| V5 independent source/test review | `7efb0cce6504bd05c3727c9ccd5ed2d61e179349fa6462a0538eb176e849a1b8` |
| V5 root source review | `7583c964721a83758ca037ae7771e97e03b393b82e291d0dda2270bc9da2582a` |
| Integration-source attribution correction | `b87e898850d27441423c6560ac1385414bc7edb334366ef46213463ac4026e29` |

#### Remaining live qualification

The completed synthetic receipt records success at 2026-10-30 22:42:21.857443 UTC
(4:42:21 PM MDT). It was recovered after the browser connection resumed at
4:51 PM MDT; the attempt was not relaunched. All three tests exited zero and
left every container inactive, with the original 214 containers and 178 files
unchanged. Its successor baseline includes the two retained fixture containers.
The actual native014 installation subsequently passed at 5:04:27 PM MDT.
Its state UUID is `d9f1e75b-7cbb-4e55-bf04-18e590383552`; its bound project is
`marty-install-d9f1e75b7cbb4e55bf0418e590383552`. The separate initial migration
audit passed at 5:05 PM MDT: 31 successful commands verified 12 ledgers and
29 version rows, four native schema verifiers, and three migration jobs. The
1,226-column catalog and setup executions stayed unchanged; the pinned database
private-key scans passed. The optional Verification compatibility feature was
disabled and both optional relations were absent. All observed restart counts
were zero and no OOM was recorded. Two normal stop/start cycles then passed at
5:11 PM MDT. All ten operator calls exited zero; required HTTPS validation
passed after both cycles. The 12 setup jobs retained their identities, successful
exits, and execution timestamps, and all container restart/OOM guards passed.
The 216 baseline containers and 178 original files remained unchanged. The
post-restart migration audit passed at 5:12 PM MDT, retaining the same
12 ledgers / 29 version rows and the same 1,226-column catalog hash. The first
functional journey attempt stopped at its UI asset-selection guard. A revised
harness passed seven preliminary checks but its credential-template request
received HTTP 422 on an unsupported pinned-client field. Omitting that exact
field in v4 still produced a definite HTTP 422. Complete contract review and a
read-only observation found that the exact v4 compliance profile remained DRAFT.
A bounded v5 setup adapter is implemented and has passed 42 local guard tests.
It remains unstaged and unexecuted on AWS. At the 6:04 PM MDT browser check,
access was unavailable because the originating browser context was missing.
The last VM observation was the 5:52 PM MDT read-only profile check. Full journey
qualification, the final migration comparison, and final stop observations
remain pending; connection loss does not establish the VM's current state.

The existing six-hour automatic-stop deadline is **October 30, 2026,
8:36:44 PM MDT** (2026-10-31 02:36:44 UTC). After browser access returns, inspect
the existing state before continuing within the already-authorized window, with
time reserved for observation and safe shutdown. Reconnection or passage of the
deadline does not establish a VM stop or extend that deadline. Normal platform
stop and an observed EC2 `stopped` state remain required; retain the disk.

Native013 build completed on 2026-10-30 at 21:28:10 UTC. Its copied source
matched all four reviewed installer changes; normal compiler removal preserved
214 prior containers and all 178 original files. Artifact receipt:
`5816b21bb8d20450e0735037f6529a4204f9a53bd3542d2e09221615c6b21b73`.
Helper SHA-256:
`1483542bd996447587e65f49a75f4dff48143a2c3e1560f615b617c4f0f1fd73`.
Native013 synthetic result:
`f45e5382394cb9abbb93b914f124522895d1cfabcd4d3c7ee3a7541fae219013`.
Its retained 216-container inactive baseline:
`d16ba93eb8dad64c073579ce0ba9ff3d8f2690f8e2b1ef9c211647ebce1242a4`.
Native013 real-bundle parser result:
`48754108b938d6bdfd90364c80a9c1700b8e9c25a98d22783574c16689b16329`.
Fresh-state receipt:
`759ec97f649b988d1db976e35fc968bf41d26f069aa6daa2db9a5c357319f7cb`.
Actual startup result:
`a5c41091e54e3816f759d7608ad59a0bf6f9be6e78df4249941e9f8aac55b0f9`.
The actual run preserved the 216-container predecessor baseline and all 178
original files. Successful migration-job exits are separate from the read-only
ledger and schema audit, whose corrected run subsequently passed.
The first native013 audit passed strict runtime preflight but stopped at command
17 while querying `verification_service.alembic_version`. This was a test-harness
expectation error: native selfhost Verification uses Redis, and the optional
credentials compatibility surface is disabled. The bound model and container
both omit its enable flag and database URL; the optional ledger/table scope is
absent. Observation receipt:
`dad312357fe5046c8e30a2370e8e45e12c8b8432f3ad65fd5a6564b33e31a6de`.
The first failed audit remains retained as
`b1006a598d1bc2b3c9f195f633200b1c402182bbe8c7fc4b1fb8f839bcc1c44a`.
The feature-aware collector corrected that expectation and completed all 12
ledger queries plus the four native schema verifiers. Its later private-key
schema scan stopped at a second harness defect: the pinned SQL lacks a terminal
semicolon, and the wrapper appended `ROLLBACK` without a statement separator.
That incomplete audit is retained as
`672efc19c6fef89fd96db444778e230c4c02a7b62f5fe5849d945df8e01730f8`;
the safe diagnostic observation is
`e26fd6d98e30e936d959cb740e9e2ba4b2768905d1e3624e835ac30e2029a7cc`.
Collector v3 added the separator without changing pinned SQL, application code,
migrations, or the strict restart/OOM checks. Its full initial audit passed on
2026-10-30 at 22:01:29 UTC: 12 expected and observed ledgers, 29 expected and
observed rows, four native schema verifiers, three migration jobs, and 31
completed observation commands. The schema catalog was unchanged, and the
pinned private-key storage scans found no prohibited patterns. The disabled
Verification compatibility surface is explicitly not applicable, with both
optional relations absent. Passing audit receipt:
`eff3f986ca02c1260263606260b0600c5bf110c72fb5bf58b61f640e6d1d73b3`.

The first normal stop/start cycle reached a successful helper start, but its
strict stability check failed on 2026-10-30 at 22:04:14 UTC. Event Stream and
Notification were running and healthy at inspection, but each had recorded six
restarts. No OOM was observed. The second cycle and functional journey were not
executed. The failure is retained as
`a269018c19a40fb9212e2839c07bc9ccab2becaa99f5a4bd34afc00973c65be6`;
the safe runtime inventory is
`20fbd183f51698ee6d6f151e1aafc1227fed9cb72d1da743b82defcc84a7a609`.
Native014 contains the live KMS readiness correction described above. Its
actual application startup, initial migration audit, and both ordinary restart
cycles passed. These new results retain the native013 failure as a separate
historical observation.

The sanitized native013 export binds ten component reports under summary SHA-256
`d1ef9fdf226feab9a4c5093a5548abbf447dcd88115e5ca0c5e20c2a18245547`.
It records the passing startup, required validation, doctor observations, and
initial migration audit separately from the failed restart. The credential
journey is not selected in that export; read-only validation still reports it
as `SKIP` and retains `installation_ready: false` and unobserved host trust.


Native012 artifact receipt: `c8d3c8ffab555a05c42b413088fa1f09b73e9bfffabc0a25d5ac6a1b07cadd07`.
Native012 synthetic result: `312f9ddcfb46c6d02d4e37a49179440712d0e8e82e16a46db59f5a9fcc62d5f2`.
Real-bundle parser result: `20184d2179b67c37139ea5f31d1fcb64d5276366fdd53336c1e489f3a29e06fa`.
Fresh-state receipt: `0128caebafda7b91844c36817c36c8cf3d06533e4652cff6918e8cb33393a2a1`.
Actual startup result: `ad2339ec706e89cd7a01dcb4b1753b7b83c107a7cfc8ee4bb1cd020c25353b96`.

Native012 normal stop/down subsequently removed only its 39 application
containers and preserved application data, credentials, one named volume, and
diagnostics. The 216 prior containers and 178 original files remained unchanged.
Recovery result: `8a2f006881898b594f64e941794523679b112e408a0c65d8546a68e50ea6dccf`.
Exact removal of the two inactive synthetic fixture containers restored the
original 214-container baseline. These cleanup results preserve the failed
stability record; they do not establish migration or platform readiness.

### Fresh-state and migration evidence

The development harness writes `evidence/development-fresh-state.json` after the
ownership canary is restored and before application provisioning starts. The
receipt binds the installation UUID, absolute path, device/inode, owner/mode,
helper hash, and authenticated fixture identity. It records that `state`,
`state/postgres`, `state/redis`, `state/applicant`, `backups`, `openbao-exports`,
and `openbao-snapshot-identity` were absent. The later migration observation also
requires PostgreSQL's data bind to be this installation's `state/postgres`.
Docker, the host OS, and cached images are retained. This establishes fresh
application data; an OS reinstall or uncached image download is outside this test.

Migration qualification checks the ledger membership and pinned version sets
required by the effective feature configuration. The normal native selfhost
configuration requires **12 migration/seed ledgers and 29 version rows**; it uses
Redis for Verification and leaves the optional credentials compatibility surface
disabled. The collector checks the bound model and observed container setting
before reporting that optional ledger as not applicable. Enabling that feature
instead requires its Verification ledger, for **13 ledgers and 30 rows**. A
missing required ledger remains a failure.

The audit includes the issuance baseline and eleven subsequent migrations,
requires the retired issuance Alembic ledger to be absent, and invokes the
existing native schema verifiers for Organization, Credential Template, Device
Registration, and Issuance without rerunning migrations. The three migration
jobs must retain successful exits, identities, and execution timestamps; all
bound setup executions must remain unchanged. Separate observations before and
after the runtime exercises compare ledgers and the schema-column catalog.
Pinned database scans check for prohibited private-key schema/content patterns.
These scans establish database evidence only; they do not establish a complete
key-custody attestation.

### Functional readiness and qualification boundaries

The native014 journey-v2 attempt stopped at 5:13 PM MDT while selecting UI
assets, before authentication or application writes. It completed three
same-origin GET requests with verified bound TLS and HTTP 200 responses; no
external request was made. The harness assumed every stylesheet reference was
local. Read-only inspection instead found three same-origin JavaScript assets,
a nonempty inline CSS block, and two external Google font/icon stylesheet
references. The retained failure concerns a qualification-harness assumption;
installer and application source were unchanged. Harness v3 passed 18 focused
guard tests and independent review, then correctly left the two exact external
font references unrequested while preserving origin, TLS, redirect, and wallet
guards. The UI observation records a nonempty inline CSS block and two selected
same-origin JavaScript assets; rendered UI and external font rendering remain
unqualified.

Journey v3 passed seven preliminary checks: UI shell/assets, master and `11id`
OIDC discovery, both token/refresh flows, public PKCE with seeded-organization
access, and managed issuer/verifier public profiles. It then stopped at
5:25 PM MDT with a definite HTTP 422 response to credential-template creation
(request 34). The original pinned client supplies non-null `schema_uri`; the
installed API contract deliberately rejects that field before forwarding
creation. The exact-revision contract review and offline payload comparison
found that omitting only that field preserves all supported claims/configuration.
There was no uncertain mutating request outcome.

Harness v4 passed 30 local guard tests (18 retained and 12 new) and review. Its
live attempt repeated the seven successful preliminary checks, resolved the two
existing managed profiles without creating or repairing keys, and omitted the
exact known schema argument once. The template request still received a
definite HTTP 422 at 5:44 PM MDT (request 32), and the wrapper restored the
original method. The attempt did not automatically retry or clean up.

The pinned test source and all 25 assertions were retained, but the complete
assertion sequence did not pass. The adaptation recorded one attempted call and
zero completed calls; its completion-dependent supported-argument proof remains
unproven. Public-key and managed-binding hashes were captured before v4, but the
after-comparison was deliberately not attempted after the original journey
failed. No before/after key-stability claim follows. That comparison would have
covered v4 alone; v3 did not retain key hashes. All v2/v3/v4 failures remain
preserved.

The complete v4 payload audit checked all 22 public template fields and defaults
and found no additional static payload mismatch after the exact schema omission.
It identified a setup prerequisite: the pinned journey creates a DRAFT compliance
profile and never activates it, while the gateway requires an active discoverable
profile. A read-only database transaction corroborated the exact v4 profile by
bound organization, unique test-name pattern, and the v4 begin/failure timestamp
window: one profile matched, with `DRAFT` status and `discoverable=true`.
That transaction rolled back without application changes or HTTP requests.

The implemented v5 setup adapter passed 42 local guard tests: 35 offline tests
and seven local loopback HTTPS tests. Root and independent source/test reviews
also passed; neither review reran the recorded suite or exercised AWS. All 30 prior tests remain, with the
predecessor fixture updated and 12 focused tests added. The adapter validates
the exact freshly created disposable compliance profile, rejects the prior v4
profile ID and name, permits one bodyless activation through the supported
public route, and requires every returned field except status and update time
to remain unchanged. It preserves the pinned source, all 25 assertions, schema
omission guard, and request boundaries. Its before/after managed-identity hashes
must match the v4 before-observation; it cannot create or repair signing keys.
No automatic retry or cleanup is permitted. These are local harness results;
no v5 staging, live activation, complete journey pass, or after-run key-stability
comparison is recorded. Neither complete credential-journey readiness nor
published schema validation is qualified.

The separate journey supervisor uses the already-generated bootstrap credentials
inside the exact disposable installation and invokes the pinned integration
journey with its assertions unchanged. Initial v3 setup created the two test
managed profiles through the public API; v4 only resolved those existing profiles
and forbade key creation or repair. Credential/presentation fixture creation and
the remaining assertions require the full journey to complete. The supervisor
uses an isolated, hash-locked test environment, the installation's CA and bound
certificate, and one HTTPS origin. HTTP checks fetch the UI shell and selected referenced assets;
this is not a rendered-browser interaction test. Foreign redirect and advertised
wallet endpoint authorities
are rejected before the integration helpers can rewrite them. Credentials,
tokens, bodies, cookies, and capability-bearing URLs stay out of the sanitized
report; raw diagnostic files remain private.

The headless wallet does not independently verify issuer credential or request
JWT signatures. The full journey requires backend verification of the presented
credential, including denial after revocation. Managed DID resolution in
this fixture can use the internal gateway, so this run does not establish
public-only DID resolution or external DNS/ingress reachability. Host/browser
trust installation, full custody attestation, and a published signed installer
remain separate qualification work. The unsigned helper remains
`unknown:unreleased`; its development installation deliberately retains
`Phase::Provisioning` and `installation_ready: false`, even if these gates pass.

The host has nominally 8 GiB RAM (`MemTotal` observed as 8,153,968,640 bytes).
Native014 startup recorded 160 samples at approximately two-second intervals,
from 4:59:07 to 5:04:25 PM MDT on October 30, 2026. The maximum observed whole-host
non-available memory was **2,004,832,256 bytes (1.87 GiB)**, with no swap configured.
The memory source receipt is
`66bf794c73bb2df3dfad1fc85b2974578b404d496009ce334fe881ff2dfb33fa`.
Whole-host `MemAvailable` observations include the OS and other retained
processes; they are not application RSS, an unsampled peak guarantee, or a
load/capacity test, and do not qualify a 3 GiB deployment. The historical
native013 startup samples reached 2,036,576,256 bytes (1.90 GiB); those results
remain bound to their earlier source and are not substituted for native014.
The development qualification launcher also requires at least **4 GiB of
`MemAvailable`**, with no swap, before starting its runtime gate. That is a
qualification safety margin, not a measured production minimum; the current
launcher would refuse a 3 GiB host.

The three synthetic gates use fresh private scopes and an approved cached
immutable fixture image. The actual-component gate uses authenticated published
Marty fixtures and a separately marked unsigned package. Functional-journey
results are recorded separately from startup and read-only `validate` results.

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
ownership canary, writes the fresh-state receipt, and invokes the installer
runtime, retaining all resources and evidence.
It does not authorize automatic failure cleanup or grant installation/release
readiness. Run only after the focused and synthetic gates pass, with the existing
VM safeguards intact, sufficient disk/memory, and time reserved for observation
and safe shutdown.

### Measured maintenance reduction

These frozen totals describe the compiled native014 installer snapshot. The
inventory compares base commit `5c5e1fe88a8053df9a79a8fc596867844b136f7b`
(tree `85eb1ff3bc11d095c34980b39fef82e0098c5c51`) with parent commit
`ea6c5ac2c6756b32ee674e5c03a644556debcd5c` plus the four compiled installer/test
changes. The computed code-only tree identity is
`5e052377e359c9ffab23177ff06e65b97680dc2c`; documentation is outside that identity.

The existing counter verified the complete Git inventory. A separate
build-provenance review confirmed all four copied compiled-source hashes against
the reviewed local and VM files. The frozen report SHA-256 is
`1068dfd8b79dea3ce3c6b60a841b260101979e8a0d5314163741b914420aec70`;
the binding verification is
`f5b4fa506cbf27c79102b68113e67555405d7d21ea5508e63941ca0e2309086d`.
Both call-site inventories have zero unresolved entries and
`callsite_review_complete: true`. Documentation and frozen CLI fixture JSON are
outside this Rust/YAML count. Source accounting is separate from runtime and CI
qualification.

| Counted scope | Before | Native014 | Change |
| --- | ---: | ---: | ---: |
| Complete installer Rust inventory, files | 61 | 58 | -3 |
| Complete installer Rust inventory, production lines | 26,172 | 22,556 | -3,616 |
| Complete installer Rust inventory, test lines | 17,287 | 14,777 | -2,510 |
| Complete installer Rust inventory, total lines | 43,459 | 37,333 | -6,126 |
| Orchestration subset, files | 22 | 18 | -4 |
| Orchestration subset, production Rust lines | 10,727 | 7,402 | -3,325 |
| Orchestration subset, test lines | 6,357 | 3,055 | -3,302 |
| Orchestration subset, total Rust lines | 17,084 | 10,457 | -6,627 |
| Installer Compose configuration | 0 files / 0 lines | 3 files / 668 lines | +668 lines |
| Production orchestration Rust plus installer YAML | 10,727 lines | 8,070 lines | -2,657 lines / -24.8% |
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

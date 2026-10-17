# Architecture test obligations and migration inventory

Initial baseline: UI `92e16b2f15045e91a92a737b0a42b431895a8b66`.
Owner: architecture-feedback implementation; see [the tracker](architecture-feedback-improvement-plan.md).

This is the initial group inventory for A0, the exact obligation record for the first A1 move, and the Canvas A4/A5 qualification split. It is not yet a complete dependency manifest for selecting other CI groups. Workflow triggers remain authoritative.

## Existing groups and ownership constraints

| Group / current entry point | Obligations and inputs | Execution / relocation constraints |
| --- | --- | --- |
| Workspace behavior: contracts lane, `cargo test --locked --workspace` | Service/domain behavior, embedded contract corpora, explicit test targets and grouped behavior modules | Some tests return early without configured environments; a successful default workspace run is not evidence of live acceptance. Preserve explicit later invocations. |
| Native PostgreSQL contracts: `scripts/ci/run-rust-db-contracts.sh` | Real persistence, tenant boundaries, migrations, concurrency, recovery; compiled artifacts and dedicated databases | Preserve suite-specific database ownership and serial requirements. Flow's shared database runs after workspace tests. |
| Managed signing/passport: contracts lane OpenBao step | Issuance signer + Signing Keys APIs + real Redis/OpenBao + independent OpenSSL verification | First A1 extraction below. Real services and explicit ignored-test execution remain required. |
| Canvas preflights: `scripts/ci/run-db-contract-groups.py preflights` | Routine CI runs native timeout and lease-expiry cases; scheduled/manual CI additionally runs the long mixed-roster and body-timeout cases | Success evidence is bound to executable digest, run identity, and qualification mode. Reuse skips only preflights actually run in that mode; routine CI also omits the two long matrices from the later worker target. |
| Canvas published/native parity: `scripts/ci/run-published-canvas-contracts.sh` | Routine CI retains owned native worker, TLS, database, and process behavior. Weekly scheduled or manually dispatched CI also qualifies mixed-roster/body-timeout matrices and all 33 pinned historical-process/repository/cycle replays. | Historical reference replays are not required on PR/merge-queue paths; run the complete qualification on demand with `gh workflow run ci.yml --ref main`. The registered-test count fails closed if a new historical replay is added without classification. Serial SQL logging and the four-thread remainder still apply. Child/helper tests must retain their parent protocols and environment configuration. |
| DIDComm/renewal and Flow acceptance: `marty-canvas-acceptance` and `marty-flow-acceptance` | Native delivery, keyed recovery, renewal persistence, HTTP/gRPC boundaries, configured main processes | Flow has a separate `flow_published_schema_contract` target and PR-only exact-source runner; the protected merge group still uses full Canvas. Shared fixtures and actual service binaries remain required. |
| Deployment/self-host acceptance: `marty-canvas-acceptance` and `marty-selfhost-acceptance` | Rendered Compose/Kubernetes/Envoy configuration, extracted bundle, actual public image and Bookworm-compatible executable | The self-host public-image target is separately packaged, but image/build prerequisites remain independent of ordinary behavior tests. The runner binds test executables by exact package/target metadata; target separation alone does not authorize a skipped installed-product gate. |
| Feature regression and passport test-mode image lanes | Distinct features and packaged default/opt-in boundaries | Preserve separate configurations and actual image contents; default workspace testing does not substitute for these lanes. |

For remaining A0 work, enumerate each group's scenario obligations and non-Cargo input closure in a reusable manifest before activating selection. The groups above deliberately remain broad where ownership has not yet been proven.

The contracts lane records Cargo `compiler-artifact` events for its exact
workspace build. Both the workflow's executable preparation and the database
runner resolve the ten Issuance Canvas PostgreSQL targets plus the proof-nonce
target through one guarded resolver: package identity, test target kind,
executable path, uniqueness and the eleven-target count must agree. CI fails
closed if the run-bound artifact log is missing; a local ad-hoc invocation
without `RUNNER_TEMP` retains its previous directory-scan fallback. In CI,
this prevents an older executable hash left in `target/debug/deps` from being
silently substituted for a compiled case. The local fallback is not
exact-source evidence. This does not prove the full
non-Cargo input graph or authorize any selection skip.

The other DB-contract targets now use the same run-bound artifact source for
both preparation and execution. Their selector requires the exact Cargo
package, test target kind, target name, one unique executable and an executable
file; a missing run log or ambiguous target fails closed in CI. The local
no-`RUNNER_TEMP` ad-hoc fallback remains non-exact evidence. This tightens
which compiled case executes but does not change the required case roster or
establish transitive runtime-input closure.

Before a release affecting Canvas integration, confirm a successful weekly/manual full-qualification run on the current main revision; if none exists, dispatch `ci.yml` on main and await its result. A PR's fast Canvas result alone does not qualify historical compatibility.

### A4 fast scoped-timeout policy matrix

The issuance library's `canvas_sync_provider_http_tests` adds two in-memory,
paused-clock tests alongside its existing scope-selection and adapter checks.
They consume the four header cases and six prompt/progress/stall body cases
from the existing `canvas-worker-*-timeout-scenarios.json` inputs. The actual
provider selects the application/roster budget, and the actual `OperationSocket`
reads scheduled bytes through its existing boxed I/O boundary. No production
clock, duration, transport implementation or fixture corpus is replaced.

The matrix checks the 17-second header distinction (application timeout, roster
success), completed-read budget resets, complete byte delivery for progressing
bodies that outlive a single budget, and the read-timeout phase/timing for stalled
bodies. Tokio's paused-clock support is a development dependency only. The
scripted writer is an inline owned future and is dropped on read completion.

These unit tests do not qualify HTTP/TLS wiring, job outcome persistence,
renewal/deadline scheduling, generation fencing, process liveness, late effects,
handler joins or cleanup. All existing native, historical, database and process
cases and their routine/full gate selection remain unchanged. This additive
batch establishes faster failure localization; it claims no measured CI saving
and authorizes no acceptance-case removal.

## First extraction: managed passport KMS chain

- Old owner: `marty-issuance-service`, `tests/passport_managed_kms_chain.rs`.
- New owner: `marty-service-acceptance`, same test-target name and unchanged Rust source.
- Exact test: `managed_passport_chain_issues_and_verifies_sod_without_exporting_private_keys`.
- Sole test in this target, ignored by default because it requires marked disposable resources and OpenSSL.
- Required invocation: contracts lane, after existing Gateway/Signing Keys fixture provisioning, with `--ignored --exact`. CI lists the target and requires the exact name before execution to reject zero-test success.
- Shared Rust code remains the real issuance `ManagedProfileSigner` and Signing Keys certificate builders/router/stores. OpenSSL strict verification remains an independent oracle.
- No file includes, compile-time binary variables, manifest-relative fixture paths, or local support modules exist in this test; moving it requires no helper duplication.

### Preserved environment and external inputs

| Input | Existing invariant |
| --- | --- |
| `MARTY_TEST_REDIS_URL` | Loopback; isolated Redis database numbered 13 or higher. CI uses database 14. |
| `MARTY_TEST_REDIS_DISPOSABLE_NONCE` | At least 16 characters; matches the pre-provisioned `marty:tests:disposable-guard` value. |
| `MARTY_TEST_OPENBAO_URL` | HTTP loopback endpoint for the dedicated disposable OpenBao instance. |
| `MARTY_TEST_OPENBAO_TOKEN`, `BAO_TOKEN` | Matching test token binding; the existing workflow supplies both. |
| `MARTY_TEST_OPENBAO_DISPOSABLE_NONCE` | Matches the pre-provisioned OpenBao guard; retain the existing verification. |
| OpenSSL, pinned Redis/OpenBao images | Independent strict certificate verification and actual managed key operations. Keep workflow provisioning and versions unchanged in this move. |

The unchanged test covers managed CSCA/DSC issuance and SOD verification, data-group hash mismatch rejection, organization isolation, immutable issuance retry receipts, revoked-CSCA rejection for new issuance, rejection of subsequent signing with untrusted DSC, and managed-key rotation/certificate binding. A default run that reports the test ignored proves discovery only, not these obligations.

### Dependency and packaging effect

The moved file is the only issuance source importing `marty_signing_keys`. Remove that development edge from issuance; the acceptance package owns dependencies on both implementations. Existing Gateway/issuance test edges remain for later work and must not be described as removed.

The acceptance package has an empty library and only development dependencies. `rust/crates/*/tests` is already excluded from both Docker build contexts, while the library keeps the workspace manifest usable by Cargo/chef. Production binary lists and features are unchanged. Validate the filtered-context metadata/planner behavior as well as normal Cargo metadata.

### Review and evidence checklist

- [x] Compare Git-normalized source hashes before and after the move: both `de3275257d6cf102d3a5d5a636b5022fa1601b13`.
- [x] Confirm lockfile changes are limited to the acceptance package and removed development edge.
- [x] Check explicit target registration and workspace membership; require all top-level test files to be registered.
- [x] Compile and list the acceptance test; the contracts job lists the expected ignored test before its explicit invocation.
- [x] Run workflow and packaging checks: 100 targeted policy tests passed. The actual public Docker `rust-service-planner` stage completed successfully with the filtered context and cargo-chef 0.1.78.
- [x] Require the real disposable Redis/OpenBao/OpenSSL acceptance test in protected CI. The [#1044 protected queue contracts job](https://github.com/ElevenID/marty-ui/actions/runs/37112907655/job/111174201305) lists and then runs the exact test successfully.
- [x] Complete self-review and reviewer-worker review; fix findings before merge. The reviewed head `ca9dbb909` passed full PR and merge-queue CI and merged as `48c77c9fc`.

No measured CI speedup is claimed for this first extraction. It establishes acceptance ownership and removes a real service test dependency; the larger Canvas split and selective execution remain separate work.

## Later service-acceptance targets: exact execution ownership

The two subsequent A1 moves, [#1118](https://github.com/ElevenID/marty-ui/pull/1118)
and [#1121](https://github.com/ElevenID/marty-ui/pull/1121), left their
cross-service tests in the explicit `marty-service-acceptance` targets below.
The contracts lane is their CI owner; a default workspace test result alone
does not prove their disposable-resource cases executed.

| Target | Required contracts-lane execution | Distinct obligation and external inputs |
| --- | --- | --- |
| `passport_gateway_postgres` | List and run `native_passport_gateway_signed_webhook_updates_durable_tenant_job` with `--exact`; the target also has a database-free Gateway fixture/route check. | Real Gateway-to-native-Issuance webhook handoff, HMAC tamper rejection, tenant isolation and durable job/tracking updates. `MARTY_PASSPORT_GATEWAY_TEST_URL` must name the dedicated loopback `marty_passport_gateway_test` PostgreSQL database; without it the live test returns early. |
| `gateway_signing_acceptance` | Require all six named cases in the compiled executable, then run each with `--ignored --exact` in the contracts lane. | Authenticated Gateway-to-Signing Keys routes, managed-key creation/rotation, profile and dedicated-service CSRs, and DSC issuance with operator grant. Cases use guarded disposable Redis databases 13/14; the CSR/DSC cases additionally use guarded loopback OpenBao Transit, and the DSC case verifies issued certificate signatures. |

The workflow creates the dedicated PostgreSQL database earlier and provisions
Redis/OpenBao disposable guards before their respective invocations. It retains
their separate Redis/OpenBao and PostgreSQL steps. The file and
target ownership is exact, but this entry is not a complete transitive
non-Cargo input graph or permission to skip protected merge-group coverage.

## Self-host public-image acceptance: execution and source input

`marty-selfhost-acceptance` owns the `selfhost_public_image_contract` target.
The self-host lane builds the local public services image and bundle packager;
`run-db-contract-groups.py selfhost-canvas` invokes
`run-published-canvas-contracts.sh selfhost-only`. That runner is the authority
for the exact 12-name roster: it rejects missing or extra cases, checks the
image ID and packager/Compose executables, and requires all 12 tests to pass.
The invoked test also checks the image's source-revision label against the
selected SHA. The separate Canvas lane omits this delegated target. Protected
merge groups retain the complete Rust matrix. A default workspace test or
`--list` result alone does not prove the environment-gated parent/child loader
executed.

| Case group | Distinct obligation |
| --- | --- |
| One remote-secret fixture case | Verified loopback HTTPS and a public CA for the test oracle. |
| Loader parent and child | Real Linux process isolation, local image and package extraction, owned PostgreSQL, synthetic secrets, guarded child environment, and recovery. |
| Seven packaged-runtime support cases | Closed failure-stage diagnostics, database-auth failure, process control, timeout/abrupt-exit recovery, cleanup-failure evidence, pending-operation exclusion, and synthetic secret mounts. |
| Two sidecar recovery cases | Exclusive pending-operation records and rejection of foreign parent, image, or mount identity. |

The target imports Canvas acceptance's `owned_cleanup.rs` with Rust `#[path]`
rather than a Cargo dependency. The A3 shadow planner includes both packages
when that exact helper changes and broadens if the source/import witness
disappears. Other non-Cargo inputs include the pinned PostgreSQL/probe images,
the extracted bundle, a compile-time Signing Keys public root-CA fixture, and
shared Issuance/Canvas/self-host test support. Unknown or mixed inputs retain
broad CI; this observed edge does not authorize a new skip.

This target tests an image/packager boundary, **not** a fresh installed
customer journey of the complete self-host Stack. Preview staging, anonymous
pulls, and Compose preflight do not substitute for installed
login/issue/present/verify/revoke/deny or KMS custody evidence.

## Canvas operations-input split: exact case owners

[#1302](https://github.com/ElevenID/marty-ui/pull/1302) kept the frozen
75-case scenario/oracle pair while assigning its observations to two native
owners. Both use `canvas_operations_input_http.rs` for the same request recipe;
the expected outcomes remain the independently frozen
`canvas-operations-input-oracle.json`, not values generated by the Rust handler.

| Owner | Required execution and distinct obligation | Inputs |
| --- | --- | --- |
| `marty-issuance-service` library test `frozen_operations_input_rejections_do_not_require_postgres` | The contracts-lane workspace test executes all 36 pre-SQL rejections: one 400, one 401, and 34 422. The real router uses an unreachable lazy PostgreSQL pool and a two-second per-request limit; any unexpected database access fails rather than becoming a mocked success. The test checks all 75 unique case names and the rejection counts. | `contracts/canvas-operations-input-scenarios.json`, `contracts/canvas-operations-input-oracle.json`, the shared Rust HTTP request helper, and the issuance router/configuration. |
| `marty-canvas-acceptance` target `canvas_published_schema_contract`, test `operations_inputs_match_frozen_published_python` | The Canvas lane explicitly discovers this named test and runs it with `MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1`. It verifies the pinned producer's complete frozen oracle output, then replays all 39 successful reads through the real router and owned PostgreSQL database. The test asserts the 39-case count; it does not substitute a mock for persistence. | The same scenario/oracle pair and shared request helper, plus the pinned historical producer image, published migrations, and an owned disposable PostgreSQL database. |

The Canvas lane also compiles the issuance library target with `--no-run` as
part of its existing shared compile; the contracts lane executes the rejection
test. The two case sets are disjoint by
frozen status and together account for all 75 named observations. This is
test-obligation ownership, not a new permission to skip Canvas or contracts
validation, and not a measured CI wall-time saving.

## Flow acceptance: exact nine-case execution owner

`marty-flow-acceptance` owns the `flow_published_schema_contract` target.
`scripts/ci/list-flow-acceptance-cases.sh` compares the compiled executable's
complete `--list` with nine exact names; additions, removals, and substituted
names fail discovery. Five environment-gated parent cases cover real keyed
HTTP admission recovery, gRPC admission, the native consumer and its retry/
legacy-HTTP behavior, actual rendered Flow-main startup, and rendered native
RPC versus legacy-HTTP selection. The remaining four names comprise two
self-spawned child entry points and two local loader/output-control tests;
discovery alone does not prove that the five live parent cases ran.

The full Canvas runner resolves the exact Cargo package/target executable,
checks its nine names through `list-flow-acceptance-cases.sh`, and executes
the target with `MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1`. The narrowly selected
PR-only Flow-source runner uses the same exact-list script and target;
protected merge groups retain the full Canvas lane. The live cases use the
owned disposable PostgreSQL
fixture; startup additionally uses owned Redis. Shared issuance test support,
actual Flow and Issuance binaries, the rendered base-Compose binary, the
DIDComm test Python, pinned PostgreSQL/producer/Redis images, and the public
startup scripts remain execution inputs. This is an execution-owner inventory,
not a complete transitive dependency closure or permission to narrow mixed,
unknown, protected, or release inputs.

## Issuance-to-Revocation Profile runtime input

Issuance has two independent non-Cargo transports to Revocation Profile. The
existing gRPC initiation validator reads `RP_GRPC_TARGET`. The HTTP client
reads `REVOCATION_PROFILE_SERVICE_URL`: Canvas readiness uses a service-token
authenticated GET to `/internal/revocation-profiles/{profile_id}/issuance-context`,
while credential lifecycle posts to
`/internal/revocation-profiles/{profile_id}/reserve-index` and
`/internal/revocation-profiles/{profile_id}/process-revocation`. The default
`issuance-native` Compose profile binds that URL to
`http://revocation-profile:8013`; Revocation Profile owns these HTTP
routes. The readiness response contains only profile ID, organization ID, and
status. The public `GET /v1/revocation-profiles/{profile_id}` still requires
user authorization; the internal read fails closed when a service token is not
configured or supplied. The A3 planner records both transports and the internal
authentication chain so future dependency review cannot infer HTTP coverage
from the gRPC witness alone. This is shadow dependency
evidence only: service changes still select the complete Rust workspace, and
the existing real database/process tests remain required.

## Trust Profile-to-Organization authorization input

Trust Profile reads `ORG_GRPC_TARGET`, injects its native Organization gRPC
control plane into the application, and checks organization-scoped requests
through `GetMember`. The client sends the configured service token, checks that
the returned user and organization match the request, requires active
membership, then checks the requested permission or owner/console access.
Organization authenticates and serves the membership lookup; base Compose
binds the `trust-profile` service to `organization:9002`. The A3 planner now
records source-scoped witnesses for the request, authorization decisions,
provider handler and registration, and deployment binding. This is diagnostic
dependency evidence, not independent proof of gRPC runtime behavior or
permission to narrow the protected Rust checks. Existing service tests retain
their owners and execution requirements.

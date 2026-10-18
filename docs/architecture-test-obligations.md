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

The normal DB runner now discovers and records each selected libtest case and
each observed outcome through `scripts/ci/rust_db_obligations.py`. It distinguishes
the default ignored roster from bodies selected by `--ignored` or
`--include-ignored`, preserves exact filters and serial execution, and compares
case identities and summary counts. A missing/zero selection, missing runtime
input, missing summary or selected/executed mismatch fails closed. Every test
body still executes once; the additional invocations only list tests.

Case completion comes from libtest's separate `--logfile` result stream. Raw
stdout/stderr still stream live: migration child processes and direct writes
can split the human `test name ... ok` display, which is not a reliable case
record. The stable result-file interface is deprecated but available on pinned
Rust 1.95; a real compiled harness probe covers direct stdout, inherited child
stdout, stderr, failed cases and ignored/filter modes. Toolchain removal or a
changed result format fails visibly instead of weakening case evidence. The
temporary result log is removed on success and failure, and ignored reasons
are excluded from the retained machine-readable inventory.

The run-bound JSONL artifact is
`rust-build-evidence/db-contract-obligations.jsonl`, retained by the existing
two-day Rust build-evidence upload. Records contain the package/target, selection
arguments, executable and compiler-artifact digests, GitHub run/attempt/job/SHA,
and declared runtime input **names** with their consumer/provisioning owners.
Readable executable copies are accepted only when byte-identical to the unique
package/target executable from this run's Cargo artifact log. The no-`RUNNER_TEMP`
local fallback is explicitly marked `local_unrecorded`.

This batch covers the 29 dispatches of `run-rust-db-contracts.sh`; the generic
guard, separate Flow invocation and published/process acceptance runners are
unchanged. Evidence proves libtest body execution and declared caller-provided
inputs, not assertion reachability, every internally provisioned child input,
or complete transitive runtime/source closure. It authorizes no selective skip
and claims no measured speedup.

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

### Mixed-roster current-input review boundary

`canvas-worker-mixed-roster-current-inputs.json` binds 21 current repository
inputs through the existing capture import/process/JSON graph. The release
pytest owner `test_canvas_worker_oracle_script_closure.py` checks every digest
and rejects newly reachable inputs. This closes a missing drift guard for the
mixed-roster producer, HTTPS fixture and transitive roster oracle; it does not
attest the original capture or establish complete runtime/mount closure.

The live consumer remains `worker_mixed_roster_reference_matches_published_process`
in `marty-canvas-worker-acceptance`: `PublishedDatabase::start_with_worker_mixed_roster`
mounts the preparer, which dispatches `run_canvas_worker_mixed_roster_oracle.py`
against the digest-pinned issuance/PostgreSQL images from
`canvas-worker-consumer-range-oracle.json`. It checks published migration/source
evidence, compares the actual report with `canvas-worker-mixed-roster-oracle.json`,
and closes owned resources. The separate native seven-stage replay is unchanged.
Both real-process cases and exact-main stable qualification remain required;
the new review record authorizes no skip or qualification reuse.

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

Both the dedicated self-host lane and the retained full/manual Canvas runner
now record outer libtest selection,
ignored status, outcomes, exact non-Cargo runner/image-pin input hashes, and
configured image ID/revision plus packager/Compose executable byte identities
through the shared Rust obligation recorder. In CI, the executable is bound to
the same-run compiler-artifact manifest; local runs without that manifest are
marked `local_unrecorded`. The shell's original 12-name
roster, image checks, test arguments, parallelism, pass-count gate, and Rust
resource cleanup remain authoritative. These records prove outer harness case
completion only: `selfhost_public_image_loader_child` is an environment-gated
child entry point, and its successful outer row does not prove the nested
loader reached every assertion. The parent test retains its own nested
completion/recovery checks. Interrupt forwarding settles the owned harness
process group; it is not evidence of completed installed-product cleanup,
upstream image/package provenance, or a complete transitive source graph. The
record grants no skip authority.

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

Both Flow entry points now use the same libtest obligation recorder as the
serial database runner, in addition to the shared exact nine-name roster.
The run-bound record associates the selected and completed cases with the
Cargo test executable, caller owner, required environment input names and
the hashes of the caller's direct image-pin and roster sources. The existing
four-thread target execution, early-return gate, full Canvas selection and
PR-only Flow selection are unchanged. Captured nested child summaries do not
stand in for parent completion; a separate libtest result stream identifies
the parent cases. This still does not prove assertion reachability, the
internally provisioned PostgreSQL/Redis state, or complete rendered/child
input closure, and grants no new selection authority.

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

## Canvas worker renewal: handler ports versus durable outcomes (draft)

This is a mapping for review, not authorization to retire a case. The common
oracle is `contracts/canvas-worker-renewal-job-outcomes.json`: failure stages
`lease`, `target`, `process`; processor outcomes `success`, `retry`, `terminal`,
`deadline`, `cancel`; durable fences `unchanged`, `owner`, `expiry`, `attempt`.
The oracle's `cutover_authorized` remains `false`. The pending fast owner in
`rust/services/issuance/src/canvas_sync_worker_renewal_tests.rs` is included
under `canvas_sync_worker::retry_handoff_tests::renewal_tests` and executes
the actual `CanvasSyncWorker::process_job` with scripted repository,
processor, and OAuth ports. It uses paused Tokio time and a controlled
processor release, not PostgreSQL or an external process.

| Failed renewal write | Five separately discoverable handler tests in the pending fast owner |
| --- | --- |
| `lease` | `lease_error_then_success`, `lease_error_then_retry`, `lease_error_then_terminal`, `lease_error_then_deadline`, `lease_error_then_cancel` |
| `target` | `target_error_then_success`, `target_error_then_retry`, `target_error_then_terminal`, `target_error_then_deadline`, `target_error_then_cancel` |
| `process` | `process_error_then_success`, `process_error_then_retry`, `process_error_then_terminal`, `process_error_then_deadline`, `process_error_then_cancel` |

Each of those 15 cases asserts the exact leased job, worker, target and config
version passed through the real handler ports; no renewal before 20 seconds;
one attempted renewal at 20 seconds; and a still-active processor/handler
after that failure. The controlled `success`, `retry`, `terminal` and
`deadline` exits then assert original renewal-error precedence over completion
or failure persistence, exact port order and one synchronous processor
cleanup. For retry, terminal and deadline outcomes, the tests also assert
the exact failure call's job ID, code, summary and force-dead-letter flag;
success makes no failure call. `deadline` reaches 30 seconds;
`cancel` instead drops the pending handler and asserts cleanup without a
`fail_job` call. The leaf also registers three distinct secondary-write-error
cases—`lease_error_survives_failed_completion`,
`target_error_survives_failed_retry_persistence`, and
`process_error_survives_failed_deadline_persistence`—and
`actual_cycle_does_not_count_persisted_success_after_renewal_error`, which
checks the real cycle's `(scheduled, leased, succeeded, retried, dead_lettered)`
counts `(0, 1, 0, 0, 0)`. These four are additional port-level obligations,
not substitutes for durable rows. The contracts-lane workspace unit-test
execution owns all 19; the pending source includes an exact test-only Docker
context exclusion and registration guard.

The existing `canvas_sync_worker_postgres_contract` target owns the separate
`scheduler_recovery_renewal_and_heartbeat_match_frozen_postgres_vectors` test.
Its support module `tests/support/canvas_worker_renewal_job_outcomes.rs` runs
all **60** combinations: three failed writes × five processor outcomes × four
fences. It makes three separately named disposable `_test` databases (one per
failure stage), creates the worker schema, and runs six actual cycles: for
each stage, one 16-job completing cycle and one four-job externally cancelled
cycle. Each nested SQL case uses the source-defined identity
`{stage}/outcome-{outcome}-{fence}` (for example,
`lease/outcome-success-unchanged`); these are 60 checked observations inside
one compiled libtest case, not 60 separate `--list` entries. The contract
runner provides `MARTY_ISSUANCE_POSTGRES_CONTRACT_URL`;
the contracts lane discovers and executes the exact compiled PostgreSQL
target. The three stage groups settle before an error propagates, and each
owned pool closes before its generated database is dropped. These are real
20-second renewal writes and 30-second deadlines, not paused-clock tests.

| SQL fence per stage/outcome | Distinct retained database assertion |
| --- | --- |
| `unchanged` | Actual trigger-injected renewal-write failure leaves every processor active and each job `leased` until controlled release or external cancellation; after release, the real repository writes the oracle's `status`, `completed_at`, and `last_error_code`. A successful unfenced job also persists `result = {"facts_changed": 1}`. The external-cancel outcome leaves the full job and target rows unchanged. |
| `owner` | SQL changes `lease_owner` to another worker before processor exit. Completion/failure must not mutate the full job or target row; status stays `leased`. |
| `expiry` | SQL moves `lease_expires_at` behind the database clock. The stale handler must not mutate the full job or target row. |
| `attempt` | SQL increments `attempt_count` before processor exit. The stale attempt must not mutate the full job or target row. |

For every stage the SQL trigger counters also prove the expected attempted
renewal writes (`lease`: lease only; `target`: lease and target; `process`: all
three), and SQL reads prove the rows remain `leased` while processors are
active. The contract asserts exact per-job original repository-error events,
zero success/retry/dead-letter cycle accounting after escaped errors, no
unacknowledged processor after completion/cancellation, all 20 cases per
stage, and all 60 overall. The adjacent generation-change and write-boundary
real-PostgreSQL tests remain independent obligations. No scripted repository,
paused clock, or source inventory proves these transaction, database-clock,
trigger, row-fence, isolation, or cleanup properties.

Before any future case move, review a per-identifier mapping of every old SQL
assertion, runtime input, clock behavior and lane to a new executing owner;
retain explicit real-database exemplars for all four fence variants and
both completion and cancellation. Prove discovery and successful execution
in the protected lane, plus unchanged producer/oracle pins and disposable
database cleanup. The 93.8-second Cargo timing observation is the entire
Issuance `lib(test)` compile, not a worker-specific saving, and does not
justify a new crate or a test reduction by itself.

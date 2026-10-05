# Architecture test obligations and migration inventory

Baseline: UI `92e16b2f15045e91a92a737b0a42b431895a8b66`.
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
| DIDComm/renewal/Flow composition inside the Canvas executable | Native delivery, keyed recovery, renewal persistence, HTTP/gRPC boundaries, configured main processes | Shared support modules and actual service binaries; separate ownership is needed before selecting independently. |
| Deployment/self-host acceptance inside the Canvas executable | Rendered Compose/Kubernetes/Envoy configuration, extracted bundle, actual public image and Bookworm-compatible executable | Has image/build prerequisites independent of ordinary behavior tests. Relative paths, compile-time executable variables and artifact package-ID filters currently bind it to issuance. |
| Feature regression and passport test-mode image lanes | Distinct features and packaged default/opt-in boundaries | Preserve separate configurations and actual image contents; default workspace testing does not substitute for these lanes. |

For remaining A0 work, enumerate each group's scenario obligations and non-Cargo input closure in a reusable manifest before activating selection. The groups above deliberately remain broad where ownership has not yet been proven.

Before a release affecting Canvas integration, confirm a successful weekly/manual full-qualification run on the current main revision; if none exists, dispatch `ci.yml` on main and await its result. A PR's fast Canvas result alone does not qualify historical compatibility.

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

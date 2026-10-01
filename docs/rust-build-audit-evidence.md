# Rust build audit evidence (snapshot 2026-10-01)

This appendix records the exact observations behind [the recommendations](rust-build-audit.md). Repository paths are relative to `ElevenID/marty-ui` unless noted. GitHub step times and Docker `DONE` times are rounded only where indicated. They are not Cargo crate timings.

## Revisions and existing runs

| Source | Revision / run | Observation |
| --- | --- | --- |
| UI | `737a52e1e0198f3953304f4bf446e90b8f98b7f1` | Audited `origin/main`; `rust/Cargo.toml` pins MMF `c55d323`, Core 0.1.62 `bdbd151`, and eMRTD issuance Core 0.2.0 `83cdaeb`. |
| Core | `73f6d5898b2147d0ab4f7cca318c76006a2fa3d6` | Audited `origin/main`; maintenance PRs #336–347 follow UI's 0.1.62 pin. |
| MMF | `c55d323e6aa64cad4f49308792f1d21eaab0ebc8` | Audited `origin/main`; exact revision consumed by UI. |
| [UI merge-group CI](https://github.com/ElevenID/marty-ui/actions/runs/36840266805) | `36840266805`, successful, post-maintenance | Required jobs all passed; Rust Service Tests ran 09:03:47–10:46:21 UTC (102.57 min); total allocated job time across concurrent jobs about 146.7 min. |
| [UI release attempt](https://github.com/ElevenID/marty-ui/actions/runs/36865248181) | `36865248181`, UI `737a52e`, overall failed downstream | `build-services` succeeded 12:58:21–13:20:58 UTC (22.62 min); service image action 18.5 min and migrations action 3 min. The run failed later in verifier-differential/public-stack-smoke. |
| [UI warmer](https://github.com/ElevenID/marty-ui/actions/runs/36851313942) | `36851313942`, UI `0bee3e0`, successful | Test compilation 4.68 min; Clippy 2.95 min. Sccache: 3,166 requests, 2,255 executed, 2,247 hits, 0 misses, 0 read/write errors; 8 non-cacheable calls. |
| [MMF CI](https://github.com/ElevenID/marty-microservices-framework/actions/runs/36803459536) | `36803459536`, MMF `c55d323`, successful | `Rust platform` job 4.63 min on Rust 1.93.0. |

The following read-only commands provided the timing and graph evidence (run from the UI repository, with Core/MMF queried separately):

```text
gh run view 36840266805 -R ElevenID/marty-ui --json jobs
gh run view 36840266805 -R ElevenID/marty-ui --job 110297502397 --log
gh run view 36865248181 -R ElevenID/marty-ui --json jobs
gh run view 36865248181 -R ElevenID/marty-ui --job 110379477372 --log
cargo +1.95.0 tree --locked --offline --manifest-path rust/Cargo.toml -p marty-issuance-service --target x86_64-unknown-linux-gnu -e normal,build --duplicates
cargo +1.95.0 tree --locked --offline --manifest-path rust/Cargo.toml -p marty-issuance-service --target x86_64-unknown-linux-gnu -e normal,build -i cedar-policy@4.12.0
cargo +1.95.0 tree --locked --offline --manifest-path rust/Cargo.toml -p marty-issuance-service --target x86_64-unknown-linux-gnu -e normal,build -i marty-crypto@0.2.0
```

The `cargo tree` commands resolve the locked Linux graph; they do not compile it or prove exact compiler invocations. Test-only edges were kept separate from `normal,build`. No clean build, full suite, Cargo timing probe, cache deletion, or target deletion was performed.

## CI gate and Docker phase evidence

In run `36840266805` (job `110297502397`):

| Exact log/step observation | Result |
| --- | ---: |
| `Run isolated database contract suites concurrently` GitHub step | 40.8 min |
| `published-canvas` completion heartbeat | 2,451 s |
| Concurrent `rust-db` completion heartbeat | 129 s |
| Final published-schema test executable: `274 passed`, `2 ignored`, `1 filtered out` | 2,436.08 s |
| Four early preflight groups, max group completion | 491 s step elapsed; individual successful test harnesses reported 367.38, 259.85, 111.90, 107.27 s |
| `Owned published-schema PostgreSQL` and `Owned published migration probe` lines across the job log | 250 each |
| Public image builder `RUN build-rust-service-binaries default` Docker layer | 919.2 s |
| Opt-in test image: default layer `CACHED`, then variant build Docker layer | 447.2 s |
| `Compile reusable Rust test executables` | 5.7 min |
| `Compile Bookworm-compatible base runtime acceptance` | 8.4 min |
| `Rust Service Images` parallel job | 13.9 min; first image step 11.5 min |

The published Canvas script first pulls pinned oracle images, selects the already compiled `canvas_published_schema_contract` executable from `rust-test-artifacts.json`, runs one SQL-logging diagnostic serially, then runs remaining tests with `--test-threads=2`. Its four preflight modes use exact filters on that same executable. The full invocation skips only the SQL-logging diagnostic, so those four run again. The 2,436-second harness report is direct test-execution evidence; the `published-canvas` heartbeat is group wall time. Because the two groups run concurrently, adding their elapsed seconds would be wrong. Buffered group logs share the final flush timestamp, so individual `test ... ok` line timestamps are **not** used as per-test wall times.

In release run `36865248181`, the public service Docker action lasted 18.5 min, with Docker layer `[rust-service-builder 8/9] RUN build-rust-service-binaries default` reporting **1,066.5 s**. The action includes image packaging/push/attestation setup beyond compilation. `services/Dockerfile:5-14` copies the source before that layer, and `scripts/build-rust-service-binaries.sh` invokes one release Cargo build for the entire shared-image binary list. `rust/services/Dockerfile.ci` instead has chef, mold, sccache and BuildKit cache mounts. The two Dockerfiles are distinct build paths; the CI-only one does not automatically cache the public release one.

## Dependency, invalidation, and cache checks

- `marty-issuance-service` normal/build graph: `marty-crypto` 0.1.62 is direct and transitive through old `marty-oid4vci`/`marty-verification`; `marty-crypto` 0.2.0 enters through `marty-emrtd-issuance` and its `prepare_sod` call in `passport_signer.rs`. This proves two generations, not their timing impact.
- `cedar-policy` 4.12.0 has two normal/build parents in the same selected graph: old `marty-verification` and MMF `mmf-security`. MMF's focused `cedar,redis` feature selection therefore does not alone remove Cedar from issuance. The feature tree also shows other UI services enabling the focused MMF features.
- Thirteen UI service `build.rs` files were inspected for rerun declarations. They name specific proto inputs; no broad directory rerun or rewritten-output trigger was established. Cargo's [build-script documentation](https://doc.rust-lang.org/cargo/reference/build-scripts.html) defines the trigger behavior.
- The service-test job's available sccache block reported 14 requests, 6 cacheable misses, 0 hits, 6 write errors, 8 non-cacheable calls (`crate-type`), and 0 read errors/timeouts. The cache was configured read-only for the PR. This small snapshot is not an entire-workflow hit rate or evidence that write errors caused the long test step.
- The warmer's much larger sccache report had 2,247 hits and no misses/read/write errors. It includes Rust, C/C++, and assembler requests, and is not a Cargo timing report. The public Dockerfile did not use that sccache setup.
- No `cargo-timing*.html` was found in the inspected local UI/Core/MMF target timing directories, and the referenced CI runs exposed Docker/Vitest/security artifacts but no Cargo timing artifact. Hence the expensive Rust compilation units and dependency-unblocking chain remain unknown. The additive CI patch next to this report collects those data from an ordinary run; it intentionally does not trigger a run for this audit.

# CI and release execution

## Source checks precede expensive work

`Release Source Preflight` validates the stack lock, independent product package
plans, and the UI's immutable dependency coordinates before selected CI jobs
start. A release hold is valid for development CI; claim producers require an
eligible release. Independent product versions are not forced to equal the stack
version. Existing tag lookups distinguish an absent tag from a failed lookup.

Nightly intake downloads its authenticated claim under `RUNNER_TEMP` before
checkout. Cleaning or replacing the workspace cannot erase the admitted input.

## A closed CI plan controls allowed skips

`scripts/ci/affected_components.sh` retains the exact source-ownership and Rust
test-only proofs. Its Python companion produces a closed plan tied to the event,
comparison base, event head and checked-out source. A missing comparison identity,
failed fetch, failed diff, or unexpected checkout fails classification.

The required `CI Gate` checks both the detailed Rust/leaf policy and the closed
job roster. Selected jobs must succeed; unselected jobs must be skipped. Missing,
cancelled, failed or unexpectedly successful jobs cannot satisfy a different plan.
Changing the job roster requires updating the plan's explicit mapping and tests.

| Change | Required work |
| --- | --- |
| Exact marketing modules in `contracts/website-source-ownership.json`, website entry or dedicated website directory | Source checks and `Website Surface` |
| Shared UI, routing, public assets, dependencies or build configuration | Existing UI/security checks and `Website Surface` |
| Verified Rust test-only leaves in a pull request | Existing exact owned Rust matrix and associated checks |
| Other merge-group changes, unknown owners, workflow/policy inputs | Full existing qualification |
| Scheduled or manually dispatched CI | Full existing qualification |

The website exception works for both pull requests and merge groups. It only
accepts a nonempty diff of regular owned files. Moves, deletions, symlinks, mixed
changes, roster edits and guard edits retain broader checks. The website job tests
navigation, builds crawlable website output, and builds both application and
customer outputs with emitted-module guards. Those guards must continue to reject
every marketing roster member from the other surfaces.

Both required CodeQL checks use the complete exact Git diff, including both
rename endpoints. They do not rely on a truncated pull-request file listing.
Website-only merge groups complete the named checks without unrelated analysis;
other merge groups and scheduled/manual runs retain full analysis. Existing Rust
test-only production-scope proofs remain limited to pull requests.

## The offline compiler gets its own usable cache

The Bookworm compiler containers retain their pinned image, read-only root and
source mount, empty target directory, locked dependencies and disabled network.
A checksum-verified static sccache binary is mounted read-only and a local disk
cache is mounted writable. The wrapper probes the actual container's Rust 1.95.0
compiler rather than the host rustup shim. No Actions cache credentials are
forwarded into the compiler container.

The cache namespace binds the builder digest, architecture, sccache version,
Cargo lock and manifests, and the full compile recipe/profile configuration.
All Bookworm lanes share the same profile/linker settings and cache namespace;
sccache additionally keys each object by its compiler inputs and features.
Only a successful full Canvas qualification on trusted repository `main`, from
a scheduled or manually dispatched run, saves shared objects. Pull requests and
merge groups only restore the shared cache. The first trusted full run after a
key change populates it. Download, restore, save or cache-daemon failure leaves
the Rust checks compiling directly. Cache objects never replace the test-result
or source-attestation gates.

The ACME polling fixtures reuse the ledger already read for their assertions when
scheduling the next fake-clock deadline. Both 520-poll regression cases, the
reopen assertions and production persistence behavior are retained.

## Nightly preparation runs alongside image production

After claim admission, native packager/operator preparation and image builds run
in parallel. Native preparation runs the deployment catalog tests and the real
source-only Compose model qualification. Packaging joins both successful paths.
It restores the native executables only after validating the exact artifact ID,
source, run, attempt, metadata and checksum through the closed archive contract.
A rerun cannot relabel native output from an earlier attempt.

Nightly image production invokes the shared source-bound product-image action.
It rederives the existing recipe from the admitted source and validates the whole
matrix row. The caller retains its existing signing and attestation identity,
and nightly's compiler cache authority remains read-only.

## Local qualification

Run the focused policy suites with the repository Python requirements installed:

```sh
python -m pytest -q tests/test_affected_components.py tests/test_bookworm_compiler_cache.py \
  tests/test_release_preflight.py tests/test_nightly_native_artifact.py \
  tests/test_ci_workflow_performance.py tests/test_ci_canvas_compile_scope.py
cargo +1.95.0 test --locked --manifest-path rust/Cargo.toml \
  -p marty-deployment-catalog --lib installer_acme::tests::polling_tests
```

The website build and crawler commands live in the `Website Surface` job and can
also be run locally after the verified released UI dependencies are installed.
Docker-dependent qualification remains necessary for actual compiler-container
and Nginx execution; source-policy tests do not stand in for those runs.

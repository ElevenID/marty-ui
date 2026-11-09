# CI and release execution

## One request coordinates release execution

`Release pipeline` coordinates full CI, the selected nightly/stable claims and
producers, automatic stable publication, and optional production web packaging.
The stable publication stage reuses a unique authenticated automatic publisher if
already present; otherwise it explicitly dispatches the existing publisher once
with the original successful candidate run ID. It waits only for the returned
original run and never searches for a replacement after an uncertain response.
Both entry points retain the publisher's per-tag concurrency, signed ownership
and asset checks. GitHub token-created events generally do not start further
workflows, with explicit dispatch exceptions; see the
[GitHub token documentation](https://docs.github.com/en/actions/concepts/security/github_token).

Each child retains its existing source and artifact checks. The coordinator
passes exact run IDs between stages and fails on a failed, skipped, foreign or
ambiguous required result. The runtime path has no screenshot review, private
decryption key, approval PR or timed operator dispatch.

After durably recording a confirmed dispatch, the coordinator immediately logs
the exact child run ID and original attempt. This makes a running stage
observable before its final journal artifact is uploaded. A stopped stage adds
a bounded `failure` object to that journal and emits a matching job annotation:
the fixed error code and explanation, stage, operation, and known child ID.
A main-source mismatch also includes the expected and observed public commit
SHAs. These diagnostics exclude arbitrary exception text, response bodies,
credentials and request payloads. If journal finalization also fails, the first
failure annotation remains and a separate warning identifies the incomplete
journal; preserve the last saved dispatch record.

Immediately after that durable acknowledgment, only the exact returned child ID
may receive an initial visibility allowance: at most 60 seconds, five seconds
between valid HTTP 404 "Not Found" observations, and at most 13 observations.
The stage deadline and any tighter transport deadline still apply to every read,
including the protected-main check before each observation. The first visible
response must pass all existing child identity checks; HTTP 200 with null or
malformed metadata is not absence. That first visible payload goes through the
ordinary state, conclusion, title and required-job checks before any later child
read. Once visible, the allowance is consumed and ordinary polling remains
strict. Other HTTP errors, malformed absence evidence,
unknown dispatch outcomes, inherited runs, automatic publisher listings and job
reads receive no allowance. This never repeats a dispatch or discovers another
run, and the saved journal records the bounded visibility observations.

This reporting does not change source admission: protected main must still
match the request throughout the existing release checks. A main advance stops
the request. Preserve its original child results, and reconcile the release
state before any new request; an uncertain dispatch is never repeated.

The [automated release requirements](automated-release-requirements.md) define
the deterministic replacement for known upstream review obligations and the
local development workflow. Source review and exploratory/visual work remain
part of development; no incomplete installer checkpoint is relabeled Ready.

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


An acknowledged child may initially expose a default display title while active.
The coordinator observes only that exact run until its input-derived title is
available or the original stage deadline expires. Completed child evidence must
match the expected title; source, repository, workflow, event, attempt, creation
window and required-job validation remain mandatory. A title mismatch never
causes a replacement dispatch or an alternate child search.

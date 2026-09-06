# Canvas worker image launch contract

Status: all eight packaged preflight cases passed at `e424761f5`, image job
101523616820 in CI34046951418. Existing deployment consumers remain on Python.
This does not qualify database startup, active work, all secret sources or cutover.

The public shared image already builds and copies `marty-canvas-sync-worker`.
Its closed service selector now accepts `canvas-sync-worker` and
`canvas_sync_worker`, executing that binary directly. It does not invoke a
Python loader, start the issuance API, or create an HTTP listener. Existing
service selectors, including verification argument forwarding, remain unchanged.

The dedicated `rust/services/Dockerfile.ci` issuance image now executes the same
shared entrypoint. Its default remains `SERVICE_NAME=issuance_native`, retaining
the existing API smoke test and health configuration. Worker consumers must
still explicitly disable the API health check and publish no ports at cutover.

Secret loading has one source owner, `scripts/load-secrets-env.sh`. The public
image's `/app/load-secrets-env.sh` retains precedence. The shared entrypoint also
supports the dedicated image's existing `/usr/local/bin/load-secrets-env.sh`
location, which remains installed for compatibility. Direct/file conflict and
missing-file rejection occur before worker launch. No secret-loading semantics,
database-template implementation or application defaults were rewritten here.

The mandatory image smoke executes eight real-container preflight cases: both
worker-name aliases, direct and CRLF file keys, conflicting key sources, missing
file, unknown selector, and empty selector. Successful key loading is followed
by deliberately invalid database URL rejection before any connection. The
native diagnostic was independently observed as
`Error: Configuration(RelativeUrlWithoutBase)` with exit one using a cleared
environment and synthetic key. These are launch/preflight observations, not
database or worker-cycle acceptance.

Each smoke container has no network, published ports or deployment mounts. It
is read-only, has no capabilities, and receives only fixed synthetic inputs.
Waits are bounded; exact container IDs are removed on success, command failure,
timeout or assertion failure. Unit tests cover these cleanup paths and ensure
stderr diagnostics are collected alongside stdout without printing key material.

The pre-existing local issuance image has no worker binary, so it cannot supply
packaged runtime evidence. The CI gate must use the freshly built exact-head
issuance image. No beta/production image is replaced by this work.

Whole-worker behavior, every deployment definition, file/template/environment
configuration combinations, readiness, migration ordering, signals and the final
beta-only soak remain requirements in the
[cutover inventory](canvas-worker-cutover-readiness.md).

Local validation: all 854 executed repository Python contracts pass in 34.68
seconds, with one opt-in verifier containerd/Buildx contract skipped. The run uses
CI's `PYTHONPATH=packages` plus an isolated copy of the hash-verified released
`marty-common` 0.2.16 dependency. Ruff, shell syntax, diff checks and Docker's
issuance build-definition check pass; Docker reports no warnings. These results
do not replace native worker gates. The subsequent image job verified all eight
real-image cases and retained the API health smoke; Rust CodeQL34046951414 passed.
The same head's configured runtime suite subsequently passed all 65 tests in
1151.92 seconds (job101523616800), including the actual retry-reclaimer two-request
case and all earlier concurrency/recovery/signal cases. Its separate 0.31-second
unconfigured result is not runtime evidence.
The newer [24-case database-startup extension](canvas-worker-image-startup.md)
and its shared-helper extraction still require their own fresh image execution.

# Canvas provider configuration continuation

This extends the [status provider candidate](canvas-status-provider.md), not a
consumer cutover or deployment approval. The prior pushed runtime commit
`6fdc86272cc7f43a8236843fb6cf5ba0bbbbb1e2` passed CI33997949251 and Rust
CodeQL33997949236, including image and lifecycle browser gates. Those results
do not qualify the newer changes described here.

## Independent behavior boundary

`run_canvas_provider_configuration_oracle.py` executes selected, unmodified AST
helper bodies and ordered timeout assignments from the immutable credentials
source at `51f0a758a076777cb18a30b1db3f89c74ac23e01`. It checks adapter SHA256
`24f5c0f22c075af3a11abbb48be52bcc6535e0d4fc31e446f7fb218bfe40d679`.
Repeated local CPython 3.12 captures agree for 20 secret and 19 timeout cases.
Tenant lookup, environment, and file boundaries contain synthetic values only;
the file double uses Python's actual UTF-8 text reader and universal newlines.
All original 37 observations remain unchanged after adding two newline cases.

The native library replays the same frozen observations. A new mandatory hosted
schema test, `provider_configuration_matches_published_helpers`, cross-checks the
helper capture inside the pinned published image. It has now passed locally,
including the later 19 fresh-process full-import assertions. The original helper
qualification does **not** prove full module import, endpoint error projection,
or actual HTTPX timeout behavior.

## Shared Rust implementation

- One lazy operator-secret owner serves validation and status delivery. Nonempty
  direct tokens remain raw and bypass file reads. Tenant status tokens take
  precedence, and token-file rotation is observed on each fallback invocation.
- Optional file I/O errors and empty files produce no token. Invalid UTF-8 remains
  an error with a static, redacted native diagnostic. File text applies Python
  whitespace stripping and universal newlines; direct/tenant values do not.
- Validation retains its distinct canonical policy: nonempty tenant configuration
  never falls back to an operator file. Required non-Canvas startup secrets retain
  their existing fail-closed loader. Real-file and configuration tests cover both.
- The shared MMF float parser preserves grammar and publish-before-status
  evaluation, including a malformed publish value despite a valid status override.
  Checked Duration conversion removes an out-of-range startup panic.

## Actual socket timeout qualification continuation

The next qualification adds `canvas-timeout-consumer-scenarios.json` and a
17-case frozen oracle. Repeated local captures execute the exact published
Canvas HTTP factory, DNS-pinning transport and its helper bodies from credentials
`51f0a758a076777cb18a30b1db3f89c74ac23e01`, with LTI source SHA256
`ab5b5a6de0e1c3ed45838e6ca0c1df1c84f3eb311de41060a60754769d7ac6b3`.
They use actual HTTPX sockets against an owned loopback TLS server, not a mock
transport. Only the exact synthetic origin allowlist and its connection pool's
test CA trust are supplied; machine trust and production policy remain unchanged.
The untrusted-certificate control fails with `ConnectError` as expected.

Observed behavior: stalled headers/body produce `ReadTimeout`; a response that
keeps making read progress succeeds even beyond the scalar timeout's total
duration. Zero, negative, negative infinity and the tested tiny value reach the
network consumer and produce `ConnectTimeout`. NaN, positive infinity and huge
values permit both immediate and delayed responses. The local versions are
HTTPX0.28.1, httpcore1.0.9 and AnyIO4.13.0, recorded as provenance rather than
invented requirements on the published image. The immutable issuance Dockerfile
pins HTTPX0.26.0, so the image cross-check is essential; do not silently use the
local version as the release baseline. The TLS fixture uses the image's existing
cryptography dependency and does not require a system OpenSSL executable.

The mandatory `timeout_consumer_matches_published_socket_behavior` image test
compares those observations and records the image's actual dependency versions.
The existing helper image gate now also checks full adapter imports in 19 fresh
child processes, one per timeout configuration, against the ordered-assignment
oracle. Both extensions require new hosted qualification. Docker became available
again and both passed locally; the original 39 helper observations are unchanged.

This continuation changes tests, not the native timeout runtime. Rust currently
uses a positive startup Duration and reqwest's whole-request `.timeout()`, so the
startup acceptance and progress-response differences remain real repair targets.
The dependency source offers connect/read timeout settings, but those alone do
not prove HTTPX-equivalent write/pool/TLS/cancellation behavior. Preserve the full
operation semantics and audit all shared-policy consumers before adoption.

Local timeout-continuation verification: repeated 17-case TLS captures and all
39 unchanged helper observations pass; the expanded schema target compiles and
strict all-target Clippy passes (7.46s, final retry 1.25s); 33 workflow/image tests
pass (1.43s). The final 20-test schema target compiles (4.35s) and its Docker-free
63-case protocol replay passes (0.02s).
At that initial checkpoint the new image/import assertions had not run locally;
the subsequent results below supersede that limitation.

## Native deadline owner and published-image verification

The first full local 20-test schema run passed 19 tests, including the full-import
gate. The TLS probe failed before assertions because its read-only image had no
writable temporary directory for the synthetic certificate. Only that statically
selected probe now receives an 8 MiB `/tmp` tmpfs with noexec/nosuid/nodev; the
image and host mounts remain read-only. No deployment or host trust changed.

The corrected socket gate passes all 17 observations in the actual published
image (10.15s). Its installed versions are HTTPX0.26.0, httpcore1.0.9 and
AnyIO4.14.2. These agree with the frozen outcomes despite the local version
differences. This proves the tested import/network baseline, not native HTTP parity.

`canvas_network_timeout.rs` implements a lossless IEEE-bit scalar and one scoped
deadline runner for connect, TLS, read, write and pool operations. It preserves
NaN and signed zero, accepts all frozen parsed scalars, safely handles deadlines
beyond the platform clock, and drops operations/timers together on timeout or
caller cancellation. Six tests cover immediate connection timeout, delayed
NaN/infinity/huge operations, fresh budgets after progress, independent duplex
read/write stalls, and cleanup. It is **not wired into runtime consumers yet**.

The new primitive passes the complete 280-library-test suite (6.41s), five worker
tests, 22 behavior tests, 33 workflow/image tests (8.95s), and strict all-target
Clippy (70s). The full configured schema rerun after the tmpfs correction passes
all20 tests (432.49s), including every published import/socket and database/HTTP
assertion; no tests are ignored or filtered. The slower run followed build-cache
contention, not a widened behavioral timeout or an excluded case.
No dependency, lockfile, startup acceptance or live HTTP policy changed here.

Transport adoption must use actual operation boundaries: reqwest0.13.4 creates
its read-timeout future when constructing the pending request, before response
headers arrive, and checks it while polling the entire in-flight request. Merely
replacing `.timeout()` with `.read_timeout()` therefore does not independently
bound write and response-header operations like the published HTTPX owner. Its
connector layer also fixes the connection response type, preventing a simple
external stream-wrapper replacement. Do not infer full parity from builder names.

## Prior checkpoint outstanding gates (superseded by integration below)

Prior lazy-secret implementation verification passed: 274 library tests (5.38s), five
worker executable tests, 22 combined behavior tests, the unchanged 63-case
protocol replay (0.02s), 33 workflow/image tests (1.26s), strict all-target Clippy
(final 0.72s), and changed-file Rustfmt/Ruff/diff checks. The 19-test published
schema target compiles; only its Docker-free protocol test was executed locally
for that continuation. Do not count the other 18 as passed or skipped successes.
The timeout continuation adds a twentieth schema test, likewise requiring the
configured hosted image gate rather than credit from unconfigured early returns.

The existing startup Duration boundary still rejects zero, negative, non-finite,
and huge values accepted by Python's assignments. This is an explicit remaining
parity gap, not an approved restriction. Freeze actual import and network-consumer
behavior before changing the representation and all timeout consumers. Also
qualify the full managed-validation invalid-UTF-8 response boundary; the native
safe-failure regression alone does not establish published endpoint parity.
Source review locates that boundary in the published
`infrastructure/api/canvas_routes.py::validate_canvas_credentials_provider`,
which directly awaits the adapter result. The bridge adapter reads the token
before its URL-error handler; the real-provider handler catches RuntimeError,
not UnicodeDecodeError. Also qualify unsupported-provider precedence: published
validation rejects an unsupported provider without loading a token, while the
current native validator loads the token first. Capture the actual HTTP response
and lookup side effects before changing the public result/error contract.

The status-provider URL/template, transport, persistence/recovery and all-consumer
gates remain in force. No reachable Python was removed, no pending-only default
was switched, and no beta, production or persistent self-host deployment changed.

## Native operation HTTP integration and maintainer repair

This continuation supersedes the earlier statements that the primitive was
unwired and startup still required a positive Duration. The actual issuance
config now retains CanvasNetworkTimeout's original IEEE bits, with all19 frozen
full-import acceptance cases replayed through from_values. The existing shared
MMF parser still owns lexical grammar and publish-before-status evaluation.

One private CanvasOperationHttpClient now serves status synchronization and
credentials validation. It uses Hyper's HTTP/1 framing, separately scoped TCP
and TLS connection deadlines, and scoped read/write budgets. Response-read
timing starts after request headers/body flush; split writes retain the intended
header/body boundary. The response stream owns the connection task, and timeout,
caller cancellation or response drop closes it. No shared pool, redirects or
proxy is introduced. Production TLS uses rustls platform verification and the
original host; the synthetic exact-leaf trust override exists only in the test
child. Shared origin resolution/pinning is extracted without changing the
existing catalog/OAuth/worker HTTP policy.

The issuance crate adds eight direct dependencies already present in Cargo.lock:
bytes, http, http-body-util, hyper, hyper-util, rustls, rustls-platform-verifier
and tokio-rustls. No locked package versions change. The main validation assembly
uses the new transport; the lifecycle factory remains a candidate, not a live
default cutover. Neither source assembly constitutes a deployment.

All17 native TLS observations match the unchanged published oracle using actual
startup config. CI now requires explicit artifact discovery and the configured
child replay, not credit from the unconfigured child's early return. The CI
httpx0.26.0/cryptography44.0.3 fixture dependencies were installed into an isolated
local venv and the native replay passed there too. Published-image dependency
observations remain independently recorded; local transitive versions are not
asserted to equal that image.

Review found another transport consumer gap: validation returned successful
headers before reading the body. It now drains successful bodies without storing
them, preserving HTTPX get() completion semantics. A real socket regression
failed before repair (the prematurely dropped response aborted the progressing
server) and passes after it: progressing response, truncated response and stalled
response. Split-header/read-budget ordering and connection cancellation/drop
regressions pass as well.

Hosted head40fccb65e failed both Python lint and release-contract ownership checks
on the TLS fixture imports. Four exact path/statement/count allowances now state
the test-only ephemeral certificate rationale; no service implementation is
approved. A regression verifies the same imports in a service remain rejected,
and an additional copy in the fixture is rejected. The guard implementation and
scan scope are unchanged. This is test infrastructure, not new Python product
cryptography. No certificate, private key or machine trust is persisted.

Local integration qualification:285 library tests (5.79s),5 worker tests,
22 behavior tests (0.01s),35 ownership/workflow tests (1.59s), strict all-target
Clippy (15.26s), and native17-case TLS replay pass. The initial full configured
20-test schema integration run passed (132.28s). After the response-completion
repair, one full run failed19/20 at lifecycle database cleanup (Docker rm failed,
236.80s). No labeled containers remained after its terminal failure; no daemon
restart or cleanup relaxation was performed. The next complete run passes all20
tests (126.72s), including both lifecycle variants and all published imports/TLS.
Final library rerun passes285 (11.53s), all-target Clippy passes (66s), and the
expanded ownership/workflow/image set passes40 (9.26s). Native17 TLS passes again
against the final executable. No cases were ignored or filtered from the full
schema run. New hosted qualification remains required.

Still open: full managed-validation invalid-UTF-8 HTTP response and unsupported
provider/token-lookup precedence; URL/port/template and response-encoding parity;
backpressured full-request writes, early server replies and TLS handshake edge
cases; failure-excerpt truncation versus full response completion; persistence,
recovery and all-consumer cutover. The17-case socket baseline is not proof of all
those behaviors. Reachable Python stays until its replacement gates pass; no
runtime feature, other-worker change or deployment was removed.

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
helper capture inside the pinned published image. The local Docker engine is
unavailable, so that new image gate has not yet been run locally. This helper
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
oracle. Both extensions require new hosted qualification; local Docker remains
unavailable. The original 39 helper observations are unchanged.

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
The new published-image and full-import assertions have not been executed locally.

## Outstanding gates

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

The status-provider URL/template, transport, persistence/recovery and all-consumer
gates remain in force. No reachable Python was removed, no pending-only default
was switched, and no beta, production or persistent self-host deployment changed.

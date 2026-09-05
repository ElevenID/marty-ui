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

## Outstanding gates

Local verification of this continuation passed: 274 library tests (5.38s), five
worker executable tests, 22 combined behavior tests, the unchanged 63-case
protocol replay (0.02s), 33 workflow/image tests (1.26s), strict all-target Clippy
(final 0.72s), and changed-file Rustfmt/Ruff/diff checks. The 19-test published
schema target compiles; only its Docker-free protocol test was executed locally
for this continuation. Do not count the other 18 as passed or skipped successes.

The existing startup Duration boundary still rejects zero, negative, non-finite,
and huge values accepted by Python's assignments. This is an explicit remaining
parity gap, not an approved restriction. Freeze actual import and network-consumer
behavior before changing the representation and all timeout consumers. Also
qualify the full managed-validation invalid-UTF-8 response boundary; the native
safe-failure regression alone does not establish published endpoint parity.

The status-provider URL/template, transport, persistence/recovery and all-consumer
gates remain in force. No reachable Python was removed, no pending-only default
was switched, and no beta, production or persistent self-host deployment changed.

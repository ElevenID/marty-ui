# Canvas credentials validation boundary

The new 20-case corpus closes the known operator-file exception and token-lookup
ordering differences for the managed validation endpoint. It does not declare
all validation URL, encoding, transport or deployment behavior complete.

## Independent baseline

`contracts/canvas-validation-boundary-scenarios.json` describes only synthetic
configuration, organization metadata, operator-file contents and controlled HTTP
responses. `run_canvas_validation_boundary_oracle.py` runs inside the immutable
published issuance image against the actual `main.create_app()`, its middleware,
managed Canvas route and full credentials adapter. Lifespan/background work is
disabled; repository, file and external HTTP ports are synthetic. No deployment
URL, host secret, alternate caller-selected path or production trust is accepted.

The main, Canvas router and adapter source SHA256 values are verified against
credentials source `51f0a758a076777cb18a30b1db3f89c74ac23e01`. Two independent
captures agree exactly before native changes. The frozen response fields are
status, content type and body; only validated ISO timestamps become `$timestamp`.
Ordered secret metadata/value lookups, file-read counts and synthetic outbound
HTTP requests are retained. This is not an assertion about every response header.

Initial fixture attempts stopped at authentication or body parsing, so they did
not qualify validation behavior. The final fixture sets the management key before
module import, supplies an empty object rather than null, and rejects503/422.
It observes raised exceptions and permits only the intended UnicodeDecodeError,
so an assertion failure cannot silently become a frozen500 observation.

## Repairs

- Unsupported operator provider selection returns before token access, including
  after the managed route has checked a canonical tenant secret's metadata.
- Invalid operator UTF-8 is a typed Rust error, not an HTTP200 validation result.
  Management maps it to the published plain500 `Internal Server Error`, without
  disclosing the path, secret bytes or exception details.
- Real-provider preparation preserves base/scope/issuer/badge/token/URL order.
  Configuration errors produce the published empty/default result fields rather
  than partially populated success fields.
- The configuration-error branch performs its own lazy token lookup. A missing
  issuer therefore reads an operator file twice, observing a rotation to empty
  or invalid UTF-8 exactly as the published adapter does.
- Canonical tenant validation remains mandatory. Wrong-owner/missing-reference
  requests stop before the adapter, and a valid tenant token does not touch an
  invalid operator file. No operator fallback policy was widened.

The native replay uses the real management router, service, actual startup config
and credentials validator. It reuses the existing management repository fixture
and shares one ordered lookup log across metadata validation and token access;
it does not reconstruct an assumed lookup order. One trusted-reader injection
method reuses the existing secret-reader port rather than introducing new file
selection logic. All20 native observations match the frozen published corpus.

## Gates and limits

Local:285 library tests,5 worker tests,28 management HTTP tests (including the full
20-case replay),22 combined behavior tests,40 ownership/workflow/image tests and
strict all-target Clippy pass. The new configured published-image comparison is
registered explicitly in the mandatory CI schema gate; the full schema suite now
contains21 tests. Hosted checks must qualify the final commit.

Final configured schema run:21 passed,0 failed,0 ignored,0 filtered (134.71s).
The native suites passed285 library (7.07s),5 worker,28 management HTTP (0.03s),
22 behavior (0.01s),40 workflow/image/ownership tests (2.72s), and Clippy (29.97s).
The preceding transport headcd5396ef2 independently completed CI34002852973 and
Rust CodeQL34002852955 successfully; that evidence does not qualify this new patch.

Remaining: malformed/alternate URL and template inputs, response encoding and
failure-excerpt completion, provider network-error projection, full backpressured
write/TLS/early-response behavior, persistence/recovery and all-consumer cutover.
The surrounding migration inventory, branches, demos, beta aggregate and soak
remain active. No reachable Python, lifecycle default or deployment changed here.

The subsequent [complete-body continuation](canvas-provider-configuration.md)
repairs early failure-excerpt termination separately: the shared TLS corpus now
has21 cases, preserving the earlier17, and a real validation transport regression
covers valid JSON at/above the old64KiB cutoff plus stalled/truncated bodies.
Complete bodies precede JSON/text projection; this does not yet qualify all
response charset/compression or provider network-error behavior. The20-case
managed app corpus above remains unchanged and still passes through the native
router after this repair.

# Canvas mirror publication: frozen-reference phase

Baseline UI: `65807a94e4a8f7a2c3fac9eb23f68e7b7fda8192`.
Reference Credentials: `578e86ef43166be79add2d812e92ef650535edaa`.

This slice covers six HTTP operations, bridge and Badgr publication, mirror
health/provenance, publication and lifecycle-retry batches, alerts/webhooks, and
the API-process `run_canvas_mirror_automation_loop`. It does **not** replace the
separate Canvas evidence `CanvasSyncWorker`. No native implementation, route
selection, Python deletion, deployment, signing, or KMS change is authorized by
this reference checkpoint.

## Ownership and deletion boundary

The frozen `infrastructure/api/routes.py` owns the six routes at lines 6190,
6240, 6259, 6276, 6295 and 6432; mirror helpers at 2000–3068; response models
at 1436–1544. `infrastructure/adapters/canvas_credentials_adapter.py` owns
publication payloads and bridge/Badgr HTTP calls. `main.py:358` starts the
optional mirror loop and cancels/awaits it during shutdown.

Reuse native `canvas_lifecycle_delivery`, `canvas_credentials_status`,
`canvas_credentials_validation`, the integration-secret owner, outbound HTTP
policy and lossless JSON/text codecs. Validation is not publication. HTTP and
automatic batches must share one domain implementation.

Do not delete the whole Python adapter: `canvas_routes.py:128` still imports
validation and evidence functions. Legacy credential lifecycle handlers call
`_sync_canvas_lifecycle_delivery_records` at `routes.py:5933,6016,6071`.
The mirror loop is another consumer even when disabled by default.
UI consumers include `ui/src/services/canvasIntegrationsApi.js:249–294`,
`CanvasIntegrationsPage.jsx` and `CredentialTemplateDetailPage.jsx`.
Gateway authorization/ownership and every intended runtime profile must be
qualified before their Python consumer is removed. Approximately 1,415 route,
helper and DTO lines plus 310 publication-related adapter lines are a migration
envelope, not an immediately deletable count.

## Reference proof boundary

The additive adapter corpus records 51 direct calls to the same pinned original
publication function, using original seed models with explicit input changes and
the existing controlled HTTP transport. It covers bridge/Badgr payload options,
eight aggregate identity mismatch cases, recipient precedence, delivery-secret aliases
and fallback, HTTP errors, response IDs, UTF-16 JSON and Unicode text excerpts.
It does not execute ASGI admission, persist deliveries, test real filesystem
secret rotation, or replace the original 64/4/9/4 reference corpus.
The foreign delivery-organization case explicitly includes that organization in
the synthetic pilot list to reach aggregate ownership; a separate unchanged
pilot-list case preserves the earlier portable-feature rejection.

Adapter successes use `result_encoding: "python-json-text"` with complete
`result_json` text from Python JSON serialization of the original result model.
The outer artifact is strict JSON. Decode the tagged text using the existing
lossless Python-compatible response decoder for native comparison: numeric NaN,
string `"NaN"`, and escaped unpaired surrogates remain distinct. This is not an
observation of an ASGI renderer or a production persistence representation.
Run the same capture command with `--adapter-reference --check` for this corpus.
Both corpora retain independent hashes and mandatory root-discovered guards.

Checked-in reference and scenario artifact identities use strict UTF-8 with
CRLF normalized to LF only. The capture and inert artifact guards share this
normalization, so Windows checkouts preserve the same recorded digests. No JSON
content, other whitespace, Unicode form, or pinned Git blob bytes are changed;
pinned source identities continue to hash their exact raw Git object bytes.

The capture reads exact pinned Git blobs, selects unchanged source AST bodies,
models and registration, and executes them with synthetic configuration. It
uses the frozen in-memory repository and source-derived seed helpers, a fixed
clock/UUID source, and controlled HTTP transports. It records whole responses,
stored snapshots and external request traces. Those observations do not prove
PostgreSQL transactions, native execution, gateway middleware, real provider
acceptance, TLS/DNS behavior, or deployed parity.

Management route dependency checks and trusted-organization checks must remain
in the ASGI capture; they are not evidence for outer gateway authorization.
In particular the frozen batch operations allow an omitted organization for a
management-key caller; do not invent a tenant restriction in the oracle.

The loop uses controlled monotonic time and sleep. Preserve completion-relative
rescheduling, independent publish/resync schedules, one-second minimum sleep,
startup behavior, exception continuation and cancellation propagation. This
does not prove OS scheduling or graceful process shutdown; actual packaged-main
startup/shutdown remains a later required gate.

The initial corpus contains 64 HTTP cases, four cancellations while an actual
selected bridge/Badgr transport callback is held (two ASGI calls and two actual
loop-to-batch paths), nine separately controlled scheduling cases, and four
configuration cases. Repeated whole snapshots are losslessly interned by their
canonical JSON SHA-256; no timestamp fields or raw metadata are omitted.
The generic scheduling matrix substitutes batch ports; the four provider-held
cases retain the actual batch/adapter graph. These are distinct proof scopes.

The parent verifies Git blobs before spawning a single observation child. The
child rechecks the source envelope and performs no Git/subprocess work. Its
complete observation phase has a 30-second parent deadline and 4 MiB per-stream
capture limits. Deadline, output, pipe-reader, startup, missing-global, or
unowned-origin failure cannot produce an accepted artifact. Source reads have
their own per-command bound; the 30 seconds does not include those reads.

Reproduce using a Python environment with the dependency versions recorded in
the artifact:

```text
python scripts/capture_canvas_mirror_reference.py <credentials-git-checkout> --check
python -m pytest tests/test_canvas_mirror_reference.py
```

The normal root test suite discovers the artifact guards without importing
FastAPI/httpx. `--check` additionally executes the controlled oracle; neither
command substitutes for the later native/PG/runtime gates. This initial corpus
does not claim exhaustive provider configuration/response grammar coverage.
Further input vectors belong in the reference before their native behavior is
implemented, with prior observations retained.

## Required next implementation gates

Reuse the owned `PublishedDatabase` and existing provider/lifecycle fixtures for
actual native HTTP/PG/provider tests, full lossless state, denied-request zero
side effects, both publication providers, replay/retry behavior, alerts and
webhooks. Qualify concurrent outcomes against observed legacy behavior instead
of assuming exactly-once remote publication. Keep existing lifecycle, worker,
UI and demo tests. Native routing stays unchanged until those gates pass.

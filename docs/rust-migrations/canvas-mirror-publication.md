# Canvas mirror publication: frozen-reference phase

Baseline UI: `b5d9d5203511159ff38412fc6eaa691cae636ff8`.
Reference Credentials: published `v0.1.76`, protected-main commit
`aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26`, tree
`819b7458a31c75d28043a4660643b029c5ec4567`.

This slice covers six HTTP operations, bridge and Badgr publication, mirror
health/provenance, publication and lifecycle-retry batches, alerts/webhooks, and
the API-process `run_canvas_mirror_automation_loop`. It does **not** replace the
separate Canvas evidence `CanvasSyncWorker`. No native implementation, route
selection, Python deletion, deployment, signing, or KMS change is authorized by
this reference checkpoint.

## Ownership and deletion boundary

The frozen `infrastructure/api/routes.py` owns the six route definitions at
lines 6151, 6201, 6220, 6237, 6256 and 6393. They contain 237 definition lines
inside a 277-line registered route envelope; the larger helper/DTO/publication
envelope remains a separate implementation concern. The
`infrastructure/adapters/canvas_credentials_adapter.py` module owns publication
payloads and bridge/Badgr HTTP calls. `main.py:372` starts the optional mirror
loop and cancels/awaits it during shutdown.

Reuse native `canvas_lifecycle_delivery`, `canvas_credentials_status`,
`canvas_credentials_validation`, the integration-secret owner, outbound HTTP
policy and lossless JSON/text codecs. Validation is not publication. HTTP and
automatic batches must share one domain implementation.

Do not delete the whole Python adapter: `canvas_routes.py:132` still imports
validation and evidence functions. Legacy credential lifecycle handlers call
`_sync_canvas_lifecycle_delivery_records` at `routes.py:5889,5972,6027`.
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
secret rotation, or replace the updated 73/4/9/4 reference corpus.
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

The current corpus contains 73 HTTP cases, four cancellations while an actual
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
command substitutes for the later native/PG/runtime gates. This corpus does not
claim exhaustive provider configuration/response grammar coverage. Further
input vectors belong in the reference before their native behavior is
implemented, with prior observations retained.

The HTTP corpus includes a success/effect case for every route and rejects
missing or incorrect management authentication before tenant checks, query
validation, repository access, provider access, or mutation. Dedicated order
cases combine invalid authentication with a foreign tenant or invalid query.
The publish route intentionally reads the credential before its hidden-resource
tenant decision; provenance intentionally validates trusted organization
context before any repository access. Health and batch routes remain
management-key scoped and do not acquire an invented tenant-header rule.

Each route also has a controlled first-repository-call failure. The frozen HTTP
result is a generic 500 body with unchanged complete repository snapshots, no
provider or secret access, and no Python exception/private fixture text in the
response. Feature-gate regressions preserve their existing blocked-record
metadata side effect while proving zero provider access. These controlled
memory-repository cases do not establish PostgreSQL outage or transaction
semantics; those remain an implementation gate.

## Required next implementation gates

### Unselected publication-adapter candidate

The current Rust candidate shares delivery configuration and transport with the
existing status adapter through compatibility aliases. Management validation
retains its separate canonical-tenant secret fallback policy. Publication uses
its own parsed publish timeout; validation/status still use the status timeout.
The borrowed lossless JSON node view moved mechanically to `python_value`, with
the existing signing diagnostic alias and caller policies retained.

`CanvasPublicationContext` borrows complete persisted credential/platform/
delivery projections and the existing typed transaction. It is not a public
JSON admission DTO: a later repository/orchestrator must validate and construct
these projections from its typed rows before calling the adapter. The current
tests use exact frozen model snapshots through the existing transaction decoder.
They do not qualify arbitrary unchecked input values, nullable-metadata defaults
or normalization of database timestamp strings. Publication observation time
already uses the existing microsecond `timestamp_string` owner; additional
non-whole-second credential/expiry vectors remain required before that boundary
is claimed.

The 51 controlled adapter cases prove 50 exact lossless provider projections and
one explicitly governed privacy projection: the existing native secret port
exposes a closed failure, not the Python resolver's arbitrary exception text.
The raw frozen observation stays unchanged. This candidate returns
`Canvas Credentials secret lookup failed`, with the same zero HTTP/state effects.
Later orchestration must retain this closed error through HTTP and persistence;
the current adapter test is not evidence for those outer boundaries.

The separate Linux HTTPS runner reuses that same graph and the production
platform verifier. Its independent peer compares complete structured requests
and both attempted/accepted counts. Only the two known fixture origins and
their matching transport metadata are rebased to the owned TLS listener;
credential, provenance and provider-response content are unchanged. Untrusted
TLS and private-origin denial are separate zero-HTTP controls. Trust is scoped
to an isolated child, never installed on the machine. This gate remains required
in CI; Windows fixture controls and an unconfigured `https_child` return do not
count as native HTTPS proof.

Custom assertion formatting is deliberately incomplete and unselected pending
the separately frozen shared Python-format candidate. The existing validation
and revoke template callsites also require that shared grammar correction while
retaining their distinct policies. No adapter-complete, route, loop or deletion
claim is permitted before custom-template parity. Filesystem-secret rotation,
additional timestamp/cancellation vectors, real PG persistence, orchestration
failure propagation, webhooks and health remain separately required. No Core,
KMS, crypto implementation, dependency pin or runtime owner is changed here.

Reuse the owned `PublishedDatabase` and existing provider/lifecycle fixtures for
actual native HTTP/PG/provider tests, full lossless state, denied-request zero
side effects, both publication providers, replay/retry behavior, alerts and
webhooks. Qualify concurrent outcomes against observed legacy behavior instead
of assuming exactly-once remote publication. Keep existing lifecycle, worker,
UI and demo tests. Native routing stays unchanged until those gates pass.

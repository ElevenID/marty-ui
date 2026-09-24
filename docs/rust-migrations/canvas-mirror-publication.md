# Canvas mirror publication: frozen-reference phase

Baseline UI: `b5d9d5203511159ff38412fc6eaa691cae636ff8`.
Reference Credentials: published `v0.1.76`, protected-main commit
`aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26`, tree
`819b7458a31c75d28043a4660643b029c5ec4567`.
The behavioral oracle runs only inside immutable issuance image
`ghcr.io/elevenid/marty-credentials-issuance@sha256:815cbba6efc7c91e770a8dd15fe5fa102d252a485073bf60f0e0d5e0a73b28e5`.
It verifies the release Dockerfile blob and refuses any runtime other than the
deployed FastAPI `0.109.0`, Pydantic `2.11.7`, and httpx `0.26.0` profile before
executing a route. CI executes the complete `--check` capture in that image;
all three reference modes must pass, so static artifact hashes are not accepted
as behavioral replay evidence. Artifact checks and writes refuse to run without
the release-image controller.

This slice covers six HTTP operations, bridge and Badgr publication, mirror
health/provenance, publication and lifecycle-retry batches, alerts/webhooks, and
the API-process `run_canvas_mirror_automation_loop`. It does **not** replace the
separate Canvas evidence `CanvasSyncWorker`. No native implementation, route
selection, Python deletion, deployment, signing, or KMS change is authorized by
this reference checkpoint.

## Native implementation checkpoint (2026-09-21)

The follow-on native branch now implements the six frozen routes, shared
publication/status orchestration, health/provenance projections, alert events
and optional critical webhooks in the Rust issuance service. The packaged main
constructs that service from the existing publication/status providers and
integration-secret vault, mounts the router, starts the optional automation
worker, and aborts/awaits it during shutdown. Worker configuration, alert
thresholds, webhook URL and bounded webhook timeout are typed once in
`IssuanceServiceConfig`.

Maintainer review found that the implementation and gateway router had not
added these six routes to the canonical native-coverage ledger. That omission
would have left the deletion gate blind to the actual owner. The reviewed
branch now binds every exact method/path/operation to this frozen contract,
rejects sibling and malformed template paths at the gateway, and reports the
lane-local 131-route ledger as **113 native / 18 remaining**. The separate
OID4VCI lane adds seven further routes; the combined count is not claimed until
the branches are restacked together and their exact integrated tree passes CI.
The same audit binds fourteen frozen Canvas Credentials/mirror environment
variables to their typed Rust consumers, moving the historical configuration
ledger from **28 frozen-native / 61 remaining** to **72 frozen-native / 17
remaining**. Fourteen newly migrated mirror settings and thirty previously
implemented typed Rust inputs are now accounted for. Five newer Rust-owned
settings are tracked separately as platform-additive, without claiming the
still-dynamic Python lookups or unrelated runtime modes.

PostgreSQL batch selection now uses `FOR UPDATE SKIP LOCKED` leases. A durable
effect-start marker prevents an expired claim from automatically repeating an
external provider action whose outcome became ambiguous before persistence.
Normal provider failures remain retryable. Claim metadata is internal and is
removed from public projections and successful final writes. This is an
intentional safety correction to the Python implementation's unclaimed
`SELECT ... LIMIT` batches; it preserves successful/error response behavior
while preventing concurrent duplicate provider effects.

Global automation also keeps alerts tenant-isolated. Durable alert events use
the organization on their source delivery record, and critical webhook calls
are deterministically partitioned into one payload per organization. This is an
intentional security correction to the Python implementation, which labelled a
multi-organization batch with its first record's organization and could combine
later tenants' alerts into that webhook payload. The native regression gate
exercises two organizations in one global batch and proves that neither event
metadata nor webhook alert arrays cross that boundary.

The native gate currently proves the route/authentication/validation matrix,
tenant-hidden publish admission, shared batch/automation behavior, provider
cancellation before persistence, alert/webhook ordering, health/provenance
output, and real-PostgreSQL tenant/claim/contention/fence behavior. Remaining
before cutover are the full frozen HTTP corpus comparison, independent
maintainer review, and all repository CI. The packaged-main gate now starts the
real issuance executable against the owned PostgreSQL/provider fixture, proves
all six routes are mounted with authentication-first admission, and performs an
authenticated mirror-health read. The publication adapter's 51-case corpus and
15 additional timestamp/cancellation/response cases remain required CI gates.
Only after those gates pass may the superseded Python route/helper/worker code
be deleted and the aggregate beta deployment proceed.

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
Run the same release-image capture command with
`--release-image --adapter-reference --check` for this corpus.
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
The container controller has its own 45-second streaming bound and runs with no
network, a read-only root filesystem and repository mount, no Linux capabilities,
no-new-privileges, and a bounded 16 MiB temporary filesystem.

Reproduce through the pinned container controller; an ambient Python environment
is deliberately rejected before route execution:

```text
python scripts/capture_canvas_mirror_reference.py <credentials-git-checkout> --release-image --check
python scripts/capture_canvas_mirror_reference.py <credentials-git-checkout> --release-image --adapter-reference --check
python scripts/capture_canvas_mirror_reference.py <credentials-git-checkout> --release-image --publication-boundary-reference --check
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

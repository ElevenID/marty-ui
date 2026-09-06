# Composed Canvas worker / REST reference

Status: independent published reference frozen; native composed-worker replay
is implemented and awaiting its required Linux execution result. This is not
Rust cutover or deployment proof.

## Actual execution boundary

`scripts/run_canvas_worker_rest_oracle.py` launches the real published worker
process, including the default processor loader, on the immutable image's
official PostgreSQL migrations. An actual loopback HTTPS server supplies the
assignment evidence. The worker reads and decrypts its organization-owned OAuth
token through its real repository, schedules the due target, leases the job,
calls the provider, commits fact/policy/review effects, records the durable job
outcome and reaches an idle heartbeat. No worker, processor, OAuth token loader,
provider response parser, database query or application clock is mocked.

The existing issued-review seed and snapshot SQL are reused. Before each stage,
the fixture makes the same target due and clears old heartbeat rows, then starts
a new worker. It does not manually insert or complete jobs. Each child is
interrupted only after its terminal/retry job and idle heartbeat are observed,
and is reaped on success or failure. Raw child logs are discarded.

## Frozen observations

| Stage | Durable outcome | Business effects |
| --- | --- | --- |
| Initial positive evidence | Succeeded, one attempt | One fact; policy allows; issued credential unchanged. |
| Later negative evidence | Succeeded, one attempt | New negative fact and one open correction review; credential remains active. |
| Duplicate negative evidence | Succeeded, one attempt | Existing fact reused; no duplicate fact, review or event. |
| HTTP 429 / Retry-After 37 | Retry, incomplete, lease released | Prior evidence/review retained; connected OAuth grant and encrypted token retained. |

The artifact records exact selected request fields (method, path/query, Accept
and synthetic bearer token), accumulated durable job projections, full fact
assertions, payload hashes, verification method, provider-effective timestamps,
review/application/event projections, OAuth/secret-use state and idle heartbeat.
The rate-limit delay is checked against 37 seconds with an explicit one-second
tolerance between database timestamps, not recorded as a fabricated exact delay.
Other Retry-After forms, jitter ranges and retry recovery still require their
own whole-worker gates.

Full issued-credential and issuance-transaction rows are compared within each
implementation before and after every stage; the encrypted token bytes must
also remain unchanged and differ from its plaintext. Random ciphertext, generated
row IDs and wall-clock timestamps are not used as cross-language equality keys.
This is a selected-projection reference, not full-row equivalence for every
worker table, all fact types, all providers or concurrent mutation scenarios.

## Provenance and test trust

The image and migration ownership remain those of the shared published-schema
fixture:
`ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`.
The frozen artifact retains worker and Canvas-router source SHA-256 values.
Two finalized raw captures agree byte-for-byte with SHA-256
`c5a58f293b327278c4ec9f4f2ee0d02ea3bc1112b701b5672b34fcbc0d3357d5`.
No native runtime implementation was changed to obtain this reference.

The checked-in JSON is whitespace-only formatting of the raw capture: numeric
tokens such as `90.0` are retained, not converted through a JavaScript number
round trip. An initial formatting pass lost those representations and was
corrected from the independent raw capture before qualification. Payload hashes
and all other expected observations remain those of the published process.

The initial HTTP seed failed the published OAuth HTTPS constraint. The fixture
was corrected to use HTTPS; the constraint was neither dropped nor relaxed.
Another observer setup error assumed a scalar verification-method column;
the published fact stores it in verification JSON, which the corrected query
now reads. Neither failed setup supplies reference expectations.

Certificate creation reuses the existing LTI HTTPS helper. The private key and
public certificate live only in the owned probe's temporary filesystem. HTTPX
deliberately ignores environment CA overrides with `trust_env=False`, so a
read-only, test-child-only `sitecustomize` selects the exact temporary public CA
through `certifi.where`. The application and transport implementations remain
unchanged: hostname/certificate verification, pinned-address connections,
no-proxy behavior and the exact private-origin allowlist are preserved. No host
trust store, deployment image or production setting is modified. This trust
configuration is explicit fixture scope, not proof of every production CA setup.

The unchanged Python subprocess SIGINT result -2 is retained; it corresponds to
the already-established shell/Docker exit 130. Native signal comparison must
preserve that representation distinction and keep Windows versus Linux evidence
separate.

## Required continuation

Local qualification passed all 38 configured published-image/schema tests with
zero failures, ignored or filtered cases (329.34 seconds), including regeneration
of the new reference and the existing startup replay. The 53 affected Python
contracts, strict all-target Clippy, Rustfmt, Ruff and Bash syntax checks passed.
Fresh hosted checks are still required for this reference checkpoint.

`worker_rest_reference_matches_published_process` regenerates the complete
reference in the mandatory configured image/schema suite. The native
`worker_rest_matches_frozen_published_process` gate now launches a child replay
with the same frozen HTTPS bodies. Its Rust test launches the actual worker
binary through the shared process owner, using native encrypted OAuth persistence
and a separate fresh published-schema database. The Python parent checks every
actual request; Rust compares each stage's durable jobs, facts, policy/review
snapshot, OAuth state and idle heartbeat, plus unchanged full issued rows and
ciphertext. No provider, worker cycle or outcome repository is substituted.

The native HTTPS/process-signal gate requires Linux, matching the existing
child-scoped trust harness. Windows compilation is not an execution pass for
this gate. Its helper test returns without the parent fixture environment during
normal test enumeration; the mandatory parent launches that exact helper with
the real fixture. Both test names are checked by the configured CI runner.
Keep the original reference immutable when diagnosing native differences and
preserve stronger native safety/event behavior where explicitly established.

The certificate helper's existing AGS/NRPS HTTPS gate remains mandatory on Linux.
A direct Windows invocation failed at its trusted-child read with both the
unchanged committed helper and this refactor; it is not claimed as a passing
Windows gate or weakened to bypass platform trust. The original runtime head's
hosted CI and Rust analysis are green; this checkpoint needs fresh hosted checks.

Continue the complete [worker cutover inventory](canvas-worker-cutover-readiness.md),
including other facts/providers, OAuth refresh/revocation, failures/recovery,
concurrency, active-I/O shutdown, readiness and every consumer. Keep the broader
issuance migration, feature-preserving branch cleanup, CSCA follow-up, recordings,
device/wallet acceptance and beta-only aggregate soak. Production is unchanged.

# Canvas worker provider timeout audit — 2026-09-07

Status: source-derived parity gaps, not a completed timeout replay or permission
to change worker routing. Do not apply a blanket 15-second timeout: the published
background roster intentionally uses 20 seconds. Equal numeric limits also do not
establish equal inactivity/deadline behavior.

This audit supplements the [cutover gates](canvas-worker-cutover-readiness.md)
and [normative worker contract](../../contracts/issuance-canvas-sync-worker.json).
It does not close gates 3–5, OAuth revocation gate 10, signing qualification,
consumer adoption or beta acceptance.

## Reference provenance and evidence boundary

Installed source was read from the already-present immutable image:

```text
ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176
```

Inspection used disposable containers with `--read-only --network none`, no
mounts, no application imports, no credentials and no deployment operations.
The following paths are relative to `/app/services/issuance/`; line references
below refer to this installed source, not a moving Python checkout.

| Source | SHA-256 |
| --- | --- |
| `infrastructure/api/canvas_routes.py` | `f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943` |
| `application/canvas_lti_services.py` | `ab5b5a6de0e1c3ed45838e6ca0c1df1c84f3eb311de41060a60754769d7ac6b3` |
| `application/canvas_oauth.py` | `ac040197766d630d86523552a619bef081de6a1c20c7426cbf7f54e7db23e36f` |
| `canvas_worker.py` | `c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a` |
| `infrastructure/api/signing_context.py` | `5ff4468fc6ffe097b6dfffe2c307249a1ecc4059dce5d52f8dabe5c0e1732c34` |

No new capture or Rust test was run for this audit. The preliminary two-read
deadline experiment's missing first fact is recorded separately in the
[provider-deadline report](canvas-worker-provider-deadline.md); it was not frozen
and is not a paired Python/Rust timeout observation. The actual mixed-roster
request/token-count mismatch recorded in [cutover readiness](canvas-worker-cutover-readiness.md)
is a separate token-reuse finding, not evidence that a timeout case passed or
failed.

## Per-operation mapping

The native values below are the current binary construction in
[`canvas_sync_worker.rs`](../../rust/services/issuance/src/bin/canvas_sync_worker.rs)
at lines 109, 151, 156 and 164. They are numeric settings, not claims of equivalent
wire behavior.

| Target / operation | Published Python | Current native | Published owner |
| --- | --- | --- | --- |
| Learner application and active issued-drift: assignment, quiz, module and course REST evidence | 15s | 20s | `canvas_routes.py:5649`, passed into `_read_canvas_rest_evidence` at 5358; stream at 5400 |
| Same targets: AGS token acquisition and result collection/pages | 15s | 20s | Same application client and requirements loop; `request_lti_access_token` / `read_ags_results` receive it |
| Background roster: REST users, bulk progress and individual candidate evidence | 20s | 20s | `_process_background_canvas_roster`, `canvas_routes.py:5902`; candidate loop remains inside that client scope |
| Background roster: NRPS token and memberships/pages | 20s | 20s | Same roster client passed to grant and membership helpers |
| Background roster: AGS token and per-candidate result pages | 20s | 20s | Same roster client, including candidate AGS calls around `canvas_routes.py:6115–6140` |
| OAuth refresh needed by either target family | 15s | 10s | Independent client in `_canvas_oauth_access_token`, `canvas_routes.py:1198` |
| Worker OAuth revocation retry sweep | 10s | 10s | Independent client in `canvas_worker.py:201` |
| Internal issuer-DID resolution | 10s | 10s | `signing_context.py:140` |
| Internal issuer-DID signing | 15s | 15s | `signing_context.py:197` |

`process_authoritative_canvas_sync_target` at `canvas_routes.py:6250` separates
background roster from learner application/issued drift. An AwardCandidate
target is unsupported and terminal before authoritative provider I/O; do not
assign it the roster timeout merely because roster processing writes candidate
observations. Rollout-disabled and already-expired drift paths likewise do not
establish provider timeout behavior.

REST collection helper `canvas_routes.py:1381`, evidence helper at 5358, LTI token
helper `canvas_lti_services.py:487`, collection helper at 546 and AGS/NRPS wrappers
at 644/665 all consume their supplied client without a per-request timeout
override. Pagination does not establish a new whole-collection deadline. OAuth
refresh uses a separate client, including when called before the roster's client
is opened. Internal signing also has separate clients; it does not inherit the
15s or 20s Canvas client.

Native authoritative REST, LTI grant and collection construction currently all
use the same `CanvasHttpClientPolicy` in
[`canvas_sync_provider_http.rs`](../../rust/services/issuance/src/canvas_sync_provider_http.rs)
at lines 234, 346, 400 and 529. Refresh and revocation share the separately
constructed [`HttpCanvasOAuthProvider`](../../rust/services/issuance/src/canvas_oauth_http.rs).
Changing that provider's global value to fix refresh would also change the
currently separate revocation requirement. The Python API disconnect endpoint's
15s client (`canvas_routes.py:4368`) is not the worker's 10s retry sweep.

## Inactivity is not a total request deadline

`canvas_lti_services.py:255–262` passes a float to `httpx.AsyncClient(timeout=...)`.
The pinned transport at lines 213–243 preserves request extensions when rewriting
the connection address. In the image's installed HTTPX `_config.py:247–250`, the
float populates connect, read, write and pool limits. Installed httpcore
`_async/http11.py:174–218` applies the read timeout to individual network reads,
including reads while streaming the response body. Successful progress can
therefore outlast one numeric timeout interval without timing out.

By contrast, native
[`client_for_canvas_origin`](../../rust/services/issuance/src/canvas_provider_http.rs)
at line 77 uses reqwest `ClientBuilder.timeout`, a total request deadline through
completion of the response body. Changing only 20 to 15 does not repair this
distinction. Numeric matches for roster, revocation or signing are not full
inactivity-parity qualification either; signing's implementation remains a
separate owner and scope.

The [three-read job-deadline corpus](../../contracts/canvas-worker-deadline-scenarios.json)
deliberately completes each of the first two responses below the published 15s
HTTP limit, then observes the 30s job deadline during the third read. Its early
release control, committed-prefix preservation and cancellation evidence must
remain intact. Passing that corpus **does not close these per-operation timeout
gaps**, nor prove real-provider lease-expiry behavior.

## Four required reference additions before timeout repair

1. **Target-sensitive delayed headers.** Use owned HTTPS barriers to release
   valid responses safely between 15s and 20s. Cover application REST and AGS
   acquisition/collection separately, with corresponding roster REST, NRPS and
   AGS controls. The source-derived expectation is application timeout versus
   roster success; capture the actual outcomes rather than fabricating them.
2. **Refresh versus revocation.** Delay a valid OAuth refresh response between
   10s and 15s and verify actual persisted token/connection outcome, then retain
   a separate revocation 10s stalled-response control. Use synthetic secrets and
   existing encrypted-storage owners. Do not conflate grant acquisition, refresh
   and revocation or change signing to satisfy these tests.
3. **Progress versus a real stall.** Stream bounded valid JSON with each read
   gap below the operation limit but total response duration above it. Pair it
   with a stopped-progress negative control and ordinary prompt-success control.
   Include collection pages and token-body handling at their owned boundaries;
   test compression through existing decoder fixtures where applicable.
4. **Composed durable outcomes and late-release stability.** Replay the new
   frozen observations through the actual worker with the published schema,
   exact request/grant traces, error codes and safe results. Preserve preexisting
   facts, heads, candidate observations and independently committed prefixes;
   distinguish an unavailable read from verified negative evidence. Prove no
   late effects after timeout, bounded child/handler cleanup and no leaked
   synthetic sentinels. Configure a sufficiently longer job deadline before
   startup so it cannot mask the request boundary. Never edit live job clocks,
   leases or schedules to manufacture a result.

Independent published regeneration and native comparison remain required. These
are proposed additions, not recorded passes or permission to replace existing
failure classifications, fences or corpora.

## DRY reuse candidates, not a new parallel timeout stack

- [`canvas_network_timeout.rs`](../../rust/services/issuance/src/canvas_network_timeout.rs)
  already owns lossless timeout values, phase classification, fresh operation
  budgets and cancellation-by-drop. Existing tests cover repeated successful
  operations exceeding one interval, stalled reads/writes and cancellation.
  Reuse this owner; do not duplicate timers or introduce a detached timeout task.
- [`canvas_operation_http.rs`](../../rust/services/issuance/src/canvas_operation_http.rs)
  already combines that owner with pinned HTTP/1 transport. `OperationSocket`
  resets read budgets after completed reads; `send` separates connect/TLS budgets;
  the response stream owns the connection driver and aborts it on drop. Existing
  credentials validation/status consumers use this client. It is a concrete
  reuse candidate, not an already-qualified worker replacement: it creates a
  single-request connection without a shared pool, and its request/write and
  response semantics still need the worker's form, pagination and cancellation
  evidence before adoption.
- [`canvas_provider_http.rs`](../../rust/services/issuance/src/canvas_provider_http.rs)
  already shares `resolve_canvas_origin` / `CanvasOriginPolicy` between the
  total-deadline and operation-deadline clients. Retain that DNS/private-origin,
  destination and TLS policy owner rather than creating new origin exceptions.
- `CanvasOperationResponse.chunk()` retains the existing
  [`content decoder`](../../rust/services/issuance/src/canvas_content_decoder.rs).
  Its convenience `bytes()` collects without a worker byte bound; do not replace
  the worker's bounded `read_json_response` or OAuth `limited_json` with that
  convenience method. Any shared response adapter must preserve size limits,
  status/Retry-After precedence, JSON behavior and cancellation. The
  [response-codec report](canvas-response-codecs.md) records separate boundaries;
  do not silently broaden this timeout repair into a codec-policy change.
- The existing [timeout-consumer scenarios](../../contracts/canvas-timeout-consumer-scenarios.json),
  [frozen oracle](../../contracts/canvas-timeout-consumer-oracle.json) and
  [loopback reference owner](../../scripts/run_canvas_timeout_consumer_oracle.py)
  already contain headers/body stalls and `progress_exceeds_total_budget`, plus
  compressed-progress cases. Their factory source hash matches the installed
  factory above. Reuse the transport cases and compare their recorded boundary;
  they execute the factory/helpers, not the worker's target-specific clients or
  durable business effects. The existing
  [indexed worker barrier](../../scripts/canvas_worker_deadline_https_fixture.py)
  and [worker HTTPS owner](../../scripts/canvas_worker_https_fixture.py) provide
  complementary actual-worker orchestration without replacing worker functions.

Future repair should select the timeout at the actual operation/target scope
while preserving per-run token reuse and cross-run isolation. Neither a blanket
numeric change nor replacing the whole response/provider stack is justified by
this source audit alone. Production and beta deployments remain unchanged.

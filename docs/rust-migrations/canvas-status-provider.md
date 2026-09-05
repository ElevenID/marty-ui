# Canvas lifecycle status provider candidate

## Implementation and feature boundary

`CanvasCredentialsStatusService` implements the next external-provider boundary
for the lifecycle delivery owner. It is a candidate, not a consumer cutover.
The existing pending-only default adapter and reachable Python remain active
until whole-consumer parity gates pass; their deletion remains required afterward.

The candidate preserves bridge POST status synchronization, Badgr DELETE
revocation, and Badgr's canonical-provenance-only suspension/reinstatement. The
latter intentionally makes no external call: the published provider does not
expose those operations, while ElevenID's canonical status remains authoritative.
Unknown provider names retain the published status path's bridge fallback rather
than borrowing the validation endpoint's unsupported-provider rejection.

Credential transaction identity is loaded from the credential's PostgreSQL row
and carried separately from the delivery. Ownership comparisons therefore do not
mistake a delivery's self-reported transaction for credential-side evidence.
The existing 17 lifecycle cases assert that this context reaches the provider.

Provider aliases, HTTPS-origin parsing and response excerpts now have one shared
implementation with management validation. Validation's stricter canonical-tenant
secret policy is unchanged. Delivery retains ordered nested metadata sources,
legacy aliases, tenant-scoped secret lookup and the fixed operator-token fallback.
Tenant metadata cannot select arbitrary environment variables or filesystem paths.
An operator-configured API base contributes a trusted origin; tenant metadata alone
does not. No new dependency, version, lockfile or public runtime route was added.

## Independently frozen evidence

`contracts/canvas-status-provider-scenarios.json` now contains 63 cases. Before the
initial Rust implementation, the first 55 cases were captured twice independently
against the pinned image and official corrected schema; another independent pair
retained complete output after the first display was truncated. The former
`badgr_untrusted_origin` label was corrected to `badgr_operator_configured_origin`:
the original input configured an operator origin, not an untrusted tenant origin.
Separate tenant-rejected and tenant-allowlisted cases prevent hiding this difference.

Published adapter SHA256:
`24f5c0f22c075af3a11abbb48be52bcc6535e0d4fc31e446f7fb218bfe40d679`.
Current scenario blob: `c7a777a104ac5040fdefa3a60317ef759761810f`.
Current oracle blob: `f8b20936c4c1fcf6fa0bdc7a58983d9908451a69`.
The original 55-case scenario/oracle blobs remain in commit `340a0503b`.

The corpus covers provider aliases/default selection, nested configuration and
issuer precedence, five tenant-secret reference aliases, missing-secret fallback,
ignored inline/env/file selectors, rollout and ownership rejection, action/reason
mapping, URL identifier escaping, a custom revoke template, HTTP failures,
transport failures, redirects, object/array/scalar/text/empty responses and bounded
error excerpts. It compares ordered secret lookups and HTTP calls, payloads,
selected headers, metadata and errors. Valid timestamp values become a marker;
synthetic bearer values become source labels. No real credential or deployment
endpoint is used, and credential/transaction database rows are verified unchanged.

Review found that the published URL validator resolves DNS before reaching the
mock HTTP transport. The harness now supplies a deterministic public DNS result
while retaining the actual validator. The original 55 observations are unchanged;
only the evidence-boundary description was corrected. This avoids depending on
host DNS or implying that the initial HTTP mock alone suppressed DNS lookups.

`status_provider_matches_frozen_protocol` always runs without Docker.
`status_provider_matches_published_python` additionally verifies a fresh published
capture against the committed golden and replays it through the native provider.
Both names are explicitly required by the configured hosted schema gate. The
golden is not generated from the Rust candidate.

The HTTP implementation uses the shared pinned-address client for the actual
request destination, disables redirects, and retains the configured request
timeout. A separate owned-loopback HTTP test verifies POST/DELETE, actual headers,
optional bearer authentication, Unicode JSON payloads, responses, no redirect
follow-up, and rejection when the localhost exception is disabled. Debug output
excludes token values and operator URLs. These tests are not real-provider or TLS
deployment acceptance.

## Initial provider qualification at 340a0503b

- All 17 configured published-schema tests passed in 95.58s, including the
  prior review/lifecycle tests with credential-side transaction context.
- After the DNS-boundary correction, two additional fresh published-provider
  runs passed in 4.06s and 3.94s against unchanged observations. Owned labelled
  schema containers were absent afterward.
- All 266 library tests passed in 4.84s, including actual loopback HTTP and
  redacted-configuration tests. Strict all-target Clippy passed in 29.75s.
- Five worker executable tests and 22 combined behavior tests passed.
- All 33 workflow/image tests passed in 1.23s. The first sandboxed invocation
  encountered Windows temporary-directory permission errors; the scoped rerun
  used a fresh owned directory and passed without modifying the tests.
- Changed Rustfmt, Ruff and `git diff --check` passed.

These results qualify this local candidate, not its eventual hosted merge or
deployment. Prior-head CI success must not be attributed to these new changes.

## Runtime configuration and persistence continuation

`IssuanceServiceConfig` now constructs the status-provider configuration from the
same parsed provider, fixed operator secret, timeout, rollout and pilot owners.
`CanvasCredentialsStatusService::from_runtime` assembles the actual HTTP transport
with those policies and the existing tenant-secret resolver. The production entry
point has not adopted this factory yet; no new provider policy is silently enabled.

Eight additional actual-Python cases were captured twice independently before
the corresponding corrections. All original 55 observations are unchanged.
The entire 63-case Rust replay now consumes `IssuanceServiceConfig::from_values`
rather than hand-building its provider configuration. It preserves absent/blank
issuer as JSON null, numeric/boolean issuer string conversion, legacy BASE_URL
fallback without implicit trust, explicit allowlisting, primary-base precedence,
and empty-organization rollout rejection.

A separate configured database/HTTP contract exercises real configuration,
encrypted tenant-secret storage and lookup, credential persistence, delivered-row
selection/hydration, provider HTTP, and success/error metadata. Suspend succeeds,
reinstate receives HTTP503 but durably records it, and revoke succeeds afterward.
The local HTTP handler verifies credential state is already persisted; the tenant
token wins over the operator token; the vault records usage; attempt counts and
unrelated delivery metadata survive all transitions. Canonical status publication
alone is controlled, not the mirror or repositories.

A fourth, separately reset synthetic starting state removes the selected delivery
row immediately before the HTTP server returns success. The service must report
`CanvasRetryUnavailable`, preserve the already-revoked credential, and emit no
fourth success event. This is a native fault regression for a disappearing row,
not a newly frozen Python storage-failure oracle or a claim about every SQL error.

The runtime contract is explicitly required by hosted test discovery. A unit test
also reads an actual synthetic token-file fixture, verifies direct-token precedence
without reading an unused missing file, checks normal publish/status timeout
precedence and pilot filtering, and checks redacted configuration diagnostics.

Hosted CI33996860721 and Rust CodeQL33996860698 passed at the prior provider
commit `340a0503bfd590c257f3e5168fd028eec9a43971`. Subsequent runtime changes require
fresh checks. No persistent deployment was changed.

Continuation verification: 267 library tests passed (13.43s); the full runtime
contract passed before the Docker outage (7.44s), then passed with the disappearing
row fault added (5.34s). Five worker executable and 22 combined behavior tests
passed; 33 workflow/image tests passed (2.14s); changed formatting/lint checks passed.
The first Clippy run failed writing compiler caches with OS error112. A subsequent
host check reported about27GiB free; the scoped retry passed strict all-target
Clippy (2.25s), followed by schema compilation (11.70s). No cache was deleted.

The final 18-test schema run did **not** pass: its Docker-free 63-case replay passed,
but all17 Docker-dependent tests failed at `Docker create`, before their behavior
assertions. A direct daemon query reported `Docker Desktop is unable to start`.
This is an infrastructure-blocked local full gate, not evidence that those tests
passed or that behavior regressed. No Docker restart or persistent deployment
mutation was attempted. Fresh hosted checks remain mandatory; local full-suite
qualification must be rerun after the backend is available.

## Remaining gates before cutover

- Close the remaining configuration behavior differences before consumer wiring.
  Python's fixed token-file helper tolerates OSError/empty files and is invoked
  lazily after tenant-secret selection; the existing shared Rust configuration
  loader is eager and rejects unreadable/empty files. Python float parsing accepts
  lexical/non-finite/range inputs that the existing positive-Duration parser does
  not. Freeze actual import and consumer behavior, preserve error timing and use
  the shared MMF numeric parser; do not narrow acceptance just to fit Duration.
- Extend published qualification for alternate URL/port normalization, template
  grammar, metadata shapes, response encodings, secret-lookup outages and safe
  persistent diagnostics. Controlled transport error parity does not prove identical
  HTTPX/reqwest network-error strings; native real-transport errors deliberately
  omit raw client details. Qualify that public diagnostic boundary explicitly.
- Qualify actual TLS, timeout/cancellation, configured private-provider behavior,
  and further persistence failures beyond the disappearing-row regression.
  The passing real HTTP chain does not qualify TLS or all SQL failure modes.
- Finish hydration, multiple-delivery and recovery cases; wire every intended
  consumer; remove pending-only staging and superseded Python after the gates.
- Land through protected review/checks, adopt the released migration component,
  complete demos/device acceptance and the aggregate beta-only release/soak.

No beta or production deployment was performed for this candidate.

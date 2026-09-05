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

`contracts/canvas-status-provider-scenarios.json` contains 55 cases. Before the
Rust implementation, the actual published adapter was captured twice independently
against the pinned image and official corrected schema; another independent pair
retained complete output after the first display was truncated. The former
`badgr_untrusted_origin` label was corrected to `badgr_operator_configured_origin`:
the original input configured an operator origin, not an untrusted tenant origin.
Separate tenant-rejected and tenant-allowlisted cases prevent hiding this difference.

Published adapter SHA256:
`24f5c0f22c075af3a11abbb48be52bcc6535e0d4fc31e446f7fb218bfe40d679`.
Scenario blob: `43ab72756ac781ba48bcb417b5c97b453e65b0d1`.
Final oracle blob: `a1e1f3b5512c83e34238c98ec3ea1e3c0f3f9de0`.

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

## Local qualification

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

## Remaining gates before cutover

- Complete actual environment/factory wiring, including legacy base-URL fallback,
  fixed operator secret-file loading and status-timeout/publish-timeout precedence.
  These must reuse the existing configuration/secret owner, not duplicate it.
- Extend published qualification for alternate URL/port normalization, template
  grammar, metadata shapes, response encodings, secret-lookup outages and safe
  persistent diagnostics. Controlled transport error parity does not prove identical
  HTTPX/reqwest network-error strings; native real-transport errors deliberately
  omit raw client details. Qualify that public diagnostic boundary explicitly.
- Qualify actual TLS, timeout/cancellation, configured private-provider behavior
  and the complete service/repository/provider chain, including persistence failure
  after successful external publication. Protocol replay alone is not enough.
- Finish hydration, multiple-delivery and recovery cases; wire every intended
  consumer; remove pending-only staging and superseded Python after the gates.
- Land through protected review/checks, adopt the released migration component,
  complete demos/device acceptance and the aggregate beta-only release/soak.

No beta or production deployment was performed for this candidate.

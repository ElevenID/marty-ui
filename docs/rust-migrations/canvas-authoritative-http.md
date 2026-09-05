# Authoritative Canvas provider integration

Status: three real REST HTTP tests and all three published-schema contracts pass
locally. A reproduced background AGS projection mismatch is corrected at the
candidate boundary. Hosted integration remains required; the worker is unrouted.

## Real REST transport

`tests/support/canvas_authoritative_http.rs` is included by the existing OAuth
behavior suite. It reuses its repository, secret-vault and token fixtures rather
than duplicating OAuth mocks. Tests construct the actual
`HttpCanvasAuthoritativeProvider` and `CanvasOAuthService`, then send real requests
to an exact-owned ephemeral loopback Axum server. The existing explicit localhost
test policy is used; production origin validation is unchanged. The server task
is aborted on drop, including failed assertions. No external provider is called.

Coverage includes all four REST fact types, exact paths/query parameters,
authorization and Accept headers, timestamp/assertion projections, discarded
synthetic name fields, paginated roster discovery and bulk progress. A missing
row in a successfully read bulk collection remains a verified negative. A429
retains Retry-After37; a rejected401 token marks reauthorization through the real
OAuth service, and a subsequent read fails before another HTTP request. REST
calls fail the test if they invoke LTI signing or key resolution.

This is real REST transport, not real PostgreSQL OAuth persistence or token
exchange: those boundaries retain the existing in-memory test fixtures.

## Background AGS projection correction

Published Python learner facts include `result_status` in their assertion and
`id` in the AGS source payload. Background-roster observations exclude both.
The shared native HTTP provider emits the full learner shape; previously the
roster processor persisted it unchanged, producing different observation hashes.

The mixed-roster test now supplies the full provider shape. Before correction,
the unchanged frozen Python corpus rejected the first verified mixed-source join:
the native assertion contained `result_status` and its payload hash differed.
The correction projects only AGS candidate observations before persistence;
learner/issued-drift and REST observations retain their full fields. A unit test
checks the exact candidate projection and preservation of the original input.
No frozen corpus, public feature, deployment consumer or Python runtime is removed.

All three configured schema contracts pass in33.06seconds, including the stronger
mixed-roster provider shape and the existing issued-review lifecycle. The combined
library/binary/OAuth/worker/configuration run passes286 tests. This is not a claim
that the whole service's integration or all-provider gates are complete.

## Still required

Actual AGS/NRPS HTTPS requests, service trust, token exchange, pagination and
provider-wide errors remain to be qualified. The mixed-roster replay controls
normalized provider outputs; it is not an AGS HTTP test. Complete published-Python/
native transport differentials, concurrency/audit rollback, manual review
endpoints, readiness and every deployment consumer remain open. Keep the reachable
Python worker until complete cutover gates pass. No beta or production deployment
is included here.

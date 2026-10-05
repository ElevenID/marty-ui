# Canvas LTI login test-pyramid slice

The source-owned `CanvasLtiLoginSubmission::validate` unit matrix covers the pure
missing-hint, issuer-mismatch, and client-ID-mismatch decisions with literal
expected errors. It also checks that matching padded values normalize. These
decisions do not require a router, repository, database, or launched service.

The mock-repository HTTP behavior suite retains the missing-platform,
pilot-disabled, missing-hint, issuer-mismatch, and client-ID-mismatch responses,
asserting status, response detail, and no launch-state write. Its happy JSON and
form cases retain redirect,
request parsing, generated state/nonce, and persistence assertions. Malformed
bodies, content type, and persisted trust-metadata drift also remain HTTP-owned.
The PostgreSQL contract is unchanged: it proves schema use, atomic state
persistence, and database-clock expiry. No database case is replaced by a mock.

The issuer and client-ID route cases are not redundant with the unit matrix:
without them, a route that bypasses either validation branch after receiving a
present hint could still pass the HTTP suite. The test inventory for this seam
is three source-owned negative unit cases plus one positive normalization case;
five retained HTTP test functions (including five cases in the failure loop);
and one PostgreSQL contract test function. Searches in this repository,
`marty-integration-tests`, and `marty-demo-recorder` found no released-stack E2E
matrix for these exact mismatch inputs. With both boundary checks retained,
the extraction does not reduce the HTTP workload and should not be presented
as a test-pyramid speed improvement. This patch does not reclassify any case as
nightly or major-only and does not change protected test selection.

# Canvas LTI login test-pyramid slice

The source-owned `CanvasLtiLoginSubmission::validate` unit matrix covers the pure
missing-hint, issuer-mismatch, and client-ID-mismatch decisions with literal
expected errors. It also checks that matching padded values normalize. These
decisions do not require a router, repository, database, or launched service.

The mock-repository HTTP behavior suite retains the missing-platform,
pilot-disabled, and missing-hint responses, asserting status, response detail,
and no launch-state write. Its happy JSON and form cases retain redirect,
request parsing, generated state/nonce, and persistence assertions. Malformed
bodies, content type, and persisted trust-metadata drift also remain HTTP-owned.
The PostgreSQL contract is unchanged: it proves schema use, atomic state
persistence, and database-clock expiry. No database case is replaced by a mock.

The two mismatch cases removed from the HTTP failure loop repeated the pure
validation decision and generic `Invalid` response mapping already covered by
the remaining missing-hint HTTP sentinel. The test inventory for this seam is
three source-owned negative unit cases plus one positive normalization case;
five retained HTTP test functions (including three cases in the failure loop);
and one PostgreSQL contract test function. Searches in this repository,
`marty-integration-tests`, and `marty-demo-recorder` found no released-stack E2E
matrix for these exact mismatch inputs. This is a small ownership improvement,
not a measured CI-speed or E2E-count reduction. This patch does not reclassify
any case as nightly or major-only and does not change protected test selection.

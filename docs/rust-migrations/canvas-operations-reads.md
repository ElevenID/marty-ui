# Native Canvas operations reads (candidate, not routed)

The existing Rust issuance crate now contains job list/detail, candidate list,
and correction-review list handlers. They are exposed only by the candidate
router; the live issuance router, gateway allowlist and deployed consumers are
unchanged. All eight operations remain reachable through Python until the
whole operations/worker cutover is qualified. The four writes are not implemented
by this read-only increment.

The service reuses shared management-key verification, worker job statuses and
lossless integer parsing. Fixed SQL statements bind every caller value. Public
projections retain the published DTO fields/nulls but omit private learner,
lease, claim and provider fields. Job results retain only the published scalar
allowlist and error summaries use its redaction and character-limit rules.
Candidate binding filtering occurs before LIMIT; job/review binding and
job/candidate platform filters retain the published bounded post-query window.

## Evidence

- The original 46-case published HTTP/database golden is unchanged. Its first
  25 read cases replay against native Axum and real officially migrated
  PostgreSQL, comparing status, content type, full normalized response, selected
  durable state and unchanged credential/transaction rows.
- A separate 75-case corpus captures published ASGI/auth/input validation with
  an empty memory repository. Its source hash and Pydantic version are frozen.
  This supplements, not replaces, the real-database baseline. The published
  capture repeats identically inside the existing schema harness before native
  replay on empty PostgreSQL tables. Input golden blob:
  `d2fbd9c671e14f8affbf0ad6bd7a3524b164096e`.
- The input replay first failed on `1_0.00`: published200/native422. The fix
  accepts the captured decimal-zero/underscore grammar using the shared
  lossless integer parser and checks bounds before machine conversion. Huge
  integers preserve range-error rather than parse-error responses. Unknown
  status, whitespace, duplicate query values and validation precedence are
  covered. Neither golden was rewritten to make Rust pass.
- Additional real-database checks place a matching review at positions501 and
  500, verify the default100 limit and empty-filter semantics, hide a foreign
  tenant, and verify a closed pool produces a sanitized500 response. These
  directly exercise the previously frozen normative500-row rule; they are not
  an additional published differential fixture.
- Seven configured schema tests pass locally (39.44s), all258 library tests
  pass (6.58s), and20 focused CI/image tests pass (0.74s). Mandatory CI registration
  includes both new tests; hosted qualification is still required.

Timestamp values are checked as RFC3339 and normalized to presence as in the
original baseline; exact temporal/wire-format equality is not claimed. The
corpus is not exhaustive proof of malformed-input, very-large JSON numeric or
every job/candidate pagination boundary. Preserve these remaining gates.

## Next work, not optional cleanup

Implement application enqueue, dead-letter retry/resolve and manual review
resolution using the existing enqueue and credential lifecycle owners. Reuse
the shared review locking/audit mechanisms and qualify recovery on the corrected
schema from credentials #266, merged as
`51f0a758a076777cb18a30b1db3f89c74ac23e01`. That repair does not change the
historical published golden. Finish failure/race/rollback/provider coverage,
route every intended consumer, delete superseded Python after gates, and perform
aggregate beta-only acceptance and soak. No production deployment is authorized
by this candidate or its tests.

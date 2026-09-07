# OAuth revocation coverage audit

Scope: gate 10 of the whole-worker cutover, checked against
`contracts/issuance-canvas-sync-worker.json` sections `oauth_revocation`,
`retry_and_backoff.oauth_revocation`, and the explicit legacy-oracle gap.
This is not a completion claim for the worker or the wider migration goal.

| Requirement | Evidence inspected | Remaining qualification or gap |
| --- | --- | --- |
| Remote success, rejection, timeout and rate-limit classification | Seven published-process captures and actual native Linux PASS markers at31355; scoped real adapter regression | Qualified for the captured transport cases, not arbitrary provider failures |
| First retry, stored deadline and token retention | Seven transport cases and eight separately frozen Retry-After cases | Eight-case native extension still awaits its exact-head hosted run |
| Later-attempt exponential backoff and cap | Five independently captured published-process histories at counts1,9,10,11,999; native replay and bounded-helper checks implemented | Fresh native Linux qualification remains pending; first-attempt evidence is not substituted |
| Owner-fenced success and retry writes | Two held-response replacement-owner process captures; full replacement-row and ciphertext equality | Both native PASS markers verified at d0a09792, CI34068063872 |
| Failed disconnected projection still cleans up tokens | Actual platform UPDATE barrier and synthetic write-failure capture; separate qualified privacy/counter replay | Native whole-process PASS marker verified at d0a09792, CI34068063872 |
| Stronger native tenant-atomic cleanup | Existing real PostgreSQL OAuth contract, shared transaction implementation; token and unrelated-tenant checks in every process capture | Retain improvement; do not require Python's weaker intermediate transaction order |
| Due selection, status/lease eligibility and order | [Two actual multi-row queue captures](canvas-worker-oauth-revocation-queue.md), exact unchanged excluded rows, actual acquisition journal, and real repository differential regression | Rust null-order discrepancy corrected; native whole-process queue qualification pending |
| Batch cap and lease duration | Frozen environment/range corpora, actual normal-batch queue selection, and [four actual acquired-lease captures](canvas-worker-oauth-revocation-lease.md) with native replay implemented | Native acquired-duration qualification pending; exact nonempty 500-row cap still needs focused evidence |
| Returned revocation success/retry counters, including owner-fence loss | Qualified privacy replay checks successful cleanup despite marker error; process heartbeat does not expose cycle counters | Add direct real-cycle observations for retry and fence-loss counters; do not infer them from idle alone |
| Exact tenant-scoped secret references | Shared reference parser unit tests reject foreign tenant and nested paths; valid encrypted-secret process cases | Worker composition for unavailable/malformed/foreign references needs explicit observation before claiming the whole branch |
| Logging privacy | Independently captured twelve-case hardened worker corpus, actual native replay and known-error controls | Retain this separate provenance; do not claim the older transport image is the hardened privacy source |

The remaining sequence is finite: qualify the implemented process extensions,
including later-history backoff; then address nonempty queue/lease boundaries,
cycle counters and secret-resolution branches. Each addition must close a named
contract requirement rather than introduce an unspecified new acceptance gate.
Repository/unit evidence remains useful but is not relabeled as whole-process
differential parity. All consumer/readiness/deletion/beta gates remain separate.

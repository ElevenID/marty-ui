# OAuth revocation coverage audit

Scope: gate 10 of the whole-worker cutover, checked against
`contracts/issuance-canvas-sync-worker.json` sections `oauth_revocation`,
`retry_and_backoff.oauth_revocation`, and the explicit legacy-oracle gap.
This is not a completion claim for the worker or the wider migration goal.

CI34072045954 at3e9b401f6 finished with 84/86 configured entries passing in
1871.63s. The limited queue case and all four lease cases failed in the test
observer: a retained, unselected connection has a SQL NULL retry deadline, but
the scalar decoder handled only absence of a row. All23 prior native revocation
markers and the all-eligible queue case passed; separate worker DB4/4 passed in
96.79s. This failed run does not qualify the composed checkpoint.

The decoder now distinguishes nullable column decoding from optional row lookup,
then maps either absent deadline to the existing optional observation. A real
published-schema regression reproduced the exact UnexpectedNullError before the
fix and covers SQL NULL, a numeric deadline and no row. No runtime, frozen oracle,
assertion tolerance or case was changed or removed. Fresh native qualification
is still required for the corrected queue/lease and new selection/counter entries.

| Requirement | Evidence inspected | Remaining qualification or gap |
| --- | --- | --- |
| Remote success, rejection, timeout and rate-limit classification | Seven published-process captures and actual native Linux PASS markers at31355; scoped real adapter regression | Qualified for the captured transport cases, not arbitrary provider failures |
| First retry, stored deadline and token retention | Seven transport cases and eight separately frozen Retry-After cases | All eight native timing markers qualified at75d82, CI34069978028 |
| Later-attempt exponential backoff and cap | Five independently captured published-process histories at counts1,9,10,11,999; native replay and bounded-helper checks | All five native history markers qualified at75d82, CI34069978028; first-attempt evidence is not substituted |
| Owner-fenced success and retry writes | Two held-response replacement-owner process captures; full replacement-row and ciphertext equality | Both native PASS markers verified at d0a09792, CI34068063872 |
| Failed disconnected projection still cleans up tokens | Actual platform UPDATE barrier and synthetic write-failure capture; separate qualified privacy/counter replay | Native whole-process PASS marker verified at d0a09792, CI34068063872 |
| Stronger native tenant-atomic cleanup | Existing real PostgreSQL OAuth contract, shared transaction implementation; token and unrelated-tenant checks in every process capture | Retain improvement; do not require Python's weaker intermediate transaction order |
| Due selection, status/lease eligibility and order | [Two actual multi-row queue captures](canvas-worker-oauth-revocation-queue.md), exact unchanged excluded rows, actual acquisition journal, and real repository differential regression | Rust null-order discrepancy corrected; native whole-process queue qualification pending |
| Batch cap and lease duration | Frozen configuration/range corpora, [four actual acquired-lease captures](canvas-worker-oauth-revocation-lease.md), and [matched real-repository selections](canvas-worker-oauth-revocation-selection.md) from 509 rows at limits around 500 | Nonempty cap matches locally; exact-head hosted repository and acquired-lease process qualification pending. Repository selection is not 500 remote requests |
| Returned revocation success/retry counters, including owner-fence loss | [Four actual cycle-return captures](canvas-worker-oauth-revocation-counters.md), exact regeneration, real Rust cycle replay implemented; separate qualified privacy marker-error counter replay retained | Native Linux cycle replay awaits exact-head qualification; no counters inferred from heartbeat or stored retry count |
| Exact tenant-scoped secret references | Shared reference parser unit tests reject foreign tenant and nested paths; valid encrypted-secret process cases | Worker composition for unavailable/malformed/foreign references needs explicit observation before claiming the whole branch |
| Logging privacy | Independently captured twelve-case hardened worker corpus, actual native replay and known-error controls | Retain this separate provenance; do not claim the older transport image is the hardened privacy source |

The remaining sequence is finite: qualify the queue/lease process extensions
and nonempty cap repository differential; qualify the implemented cycle-counter
replay and observe remaining secret-resolution branches. Each addition must close a named
contract requirement rather than introduce an unspecified new acceptance gate.
Repository/unit evidence remains useful but is not relabeled as whole-process
differential parity. All consumer/readiness/deletion/beta gates remain separate.

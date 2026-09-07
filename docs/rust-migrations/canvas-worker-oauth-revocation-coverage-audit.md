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
assertion tolerance or case was changed or removed.

The corrected checkpoint e70e3abccd83b4f6893ea655f9a97b000aa97e54 subsequently
passed CI34074425466: 90 configured entries in 1960.69s, separate worker DB4/4
in 96.98s, and all applicable exact-head checks including Rust CodeQL34074425459.
All 33 native markers were inspected: the earlier23 plus two queue, four lease
and four cycle-counter cases. Both real repository comparisons passed.

The later df3ed290b19a2cd8e82ef21bfa83355cb2c62a83 checkpoint passed CI34076998603:
98 configured entries in 2085.34s, separate worker DB4/4 in 96.39s and all applicable
exact-head checks, including Rust CodeQL34076998599. All 39 OAuth native markers
were verified, including six secret-resolution cases with zero requests. Actual
schema-rejection and native empty-token tests passed alongside retained repository
and nonempty transport cases. Later completion-race changes remain unqualified.

| Requirement | Evidence inspected | Remaining qualification or gap |
| --- | --- | --- |
| Remote success, rejection, timeout and rate-limit classification | Seven published-process captures and actual native Linux PASS markers at31355; scoped real adapter regression | Qualified for the captured transport cases, not arbitrary provider failures |
| First retry, stored deadline and token retention | Seven transport cases and eight separately frozen Retry-After cases | All eight native timing markers qualified at75d82, CI34069978028 |
| Later-attempt exponential backoff and cap | Five independently captured published-process histories at counts1,9,10,11,999; native replay and bounded-helper checks | All five native history markers qualified at75d82, CI34069978028; first-attempt evidence is not substituted |
| Owner-fenced success and retry writes | Two held-response replacement-owner process captures; full replacement-row and ciphertext equality | Both native PASS markers verified at d0a09792, CI34068063872 |
| Failed disconnected projection still cleans up tokens | Actual platform UPDATE barrier and synthetic write-failure capture; separate qualified privacy/counter replay | Native whole-process PASS marker verified at d0a09792, CI34068063872 |
| Stronger native tenant-atomic cleanup | Existing real PostgreSQL OAuth contract, shared transaction implementation; token and unrelated-tenant checks in every process capture | Retain improvement; do not require Python's weaker intermediate transaction order |
| Due selection, status/lease eligibility and order | [Two actual multi-row queue captures](canvas-worker-oauth-revocation-queue.md), unchanged excluded rows, actual acquisition journal and real repository comparison | Both native process markers and repository comparison qualified at e70e3abcc; corrected Rust null ordering retained |
| Batch cap and lease duration | [Four acquired-lease captures](canvas-worker-oauth-revocation-lease.md) and [real-repository selections](canvas-worker-oauth-revocation-selection.md) from 509 rows at limits around 500 | All four native lease markers and repository comparison qualified at e70e3abcc. Repository selection is not 500 remote requests; huge lease input remains scoped to revocation phase |
| Returned revocation success/retry counters, including owner-fence loss | [Four actual cycle-return captures](canvas-worker-oauth-revocation-counters.md), exact regeneration and real Rust cycle replay; separate privacy marker-error counter replay retained | All four native cycle markers qualified at e70e3abcc; no counters inferred from heartbeat or stored retry count |
| Exact tenant-scoped secret references | [Six published worker observations](canvas-worker-oauth-revocation-secrets.md), independent regeneration, real schema rejections and actual native replay | All six zero-request markers and schema-rejection test qualified at df3ed290b; empty plaintext is separately rejected by the published save API, not a captured worker scenario |
| Empty plaintext from the native vault | Real native cycle regression reproduced dispatch absent from the published guard; non-empty check, retry and ciphertext preservation verified | Qualified at df3ed290b alongside nonempty transport cases; counting-provider regression is not HTTPS parity |
| Logging privacy | Independently captured twelve-case hardened worker corpus, actual native replay and known-error controls | Retain this separate provenance; do not claim the older transport image is the hardened privacy source |

The named queue/lease, cap, cycle-counter, six-case secret-resolution, native
empty-token and schema-rejection extensions are now qualified at the recorded
boundaries. Retain them in fresh exact-head runs. Each addition must close a named
contract requirement rather than introduce an unspecified new acceptance gate.
Repository/unit evidence remains useful but is not relabeled as whole-process
differential parity. All consumer/readiness/deletion/beta gates remain separate.

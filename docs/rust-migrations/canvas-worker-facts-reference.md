# Whole-worker reference for all four Canvas REST facts

Status: independently frozen reference and actual native replay qualified on
Linux at `6977a70bad8feeb69ba3a456133f4ccd6e5f68ab`.
This extends the [assignment-only reference](canvas-worker-rest-reference.md)
without replacing its inputs or expected observations.

The existing actual-process harness accepts a statically mounted scenario
extension. It reuses the original issued-review seed, encrypted OAuth setup,
real HTTPS and official published migrations, then supplies four required
requirements on the same binding: assignment score, quiz score, module
completion and course completion. No processor/provider or database outcome
is mocked. Each process performs all four HTTP reads.

| Stage | Facts and policy | Durable job |
| --- | --- | --- |
| All four permit | Four new facts; policy allows | Succeeded |
| All four deny | Four new facts; one open correction review; policy denies | Succeeded |
| Duplicate denial | Four facts reused; no duplicate facts/reviews/events | Succeeded |
| Assignment rate-limited; other three recover | Three new facts retained; old negative assignment head remains; policy denies | Retry after 37 seconds |

The partial-failure stage matters: a blanket rollback would discard successful
observations, while treating partial success as a successful job would lose its
required retry. The credential stays active, the application stays approved, and
complete issued-credential/transaction rows and encrypted token bytes are unchanged
after every stage. The reference records all 16 exact HTTPS requests.

## Provenance and boundaries

Both independent raw captures agree byte-for-byte with SHA-256
`e44c5da98cd05218a2ee492a8a4b6732ae819c17fa23e72ed16a81604198375c`.
The frozen JSON retains every non-whitespace token, including floating-point
representations. No native result supplies expectations. Published image/source
pins, TLS verification and test-child-only trust are unchanged.

Facts are ordered by type, effective timestamp and payload hash; random IDs do
not define cross-language equality. Fixed provider timestamps remain observed,
not replaced with wall clock. Full assertions, hashes, verification methods and
effective timestamps are recorded. Jobs and the existing review/application/event
snapshot retain their original queries; the review projection is not full-row
or all possible triggering-fact equivalence.

`worker_facts_reference_matches_published_process` regenerates this reference
in the mandatory configured suite. The original assignment reference must
regenerate unchanged after the shared harness extension. Native adoption must
retain both corpora and use the actual worker binary, HTTPS and encrypted OAuth
persistence. That configured execution passed at the recorded head.

The native `worker_facts_match_frozen_published_process` gate now reuses the
assignment replay's actual process/database/OAuth owners and checks this second
corpus. The shared HTTPS parent supplies the 16 frozen responses and checks all
actual requests; Rust compares every stage's durable state and unchanged issued
rows/ciphertext. Both assignment and all-fact parent gates remain mandatory.
No production runtime or expected observations were modified for adoption.

Exact-head CI `34034992317` and Rust CodeQL `34034992376` passed. The configured
database job explicitly records the all-fact replay passing all 16 requests and
the original replay passing all 4 requests; all 42 configured tests passed in
450.86 seconds. Its earlier unconfigured 0.25-second run is not runtime evidence.
See the [completed database job](https://github.com/ElevenID/marty-ui/actions/runs/34034992317/job/101491334491).

Reference validation at `853e9f099`: the configured executable passed 41 tests in
336.36 seconds, including both reference regenerations. Its Linux-native parent
and fixture-child entries do not establish native HTTPS execution on Windows.
Native adoption compiles; strict all-target Clippy, formatting, Bash syntax and
53 affected Python contracts passed. Further extensions need fresh exact-head CI.

This reference alone closes no deployment or whole-worker gate. Continue the
full [14-gate and consumer inventory](canvas-worker-cutover-readiness.md), including
other providers, OAuth transitions, failure/recovery, concurrency and active
shutdown. No runtime feature, consumer selection or deployment changes here.

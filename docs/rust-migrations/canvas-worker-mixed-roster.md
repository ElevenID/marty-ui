# Complete-worker mixed roster, resume and wrap

This extends the older twelve-stage direct-processor corpus with actual
published worker processes, real loopback Canvas HTTPS and a scoped synthetic
signer HTTP fixture. It does not qualify the remote signer or cryptographic
service. Production and deployment consumers remain unchanged.

## Behavioral capture

The fixture seeds only a fresh, owned published-schema database before worker
startup. It retains issued credentials, issuance transactions and encrypted
OAuth material. A six-user roster arrives unsorted with a duplicate; the worker
must deduplicate and order it, process three users per naturally scheduled
minute, persist its cursor, and resume after an idle-process restart.

Initial claimed and dismissed candidates retain independently frozen positive
observation heads. Other learners exercise missing identity, subject-only
identity, inactive/active membership, pending and observed candidate states.
Provider changes introduce negative AGS evidence, an outage, duplicate evidence
and positive recovery. No running job, lease, clock, schedule timestamp,
candidate state or schema constraint is edited.

Two independent actual published captures passed in 366.35 and 365.89 seconds.
Their 60,667-character serialized observations were byte-identical (SHA-256
`ad31e821786326701f19d3eac315230ea54591572ff0530c6b0b75de69d016b0`), without
additional normalization. The parent independently parsed and compared both
before freezing `contracts/canvas-worker-mixed-roster-oracle.json`. That file
preserves the raw captured JSON, including floating-point numeric tokens.
The observations:

| Stage | Cursor | Canvas requests | New observations | Pending in batch |
| --- | ---: | ---: | ---: | ---: |
| Tail positive / wrap | 0 | 10 | 2 | 1 |
| Head identity gates / idle restart | 3 | 3 | 0 | 0 |
| Resumed tail negative | 0 | 10 | 3 | 0 |
| Head active membership | 3 | 6 | 2 | 1 |
| Tail provider outage | 0 | 10 | 0 | 0 |
| Head duplicate observations | 3 | 6 | 0 | 1 |
| Tail positive recovery / wrap | 0 | 10 | 3 | 1 |

Every job succeeded on its first attempt. Claimed/dismissed states, issued rows,
transactions and ciphertext survived every stage and shutdown. Raw roster
name/email sentinels were not retained in candidate/observation storage. The
idle restart and final interrupt left durable projections and raw job rows
unchanged in both runs. Seven frozen-corpus integrity tests and thirteen actual
fixture transport tests passed together in 5.59 seconds. This is reproducible
published behavior and fixture evidence, not native parity qualification.

The permanent configured published-reference comparison subsequently passed in
366.31 seconds. An earlier comparison correctly caught a freezing-tool error:
JavaScript reformatting had changed `90.0` tokens to `90`. The artifact was
restored from the raw capture, not reconciled to weaker expectations; its hash
now matches both original captures exactly. Numeric integrity tests and lossy
rewrite controls separately require floating-point scores and integer counters.

## Composition matters

The actual durable job result contains `candidates_seen`, `pending_claim`,
`identity_link_required` and `observations_written`. Unlike the direct processor
result, it excludes `roster_remaining`; that is the published worker's existing
safe-result projection. The native safe-result allowlist already matches this
source behavior, but actual native execution must still prove the composition.
The target's projected `worker_id` is null after roster saves. Do not normalize
these observed values away to match a different test layer.

NRPS uses one scoped token exchange per stage; stages reading AGS obtain one
additional AGS token. The fixture verifies real resolver/signing HTTP shapes
and generated assertion claims without storing dynamic claims or providing
real signing keys. Both the native HTTP path and its scoped token reuse remain
to be compared against the frozen request trace.

The initial capture attempt exposed a fixture setup omission: a self-managed
Canvas origin needs its exact origin in `CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST`,
in addition to private-origin HTTPS permission. The successful fixture supplies
that exact loopback origin before startup. No runtime trust guard was relaxed.

## Remaining qualification

The frozen published reference now has a mandatory configured regeneration
test. The native replay and Python transport driver are implemented and
registered in the mandatory Linux suite; compilation and local fixture tests
do not establish native runtime parity. Execute
the same seven stages through a continuously running native worker, including
the one specified restart. Reuse shared seed, snapshot, TLS and process owners;
do not substitute direct processor calls or restart after every stage. Compare
complete durable state and exact transport traces before changing any runtime
behavior. Preserve the original twelve-stage corpus and all other
[worker cutover gates](canvas-worker-cutover-readiness.md).

The native driver compares the four exact transport ledgers before acknowledging
each stage, holds both observer locks across final comparison and stage reset,
and retains the final ledger through worker/child exit and joined fixture
shutdown. Output uses owned temporary files, avoiding pipe backpressure while
waiting for stage markers. Failure reports retain bounded diagnostic tails.
Thirty-two driver tests include a real failing child that writes 256 KiB to each
stream; failure remains prompt, cleanup completes, and no stage advances.

Source review identified possible native token-reuse and target-metadata
differences. They remain hypotheses until the Linux replay produces actual
evidence. Neither the frozen traces nor runtime guards have been relaxed to
anticipate those results. This batch changes test infrastructure, not provider
or signing implementations.

Final local checks: 1,201 Python tests passed with one existing skip in 62.16s;
strict all-target Rust Clippy passed in 6.97s; Rustfmt, changed-file Ruff and
shell syntax checks passed. Registration now contains 119 entries, not 119
qualified runtime passes. The last hosted checkpoint remains the recorded
115-entry head until the new exact-head Linux run completes successfully.

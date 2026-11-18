# Complete-worker mixed roster, resume and wrap

This extends the older twelve-stage direct-processor corpus with actual
published worker processes, real loopback Canvas HTTPS and a scoped synthetic
signer HTTP fixture. It does not qualify the remote signer or cryptographic
service. Production and deployment consumers remain unchanged.

## Current qualification — exact Linux checkpoint

Commit `9cbba6b7bc687614e8c2d74ef78fab532e5888fb` passed
[CI 34109922914](https://github.com/ElevenID/marty-ui/actions/runs/34109922914)
and [Rust CodeQL 34109922824](https://github.com/ElevenID/marty-ui/actions/runs/34109922824).
The [configured runtime job 101703569433](https://github.com/ElevenID/marty-ui/actions/runs/34109922914/job/101703569433)
provides the following actual execution evidence:

- Early mixed-roster preflight: **one passed**, 120 filtered out, in **365.39s**.
  Its log explicitly reports all **seven stages and 55 actual Canvas HTTPS requests**.
- Full configured published-schema suite: **121 passed**, zero failed or ignored,
  in **3319.49s**. This includes another successful seven-stage native replay and
  the fresh published-reference regeneration/comparison.
- Configured worker PostgreSQL suite: **four passed** in **96.40s**, including the
  database-backed scheduler/recovery/renewal/heartbeat vectors and helper controls.

The workspace's earlier 121-test result in 0.34s and four-test worker PostgreSQL
result in 0.01s are **not** database qualification: those invocations lack the
database opt-in, so gated bodies return early while pure controls still run.
The 121 configured suite entries are also not a claim of 121 independent
whole-worker scenarios. Concurrent suite logs were buffered and emitted together;
their printed wall timestamps are not individual test execution times.

The passing driver compares complete ordered lists for Canvas requests, token
scopes, signer requests and signer operations at every stage. The counts below
come from the **exact commit's frozen reference arrays**, whose equality the
successful run enforces; CI prints the seven-stage/55-request summary, not every
passing ledger. Signer traffic remains synthetic HTTP fixture traffic.

| Stage | Canvas requests | Token scopes | Signer requests | Signer operations |
| --- | ---: | ---: | ---: | ---: |
| `tail_positive_wrap` | 10 | 2 | 4 | 4 |
| `head_identity_gates` | 3 | 1 | 2 | 2 |
| `resumed_tail_negative` | 10 | 2 | 4 | 4 |
| `head_active_membership` | 6 | 2 | 4 | 4 |
| `tail_provider_outage` | 10 | 2 | 4 | 4 |
| `head_duplicate_observations` | 6 | 2 | 4 | 4 |
| `tail_positive_recovery` | 10 | 2 | 4 | 4 |
| **Total** | **55** | **13** | **26** | **26** |

This supersedes the metadata and excess-token failures recorded below for this
seven-stage corpus. It qualifies its populated roster, identity/evidence states,
natural cursor resume/wrap, specified idle restart and exact transport composition.
It does **not** close every [worker cutover gate](canvas-worker-cutover-readiness.md),
the separate global-deadline/provider-timeout work, remote signing/crypto,
consumer cutover, deployment or beta acceptance.

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
fixture transport tests passed together in 5.59 seconds. These capture-only
results established reproducible published behavior, not native parity by
themselves; the later Linux qualification is recorded above.

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
source behavior, and the seven-stage native run now proves this composition.
The target's projected `worker_id` is null after roster saves. Do not normalize
these observed values away to match a different test layer.

NRPS uses one scoped token exchange per stage; stages reading AGS obtain one
additional AGS token. The fixture verifies real resolver/signing HTTP shapes
and generated assertion claims without storing dynamic claims or providing
real signing keys. The native HTTP path and its invocation-scoped token reuse
now match this frozen request trace in the exact Linux checkpoint above.

The initial capture attempt exposed a fixture setup omission: a self-managed
Canvas origin needs its exact origin in `CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST`,
in addition to private-origin HTTPS permission. The successful fixture supplies
that exact loopback origin before startup. No runtime trust guard was relaxed.

## Replay mechanics and remaining scope

The frozen published reference now has a mandatory configured regeneration
test. The native replay and Python transport driver execute in the mandatory
Linux suite. The successful checkpoint runs the same seven stages through a
continuously running native worker with the one specified restart, reusing the
shared seed, snapshot, TLS and process owners. It does not substitute direct
processor calls or restart after every stage. Complete durable state and exact
transport traces remain required before changing runtime behavior. Compilation
and local fixture tests alone are not runtime qualification. Preserve the
original twelve-stage corpus and all other
[worker cutover gates](canvas-worker-cutover-readiness.md).

The native driver compares the four exact transport ledgers before acknowledging
each stage, holds both observer locks across final comparison and stage reset,
and retains the final ledger through worker/child exit and joined fixture
shutdown. Output uses owned temporary files, avoiding pipe backpressure while
waiting for stage markers. Failure reports retain bounded diagnostic tails.
Thirty-two driver tests include a real failing child that writes 256 KiB to each
stream; failure remains prompt, cleanup completes, and no stage advances.

## Historical failures and repairs — superseded for this corpus

CI `34098106567` supplied actual native evidence at `8e7f66d46`: stage 0
`tail_positive_wrap` failed target equality because `worker_id` remained
`worker-rest` instead of the frozen null projection. The configured suite passed
118 tests and failed this one in 2761.77s. Token-reuse drift was then only a source
hypothesis: the child stopped before the driver's transport comparison.

The next head `f8670830b` passed stage-0 metadata assertions, then failed the
early preflight in 25.79s (CI `34104771356`, job `101687206847`). Exact transport
then proved the next difference: 12 requests versus 10, four token exchanges
versus two, and eight synthetic signer calls versus four, with no fixture failures.
The frozen Python roster creates one invocation-local AGS token slot and reuses
successful acquisition across learners (`canvas_routes.py` lines 6041, 6115–6135);
application synchronization has the same invocation-local behavior at 5643–5675.
The worker retains token values without expiry refresh within that invocation.
The native repair therefore binds a fresh provider session per processor run,
preserves owner/scope separation and trust checks, and memoizes successful grants
without sharing tokens across jobs. Focused tests and the unchanged seven-stage
Linux replay subsequently passed at the current checkpoint; no transport ledger
was normalized away to obtain that result.

The narrow repair reconciles only the pre-touch snapshot's two heartbeat keys
while retaining unrelated current metadata and all lease/generation fences.
Ten configured fresh-database regression cases passed in 104.27s, including
natural lease expiry before the write and during a blocked UPDATE. Extra
preexisting/explicit-null snapshot cases are focused reconciliation coverage,
not additional frozen published observations. The seven-stage whole-worker
replay subsequently passed; broader worker qualification remains separately gated.
Independent read-only inspection of the exact frozen issuance image confirmed
the source semantics: `canvas_worker.py` fetches the target at line 432, touches
the database heartbeat at 448–452, and passes the same snapshot at 474.
`infrastructure/api/canvas_routes.py` lines 6225–6238 spread that snapshot's
metadata into the roster result. In `infrastructure/adapters/postgres_repository.py`,
`touch_canvas_sync_target_worker_heartbeat` lines 3615–3654 changes the persisted
heartbeat keys; `save_canvas_sync_target` lines 3539–3577 replaces metadata from
the supplied target. Thus absent, null and preexisting heartbeat values follow
the snapshot, while Python's unrelated stale-map overwrite is deliberately not
reproduced by Rust's current-map reconciliation.

All three inspected files were under `/app/services/issuance/` in immutable image
`sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`.
Worker SHA-256 `c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a`
and routes SHA-256 `f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943`
match the frozen corpus. Repository SHA-256
`34ba42bd10227e0040c99378254c3652c388bab3131aadfdba2e0fe92cf89ccb`
is newly observed source evidence from that image, not a new corpus observation.

Count-only stage diagnostics now expose ledger lengths without payloads, while
preserving original exceptions and bounded cleanup; 34 focused driver tests
passed. No frozen equality or provider/signing implementation was changed.

Historical reference-batch local checks: 1,201 Python tests passed with one existing skip in 62.16s;
strict all-target Rust Clippy passed in 6.97s; Rustfmt, changed-file Ruff and
shell syntax checks passed. That registration contained 119 entries, not 119
qualified runtime passes. The previously recorded 115-entry hosted checkpoint
and the later failed heads are historical evidence, superseded by the exact
121-entry configured Linux pass above without implying broader cutover approval.

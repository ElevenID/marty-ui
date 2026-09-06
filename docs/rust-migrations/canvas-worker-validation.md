# Actual worker validation and processor-failure reference

Status: twenty published-worker cases captured independently twice and frozen;
native replay is implemented. The initial eleven cases passed Linux at
`56f4658e1`; newer races/processor failures await exact-head qualification. This is selected
gate-9 evidence, not a completed
worker/consumer cutover. All nine normative validation errors now have captured
actual-process outcomes, including the two reference-removal races below.
Five distinct processor-failure outcomes are also captured; their remaining outcome
inventory is tracked separately rather than treated as validation coverage.

The reference reuses the existing actual REST process, HTTPS, official-schema,
OAuth and issued-row preservation fixtures. Each case owns a fresh database.
Target configuration and one queued attempt-zero job are fixture inputs before
worker startup; no running job, lease, outcome or application clock is edited.
The two reference-removal races then detach/remove only their dedicated synthetic
records after observing the worker blocked at its real validation query.
The existing scheduler sees the queued job, and the captured outcome must retain
that exact seeded job ID on attempt one.

| Cases | Published terminal code |
| --- | --- |
| Whitespace-only logical key | `canvas_sync_target_incomplete` |
| Synthetic prohibited authentication metadata | `canvas_sync_target_contains_secret` |
| Binding attached to a different same-organization platform | `canvas_sync_target_scope_invalid` |
| Disabled target; disabled/archived platform; disabled/archived binding | `canvas_sync_target_inactive` |
| Binding revalidated at version 2 while target remains version 1 | `canvas_sync_target_config_stale` |
| Learner/issued-drift target with no application reference | `canvas_sync_target_application_missing` |
| Award-candidate target with no candidate reference | `canvas_sync_target_candidate_missing` |
| Dedicated application removed after target read | `canvas_sync_target_application_invalid` |
| Dedicated candidate removed after target read | `canvas_sync_target_candidate_invalid` |

Every case observes one dead-lettered job, a disabled target, the exact error
code/summary and idle heartbeat, no Canvas requests, no facts, no OAuth-token
use, unchanged full issued rows and token ciphertext, and raw SIGINT exit -2.
The synthetic prohibited metadata value must be absent from the observation.
Child logs are discarded by the established process owner; this is not proof
of worker-log redaction or complete signing-error privacy.

The first capture attempt failed before an archived-platform worker could start:
the fixture set an archive timestamp while leaving the platform enabled. Schema
inspection identified the archival-state requirement. Final inputs disable
archived platforms/bindings and keep a version-2 binding's validation version
at 2. No constraints were disabled or weakened. The tab-only logical key passes
the database's space-trimming check but is rejected by application validation;
this gives an actual persisted input for the incomplete-target path.

The initial eleven-case captures B/C match byte-for-byte with SHA-256
`714007d69385de019231180015e416e85adb61488306e48c3b99a18ef45dac38`.
The expectation file is whitespace-only formatted, preserving numeric/string
tokens. No Rust outcome supplied expectations. Case/reference key sets and
uniqueness are checked by the shared matrix comparison owner; the exact
`worker_validation_reference_matches_published_process` test is mandatory in CI.
The retry matrix retains its public test name and uses that same owner.

Local validation completed: all 32 selected worker test entries passed in
447.81 seconds, regenerating the new matrix and all earlier worker references
after the shared owner changes. The 36 unrelated entries were filtered out;
Linux-only native parent/helper entries returning on Windows do not establish
native execution. Full configured CI now has 68 entries. All 900 Python tests
passed in 43.39 seconds with the existing opt-in verifier containerd/Buildx skip.
Strict all-target Clippy, Ruff, Rustfmt, Bash syntax, diff checks and the
capture-file preservation test passed.

The two invalid-reference codes initially remained explicitly open because
tenant foreign keys prevent ordinary missing/foreign persisted references.
The reference-removal evidence below resolves those captured-code gaps without
manufacturing invalid rows by removing foreign keys. The coverage test still
requires covered and remaining codes to be disjoint and their union to equal
the complete normative list; the remaining reference-code list is now empty.

## Native adoption and regression evidence

A focused test against the actual published schema first demonstrated the
repository mismatch: the incomplete-key case returned `Canvas synchronization
target is incomplete` instead of the frozen `Canvas sync target is missing
logical_key`. The shared Rust repository now preserves all seven covered codes'
exact summaries. The missing-field summary uses a bounded static lookup, retaining
the public static-message API and excluding supplied values. One unit test checks
all 16 field combinations under three whitespace forms. Generation fences,
tenant-scoped queries and atomic cleanup remain unchanged.

All eleven focused repository cases subsequently passed in 35.67 seconds,
including exact code/summary, terminal classification and full issued-row/token
ciphertext preservation. This is repository evidence, not native-process proof.
The native replay reuses the existing REST process/HTTPS/database fixture and
one shared validation seeder; each case runs in a separate child/database. It
compares every frozen observation, preserves the exact seeded job ID, checks
the final target enabled/version state and requires zero Canvas requests.
Native SIGINT remains exit 130 rather than the published raw -2 convention.

CI requires the published reference, focused repository and native-process
validation tests by exact name; the complete configured suite now has 70 entries.
The native parent returning on Windows must not be counted as Linux execution.
Initial eleven-case local regressions: 330 library, 34 managed HTTP, 20 OAuth/provider and
23 issuance/worker behavior tests passed, as did strict all-target Clippy.
All 901 Python tests passed in 41.17 seconds with the same existing opt-in
verifier containerd/Buildx skip. Ruff checks and formatting passed.
The configured local validation subset passed all three entries in 92.58 seconds
(67 filtered out), regenerating all eleven published cases and rerunning the
eleven actual-schema repository comparisons. Its Linux-only parent returned on
Windows; native process qualification is still pending. Bash syntax, Rustfmt
and diff checks passed, and no labelled fixture containers remained afterward.

The initial eleven-case native replay subsequently passed at
`56f4658e1ac9a3d0d8fed8cb9638352b35065879`: CI34053145533 and
Rust CodeQL34053145588 succeeded. Runtime job101540240382 recorded all eleven
actual native validation cases with zero HTTPS requests, and all 70 configured
tests passed in 1399.33 seconds at 19:24:28 UTC. Its separate unconfigured
70-test run in 0.34 seconds is not process evidence. Image job101540240397
passed eight entrypoint cases and all 24 packaged startup cases, retaining the
original issuance API health gate. This qualification does not cover the newer
reference-removal races or the processor-failure additions below.

## Reference-removal races

Each race creates a dedicated synthetic application or candidate with no issued
credentials. Before worker startup, the target refers to this valid row. The
existing process barrier holds an exclusive lock on the referenced table and
observes the actual validation SELECT waiting. Only then does the same
lock-owning transaction detach the target reference and remove the exact
synthetic row. The worker resumes with its already-read target and records the
corresponding unavailable-reference error. No job state, timestamps, configuration
version, application clock or constraints are rewritten. All original issued
rows, transactions and token ciphertext remain unchanged.

Independent thirteen-case captures A/B match byte-for-byte with SHA-256
`4446396a0defc804d357d4b650c126091f35f96c760b3b7249a26d455bfea650`.
Every original eleven-case observation is unchanged. New frozen fields require
the blocked-before-release observation and the referenced row's final absence,
in addition to the full existing job/target/heartbeat/HTTPS/preservation checks.
Captured scalar tokens were copied exactly and only whitespace was formatted.

The actual-schema Rust repository test reads the target before the fixture
removes the reference. It first failed on the application error summary; the
shared repository now uses the two exact independently captured unavailable
messages. The native process replay reuses the same barrier owner as concurrent
schedulers/reclaimers. Its existing two-worker wrapper is retained; one-worker
validation uses the same bounded owner with static fixture SQL and no SQLx
safety bypass. These local repository checks do not substitute for observing
the native process at the barrier in Linux CI.

Fixture tests cover one-worker release ordering and cleanup on release failure,
while retaining two-worker partial-start/timeout/cleanup checks. The scenario
guard restricts removal to the two exact synthetic identities and excludes job
or constraint mutation. Current local regressions: all 407 Rust tests and strict
all-target Clippy passed; 906 Python tests passed in 39.52 seconds with the same
existing opt-in verifier skip. The complete configured local worker subset
passed all 34 entries in 477.45 seconds (36 unrelated entries filtered out),
regenerating every earlier worker reference and all thirteen validation cases,
and passing all thirteen actual-schema repository comparisons. Linux-only
parent/helper returns on Windows are not process execution; fresh exact-head
native Linux replay remains required.

## Processor failures after successful target validation

Four additional actual-process cases extend the same matrix and native replay:

| Fixture input/event | Terminal processor code |
| --- | --- |
| Unsupported evidence fact type in the binding | `canvas_requirements_invalid` |
| Application Canvas context without an LTI subject | `canvas_lti_identity_missing` |
| Existing tenant-owned award candidate with no authoritative processor | `canvas_sync_target_type_unsupported` |
| Dedicated template removed after the worker reads its application | `canvas_application_template_unavailable` |

The template race uses the same reference-table barrier as the application and
candidate races. Once the actual template SELECT is observed blocked, the
lock-owning transaction restores the application's original template reference
and deletes only the dedicated synthetic template. No foreign key, job, lease,
clock, generation fence or issued row is changed. Every case observes one
attempt-one dead-letter, exact code/summary, disabled target, zero Canvas
requests, idle heartbeat and preserved issued rows/transactions/token ciphertext.

Independent seventeen-case captures A/B match byte-for-byte with SHA-256
`eb18fc2970f60f08766c1b4bc01735544685cdf1434d4d2870fec307969d41e0`.
All thirteen earlier observations are unchanged. New expectations retain their
exact captured scalar tokens with whitespace-only formatting. No Rust outcome
supplied expectations, and this extension changes no production implementation.

The existing native parent dispatched all seventeen cases at this checkpoint;
the roster-configuration extension below brings that to twenty separate children.
The focused repository-only test explicitly selects the thirteen validation
cases: processor errors cannot be inferred from a repository validator. The
coverage guard separately accounts for all nine normative validation codes and
all seventeen normative processor outcomes, rejects unknown boundaries, and
tracked the thirteen processor codes outside this four-case corpus explicitly.
The roster-configuration addition covers one further code, leaving twelve
explicitly listed processor codes outside the current corpus.
That remaining list is corpus-specific: earlier retry/provider evidence remains
valid in its own named gates. Dynamic Python processor shapes must be reconciled
with typed Rust dispatch, not reintroduced as a production Python loader.

The full local Python regression passed 907 tests in 42.37 seconds with the
same existing opt-in verifier skip. All seventeen frozen observations were
compared to the independent capture after token-preserving formatting. Fresh
configured native Linux execution must include all seventeen actual worker
cases; the existing three exact validation test names remain mandatory in CI.
The configured local subset passed all three entries in 134.08 seconds
(67 filtered out), regenerating seventeen published cases and verifying the
thirteen native repository comparisons. Its Linux-only parent returned on
Windows, not native process execution. Strict all-target Clippy, Ruff, Rustfmt
and diff checks passed. The earlier 34-entry worker regression remains recorded
above for the shared barrier implementation; this corpus extension adds no
new process/barrier implementation.

The seventeen-case checkpoint `a7e8ff3206dc4798e9ca6d890e16ec695bc21b89` is now
qualified: CI34054910209 and Rust CodeQL34054910162 succeeded. Runtime
job101545013474 passed all 70 configured entries in 1520.47 seconds at
19:59:21 UTC, with seventeen explicit native validation/failure markers, each
with zero requests, including all three actual reference-removal barriers.
Image job101545013487 passed eight preflight and 24 packaged startup cases,
retaining the original issuance API health gate. The three roster cases below
are newer and still require their own exact-head native qualification.

## Deferred roster-only configuration

Source inspection identified another composition gap: the native binary used
fallible `i64` parsing of both roster bounds during startup. A malformed value
therefore aborted the whole worker, including non-roster work. The published
processor reads those settings only when a background-roster job reaches the
configuration check, after requirement validation.

Three actual published-worker cases now freeze invalid batch size, invalid
maximum size, and an application with both roster settings invalid but its own
missing LTI subject. The first two produce `canvas_roster_configuration_invalid`
with `Canvas roster bounds are invalid`; the third retains
`canvas_lti_identity_missing`. Each keeps the worker alive to its idle heartbeat,
records the exact terminal job/target state, makes zero Canvas requests, and
preserves all issued rows, transactions, ciphertext and the original job ID.
The fixture permits only the two named roster environment settings.

Independent twenty-case captures A/B match byte-for-byte with SHA-256
`fd00e704f48da9803f3d2f2e200123f7e2ac98205e207185c59ee7f1b41c1f5a`.
All seventeen earlier observations are unchanged. New scalar tokens were copied
exactly, with whitespace-only formatting; no Rust result supplied expectations.

Rust now stores a typed `Result<CanvasRosterBounds, CanvasSyncProcessingError>`
and consumes an error only inside roster processing. The existing public
constructor remains available and delegates to the same configuration owner.
The binary no longer has its own `i64` parser: bounds reuse pinned MMF
`PythonConfigInteger`, clamp before machine conversion, and retain defaults
500/5000, batch range 1..2000 and maximum range batch..10000. Valid configuration
retains the existing debug fields; invalid configuration emits only the static
error code, never the supplied text. No dependency pin, lease/generation fence,
tenant query, processor loader or deployment consumer changes.

Unit tests cover defaults, negatives, signed/underscored and Unicode decimal
values, oversized integers, the 4300/4301-digit boundary, malformed values,
continued learner/issued-drift processing, unsupported-candidate precedence and
closed rollout. Local checks passed: 332 library, 5 worker-binary, 34 managed
HTTP, 20 OAuth/provider and 23 issuance/worker tests (414 total), strict all-target
Clippy, and 907 Python tests in 39.30 seconds with the same existing opt-in skip.
The full configured local worker subset passed all 34 entries in 515.83 seconds
(36 unrelated entries filtered out), regenerating every earlier worker reference
and all twenty validation/failure cases. Linux-only parent/helper returns on
Windows are not native process execution. Fresh exact-head Linux process/image
qualification remains required; these tests do not authorize consumer cutover.

Broader processor failures,
missing-target races, signing effects and privacy remain in the
[worker cutover inventory](canvas-worker-cutover-readiness.md).

Production, persistent self-host, consumer definitions and reachable Python
features are unchanged by this reference.

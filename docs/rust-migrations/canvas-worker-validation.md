# Actual worker target-validation reference

Status: eleven published-worker cases captured independently twice and frozen;
native replay remains pending. This is selected gate-9 evidence, not a completed
worker/consumer cutover. All nine normative validation errors remain accounted
for, including the two explicitly uncovered error paths below.

The reference reuses the existing actual REST process, HTTPS, official-schema,
OAuth and issued-row preservation fixtures. Each case owns a fresh database.
Target configuration and one queued attempt-zero job are fixture inputs before
worker startup; no running job, lease, outcome or application clock is edited.
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

Final captures B/C match byte-for-byte with SHA-256
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

`canvas_sync_target_application_invalid` and
`canvas_sync_target_candidate_invalid` remain explicitly open in the scenario
inventory. Local model inspection identifies tenant foreign keys for those
references. Their actual constraint/race paths and detached-target validation
must be reconciled separately, without manufacturing invalid rows by removing
foreign keys. The coverage test requires covered and remaining codes to be
disjoint and their union to equal the complete normative error list.

Native adoption must preserve these actual terminal summaries and target state,
not merely copy the codes. Current Rust repository messages differ from this
reference; review and correct them through the shared repository validation path
while retaining its stronger generation fences. Broader processor failures,
missing-target races, signing effects and privacy remain in the
[worker cutover inventory](canvas-worker-cutover-readiness.md).

Production, persistent self-host, consumer definitions and reachable Python
features are unchanged by this reference.

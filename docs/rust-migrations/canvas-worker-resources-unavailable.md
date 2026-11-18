# Post-validation unavailable-resource reference

Status: actual published-worker capture passed in 5.77s, followed by exact
independent regenerations in 6.03s and 6.36s. Actual native Linux process replay
is now qualified at `6914387e563d1043948aaea7a5cc514be6055038`, closing this
specific `canvas_sync_resources_unavailable` outcome in the processor inventory.
It does not authorize whole-worker cutover, deployment or Python deletion.

## Observed behavior

The [scenario](../../contracts/canvas-worker-resources-unavailable-scenarios.json)
uses a fresh official-schema database and the immutable published worker. It
seeds one disposable binding used only by the synthetic target, then starts a
normally queued job. Table-lock barriers observe both completed validation passes
and hold the processor's fresh resource lookup. While that lookup is held, the
fixture restores the target's retained binding and deletes the disposable one.

The [frozen result](../../contracts/canvas-worker-resources-unavailable-oracle.json)
records one attempt, terminal `canvas_sync_resources_unavailable`, exact summary
`Canvas synchronization resources are unavailable`, maximum attempts reduced to
one, an empty result, cleared lease and disabled target. The application stays
approved and its credential active. There are no facts, events, provider requests
or OAuth secret use. The target remains attached to the retained original binding.

The raw job row is unchanged by the fixture mutation; the worker produces the
terminal outcome on that same job. Complete platform, retained binding and
application rows, issued credentials, transactions and OAuth ciphertext remain
unchanged. After SIGINT, all observed state, resources and the raw terminal job
remain unchanged. The published process exits with signal code -2.

## Barrier fidelity and native adaptation

The Python worker validates in its wrapper and again in the authoritative hook,
then reloads application, platform and binding independently. Five observed table
barriers select the final lookup boundary. Pre-start deletion would test an earlier
validation error; waiting for provider HTTPS would be too late.

The first experiment timed out because its observer searched SQL text that can
be truncated in `pg_stat_activity`. The repaired observer uses ungranted relation
locks and each fixture lock owner's PID, without assuming worker connection reuse.
Static phase-specific exception classes preserve diagnostic privacy. No worker
functions, job/lease state, clocks or schema constraints are patched.

Rust validates once and reloads platform/binding atomically. Its replay therefore
needs two barriers at the equivalent external boundary, not five fabricated
internal steps. Python's `observed_barriers` is reference instrumentation, not a
language-neutral requirement for identical query counts. Full external snapshots,
resource edits, zero requests and durable/post-exit behavior must still agree.

Existing Rust code already classified an absent resource snapshot as terminal;
the configured native replay now supplies execution evidence in addition to
source inspection. Lease expiry
during provider effects, populated roster processing, signing/privacy integration,
all deployment consumers and beta acceptance remain separate requirements.

## Retained gates and harness review

At `6914387e563d1043948aaea7a5cc514be6055038`,
[CI34089906961](https://github.com/ElevenID/marty-ui/actions/runs/34089906961)
passed 115 configured entries in 2444.37s and four worker/PostgreSQL tests in
95.63s. Runtime job `101641133956` logs the configured result at
`2026-09-07T07:01:57.0655556Z`; the unconfigured 115-test result in 0.36s is not
evidence. The independently inspected native
`resources-unavailable/binding_removed_after_hook_validation` marker reports
one frozen stage and zero requests. Both resource-race markers also passed
with one HTTPS request each. All exact-head checks succeeded or were skipped,
including successful Rust CodeQL `34089906881` and image job `101641134087`;
the latter retained all 24 packaged startup cases.

The three resource-related codes now have native process qualification,
bringing actual-process coverage to fourteen. Two typed-dispatch reconciliations
remain open, and the separate controlled signing-result guard is not upgraded
to actual-provider evidence. Later local effect-expiry/mixed-roster work remains
unqualified by this checkpoint regardless of current registration counts.

Independent harness tests reproduced an observer gap: an unsupported POST returned
HTTP 501 but was absent from the request list. A shared request-parser observer now
records every successfully parsed method before dispatch under a fixture lock.
Unsupported verbs still return 501; existing GET/DELETE behavior and observation
fields are unchanged. Actual loopback HTTPS tests with simulated children verify
that unexpected requests cannot pass a zero-request gate. These tests do not
substitute for executing the native worker.

After that repair, exact published regeneration retained REST (10.58s), all five
roster failures (31.13s), both resource races (12.36s) and this case (6.36s), without
changing frozen results. The complete Python suite passed 1,083 tests with one
existing skip in 67.39s. Strict all-target Rust Clippy passed in 18.10s. The
reference test and native parent are mandatory in the configured Linux suite.

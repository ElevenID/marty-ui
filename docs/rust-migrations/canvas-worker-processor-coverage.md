# Processor outcome coverage across worker corpora

This reconciles gate 9 against all seventeen `processor_dispatch.stable_outcomes`
in the unchanged language-neutral contract. The validation corpus's twelve
`remaining_processor_errors` are local to that corpus, not twelve globally
untested outcomes. The machine-readable inventory is
[`canvas-worker-processor-coverage.json`](../../contracts/canvas-worker-processor-coverage.json).
Its regression derives covered codes and durable retry/dead-letter states from
the frozen references, rejects overlap, and requires an exhaustive seventeen-code
partition. It is accounting, not runtime evidence or a cutover waiver.

| Evidence category | Count | Scope |
| --- | ---: | --- |
| Actual published/native worker processes | 14 | Five validation-corpus codes, two retry-corpus codes, four roster-failure codes, two resource-race codes and one post-validation resources-unavailable code. |
| Real worker cycle and PostgreSQL, controlled typed processor | 1 | `canvas_background_signing_forbidden`: all four forbidden keys across seven values, plus two successful controls. Not actual-provider process evidence. |
| Typed-dispatch reconciliation still open | 2 | Missing processor and non-mapping processor result. The native executable directly links a typed processor; do not reintroduce Python imports or silently waive these legacy outcomes. |
| Composed outcomes still open in this seventeen-code inventory | 0 | The last three now have actual native process evidence; this does not close broader worker/provider effects or the two typed-dispatch reconciliations. |

The five actual validation-corpus processor codes are
`canvas_roster_configuration_invalid`, `canvas_requirements_invalid`,
`canvas_lti_identity_missing`, `canvas_sync_target_type_unsupported`, and
`canvas_application_template_unavailable`. The other two actual-process codes are
`canvas_rate_limited` and `canvas_authoritative_reads_failed`. Four further codes
are now qualified in the roster-failure corpus: `canvas_roster_oauth_unavailable`,
`canvas_nrps_roster_unavailable`, `canvas_roster_collection_too_large`, and
`canvas_authoritative_read_failed`. The fifth roster case's
`canvas_sync_unexpected_error` is an additional worker outcome, not an eighteenth
member of the unchanged seventeen-code processor partition.
The two resource-race codes are `canvas_platform_reconfigured` and
`canvas_application_unavailable`; the post-validation resource-removal code is
`canvas_sync_resources_unavailable`.

Separately, **all nine target-validation codes** have actual-process outcomes
across thirteen validation scenarios; these are not processor-dispatch codes.
The remaining seven scenarios cover the five processor codes above, bringing the
validation corpus to twenty. Keep these two inventories separate.

## Exact qualified evidence

At `29bf8c226e13df1a708355538cc913adcbfa987f`,
[CI34079614572](https://github.com/ElevenID/marty-ui/actions/runs/34079614572)
passed 103 configured tests in 2245.41s. Runtime job101612295594 logs contain all
twenty native validation markers (zero requests each), the complete five-stage
native retry marker (five requests), and all seven native Retry-After deadline
markers (one request each). The complete frozen state comparisons and real
reference-removal barriers are retained in the shared replay.

The separate configured worker/PostgreSQL suite passed four tests in 96.22s.
Its scheduler/recovery test calls the existing signing-result guard, which checks
28 terminal failures and two successes through the actual worker cycle and
durable repository. Its processor is controlled: this is not evidence of a live
signing service or complete provider execution. The runtime evidence, not merely
the source registration assertion, supports this scoped result.

The same actual-process corpus markers were retained at
`c3e51a4d58083625aabd50de7fba37ef1ff53d4e`, where
[CI34082559053](https://github.com/ElevenID/marty-ui/actions/runs/34082559053)
passed 107 configured entries in 2327.12s and four worker/PostgreSQL entries in
96.94s. Recovery-first and logging are qualified at that checkpoint.

The roster extension is qualified at
`5dde6b69adbca467d7fefaa1b43bc2b77ac4aa19`, where
[CI34085691302](https://github.com/ElevenID/marty-ui/actions/runs/34085691302)
completed successfully. Runtime job `101629197299` logged **109 configured tests
passing in 2361.53s** at `2026-09-07T05:56:08Z`; the unconfigured 109-test result
in 0.37s is not qualification evidence. The separate configured worker/PostgreSQL
suite passed four tests in 96.28s. All five native roster markers were inspected:
OAuth unavailable and NRPS context unavailable made zero HTTPS requests each;
oversized roster, malformed authoritative response and HTTP status failure made
one request each. The retained recovery-first marker made one HTTPS request.
Image job `101629197264` passed with all 24 startup markers, Rust CodeQL run
`34085691297` passed, and every exact-head check was successful or skipped.
The machine-readable roster entry records this exact checkpoint. These results
do not close all of gate 9 or authorize worker routing or deletion.

## Latest qualified composition and remaining gates

At `6914387e563d1043948aaea7a5cc514be6055038`,
[CI34089906961](https://github.com/ElevenID/marty-ui/actions/runs/34089906961)
passed **115 configured tests in 2444.37s**. Runtime job `101641133956` records
that result at `2026-09-07T07:01:57.0655556Z`; the earlier unconfigured 115-test
result in 0.36s is not qualification. Four configured worker/PostgreSQL tests
passed in 95.63s. Independently inspected native markers show
`platform_reconfigured` and `application_removed` made one HTTPS request each,
and `binding_removed_after_hook_validation` made zero requests. Both resource
reference regenerations and native comparisons passed within the configured run.

All five roster markers remain (0, 0, 1, 1, 1 requests), as does recovery-first
(one HTTPS request). Image job `101641134087` passed all nine entrypoint/preflight,
24 packaged startup and 16 published logging-reference cases. Rust CodeQL run
`34089906881` passed; all 24 exact-head checks completed successfully except the
expected skipped scorecard. PR #814 remains open, draft and unrouted. The common
`latest_qualification` record anchors the retained composed evidence without
duplicating it across resource corpora; the earlier roster checkpoint is retained.

The qualified [five-case roster failure corpus](canvas-worker-roster-failures.md)
preserves an existing cursor and empty candidate table, not populated candidate
lifecycle behavior. Its four normative codes have moved out of this remaining
inventory on actual native Linux process evidence, not on published capture or
library tests alone. The separate lease-expiry-during-effects and signing
diagnostic requirements remain in their named gates. No norm, frozen observation,
runtime feature, production consumer or deployment has been removed by this audit.

The [two-case resource-race corpus](canvas-worker-resource-races.md) and
[post-validation resource-removal corpus](canvas-worker-resources-unavailable.md)
now close their three codes on that actual native Linux evidence, not on
reference/repository results alone. Changed application rows still retry, and
lease loss still takes precedence; a missing application waives neither guard.

The empty remaining-composed list does not close gate 9: the two typed-dispatch
reconciliations remain open and the signing-result guard retains its controlled
processor classification. Later local effect-expiry and mixed-roster work is not
qualified by this 115-entry head or by an increased registration count. Actual
lease expiry during provider effects, populated roster behavior, all-consumer
adoption and beta acceptance remain separate gates. No norm or feature is waived.

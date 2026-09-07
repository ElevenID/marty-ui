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
| Actual published/native worker processes | 11 | Five processor codes in the twenty-case validation corpus; two in the five-stage retry corpus; four in the five-case roster-failure corpus. |
| Real worker cycle and PostgreSQL, controlled typed processor | 1 | `canvas_background_signing_forbidden`: all four forbidden keys across seven values, plus two successful controls. Not actual-provider process evidence. |
| Typed-dispatch reconciliation still open | 2 | Missing processor and non-mapping processor result. The native executable directly links a typed processor; do not reintroduce Python imports or silently waive these legacy outcomes. |
| Composed outcomes still open | 3 | Listed below; published captures and library/repository tests alone do not close them. |

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

## Remaining composed processor outcomes

- `canvas_platform_reconfigured`
- `canvas_application_unavailable`
- `canvas_sync_resources_unavailable`

The qualified [five-case roster failure corpus](canvas-worker-roster-failures.md)
preserves an existing cursor and empty candidate table, not populated candidate
lifecycle behavior. Its four normative codes have moved out of this remaining
inventory on actual native Linux process evidence, not on published capture or
library tests alone. The separate lease-expiry-during-effects and signing
diagnostic requirements remain in their named gates. No norm, frozen observation,
runtime feature, production consumer or deployment has been removed by this audit.

The [two-case resource-race corpus](canvas-worker-resource-races.md) now also
captures `canvas_platform_reconfigured` and `canvas_application_unavailable`
through actual published-worker HTTPS runs, with independent regeneration and
Rust repository repairs. Native process replay is implemented but not qualified.
These two codes remain in the three-code inventory until actual Linux replay
passes. Changed application rows still retry, and lease loss still takes
precedence; a missing application is not a waiver of either write guard.
The resources-unavailable work likewise has no qualified native process result
at this checkpoint and remains open. Neither those extensions nor their local
reference/repository evidence inherit qualification from the roster head.

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
| Actual published/native worker processes | 7 | Five processor codes in the twenty-case validation corpus; rate limiting and aggregate authoritative-read failure in the five-stage retry corpus. |
| Real worker cycle and PostgreSQL, controlled typed processor | 1 | `canvas_background_signing_forbidden`: all four forbidden keys across seven values, plus two successful controls. Not actual-provider process evidence. |
| Typed-dispatch reconciliation still open | 2 | Missing processor and non-mapping processor result. The native executable directly links a typed processor; do not reintroduce Python imports or silently waive these legacy outcomes. |
| Composed outcomes still open | 7 | Listed below; library/status mapping tests alone do not close them. |

The five actual validation-corpus processor codes are
`canvas_roster_configuration_invalid`, `canvas_requirements_invalid`,
`canvas_lti_identity_missing`, `canvas_sync_target_type_unsupported`, and
`canvas_application_template_unavailable`. The other two actual-process codes are
`canvas_rate_limited` and `canvas_authoritative_reads_failed`.

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
96.94s. Recovery-first and logging are now qualified at that checkpoint. This
does not close all of gate 9, qualify the local roster extension or authorize deletion.

## Remaining composed processor outcomes

- `canvas_platform_reconfigured`
- `canvas_application_unavailable`
- `canvas_roster_oauth_unavailable`
- `canvas_nrps_roster_unavailable`
- `canvas_roster_collection_too_large`
- `canvas_sync_resources_unavailable`
- `canvas_authoritative_read_failed`

The [five-case roster failure corpus](canvas-worker-roster-failures.md) now has
an actual published capture and independent regeneration, plus native replay and
targeted Rust repairs. Four codes above and one additional generic worker error
are exercised. They remain open until the composed native Linux replay passes;
published capture and library tests alone are not qualification. These cases
preserve an existing cursor and empty candidate table, not populated candidate
lifecycle behavior. The separate lease-expiry-during-effects and signing
diagnostic requirements remain in their named gates. No norm, frozen observation,
runtime feature, production consumer or deployment has been removed by this audit.

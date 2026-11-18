# Native Canvas processor on published issuance migrations

Status: UI #804 is merged at protected
`e8d4b54c22f79d95a919d302a1a81c01f6e4ff0f`, with its exact reviewed tree and
successful protected-queue CI33979156327 / CodeQL33979156322.
The worker remains unrouted.

The published schema exposed a real native defect: the fact-commit snapshot
guard compared `applications.integration_context` (JSON) directly with a JSONB
parameter. PostgreSQL rejected the comparison before a learner fact could commit.
The guard now explicitly casts both operands to JSONB. Its equality, tenant,
job-lease, generation, application and template conditions remain intact.
No schema, feature, deployment consumer or Python runtime was removed.

## Executable evidence

`canvas_published_schema_contract` creates a fresh UUID-labelled, tmpfs
PostgreSQL container and runs the pinned published issuance image's own
`services.issuance.manage_migrations.upgrade` entry point. Image digests, worker
source hash and expected migration head come from the existing frozen
`canvas-worker-consumer-range-oracle.json`; no migration DDL is copied into Rust.
The organization dependency table is explicitly synthetic and minimal, matching
the prior oracle's boundary. This is not the full organization migration graph.

The native test uses the real processor, repositories, job leasing, target
validation and durable completion/failure owners. Its controlled provider tests:

- bounded, deduplicated roster batches and durable cursor wrap;
- all four fact types, candidate creation, claimed-state preservation,
  observation idempotency and revision/current-head behavior;
- learner positive and negative evidence, fact reuse and policy decisions;
- unavailable, reauthorization and rate-limited reads preserving complete
  stored fact/head rows, with expected validation errors and Retry-After;
- application context changed during a provider read rejecting the old
  fact-commit snapshot without inserting facts or moving heads;
- expired drift disabling its target without provider reads;
- the legacy award-candidate processor rejection (not a newly removed feature);
- no credential issuance or application approval by reconciliation.

The behavior inventory remains `issuance-canvas-sync-worker.json`. In particular,
the frozen `test_canvas_authoritative_sync.py` learner oracle distinguishes
verified negative evidence from unavailable reads. These tests do not replace
that oracle or claim a newly recorded whole-Python/native differential.

Set `MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1` and run the issuance package's
`canvas_published_schema_contract` test after pulling the two digest-pinned
images. Without the flag, normal workspace runs do not invoke Docker and are
not published-schema evidence. CI explicitly enables the flag in a mandatory
Rust Service Tests step and validates the exact compiled executable exists.

The base migration mode mounts two public test-input files read-only. Each
behavior-oracle mode adds only its own script and data-only scenario file.
The probe has a read-only root and dropped capabilities. PostgreSQL exposes
one generated loopback port with fixed synthetic credentials. The containers
share the test database network namespace, not a deployment network. This
host-native runner is not network-none. Cleanup verifies exact container IDs,
UUID labels, probe topology and disposable database storage before removal.
No arbitrary database URL or deployment credential is accepted.

## Remaining gates

The follow-on [issued-review differential](canvas-issued-review-parity.md)
freezes ten actual published Python stages and replays them through Rust on a
separate published-schema database. Local and original hosted sequential lifecycle
evidence passes; fresh protected integration, concurrency/rollback and manual
resolver proof remain open. The [mixed-roster differential](canvas-mixed-roster-parity.md)
adds twelve locally passing processor/database identity stages with frozen hashes
and candidate state, and restores the missing `roster_remaining` result field.

The actual HTTP provider, broader identity and correction-review cases,
full provider/processor differentials, readiness,
all deployment consumers, aggregate beta cutover and acceptance remain open.
Passing this contract does not authorize deleting the still-reachable Python
worker or changing production.

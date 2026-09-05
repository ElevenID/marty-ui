# Canvas JSON storage parity

## Scope and behavioral baseline

Follow-up to the JSON/JSONB failure found during the official beta `v1.1.215`
recording and the separate token-exchange correction in PR #785. Read-only beta
schema inspection confirmed that launch-state metadata, sync-target metadata
and platform connection configuration use PostgreSQL `json`. Earlier Canvas
repository contracts used `jsonb`, masking JSONB-only operations.

The Python reference is protected credentials source
`85329f647c1d8c51ad709f1eed97cedcb3bb6464`,
`services/issuance/infrastructure/api/canvas_routes.py`. Relevant behavior:

- Platform configuration copies existing fields, changes `enabled_intent`, and
  supplies AGS/NRPS capability intent only when the key is absent. An explicitly
  empty capability list must remain empty.
- Deep-link response persistence adds the response to existing session metadata.
- Background roster reconciliation preserves other metadata, stores cursor and
  roster size, sets cycle completion only at cursor zero, and schedules another
  batch in one minute only when the cursor is nonzero.

This correction retains the existing Rust atomic updates and tenant/platform/
binding generation fences. It changes only explicit input casts for JSONB
operators, supporting either physical column type through PostgreSQL assignment.
It does not change algorithms, routing, dependencies, live schemas or Python
consumers. The same repository operations remain shared by their consumers;
there is no alternate schema-specific service or copied implementation.

## Executed regression sequence

The same complete management and deep-link PostgreSQL contracts now run for both
physical storage types and assert the actual catalog types. All schema setup is
restricted to dedicated `*_test` databases and newly created test tables.

1. Unchanged Rust queries failed the JSON deep-link response and platform
   configuration contracts.
2. Fixing those inputs exposed the sync-target upsert failure during activation.
3. Fixing that input exposed another same-column consumer: roster cursor saving.
4. With all inputs corrected, both full contracts pass for JSON and JSONB.

Additional assertions cover changed and unchanged platform configuration,
default and explicitly empty capability intent, nested metadata preservation,
fresh and conflict-updated targets, cursor progress/completion timing, eight
independent deep-link scope fences and six independent cursor scope/generation
fences. Rejected writes leave existing metadata and scheduling unchanged.
Existing archival, OAuth-revocation queuing, binding invalidation, readiness,
activation/deactivation and tenant-hiding checks execute under both storage types.

Existing CI executes these PostgreSQL binaries with a configured dedicated
database. Local actual-database contracts, the complete issuance package command
(including 244 library tests) and all-target Clippy pass on top of merged PR #784.
The nine Canvas and proof-nonce PostgreSQL binaries ran with their database
configured; unrelated credential/transaction contracts skip without their own
environment variable and are not claimed as database passes here. Maintainer
review and protected merge checks remain required for the final commit. This
document is not proof of beta deployment or acceptance.

## Remaining release and migration gates

Land with the separately reviewed token correction and merged PR #784 result
parity work, qualify a new immutable aggregate beta release, and rerun the
unchanged official recordings and acceptance soak. Never modify published
`v1.1.215` or count its failed partial recording as a pass. Production is out of
deployment scope. These storage regressions do not establish whole-worker
parity: the standalone Rust worker remains unrouted, and reachable Python code
must remain until complete consumer, failure, routing and beta gates pass.

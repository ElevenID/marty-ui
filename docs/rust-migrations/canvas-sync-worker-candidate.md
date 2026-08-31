# Rust Canvas synchronization worker candidate

Status: implemented as an unrouted candidate; not eligible for cutover or Python deletion.

The `marty-canvas-sync-worker` executable and the shared
`canvas_sync_worker` modules implement the frozen headless worker boundary:
configuration bounds, durable scheduler conflicts, concurrent leasing, lease
renewal and generation fencing, expired-lease recovery, retry/backoff,
Retry-After parsing, privacy projections, heartbeats, interruptible shutdown,
and the OAuth revocation queue. The authoritative processor implements typed
learner-evidence, issued-drift, and bounded background-roster reconciliation,
including all four frozen fact projections. It reuses the issuance crate's
atomic fact-head/policy-review transaction and its Canvas OAuth, DID-mediated
LTI signing, provider URL policy, and candidate persistence owners. The OAuth lane extends the existing
`CanvasOAuthRepository`, uses the existing integration-secret vault and HTTP
provider, and deliberately keeps Rust's stronger atomic tenant-scoped
connection/secret cleanup.

This candidate does not change Compose, self-host, Kubernetes, beta, or
production traffic. The executable uses the native processor while retaining
the rollout gate:

- while the portable rollout is closed for an organization, it preserves the
  Python `{"no_change": true}` result without provider reads;
- if rollout is open, it performs authoritative reconciliation but remains
  unrouted until every legacy oracle and real-PostgreSQL race gate passes;
- it never fabricates facts, approves or signs a credential, or reports a successful
  provider read that did not happen.

## Hard cutover and deletion gate

Landing an unrouted Rust candidate is not authorization to cut over the
worker. Every item in
`contracts/issuance-canvas-sync-worker.json` under
`migration_gates.legacy_oracle_gaps` remains mandatory. In addition, cutover
requires fresh-PostgreSQL race evidence; bounded REST, AGS, NRPS, refresh,
and revocation simulators; whole-worker mutation/failure
differentials; readiness parity; every named deployment consumer change; and
the aggregate beta-only acceptance soak.

Until those gates pass, retain the Python worker, leave its consumers intact,
and do not route traffic to this candidate. Production and persistent
self-host remain unchanged without a separate promotion decision.

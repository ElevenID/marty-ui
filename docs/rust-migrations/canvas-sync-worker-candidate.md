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

The candidate now treats lease and configuration ownership as side-effect
boundaries: the processor future is dropped on the first failed renewal,
dead-letter and expired-lease target disables use the leased target generation,
and platform/binding resources are loaded as one enabled, non-archived,
generation-bound snapshot. The fact/policy transaction re-locks and verifies
that target, platform, binding, application identity/status/context, and
template policy/status are still the exact evaluated generation before any
fact or policy effect. Provider reads use distinct frozen 64 KiB token and
8 MiB page limits, a 200-page ceiling, completeness-preserving pagination, and
semantic success validation for every REST/AGS fact shape. Self-managed LTI
origins are controlled by `CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST`, independently
of private-network authorization, and are restricted to same-origin services.
Focused unit tests execute lease-loss cancellation, malformed protocol
mutations, pagination credential/item rejection, and independent self-managed
origin policy; the PostgreSQL contract exercises dead-letter and recovery
reconfiguration races when its database gate is configured.

The follow-on parity hardening also generation-fences application state,
platform validation, roster candidate/observation and cursor writes; reloads
the canonical target before durable job completion; binds LTI collection use
to the persisted and re-derived trust profile; and preserves explicit OAuth
429, shutdown, truthy-environment and deployed-secret behavior. Target changes
that race with reconciliation retain the original job outcome without allowing
stale-generation business effects.

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

# Canvas lifecycle delivery and cancellation candidate

## Finding and boundary

The legacy Rust credential repository only marks Canvas deliveries `pending`.
Published Python instead selects delivered Canvas records, applies profile gates,
resolves their binding/platform, attempts status synchronization, and durably
projects success or retry diagnostics. Marking everything pending is not proof
of feature parity. This remains a cutover blocker until actual provider wiring
and every consumer adopt the replacement; the default adapter is retained only
as the still-active migration boundary, not an accepted final implementation.

The candidate `CanvasLifecycleDeliverySynchronizer` owns this delivery behavior.
`PostgresCredentialManagementRepository::with_canvas_lifecycle` delegates to it;
credential state policy/publication/persistence remain in the existing service.
The shared feature-name list, Python value conversion, MMF decimal grammar and
timestamp formatter are reused. No Python code has been deleted or new runtime
route activated by this change.

## Independent published evidence

The pinned published image on the exact official #266 migration was captured
twice independently before implementing the delivery candidate; a second pair
was run to retain the full output after a display truncation. The existing ASGI
capture owner now optionally calls the actual Python credential lifecycle routes
and PostgreSQL repository. Only external status publication and Canvas mirror
provider ports are controlled. It does not patch credential persistence, review
claims, delivery selection, profile gates, target resolution or cancellation.

- Lifecycle-route source SHA256:
  `2b6d2eb7cec34bb4596ef9b758d8af02a3172337e89bad3b5d26b558d0dd00b7`.
- Oracle blob: `c48e9da21da1d234fdf5ac54449b92b57237a6bd`.
- Scenario blob: `409b5ba6f9c882a28d35bfb04e8ebebb6f8fc792`.
- Original operations/read/input goldens remain unchanged.

All17 cases replay through actual Rust Axum, review resolver, credential service
and PostgreSQL repository with equivalent controlled external ports. Comparisons
include complete normalized HTTP responses, credential state/revocation reason,
full delivery rows/metadata, review claims, audit counts and ordered provider
calls. Transactions are checked unchanged. Timestamp presence is normalized;
this is not exact wall-clock/wire timing or real provider acceptance.

The old pending-only adapter is an explicit negative control: the first case
makes one external publication call and writes pending metadata, while Python
and the replacement also call the mirror provider and persist its result.

| Boundary | Published and candidate outcome |
| --- | --- |
| Delivered Canvas suspend/revoke | Publication, credential persistence, mirror call, delivery result, review/audit finalization |
| Pending/failed/non-Canvas delivery | No mirror call or mutation of that delivery |
| Profile gate or target unavailable | Durable delivery error; credential/review transition still succeeds |
| Mirror provider fails | Durable attempt/error metadata; review succeeds |
| Publication fails | 503; credential unchanged; review claim released |
| Already revoked credential | Existing 400 business error; no external call |
| Cancel during publication | Cancellation acknowledged; credential unchanged; durable claim retained |
| Cancel during mirror | Cancellation acknowledged; credential already changed; delivery unchanged; claim retained |
| Competing manual request | 409 while the first claim is active; no second publication |

Large JSON integers are now preserved with serde's arbitrary-precision feature;
the shared Python formatter keeps integer identity without conversion to f64.
Counter arithmetic is performed in decimal after MMF parsing. Unit checks assert
exact decimal output beyond u64, not equality between two rounded float values.
Existing published-schema/input goldens also pass with this feature enabled.

## Hosted shutdown failure and correction

CI33993817395 at #814 head4fcfb86de failed the preexisting packaged-worker
signal test at its10-second exit deadline; synthetic panic messages earlier in
that log belonged to passing panic-isolation tests. The failing log did not name
the signal/phase, so per-case diagnostics are now emitted without process secrets.

Inspection of pinned SQLx0.9 showed return-to-pool pings a released connection
before returning it to pool ownership. A cancelled SQL future can leave that ping
waiting on the original database lock; a subsequent pool.close() waits for it.
A disposable PostgreSQL negative control reproduces this race: the default pool
does not close within200ms while the lock remains held. The worker pool's new
after-release hook bounds validation at1s; on timeout SQLx hard-closes the released
connection. The corrected pool closes within3s before releasing the lock. Both
test paths always release their own lock and finish pool cleanup before asserting.

This is connection validation after an operation has completed or been dropped,
not a new deadline for active SQL. Normal SIGTERM drain is unchanged. The existing
10-second process exit gate is not widened or disabled. Local reproduction passes;
actual packaged POSIX signal behavior still requires mandatory Linux CI.

## Remaining work

Local verification: all15 configured schema tests pass (89.23s),264 library tests
pass (7.72s), all-target Clippy passes,5 worker executable tests and22 combined
behavior tests pass, and33 workflow/image tests pass (1.20s). The shutdown
regression was then strengthened to observe connection release directly rather
than assuming a scheduling delay; its final rerun is recorded in the PR/checkpoint.
Hosted qualification of this updated head is still required.

Implement and qualify actual Canvas Credentials bridge/Badgr status providers,
reusing existing origin, secret-resolution and provider configuration owners.
Exercise profile hydration, malformed metadata/counters, multiple records,
write failures after publication, further claim/recovery races and arbitrary
encoding/transport cases. Broaden big-number qualification across consumers.
Then wire every intended runtime consumer, remove the old pending-only path and
superseded Python after gates, and complete aggregate beta/demo/device acceptance.
Source-overlay migration tests are not released-component adoption. Production
and persistent self-host deployments remain unchanged.

# Rust revocation-profile service

This crate is the service-owned Rust orchestration layer for revocation
profiles. Status-list packing, mutation, compression, and credential-subject
generation are imported from the pinned canonical `marty-status` crate in
`ElevenID/marty-core`; this repository does not carry a second status-list
implementation.

The crate defines the domain contract, concurrency-safe service operations, the
existing gRPC surface, a PostgreSQL adapter for the released profile schema,
and a Redis adapter compatible with the existing keys and JSON records. Stable
credential-to-index reservations are transactionally owned by PostgreSQL;
Redis preserves status-list bytes and the released counter as an upgrade floor.
Status mutations use bounded compare-and-swap and still run only through
`marty-status`.

Startup runs an advisory-lock-protected, idempotent Rust schema migrator and
ensures the released default Marty profile exists without overwriting an
existing profile. It also backfills issued status-list entries into the durable
allocation table and initializes profile/format counters. This preserves both
fresh-database setup and databases that already ran the historical Alembic
revisions, and removes the last schema/seed dependency on the removed Python
service.

Allocation rows intentionally outlive profile deletion. They are immutable
scope tombstones that prevent a stable credential ID from being rebound to a
different organization, profile, or status-list format.

The compatibility `/allocate-index` HTTP and gRPC operations remain available
during the staged rollout, but they use synthetic allocation owners and the same
PostgreSQL counter as `/reserve-index`. This prevents old and new callers from
allocating the same index.
Set `RP_MIGRATE_ONLY=true` to run that database step and exit without requiring
Redis, organization gRPC, or service-auth configuration; the final deletion
change can therefore run Rust before the remaining shared migration graph.

The shared service image dispatches revocation-profile directly to this binary,
and the same binary runs its one-shot migration before the remaining shared
schema graph. Golden vectors and the disposable executable contract cover the
compatibility, authorization, storage, migration, readiness, diagnostics, and
HTTP/gRPC startup boundaries. Image rollback is the only rollback mechanism;
there is no Python runtime fallback.

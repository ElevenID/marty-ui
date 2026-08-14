# Rust revocation-profile service

This crate is the service-owned Rust orchestration layer for revocation
profiles. Status-list packing, mutation, compression, and credential-subject
generation are imported from the pinned canonical `marty-status` crate in
`ElevenID/marty-core`; this repository does not carry a second status-list
implementation.

The crate defines the domain contract, concurrency-safe service operations, the
existing gRPC surface, a PostgreSQL adapter for the released profile schema,
and a Redis adapter compatible with the existing keys and JSON records. Redis
index allocation is atomic and status mutations use bounded compare-and-swap;
the mutation itself still runs only through `marty-status`.

Startup runs an advisory-lock-protected, idempotent Rust schema migrator and
ensures the released default Marty profile exists without overwriting an
existing profile. This preserves both fresh-database setup and databases that
already ran the historical Alembic revisions, and removes the last schema/seed
dependency on the Python service before its deletion gate.
Set `RP_MIGRATE_ONLY=true` to run that database step and exit without requiring
Redis, organization gRPC, or service-auth configuration; the final deletion
change can therefore run Rust before the remaining shared migration graph.

It is selected only by the beta tunnel overlay for the next coordinated beta
release. Shared Python/Rust HTTP vectors and the disposable executable contract
cover the compatibility, authorization, storage, readiness, diagnostics, and
HTTP/gRPC startup boundaries. Application-consumer evidence and the security
soak gate must still pass before the Python service is removed. Production and
persistent self-host profiles remain unchanged.

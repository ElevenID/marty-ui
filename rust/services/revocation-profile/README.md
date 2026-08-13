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

It is not selected by any compose profile. REST/auth parity, executable image
wiring, and beta compose selection must land and pass their contract gates
before the Python service is removed.

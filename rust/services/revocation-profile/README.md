# Rust revocation-profile service

This crate is the service-owned Rust orchestration layer for revocation
profiles. Status-list packing, mutation, compression, and credential-subject
generation are imported from the pinned canonical `marty-status` crate in
`ElevenID/marty-core`; this repository does not carry a second status-list
implementation.

The initial slice defines the domain contract, concurrency-safe service
operations, and the existing gRPC surface. It is not selected by any compose
profile. Durable PostgreSQL/Redis adapters, REST/auth parity, and beta compose
selection must land and pass their contract gates before the Python service is
removed.

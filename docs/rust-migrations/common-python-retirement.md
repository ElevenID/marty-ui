# Shared Python adapter retirement

This cleanup is based on protected UI main `da70b2f22b5942b826cf0680f03f8f8559d5f1b8`.
The nine `services/common` runtime modules had no imports outside that directory
and its Python tests. The public service Docker context already excludes the
whole directory through `services/Dockerfile.dockerignore`. The migration
entrypoint imports `passport_disposable_identity`, not `common`; its image copied
the unused directory as source but did not execute it. Removing these files
does not select a new service implementation.

| Retired Python | Retained behavior owner or evidence |
| --- | --- |
| `application_event_auth.py` | Rust Flow application event HTTP/gRPC authentication and replay tests in `rust/services/flow` |
| `notification_event_auth.py` | Rust Notification event delivery and authentication in `rust/services/notification` |
| `events.py`, `grpc_event_bus.py` | Rust producer transports and Event Stream gRPC bus in `rust/services/{auth,applicant,organization,event-stream}` |
| `grpc_factory.py`, `internal_service_auth.py` | Rust tonic service transports and service authentication in the native service crates |
| `did_resolution.py`, `native_backend.py` | Native DID resolution and Rust service startup boundaries; no deployed Python binding client remains in this directory |
| `oid4vp_native.py` | Rust OID4VP request and verification paths, with shared contract vectors in `rust/crates/oid4vp-contract` |

The adapter-only Python tests were retired with the modules. The two unrelated
release-version and Kubernetes manifest tests moved to top-level `tests/`.
`services/protocol_version.py` was also unimported and is retired. Rust
ownership metadata now rejects reintroducing any `services/common/*.py` or
that protocol-version file. Historical migration plans may still mention
their former paths as point-in-time evidence.

Python remaining in the local `services/` tree is `run_all_migrations.py`
and its tests, `passport_disposable_identity.py` (used by migration and
disposable passport scripts), `conftest.py`, and `__init__.py`. The production
`db-migrate` job still runs Python from `services/Dockerfile.migrations`; its
replacement belongs to the separate bootstrap work. Current main's `issuance`,
`issuance-migrations`, and `canvas-sync-worker` Compose services use native
Rust binaries. Earlier frozen release bundles must be inventoried by their
own exact source revision; this main-tree statement does not reclassify them.

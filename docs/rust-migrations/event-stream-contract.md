# Event-stream Rust migration contract

**Phase:** 2

**Canonical binary:** `rust/services/event-stream`

**Legacy server pending beta deletion:** `services/event_stream`

The Rust service preserves the current public and operational contract before
the Python process is removed. Producer normalization remains in
`services/common/grpc_event_bus.py` until producer services migrate; it is a
gRPC client adapter and does not implement server fan-out decisions.

## Contract matrix

| Surface | Existing behavior | Rust parity evidence |
|---|---|---|
| gRPC service | `marty.ui.event_stream.v1.EventStreamService` | Generated directly from the existing protobuf. |
| `Subscribe` | Server stream filtered by event type, organization, and aggregate type; empty filters match all. | Rust unit and live generated-client contract tests. |
| Subscriber identity | Server generates a UUID when absent; a repeated explicit ID replaces the active registration. | Generation-safe replacement test prevents an old stream from deleting its replacement. |
| `Publish` | Fan out to matching active streams and return the number successfully queued. | gRPC contract test verifies tenant isolation and exact notified count. |
| Backpressure | Per-subscriber queue capacity 256; full queues drop the event for that subscriber without blocking other publishers. | Boundary test fills the queue and verifies the drop counter. |
| Event defaults | Missing event ID and timestamp are generated; timestamps use RFC 3339 UTC. | Event-bus unit coverage; Rust emits the existing `+00:00` UTC form. |
| gRPC health | Service `HealthCheck` returns `serving`; standard gRPC health is registered. | Generated-client test plus `tonic-health` registration. |
| HTTP operations | Ports 8015/9015; `/health`, `/ready`, `/startup`, `/metrics`, OpenAPI and documentation routes. | Axum route contract test; legacy JSON bodies and status codes retained. |
| Configuration | `EVENT_STREAM_SERVICE_PORT`, `EVENT_STREAM_GRPC_PORT`, `EVENT_STREAM_GRPC_ENABLED`, `RUST_LOG`. | Defaults match deployed Compose; malformed values fail startup. |
| Shutdown | Python gRPC server receives a five-second graceful stop. | Both Rust listeners receive one coordinated shutdown notification and drain in-flight requests. |
| Persistence | None; delivery is intentionally process-local and ephemeral. | No database, Redis key, or schema change. |
| Authentication | No service-local authentication today; access is constrained by the deployment network and gateway. | No auth behavior is added or removed in this implementation slice. |
| Observability | Health, logs, and Prometheus scrape endpoint. | Structured JSON tracing and explicit subscriber/publish/delivery/drop metrics. |

## Cutover and deletion gate

1. Build and attest the dedicated Rust image.
2. Run existing Python producers and gateway SSE subscribers against the Rust
   binary in the artifact-only suite.
3. Deploy only the beta event-stream container by immutable digest and observe
   health, disconnects, event lag, drops, memory, and latency.
4. Roll back by restoring the prior beta image; no runtime Python fallback is
   permitted.
5. After the seven-day beta evidence window, delete `services/event_stream`,
   its server-only tests and packaging, then enforce the Rust owner in CI.


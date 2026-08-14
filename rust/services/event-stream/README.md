# Rust event-stream service

This binary is the canonical implementation of Marty's event-stream fan-out
contract. It preserves the existing protobuf service, ports, filter semantics,
bounded subscriber queues, drop-on-backpressure behavior, health endpoints, and
Prometheus scrape endpoint.

Python producers and the gateway continue to use the existing generated gRPC
client. The service image dispatches the `event-stream` role directly to this
binary; there is no Python server or runtime fallback.


# Rust event-stream service

This binary is the canonical implementation of Marty's event-stream fan-out
contract. It preserves the existing protobuf service, ports, filter semantics,
bounded subscriber queues, drop-on-backpressure behavior, health endpoints, and
Prometheus scrape endpoint.

Python producers and the gateway continue to use the existing generated gRPC
client. The legacy Python event-stream server remains only until the beta image
cutover and deletion gate pass; it is not a runtime fallback.


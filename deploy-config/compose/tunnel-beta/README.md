# Tunnel Beta Compose

Canonical compose overlay:

- docker-compose.profile.tunnel.yml

Typical layered command:

- docker compose --env-file <tunnel-env-file> -f docker-compose.base.yml -f docker-compose.profile.tunnel.yml -f deploy-config/compose/tunnel-beta/revocation-profile-rust.yml up -d

Use beta.elevenidllc.com values in the tunnel env file.

The base service image dispatches `event-stream` directly to the canonical Rust
binary. The remaining overlay selects the Rust revocation-profile binary only
for the beta tunnel lane. Source changes do not mutate the currently pinned beta
deployment. Production and persistent self-host deployments are not updated by
this configuration.

The revocation-profile overlay declares the lane as `beta` and requires a
non-placeholder `GRPC_SERVICE_TOKEN` of at least 32 characters. Missing native
service authentication therefore fails startup rather than silently selecting a
development mode.

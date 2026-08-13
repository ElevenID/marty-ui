# Tunnel Beta Compose

Canonical compose overlay:

- docker-compose.profile.tunnel.yml

Typical layered command:

- docker compose --env-file <tunnel-env-file> -f docker-compose.base.yml -f docker-compose.profile.tunnel.yml -f deploy-config/compose/tunnel-beta/event-stream-rust.yml -f deploy-config/compose/tunnel-beta/revocation-profile-rust.yml up -d

Use beta.elevenidllc.com values in the tunnel env file.

The final overlays select the canonical Rust event-stream and revocation-profile
binaries only for the beta tunnel lane. They take effect on the next coordinated
beta release; merging them does not mutate the currently pinned beta deployment.
Production and persistent self-host deployment definitions are intentionally
unchanged.

The revocation-profile overlay declares the lane as `beta` and requires a
non-placeholder `GRPC_SERVICE_TOKEN` of at least 32 characters. Missing native
service authentication therefore fails startup rather than silently selecting a
development mode.

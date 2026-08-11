# Tunnel Beta Compose

Canonical compose overlay:

- docker-compose.profile.tunnel.yml

Typical layered command:

- docker compose --env-file <tunnel-env-file> -f docker-compose.base.yml -f docker-compose.profile.tunnel.yml -f deploy-config/compose/tunnel-beta/event-stream-rust.yml up -d

Use beta.elevenidllc.com values in the tunnel env file.

The final overlay selects the canonical Rust event-stream binary only for the
beta tunnel lane. Production and persistent self-host deployment definitions
are intentionally unchanged.

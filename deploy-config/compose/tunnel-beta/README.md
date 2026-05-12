# Tunnel Beta Compose

Canonical compose overlay:

- docker-compose.profile.tunnel.yml

Typical layered command:

- docker compose --env-file <tunnel-env-file> -f docker-compose.base.yml -f docker-compose.profile.tunnel.yml up -d

Use beta.elevenidllc.com values in the tunnel env file.
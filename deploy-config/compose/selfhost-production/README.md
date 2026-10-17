# Selfhost Production Compose

Canonical compose file:

- docker-compose.selfhost.prod.yml

Recommended command:

- docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml up -d

This stack should use elevenidllc.com domain values.

Redis listens only on a Unix socket in a Compose project-scoped volume. Only
the services that use Redis mount that volume; no Redis TCP port or workload TLS
private-key file is provisioned. Use a distinct Compose project for each
installation so its network and socket volume cannot be shared with another
stack on the same Docker host.

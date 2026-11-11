# Selfhost Production Compose

Canonical compose file:

- docker-compose.selfhost.prod.yml

On a fresh installation, initialize OpenBao and stage the reviewed secret
generation first. Then run the ordinary database migration to completion,
invoke the privileged KMS/DID initializer once, and start the application:

```sh
python scripts/check-selfhost-production.py --env-file .env.selfhost.production.local --required-secrets-only
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml up -d db-migrate
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml ps --all db-migrate
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml run --rm --no-deps kms-initialize
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml up -d
```

Require `db-migrate` to exit zero before invoking `kms-initialize`. Subsequent
restarts use only the final `up -d` command. The `kms-initialize` service is
opt-in through its `kms-init` profile; ordinary `db-migrate` has no bootstrap
token mount and cannot create KMS/DID keys.

This stack should use elevenidllc.com domain values.

After startup, run the full configuration and health check with the same
environment and Compose selection used to launch the stack:

```sh
python scripts/check-selfhost-production.py --env-file .env.selfhost.production.local
```

The checker asks Docker Compose to resolve quotes, variable interpolation and
host-environment overrides. It does not source the environment file as a shell
script. Relative `SELFHOST_SECRET_DIR` paths are relative to the selected Compose
file, including when the checker is invoked from another directory. Literal
dollar signs in paths are preserved. Failure to resolve the selected environment
is reported before runtime probes, without printing the expanded Compose model
or its credentials.

Redis listens only on a Unix socket in a Compose project-scoped volume. Only
the services that use Redis mount that volume; no Redis TCP port or workload TLS
private-key file is provisioned. Use a distinct Compose project for each
installation so its network and socket volume cannot be shared with another
stack on the same Docker host.

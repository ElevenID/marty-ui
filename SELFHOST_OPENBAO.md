# Self-Host OpenBao Setup

This is the standalone external OpenBao setup for the workstation-local self-host production stack. It stays outside the main application compose project, keeps its state on durable host storage, and writes the scoped `openbao_service_token` into the shared self-host secret directory.

## Paths

- `SELFHOST_OPENBAO_STATE_DIR` stores OpenBao Raft data and recovery material
- `SELFHOST_OPENBAO_EXPORT_DIR` stores zipped export archives created with `scripts/export-selfhost-openbao.py`
- `SELFHOST_SECRET_DIR/openbao_service_token` is the runtime token the main self-host stack consumes

The OpenBao state directory contains highly sensitive material, including the init JSON, the root token, and the unseal key written by the bootstrap flow. Treat that directory like a top-tier secret.

## Start The Standalone OpenBao Stack

```bash
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.openbao.yml up -d
```

Or use the GNU make target in [Makefile](Makefile):

```bash
make selfhost-prod-openbao-up
```

This stack does two things:

- `openbao` runs the standalone server on `127.0.0.1:${SELFHOST_OPENBAO_HOST_PORT}`
- `openbao-bootstrap` initializes, unseals, configures the transit/PKI/KV/policy layout, and writes a fresh `openbao_service_token` into `SELFHOST_SECRET_DIR` if the current file is missing, still a placeholder, rejected by OpenBao, or unable to sign the credential issuer key

For the main self-host application stack on the same machine, `BAO_ADDR` should stay set to `http://host.docker.internal:${SELFHOST_OPENBAO_HOST_PORT}` so the app containers can reach the external OpenBao service through the host-published port.

## Recovery

The recovery material lives under `SELFHOST_OPENBAO_STATE_DIR`.

- If the host reboots, restart the standalone OpenBao compose project
- For a cold move to another host, stop the OpenBao server, copy `SELFHOST_OPENBAO_STATE_DIR` to the new host, and start the same compose file there. Do not copy the live Raft data directory as a backup.
- If `openbao_service_token` is missing on the destination, rerun the bootstrap service:

```bash
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.openbao.yml run --rm openbao-bootstrap
```

Or:

```bash
make selfhost-prod-openbao-bootstrap
```

## Export

To create a portable OpenBao recovery archive:

```bash
python scripts/export-selfhost-openbao.py --env-file .env.selfhost.production.local
```

Or:

```bash
make selfhost-prod-openbao-export
```

The command requests an authenticated Raft snapshot from the running local OpenBao API. It writes a zip archive under `SELFHOST_OPENBAO_EXPORT_DIR` containing:

- `raft.snap`, the OpenBao Raft snapshot
- `recovery/selfhost-init.json`, `recovery/root.token`, and `recovery/unseal.key`
- the current `openbao-selfhost.hcl`
- a manifest with the snapshot SHA-256

The archive is not a direct replacement for the state directory: restoring `raft.snap` requires the OpenBao Raft snapshot restore procedure. A disposable recovery test initialized an empty replacement Raft node, force-restored the archive snapshot, restarted it, and unsealed it with the original recovery key; it recovered Transit ciphertext and versioned plugin keys. Use force restore only on a clean replacement cluster. Coordinated application-database recovery and qualification with the published release image remain release gates. Because the archive contains root-token and unseal-key material, protect it like production secrets.

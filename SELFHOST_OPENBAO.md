# Self-Host OpenBao Setup

This is the standalone external OpenBao setup for the workstation-local self-host production stack. It stays outside the main application compose project, keeps its state on durable host storage, and writes the scoped `openbao_service_token` into the shared self-host secret directory.

## Paths

- `SELFHOST_OPENBAO_STATE_DIR` stores OpenBao Raft data and recovery material
- `SELFHOST_OPENBAO_EXPORT_DIR` is an owner-only (0700) directory for Raft archives
- `SELFHOST_OPENBAO_SNAPSHOT_IDENTITY_DIR` holds a separate snapshot-read-only AppRole RoleID and SecretID (0700 directory, 0600 files)
- `SELFHOST_SECRET_DIR/openbao_service_token` is the runtime token the main self-host stack consumes

The OpenBao state directory contains highly sensitive material, including the initial root token, the unseal key, and OpenBao's own TLS CA and listener private keys. Treat that directory like a top-tier secret. Application containers receive only the public `openbao_tls_ca_cert` and scoped tokens; do not mount the OpenBao state directory into them. The root token is still needed by initial provisioning helpers; retirement of that token remains a separate hardening gate. Snapshot export uses its own AppRole, not the root token or the renewal AppRole.

## Start The Standalone OpenBao Stack

For a fresh state directory, initialize once in this order:

```bash
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.openbao.yml up -d openbao
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.openbao.yml run --rm --no-deps openbao-bootstrap
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.openbao.yml up -d --wait openbao-unseal
```

The GNU make equivalent is `make selfhost-prod-openbao-bootstrap`. For later
starts and restarts, use `make selfhost-prod-openbao-up` or ordinary Compose
`up -d`; neither invokes the one-time bootstrap.

This project has four services:

- `openbao-tls-init` creates or verifies the OpenBao listener certificate and CA entirely in `SELFHOST_OPENBAO_STATE_DIR/tls`
- `openbao` runs the standalone server on `127.0.0.1:${SELFHOST_OPENBAO_HOST_PORT}`
- `openbao-bootstrap` is opt-in for initial transit/PKI/KV/policy provisioning and publishes scoped runtime tokens and the public TLS CA
- `openbao-unseal` reads only the KMS-owned state directory and unseals an initialized node after restart through the authenticated HTTPS API

For the main self-host application stack on the same machine, set `BAO_ADDR=https://host.docker.internal:${SELFHOST_OPENBAO_HOST_PORT}`. The certificate covers that host name, and application containers use the published public CA. The TLS private keys stay within the KMS state volume.

The initializer renews a listener certificate that has less than 30 days left
whenever it starts. The certificate and key occupy one owner-only PEM file, so
replacement is atomic and keeps the same public CA. To rotate the listener
identity while OpenBao is running, use `make selfhost-prod-openbao-rotate-tls`;
the target renews the PEM, restarts OpenBao, and waits for the unseal service.
Plan a separate CA and client-trust cutover before the KMS-owned CA expires;
listener renewal cannot extend the CA lifetime.

## Recovery

The recovery material lives under `SELFHOST_OPENBAO_STATE_DIR`.

- If the host reboots, restart the standalone OpenBao compose project
- For a cold move to another host, stop the OpenBao server, copy `SELFHOST_OPENBAO_STATE_DIR` to the new host, and start the same compose file there. Do not copy the live Raft data directory as a backup.
- Preserve the separately owned scoped token files with the installation's
  secret generation. A missing runtime token needs explicit scoped recovery;
  normal restart and TLS rotation do not recreate it with the root token.

## Export

To prepare portable OpenBao recovery archives:

After the one-time OpenBao bootstrap, create an owner-only snapshot identity
directory and provision its dedicated AppRole once. Use absolute paths for these
private inputs:

```bash
mkdir -m 700 -p "$SELFHOST_OPENBAO_SNAPSHOT_IDENTITY_DIR" "$SELFHOST_OPENBAO_EXPORT_DIR"
python scripts/provision_selfhost_snapshot_identity.py \
  --bao-addr "https://127.0.0.1:$SELFHOST_OPENBAO_HOST_PORT" \
  --bao-ca "$(realpath "$SELFHOST_OPENBAO_STATE_DIR/tls/ca.crt")" \
  --root-token-file "$(realpath "$SELFHOST_OPENBAO_STATE_DIR/root.token")" \
  --output "$(realpath "$SELFHOST_OPENBAO_SNAPSHOT_IDENTITY_DIR")"
```

The role can only read `sys/storage/raft/snapshot`. Its identity can retrieve
the complete encrypted KMS state, so protect it separately from routine renewal
credentials. Subsequent exports need only this identity:

```bash
python scripts/export-selfhost-openbao.py --env-file .env.selfhost.production.local
```

Or:

```bash
make selfhost-prod-openbao-export
```

The command requests an authenticated Raft snapshot from the running local OpenBao API. It writes a zip archive under `SELFHOST_OPENBAO_EXPORT_DIR` containing:

- `raft.snap`, the OpenBao Raft snapshot
- the current `openbao-selfhost.hcl`
- a manifest with the snapshot SHA-256

The exporter verifies the loopback HTTPS server with `SELFHOST_OPENBAO_STATE_DIR/tls/ca.crt`. It does not include OpenBao's TLS private keys in the archive. A cold snapshot restore on a new node must establish a new TLS identity and redistribute its public CA before application traffic resumes. Copying the entire stopped state directory retains the existing TLS identity; protect that copy as KMS key material.

The archive is not a direct replacement for the state directory: restoring `raft.snap` requires the OpenBao Raft snapshot restore procedure and separately held original unseal material. It contains neither the root token nor unseal key. A disposable recovery test initialized an empty replacement Raft node, force-restored the archive snapshot, restarted it, and unsealed it with the original recovery key; it recovered Transit ciphertext and versioned plugin keys. Use force restore only on a clean replacement cluster. Coordinated application-database recovery and qualification with the published release image remain release gates. The snapshot still contains the complete KMS custody state; protect it like production secrets.

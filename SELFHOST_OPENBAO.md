# Self-Host OpenBao Setup

KMS operator public-key checks and root-retirement snapshot validation run in
Rust through the existing `marty-deploy` executable. In an extracted bundle,
install the operator from the **same release tag and source commit** as the bundle
and source its verified environment before running Python operator entrypoints:

```sh
bash scripts/install-marty-deploy.sh "$RELEASE_TAG" "$SOURCE_SHA" "$HOME/.local/lib/marty-operator"
. "$HOME/.local/lib/marty-operator/marty-deploy.lock"
```

The installer requires `gh`, `jq`, `cosign`, and `sha256sum`, verifies signatures
and source provenance, and supports Linux amd64/arm64. A source checkout can use
Cargo 1.95 instead. Python entrypoints retain their arguments. Rust conversion
accepts supported public SPKI/certificate keys; it does not establish certificate
trust or replace the existing issuer, key-version, or non-exportability checks.
The Rust exporter logs in with the snapshot-only AppRole and streams the existing
v2 archive into an owner-only file, then publishes it without overwriting another
backup. It never reads root or unseal files. Downloads use a 300-second idle read
timeout; steady progress can continue beyond five minutes. The independent Rust
validator reads an archive without extraction. Actual restore qualification
remains a separate requirement.

This is the standalone external OpenBao setup for the workstation-local self-host production stack. It stays outside the main application compose project, keeps its state on durable host storage, and writes the scoped `openbao_service_token` into the shared self-host secret directory.

## Paths

- `SELFHOST_OPENBAO_STATE_DIR` stores OpenBao Raft data and recovery material
- `SELFHOST_OPENBAO_EXPORT_DIR` is an owner-only (0700) directory for Raft archives
- `SELFHOST_OPENBAO_SNAPSHOT_IDENTITY_DIR` holds a separate snapshot-read-only AppRole RoleID and SecretID (0700 directory, 0600 files)
- `SELFHOST_SECRET_DIR/openbao_service_token` is the runtime token the main self-host stack consumes

The OpenBao state directory contains highly sensitive material, including the initial root token, the unseal key, and OpenBao's own TLS CA and listener private keys. Treat that directory like a top-tier secret. Application containers receive only the public `openbao_tls_ca_cert` and scoped tokens; do not mount the OpenBao state directory into them. The root token is still needed by initial provisioning helpers; retirement of that token remains a separate hardening gate. Snapshot export uses its own AppRole, not the root token or the renewal AppRole.

During fresh initialization, `selfhost-init.json` is created owner-only so a
crash before recovery files are written does not lose the sole unseal key or
initial root token. Bootstrap synchronizes those files and removes the duplicate
JSON before reporting success. If initialization is interrupted, preserve the
state directory and inspect the owner-only init file or the completed root and
unseal files for recovery; do not run the one-time bootstrap again against
initialized Raft state.

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
snapshot_rotator_dir="$(dirname "$SELFHOST_OPENBAO_STATE_DIR")/snapshot-rotator-identity"
mkdir -m 700 -p "$snapshot_rotator_dir"
python scripts/provision_selfhost_snapshot_rotator.py \
  --mode bootstrap \
  --bao-addr "https://127.0.0.1:$SELFHOST_OPENBAO_HOST_PORT" \
  --bao-ca "$(realpath "$SELFHOST_OPENBAO_STATE_DIR/tls/ca.crt")" \
  --root-token-file "$(realpath "$SELFHOST_OPENBAO_STATE_DIR/root.token")" \
  --output "$(realpath "$snapshot_rotator_dir")"
```

The role can only read `sys/storage/raft/snapshot`. Its identity can retrieve
the complete encrypted KMS state, so protect it separately from routine renewal
credentials. The separate rotator can only create and destroy SecretIDs for the
snapshot reader and its own role; it cannot read snapshots, sign, export keys,
or create unrestricted tokens. To rotate the reader after root retirement, use
`provision_selfhost_snapshot_rotator.py --mode rotate-reader --identity
"$SELFHOST_OPENBAO_SNAPSHOT_IDENTITY_DIR" --output "$next_reader_dir"
--rotator-identity "$snapshot_rotator_dir"` with the same `--bao-addr` and
`--bao-ca`. Validate the replacement export before retiring the old private
directory. `--mode rotate-rotator` rotates the rotator's own SecretID; both
roles have matching `retire-reader` and `retire-rotator` modes to complete an
interrupted old-SecretID retirement. Keep active and replacement identities
separately backed up until the old login is confirmed rejected. Subsequent
exports need only the reader identity:

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

After force restore, start the `openbao-unseal` sidecar and wait for OpenBao
to be healthy before starting application migrations. The restore seals the
node even if its temporary fresh-cluster key unsealed it beforehand.

Before considering revocation of the initial root token, run
`scripts/check_selfhost_root_retirement.py --help` and supply the active and
rollback secret generations, their Compose env files, the renewal, CA-rotation
and snapshot reader identities, the separate evidence, audit and snapshot rotator identities, the
owned project and an owner-private snapshot export directory. It
verifies all 21 renewable token scopes in
**both** generations, the 13 static service/grant tokens in each generation,
their live non-exportable signers and public certificates, rootless
ordinary migration, and the healthy active project's secret mounts. It creates
and checks a current v2 Raft snapshot with the separate snapshot identity. The
audit does not revoke the root or establish coordinated backup provenance, CA rollover,
or an expiry-crossing business journey. Retain the root until those separate
gates have passed on a fresh installation.

Provision the dedicated CA-rotation AppRole before the root-retirement audit.
Use a new owner-private directory and the current complete secret generation:

```bash
ca_rotation_dir="$(dirname "$SELFHOST_OPENBAO_STATE_DIR")/ca-rotation-identity"
mkdir -m 700 -p "$ca_rotation_dir"
python scripts/provision_selfhost_ca_rotation_identity.py --mode bootstrap \
  --bao-addr "https://127.0.0.1:$SELFHOST_OPENBAO_HOST_PORT" \
  --bao-ca "$(realpath "$SELFHOST_OPENBAO_STATE_DIR/tls/ca.crt")" \
  --token-file "$(realpath "$SELFHOST_OPENBAO_STATE_DIR/root.token")" \
  --current-secrets /absolute/path/to/current/secrets \
  --output "$(realpath "$ca_rotation_dir")"
```

The root-retirement audit requires `--ca-rotation-identity "$ca_rotation_dir"`
and validates a fresh rootless login and its exact ACL. This identity is
separate from routine leaf renewal. It is limited to reviewed versioned PKI
mounts and cannot export Transit keys or manage unrelated mounts. Provisioning
the identity alone does not rotate either CA or activate a new trust bundle;
complete the separate overlap and session gates before production root retirement.

After those gates, `scripts/retire_selfhost_bootstrap_root.py` takes the same
arguments as the audit. It runs the complete audit and scoped snapshot export,
requires the owner-private `root.token` inside the supplied OpenBao state,
revokes that exact token through the verified HTTPS `auth/token/revoke` endpoint,
checks that its lookup is denied, reruns the complete rootless audit, then
removes the stale root-token file from active state. If interrupted after
revocation, it can be repeated to complete the post-check and file removal.
Exclude the stale root-token file from future backups. In a separate cold-copy
rehearsal, `auth/token/revoke` succeeded and the root lookup returned 403;
`auth/token/revoke-self` returned 500 and left it valid. Keep the unseal material
under separate custody: revoking the root token does not unseal OpenBao or
replace a Raft recovery test.

## Qualification ownership and retired exploration

Current custody and release requirements belong to the
[remote KMS hardening plan](docs/remote-kms-hardening-plan.md). The uncalled
`probe_kms_hardening_capabilities.py` and April `KMS_GAP_ANALYSIS.md` are retired;
their original source is available at UI commit
`956bfa2985ef3e9854fe22cac089f190da0327ee`. The old provider matrix and completed
task counts are historical implementation claims, not current cloud-provider,
installed-release or device qualification. OpenBao evidence does not qualify
AWS KMS, Azure Key Vault or GCP Cloud KMS.

Retain the capability probe's questions as explicit acceptance requirements:

- Establish whether the selected provider supports non-exportable `x25519` or
  `ecdh-x25519` key creation and the needed derivation semantics. CLI help for
  `transit/derive-key` mentioning a named output does not prove remote DIDComm
  authcrypt, recipient interoperability or an acceptable key-custody boundary.
- For integration-secret AES-256-GCM custody, assert both `exportable=false` and
  `allow_plaintext_backup=false`, and prove a key-export request is denied.
  Rotate the remote key and decrypt the original version's ciphertext back to
  the same synthetic plaintext. Change a byte of the decoded authenticated
  ciphertext and require an authentication failure, without accepting outages,
  invalid configuration or arbitrary provider errors as tamper rejection.
- Exercise tenant/purpose isolation, persistent application writes, restart and
  coordinated Raft/database recovery through current Rust service paths.
  Disposable primitive checks do not qualify legacy ciphertext import, deployed
  authorization or a supported provider/algorithm combination.

Existing owners include `probe_selfhost_openbao_raft_bootstrap.py` for Raft and
export restrictions, `probe_integration_secret_coordinated_restore.py` for real
service recovery, and the Rust
`integration_secret_envelope_live_kms.rs` opt-in test for rotation and binding.
These are related checks, not an assertion that every exploratory case above
is executed by CI. Preserve missing assertions at these active owners when
qualifying a provider; do not restore a parallel capability-reporting script.
This cleanup executes no provider, restore or installed-release qualification.

The April gap audit also carried useful product requirements. Keep each with
its current Rust service or Core owner and qualify advertised combinations:

- Resolve tenant-scoped keys by purpose, format, credential type, issuer and
  country/authority namespace; preserve supported type/format/global selection
  precedence and explicit errors, with no local-key or runtime retry fallback.
- Discover and validate provider algorithms/curves, signature DER versus raw
  encoding, public-key retrieval, attestation and supported lifecycle operations.
  Do not infer a provider capability from static metadata or mocked connectivity.
- Bind public JWKS/DID verification methods and certificate chains to the managed
  key. Preserve publication persistence/retrieval, mdoc COSE `x5chain`, certificate
  inspection/expiry alerts, authenticated CSCA import/status/list/revocation,
  renewal lineage, chain validation and transactional lifecycle events.
- Qualify versioned rotation with old/new verification overlap, scheduled
  activation, publication updates and coordinated certificate rollover. Preserve
  holder registration and presentation-proof capabilities through the existing
  wallet/opaque-signer boundary; issuer custody cleanup must not erase them.

The retained VDS-NC format and end-to-end requirements are mapped in the
[DTC/VDS-NC decision](docs/rust-migration-phase8-dtc-vds-decision.md).

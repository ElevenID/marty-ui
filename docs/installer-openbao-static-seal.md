# Fresh installer static auto-unseal

Fresh installer-managed OpenBao nodes use a separate, customer-protected
32-byte static seal key. OpenBao reads that key itself at startup and recovers
the existing encrypted Raft state. The installer readiness process observes
status; it has no initialization, unseal, recovery-key, or restart operation.
Legacy self-host consumers keep their existing bootstrap behavior unless they
explicitly select the installer mode. This release does not migrate an existing
Shamir or other seal configuration.

OpenBao 2.5 supports the `static` seal with a raw file-backed 32-byte key and a
permanent key identifier. The installer uses:

```hcl
seal "static" {
  current_key_id = "marty-selfhost-static-v1"
  current_key = "file:///bao/seal/static.key"
}
```

See the [versioned static-seal documentation](https://openbao.org/docs/2.5.x/configuration/seal/static/).
There is no environment variable or command-line argument containing key bytes,
and no `previous_key`, rotation, migration, or missing-key generation fallback.

## Custody and mounts

| Host path below the installation | Custody | Container consumer |
| --- | --- | --- |
| `openbao-seal` | Installer owner, `0700`; never mounted | None |
| `openbao-seal/key` | Installer owner, `0755`, beneath the private outer directory | OpenBao alone, read-only at `/bao/seal` |
| `openbao-seal/key/static.key` | Installer owner, `0444`, exactly 32 raw bytes | OpenBao's static-seal implementation |
| `openbao-seal/initialization` | Installer owner, `0700` | Fresh bootstrap job only, writable at `/bao/static-init` |
| `openbao-control/socket` | Mapped OpenBao UID/GID, `0700`; socket `0600` | OpenBao writable; bootstrap/readiness consumers read-only |

The readable key projection permits the mapped nonroot OpenBao identity to read
the key without guessing a host UID. The unmounted `0700` outer directory keeps
other host users from traversing to the projection. This is separate from both
Raft state and application secret generations. The installer records the key's
creation identity, size, mode and change timestamp; public status never reads or
fingerprints its contents. Missing or changed material is a custody failure, not
permission to create another key or initialize another store.

The customer must retain the original seal material independently of the Raft
data when managing backups and recovery. A public creation receipt does not
prove that a backup exists. OpenBao's recovery shares authorize administrative
recovery operations; they cannot decrypt a store when its seal mechanism is
unavailable. See [seal and recovery-key behavior](https://openbao.org/docs/2.5.x/concepts/seal/).

## One fresh initialization

Only the installer bootstrap job sets `MARTY_OPENBAO_STATIC_SEAL=1`. It also
supplies `MARTY_OPENBAO_LOCAL_CONTROL=1`, the installation UUID, and the retained
`MARTY_OPENBAO_STATIC_INIT_ATTEMPT_ID`. This opt-in refuses conflicting network
origins or initialization paths. Its fixed initializer is:

```text
/usr/local/bin/selfhost-static-init --installation-id <UUID> --attempt-id <UUID>
```

The command runs as container root. It receives state and the private Unix
socket, plus the empty public initialization output directory. It does not
receive `/bao/seal` and never opens the static key. It verifies an uninitialized
static-seal node, the absence of prior root/unseal/recovery/init material, and an
empty private output directory. It persists `static-init-pending.json` before
making its single `POST /v1/sys/init` request.

The request specifies `recovery_shares=1` and `recovery_threshold=1` and supplies
no Shamir share parameters. OpenBao 2.5.5 rejects `secret_shares` and
`secret_threshold` when the configured seal uses recovery keys; see the
[versioned initialization handler](https://github.com/openbao/openbao/blob/v2.5.5/http/sys_init.go)
and [initialization API](https://openbao.org/docs/2.5.x/api/system/init/).

The returned root token and recovery share are private outputs:

| Container state file | Purpose |
| --- | --- |
| `/bao/data/static-init-material.json` | Root-owned `0400` retained response material until the individual files and public result are durable |
| `/bao/data/root.token` | Root-owned `0400` bootstrap authority, retired by the separate installation completion transaction |
| `/bao/data/recovery.key` | Root-owned `0400` administrative recovery share; distinct from the static seal key |
| `/bao/data/static-init-authority.json` | Root-owned `0400` private binding of the original root and recovery-share files; retained for the separate root-retirement transaction |

All outputs use exclusive creation with owner, mode, regular-file, single-link,
length and inode checks. An uncertain initialization leaves its intent and any
private outputs for reconciliation. It cannot replay initialization or adopt an
existing initialized store. The command does not submit `sys/unseal`, including
while waiting for Raft to become ready. After durable individual outputs and a
private original-authority binding, it publishes the public result and removes
the redundant private material file. The private binding contains file identity,
ownership, mode, size, timestamps and private content digests. Its contents and
digest never enter host receipts, support exports or public output. Historical
public initialization receipts remain unchanged by later root retirement.

The public output directory contains exactly these `0600` files:

- `static-init-pending.json`, schema
  `elevenid.openbao-static-init-intent/v1`: installation/attempt IDs,
  `seal_type: "static"`, `recovery_shares: 1`, `recovery_threshold: 1`.
- `static-init-result.json`, schema
  `elevenid.openbao-static-init-result/v1`: installation/attempt/cluster IDs,
  `seal_type: "static"`; `initialized`, `unsealed_ready`,
  `recovery_key_written`, and `root_token_written` are true;
  `root_retired`, `initialization_replayed`, and `installation_ready` are false.

The helper emits the same public result on stdout. The host binds both public
files to their created directory and the exact successful owned bootstrap job.
Neither receipt claims root retirement, application readiness, or customer
reboot qualification.

## Readiness and security-seal intent

The historical Compose service key `openbao-unseal` now runs
`selfhost-openbao-ready --watch` in installer mode. Its only bind is the Unix
socket directory, read-only; it receives no state, seal, recovery-share or root
token mount. The watcher uses only `GET /v1/sys/seal-status` and reports changes
in public status. It never calls an unseal endpoint.

The same command has two bounded one-shot probes:

- `--check-listener` accepts a reachable, correctly configured static-seal node,
  including before initialization or while sealed.
- `--check-ready` additionally requires initialized, unsealed state and a valid
  cluster ID. It rejects a Shamir seal, migration, missing status fields, or an
  unavailable/unsafe socket.

The public schema `elevenid.openbao-static-readiness/v1` reports
`listener_available`, `seal_type`, `initialized`, `sealed`, `recovery_seal`,
`unsealed_ready`, optional `cluster_id`, and `installation_ready: false`.
An alive watcher process is not a readiness claim; Compose uses the strict probe.

An explicit security seal requires durable host lifecycle intent. OpenBao itself
can auto-unseal after restart, including after an API seal; a readiness-only
watcher leaving that node sealed does not establish that a later automated
restart respects the operator's security intent. The host stop/restart/resume
transaction owns that boundary. See the
[documented auto-unseal behavior](https://openbao.org/docs/2.5.x/concepts/seal/).

## Verification and remaining qualification

Focused Go tests verify fresh-only initialization, pre-mutation intent, private
output custody, refusal after lost initialization responses, no adoption of
existing root/recovery/unseal material, and readiness without mutation.

The opt-in test
`TestOfficialOpenBao255StaticSealRestartsWithoutUnsealReplay` uses the verified
official OpenBao 2.5.5 binary, real Raft storage and the actual Go initializer and
readiness core. It demonstrates all of the following in temporary directories:

- Exactly one initialization request and no unseal request.
- Verified revocation of the bootstrap root; restart succeeds after removing
  the fixture root and recovery-share files.
- The same cluster and a scoped authentication token survive `SIGKILL` and
  restart with the retained static key; normal verified TCP works afterward.
- Readiness leaves a deliberately API-sealed process sealed.
- Missing and 31-byte malformed keys stop startup. An unrelated 32-byte key
  cannot make the retained store ready. Restoring the original key recovers the
  same cluster and authentication state.
- Raw, hex and base64 seal material and the root token are absent from process
  logs. No key bytes are passed through process arguments or environment.

Run the opt-in proof with `MARTY_OPENBAO_UNIX_PROOF_BINARY` pointing at the verified
official binary, then run the focused package tests and build both commands.
Temporary fixture paths and the current test UID are injected only into private
test entry points. Production paths and image-user validation remain fixed.

This proof qualifies the official binary's initialization and process restart
behavior. It does not qualify the production container image, rootless mount
projection, Docker signal path, host security-seal lifecycle, customer reboot,
or an AWS installation. Those remain acceptance steps for the composed runtime.

## Isolated snapshot restore proof

`TestOfficialOpenBao255StaticSnapshotRestorePreservesAuthorities` exercises the
documented `GET` and `POST /v1/sys/storage/raft/snapshot` endpoints against the
same verified OpenBao 2.5.5 binary. The ordinary restore endpoint verifies the
snapshot's sealed hashes with the configured seal; the proof never uses the
`snapshot-force` endpoint. See the versioned
[Raft API](https://openbao.org/docs/2.5.x/api/system/storage/raft/),
[restore command](https://openbao.org/docs/2.5.x/commands/operator/raft/), and
[restore handler](https://github.com/openbao/openbao/blob/v2.5.5/vault/logical_system_raft.go).

The test enrolls the actual local certificate-recovery AppRole and issuer,
creates a native nonexportable Transit signing key, and creates distinct scoped
snapshot and signing credentials. It runs the actual initial-root retirement
core, deliberately loses the revoke result, resumes that same immutable attempt,
and verifies root rejection and removal. A scoped read-only snapshot identity
then obtains the backup. The source process stops before any destination restore.

The restore API requires an initialized and unsealed destination. Accordingly,
the test initializes only a new, disposable destination, with temporary bootstrap
authority used solely to restore the original snapshot. It first proves that a
different valid 32-byte static key is rejected without changing that destination's
cluster. A second disposable destination using the exact original key restores
through the ordinary endpoint. Both the original retired root and the displaced
destination bootstrap root are rejected afterward.

The test verifies the original cluster, native Transit public key and signing
operation, issuer, scoped AppRole logins, scoped snapshot access and the actual
local certificate-recovery operation. The recovery share, scoped identity files,
TLS key and CA are separate protected backup inputs; they are restored separately
from Raft. The imported control CA still has its existing file-backed key and is
not described as nonexportable.

This is a binary and protocol proof. It does not implement or qualify customer
backup transport, image-level restore, filesystem identity rebinding, installed
application rollback or host reboot. The disposable destination's initializer
receipts and private original-authority binding describe its obsolete bootstrap;
they are not adopted as an installed customer's receipts. A production restore
owner must reconcile those external identities explicitly. A snapshot taken
before token revocation can restore old token state, so this proof intentionally
takes its snapshot after verified root retirement. The public proof flags keep
`customer_restore_qualified`, `customer_backup_transport_qualified` and
`container_image_qualified` false.

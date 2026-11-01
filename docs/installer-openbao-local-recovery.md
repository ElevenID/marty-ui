# Installer-owned OpenBao TCP certificate recovery

The image helper `selfhost-tls-recover` replaces the OpenBao node's TCP
certificate through a private Unix API listener. It preserves the existing node
private key and CA. The normal application and shared `OpenBaoHttp` clients
continue to require verified HTTPS.

`installer_openbao_recovery` connects the helper to an installation-owned
transaction. The host operator holds the existing installation lock, validates
the retained engine, image, container, configuration and mount identities,
records a pending attempt, invokes the fixed helper in that exact container,
signals that container, and verifies the new certificate over HTTPS. A helper receipt alone does not establish
a successful reload, complete installation readiness, or reboot qualification.

## Fixed mounts and custody

| Container path | Contents and permissions | Consumers |
| --- | --- | --- |
| `/bao/control` | Socket directory owned by the image's `openbao` UID/GID, mode `0700`; `api.sock` owned by the same UID/GID, mode `0600` | OpenBao read/write; the installer readiness watcher receives a read-only bind |
| `/bao/control-identity` | Root-owned `0700` directory; root-owned `recovery.json`, mode `0400` or `0600`; read-only mount required | OpenBao container's fixed recovery helper, run as container UID/GID `0:0` |
| `/bao/data/tls` | Existing OpenBao-owned `0700` directory; `server.pem` mode `0600`, `ca.crt` mode `0644` | Existing OpenBao state mount |

The host layout is `openbao-control/socket` and
`openbao-control/identity` beneath the installation's operator-owned private
`openbao-control` root. The socket child may change to the mapped image owner;
the outer directory and identity remain operator-owned. Rootless UID mappings
must be established by the owned setup transaction, not guessed from a host UID.
The host gains no new direct access to the image-owned TLS state.

Only the fresh TLS setup job sets `MARTY_OPENBAO_LOCAL_CONTROL=1` on
`selfhost-tls-init`. That mode requires distinct, empty, root-owned `0700`
state/socket/identity directories and absent TLS material, then transfers only
the socket directory to the image's OpenBao UID/GID. It refuses existing
contents, unsafe paths, ownership adoption, and replay. With the variable unset,
the existing TLS initializer and its separate explicit rotation behavior remain
unchanged.

`docker/openbao-selfhost-installer.hcl` retains the existing TCP/Raft settings and
adds only the fixed Unix listener. OpenBao 2.5.5 applies socket permissions only
when `socket_mode`, `socket_user`, and `socket_group` are all supplied. The
template supplies all three. See the
[versioned listener factory](https://github.com/openbao/openbao/blob/v2.5.5/command/server/listener_unix.go)
and [Unix listener documentation](https://openbao.org/docs/2.5.x/configuration/listener/unix/).

Every local connection rejects symlinked path components, unsafe directory or
socket modes, wrong owners, and an inode change while connecting. Linux
`SO_PEERCRED` must report the expected mapped UID/GID. A sibling container's PID
need not be visible in the client's PID namespace, so a peer PID is neither
required nor used for signaling. Network dialing, environment proxies, and
redirect following are disabled. See
[Unix peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html) and
[PID namespace translation](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).

## Fresh installation enrollment

Enrollment belongs to the fresh installation's existing privileged setup phase.
It is never replayed by recovery. The existing TLS initializer creates a
**file-backed CA key**, `ca.key`, and a combined certificate/private-key
`server.pem`. Enrollment imports that existing CA into the dedicated
`selfhost-control-pki` mount, pins the returned issuer ID, and creates the exact
`openbao-network` signing role. The original `ca.key` remains unchanged. An
imported CA with a retained file copy must not be described as nonexportable.
The [OpenBao 2.5.5 PKI API](https://github.com/openbao/openbao/blob/v2.5.5/website/content/api-docs/secret/pki.mdx)
documents `issuers/import/bundle` and its returned issuer/key mapping.

The role permits only `openbao`, `host.docker.internal`, `localhost`, and IP
`127.0.0.1`. It uses EC P-256, digital-signature key usage, server authentication
only, no arbitrary/subdomain names, and a maximum lifetime of `720h`.
`use_csr_common_name` and `use_csr_sans` must be false; the fixed request values
and role restrictions supply the names.

The dedicated AppRole lives under `auth/selfhost-control`, with policy
`selfhost-openbao-tcp-recovery`, no default policy, and service-token TTL,
maximum TTL, and explicit maximum TTL bounded to 300 seconds. Its policy grants
only the following authenticated operations:

| API path | Capability |
| --- | --- |
| `auth/token/lookup-self` | `read` |
| `auth/token/revoke-self` | `update` |
| `selfhost-control-pki/issuer/<pinned issuer UUID>` | `read` |
| `selfhost-control-pki/issuer/<pinned issuer UUID>/sign/openbao-network` | `update`, with the exact parameters below |

The signing policy requires `csr`, `common_name`, `alt_names`, `ip_sans`, `ttl`,
`format`, and `exclude_cn_from_sans`. All parameters other than the CSR are
restricted to one value: `openbao`, `openbao,host.docker.internal,localhost`,
`127.0.0.1`, `720h`, `pem`, and `true`, respectively. It grants no CA import,
mount mutation, role/policy mutation, token creation, or other signing role.

The fixed setup entry point is:

```text
/usr/local/bin/selfhost-control-enroll --installation-id <UUID> --attempt-id <UUID>
```

Its owned setup container receives `/bao/data` and `/bao/control` read-only and
`/bao/control-identity` writable. It reads the existing root-owned `0400`
`/bao/data/root.token`, verifies root authority and the unsealed cluster, and
requires the dedicated PKI mount, auth mount, and policy all to be absent. It
requires an empty output directory and persists `enrollment-pending.json`
before its first remote mutation. Existing or uncertain authority is never
adopted, deleted, or automatically retried.

The enrollment helper reads back the exact PKI role, policy, and AppRole before
writing the private `recovery.json`. It then verifies scoped login, signs and
validates an unused probe certificate, verifies denials for administrative
inspection, CA import, token creation, and unauthenticated signing, revokes the
probe token, and verifies that the token is rejected. It preserves and rechecks
the root token file, CA key, CA certificate, and existing node PEM throughout.
Its AppRole secret ID has no automatic expiry or use limit; each token obtained
from it remains bounded to five minutes. Revocation or rotation of that retained
operator credential is a separate operation.

Only after those checks does it persist `enrollment-result.json` and emit the
same public JSON on stdout. The result schema is
`elevenid.openbao-control-enrollment-result/v1`, with string fields
`installation_id`, `attempt_id`, `cluster_id`, `issuer_id`, `ca_sha256`,
`spki_sha256`, and `policy_sha256` (SHA-256 of the exact UTF-8 ACL); boolean fields
`scoped_login_verified`, `scoped_signing_verified`,
`forbidden_operations_denied`, `verification_token_revoked`,
`existing_ca_key_retained`, and `node_key_preserved` are all true.
`root_retired` is false: the separate host-owned completion phase retires the
bootstrap root afterward. Neither this result nor a successful setup container
is authorization to replay enrollment.

`recovery.json` is a strict JSON object with no duplicate or unknown fields:

| Field | Required value |
| --- | --- |
| `schema` | `elevenid.openbao-tcp-recovery/v1` |
| `installation_id` | Retained installation UUID |
| `cluster_id` | Existing OpenBao cluster ID |
| `role_id`, `secret_id` | Scoped AppRole credentials |
| `issuer_id` | Pinned imported issuer ID |
| `ca_sha256` | Lowercase SHA-256 of the existing CA certificate DER |
| `spki_sha256` | Lowercase SHA-256 of the existing node SubjectPublicKeyInfo DER |

OpenBao IDs use canonical lowercase UUID-shaped syntax; they need not contain
RFC UUID version/variant bits. Credentials and this identity file are private
inputs and must never enter a host public receipt or process arguments. The
production helper requires the identity mount to be read-only and rejects
symlinks, hardlinks, special files, unsafe owners/modes, oversized input, and
changes to the input while it is being used.

Recovery also requires matching, complete `enrollment-pending.json` and
`enrollment-result.json`, both root-owned `0600` files on the read-only identity
mount. It binds their installation, attempt, cluster, CA, SPKI, issuer, and exact
policy fingerprints, requires the explicit successful verification flags, and
rechecks all three files before publication. A private identity left by a partial
enrollment is insufficient.

## Recovery operation

The exact command is:

```text
/usr/local/bin/selfhost-tls-recover --installation-id <UUID> --attempt-id <UUID>
```

There are no URL, path, signing-role, TTL, SAN, init, unseal, or signal flags.
The helper first verifies that the existing leaf and retained node key match
the pinned CA, SPKI, and exact names. An expired leaf is checked at its former
valid instant; the CA must still be valid with more than 31 days remaining.
CA expiry requires a separate supported trust-anchor operation.

It then verifies the initialized, unsealed cluster through the Unix API, logs
in with the scoped AppRole, checks the short-lived token's policy and creation
path, verifies the pinned issuer certificate, and signs a CSR made by the
retained node key. The new leaf must preserve the CA, SPKI and names, carry
server-only usage, and have a bounded current lifetime. A returned private key
is refused. The helper never opens `ca.key`, `root.token`, or `unseal.key`.

The helper retains a nonblocking kernel lock on `.recovery.lock` throughout its
execution. A disconnected or cancelled Docker client is insufficient evidence
that its in-container helper stopped; another helper refuses promptly while
that process still holds the lock. The host installation lock remains necessary
to serialize the wider operation, including reload and verified HTTPS.

The fixed atomic `.recovery-transaction.json` journal contains only public
identity, certificate fingerprints, phase, and the candidate certificate. Before
any signing operation, an `issuing` phase binds the installation, attempt,
cluster, issuer, CA, node SPKI, and previous leaf. After validation and confirmed
token revocation, the helper durably saves the exact public candidate. It then
writes `.recovery-<attempt UUID>.pem` with that certificate followed by the
**unchanged existing private-key PEM bytes**, verifies and fsyncs the stage,
renames it to `server.pem`, and fsyncs the directory. A `published` journal and
compact `.recovery-result-<attempt UUID>.json` retain the public result.

| Interrupted point | Same-attempt continuation |
| --- | --- |
| Before a durable candidate, including a lost local signing or token-retirement response | Fresh scoped login may repeat this bounded local signing operation with the same node key, CA, names and role. An unknown earlier token expires within its five-minute bound. |
| After the candidate is durable, including an empty or prefix-written private stage | Publish the saved certificate without further API calls or issuance. A stage containing unrelated bytes is refused. |
| After the certificate rename but before result output | Reobserve the saved certificate, finish durable result publication, and return the same receipt. |
| After a completed result | Reobserve the active certificate and return the retained receipt without changing the certificate inode or contacting the API. |

A different attempt cannot bypass an unexpired unfinished journal. After completion, the
next owned renewal can advance the current journal; older completed receipts
remain bounded public files. A historical attempt whose certificate is no longer
active cannot issue again or replace a newer leaf. Journal, lock, result and
public temporary files are container-root-owned `0600` files inside the private
TLS directory. The final node PEM remains OpenBao-owned `0600`. Every input and
temporary is checked for expected owner, mode, regular type, single link and
bounded length; malformed state, unsafe links and unrelated file replacement
are refused. Publication also rechecks the private enrollment and CA bindings.

These retries apply only to the narrowly scoped local OpenBao leaf operation.
They authorize no public ACME account, order, enrollment, initialization, seal
change or trust-anchor operation. A saved candidate that expires during a long
outage is never newly published. The host records a new attempt linked to the
exact old transaction, its digest, expiry and observed active leaf. The helper
then durably writes `.recovery-superseded-<old UUID>.json` before advancing its
current journal or signing again. This public record retains the old candidate
and replacement UUID. An interrupted replacement must resume that UUID.
An old private stage is removed only after the link is durable and its bytes
match the old candidate plus the retained key, or a prefix of those bytes.
Unrelated stages are refused. An already published expired candidate keeps a
historical completed receipt. Superseded attempt IDs cannot sign, publish, or
roll back a later leaf. This continuation is automatic under durable running
intent and requires no customer approval.

Success emits one public JSON object with schema
`elevenid.openbao-tcp-recovery-result/v1`: installation/attempt/cluster/issuer
IDs; previous and replacement certificate DER fingerprints; CA and SPKI
fingerprints; RFC3339 `not_after`; and these explicit observations:

```json
{
  "node_key_preserved": true,
  "certificate_published": true,
  "reload_performed": false,
  "network_tls_verified": false
}
```

The host owner must signal only the already verified container, then perform a
new verified HTTPS handshake and confirm the exact new certificate fingerprint
and cluster. OpenBao 2.5.5 reloads the originally configured certificate/key paths
on SIGHUP; file replacement alone is not proof of reload. See the
[2.5 TCP listener documentation](https://openbao.org/docs/2.5.x/configuration/listener/tcp/).
Container PID1 signal forwarding remains an image-level acceptance check.

## Read-only inspection and host transaction

The additional fixed command is:

```text
/usr/local/bin/selfhost-tls-inspect --installation-id <UUID>
```

It makes no API request and creates no file. If the recovery lock exists, it
takes a nonblocking shared lock and refuses a surviving writer. It validates
the private enrolled identity, public enrollment receipts, retained CA, leaf
and matching node key, then emits public data only. The schema is
`elevenid.openbao-tcp-inspection/v1`: installation/cluster/issuer IDs; CA, SPKI
and leaf fingerprints; public leaf PEM; RFC3339 validity bounds; key-match and
issuer-renewal-window flags. Optional transaction, completed receipt and
incoming/outgoing supersession observations include exact retained-file
SHA-256 digests. It can diagnose an expired CA without treating it as usable
for renewal. It never emits an AppRole identifier, SecretID, token or private key.

The host starts only the existing OpenBao and readiness watcher dependencies
before recovery, while preserving the complete native Compose resource
receipts. `reconcile_locked` is called only under durable running intent and
the held installation lock. `inspect_locked` provides the read-only path when
the owned OpenBao container is already running; it never starts a stopped
container. The renewal horizon is seven days for a 720-hour listener leaf.

The only added Docker operations are fixed helper invocations with
`--user 0:0 --workdir /`, an absolute helper path, canonical installation and
attempt IDs, and the exact retained 64-hex container ID; and
`docker kill --signal=HUP <that same ID>`. The generic Docker command allowlist
does not admit `exec` or `kill`. Engine and endpoint identity are checked before
and after each operation. Full native Compose identities, successful setup
completion, images, configurations and mounts are reobserved around actions.

Append-only `openbao-tls-recovery-<UUID>-*.json` host records distinguish intent,
file publication, reload intent, reload acknowledgement and verified completion.
Each record binds its predecessors. An ordinary transient failure keeps the
same attempt UUID; each invocation has bounded helper and network retries.
Expired-candidate supersession records a new linked intent before local signing.
There is no lifetime attempt-count limit on legitimate subsequent renewals.
Older completed local receipts remain compact public files without node PEM or
private keys.

Completion requires a fresh ordinary TLS handshake to the retained loopback
OpenBao port, using only the enrolled CA, then exact leaf/SPKI fingerprint and
initialized/unsealed cluster checks on `/v1/sys/health`. That request sends no
token. There is no proxy, redirect, certificate-verification bypass or historic
verification time on the network path. Every report keeps
`installation_ready: false`; application readiness remains a later gate.

## Sealed startup and health checks

Fresh installer deployments now use the
[static auto-unseal path](installer-openbao-static-seal.md). OpenBao alone reads
the separately protected static key; the historical `openbao-unseal` service
key runs `selfhost-openbao-ready --watch` with only a read-only socket mount.
`--check-listener` distinguishes listener availability from `--check-ready`
initialized/unsealed readiness. These operations never submit an unseal request
or read state, root, recovery-share or seal-key files.

The legacy `selfhost-unseal` remains available to other deployment consumers.
It selects the fixed Unix channel only when
`MARTY_OPENBAO_LOCAL_CONTROL=1`. Other values and conflicting installer paths or
network origins are rejected. A missing or unsafe socket fails closed; there is
no unverified TCP fallback. With the variable unset, the existing verified HTTPS
behavior remains unchanged.

Its Unix mode retains the existing Shamir behavior: it waits for explicit first
initialization, refuses an uninitialized node with existing unseal material,
and uses the existing unseal key only when the initialized node is sealed.
It never reads the bootstrap root token or initializes a node.

Its `--check-listener` and `--check-unsealed` are separate read-only modes. Both
perform only `GET sys/seal-status`. The first accepts an available listener
while sealed or uninitialized; the second succeeds only when initialized and
unsealed. Their JSON records `listener_available`, `initialized`, `sealed`,
`unsealed_ready`, and always `installation_ready: false`. Compose must not gate
this recovery/unseal path on the expired TCP certificate's health check.

## Verification and remaining acceptance

The focused Go tests exercise real Unix sockets, filesystem and peer checks,
credential/identity refusal, old expired combined PEM input, CSR key continuity,
strict certificate admission, input replacement, uncertain local signing and
token-retirement responses, eleven persistence interruption boundaries,
partial-stage resumption, concurrent-helper refusal, retained attempt history,
read-only inspection, expired-candidate replacement at five persistence
boundaries before and after certificate publication, supersession binding,
fresh mount handoff, authority/enrollment adoption refusal, completion-chain
binding, and health-state separation. The opt-in
`TestOfficialOpenBao255RecoveryCoreAfterNaturalTCPExpiry` invokes the actual Go
enrollment and recovery cores against the official OpenBao 2.5.5 binary. It
imports the retained file CA, verifies refusal to replay completed enrollment,
retires and verifies rejection of the bootstrap root, verifies scoped
denials, lets a 15-second leaf expire naturally, interrupts after the candidate
is durable, resumes publication and reobserves the completed result without
another API call, and verifies normal TCP recovery only after signaling the
same owned process.

```sh
cd openbao/didcomm-authcrypt
MARTY_OPENBAO_UNIX_PROOF_BINARY=/absolute/path/to/verified/bao \
  go test -count=1 -run TestOfficialOpenBao255RecoveryCoreAfterNaturalTCPExpiry -v ./internal/openbaocontrol
```

That test injects temporary paths, the current test UID, and a writable private
identity fixture into the internal core. The production entry point keeps the
fixed image paths, image UID lookup, root invocation, and read-only mount check.
Real image mount ownership, rootless mappings, exact Docker execution and signal
ownership, complete host reboot/crash recovery, and any AWS KMS auto-unseal configuration
remain separate acceptance gates. This private node-CA test makes no public-CA
or browser-trust claim.

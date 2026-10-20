# Self-host KMS credential renewal candidate

This source-level procedure is for an isolated KMS-only installation. A
disposable HTTPS/Raft probe has crossed the one-hour evidence and audit token
expiry boundary and recovered both with their separate scoped identities. The
full installed two-generation business journey has not crossed that boundary;
this is not yet a supported continuous-runtime or public cutover procedure.
Keep the old generation until
the renewed installation passes its business and custody journeys. Neither
generation may contain local private keys.

After the initial KMS-only installation, use
`scripts/provision_selfhost_renewal_identity.py --mode bootstrap` once with
the existing private generation, HTTPS OpenBao CA, and the bootstrap root
token. Its separate empty 0700 output directory holds a RoleID, SecretID,
and the exact 21-policy receipt. The script requires the current keys,
certificates, and scoped tokens to pass live custody checks before creating
the AppRole and token role. Protect and back up these operator-only identity
files with the coordinated Raft/applicant/database state. Root-token
retirement and recovery still need their own rehearsed procedure.

Before each renewal, use `--mode login` with that identity and a new empty
0700 output directory. It writes an eight-hour-or-shorter scoped operator
token after checking the token role and forbidden OpenBao operations. Give
that token file to the Rust and Python stages via `BAO_RENEWAL_TOKEN_FILE`;
give it to activation via `--bao-token-file`. The stages reject a root token
presented under the renewal variable. The AppRole SecretID itself stays out
of the application Compose secret generation.

Rotate the AppRole SecretID with `--mode rotate --identity <current-private-identity>
--output <new-empty-0700-directory>` and the same HTTPS OpenBao address/CA.
The scoped operator token mints a replacement SecretID, validates its login
and forbidden-operation denials, writes the replacement identity as 0600
files, then revokes the old SecretID. Keep the old identity directory until
revocation has been confirmed; after a failure following the new files being
written, finish with `--mode retire --identity <replacement-identity>
--retired-identity <old-identity>` (no `--output`). A failed rotation before
the replacement is written destroys the newly minted SecretID. After success,
the old identity must fail login and a fresh `--mode login` with the new one
must pass. This rotates the AppRole credential only, not a Transit key or CA;
coordinated Raft restore and lost-identity recovery still need rehearsal.

Do not revoke the bootstrap root token while any installed or rollback
generation still uses tokens minted beneath it. In a cold Raft-copy rehearsal,
root revocation invalidated all 21 tokens in the initial generation; a fresh
AppRole login and scoped Keycloak renewal still worked. The renewal producers
and activation preflight require every **new** leaf token to be an orphan from
the named `selfhost-renew-leaf` role. Retire root only after the active and
rollback generations have been replaced by independently qualified orphan
tokens, the public journey and custody scans pass, and a separate rootless
restore/recovery rehearsal passes. The current command does not retire root.
The ordinary restart path uses `openbao-unseal`, which reads the separately
protected unseal key and never reads the root token. `openbao-bootstrap` is
confined to the explicit `kms-init` profile for one-time provisioning and must
not run during ordinary restart or renewal. A disposable root-revoked cold
copy passed, but a full installed rootless restart and coordinated rollback
remain required before live root retirement. Preserve the original unseal
material separately from Raft snapshots for recovery.

Stage the workload TLS set with the Rust `selfhost-renew` profile against the
existing Raft OpenBao issuer and version-one Transit signers. Stage the
Keycloak set with `scripts/provision_selfhost_keycloak_kms.py` using
`SELFHOST_KEYCLOAK_MODE=renew`. Assemble a new
complete generation with `scripts/stage_selfhost_renewed_secrets.py`. Each
candidate directory must be empty and private. The assembly verifies the
same file inventory and modes, unchanged static inputs and public CA, and
changed certificates and scoped tokens. It refuses CA rollover; that needs
a separate trust-overlap procedure.

Replacement-issuer preparation is a separate rootless source stage, not an
activation shortcut. After provisioning the CA-rotation AppRole while the
bootstrap root still exists, use
`provision_selfhost_ca_rotation_identity.py --mode stage-issuer` with its
private identity, an empty 0700 output directory, `--kind workload` or
`--kind keycloak`, and an unused version from 2 through 8. It creates only
that exact PKI mount and a one-year internal CA, then writes its **public**
certificate. `--mode login` writes a short-lived token for
`BAO_CA_ROTATION_TOKEN_FILE`. The Rust workload producer can select the
corresponding `MARTY_SELFHOST_WORKLOAD_PKI_MOUNT=workload-pki-vN`; the Keycloak
producer can select `SELFHOST_KEYCLOAK_PKI_MOUNT=keycloak-pki-vN`. Both retain
the existing non-exportable Transit key versions. These source stages do not
make the new issuers trusted by an installed app: the ordinary generation
assembler and activation deliberately reject that change until the public
dual-trust, old/new leaf, session and retirement gates are implemented and
qualified. Do not substitute the new leaf files into a live generation by
hand.

Use a self-host Compose release whose ordinary `db-migrate` renders with
`MARTY_KMS_BOOTSTRAP_ENABLED=false`, without a bootstrap-token mount, and
whose separate `kms-initialize` role is confined to the `kms-init` profile.
Activation checks those properties in both rendered models. Make a private
copy of the installed env file, changing only
`SELFHOST_SECRET_DIR` to the assembled generation. Keep the current env file,
Compose file, and old secret root unchanged. On a Linux host with Docker and
access to the same isolated project, invoke
`scripts/activate_selfhost_renewed_secrets.py` with:

```text
--project-name <owned marty-selfhost-* project>
--compose-file <absolute rendered Compose file>
--compose-override <optional absolute operator Compose override used by the live project>
--current-env <absolute private original env file>
--renewed-env <absolute private candidate env file>
--current-secrets <absolute original secret directory>
--renewed-secrets <absolute assembled secret directory>
--bao-addr <HTTPS OpenBao address>
--bao-ca <absolute OpenBao CA file>
--bao-token-file <absolute private renewal-operator token file>
--log-dir <absolute empty private 0700 directory>
--report <absolute new file inside log-dir>
```

The command validates the generation, both live token sets, exact scoped
policies and signer/JWE access, current certificate validity, each leaf's
public key against its version-one non-exportable Transit signer, both live
issuers, and the Compose model before changing the
owned project. It recreates only that project, checks all expected services
and renewed secret mounts, and writes a private result report. On failure
after recreation starts, it attempts to recreate the prior **KMS-only**
generation and reports `rolled_back`; a failed rollback is an incident that
requires operator recovery. The command is not a zero-downtime switch and
does not itself run the issue/present/verify/revoke, session, database custody,
or expiry-crossing checks. Run those independently before accepting the
generation. Do not use an old local-key installation as the rollback target.
Pass the same `--compose-override` to the root-retirement audit when the
installed project uses one; both checks render it with each secret generation.

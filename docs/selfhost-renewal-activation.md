# Self-host KMS credential renewal candidate

This source-level procedure is for an isolated KMS-only installation. A
disposable HTTPS/Raft probe has crossed the one-hour evidence and audit token
expiry boundary and recovered both with their separate scoped identities. The
full installed two-generation business journey has not crossed that boundary;
this is not yet a supported continuous-runtime or public cutover procedure.
Keep the old generation until
the renewed installation passes its business and custody journeys. Neither
generation may contain local private keys.

Keycloak remote provisioning and renewed-generation assembly run in the matching
Rust `marty-deploy` operator. Python entrypoints retain their arguments and the
separate privileged root-to-operator file handoff. Install and source the signed
operator receipt first; sudo staging preserves only the four public
`MARTY_DEPLOY_*` identity variables shown in the disposable qualification runbook.
The bridge validates binary digest/source/tag before provisioning and does not
use a source-build fallback under sudo. Mutating provisioning has no overall
kill timeout; individual HTTPS operations remain bounded. Exit 3 requires
operator reconciliation of potentially live authority before retrying.

Custody evidence uses the same native public-key and non-exportability checks.
Read-only journey/fixture consumers may inspect the current positive signer
version; initial provisioning, refresh and evidence bootstrap still require
version one. Native conversion accepts only canonical 32-byte Ed25519 public
values. Root/operator file ownership, pending-token preservation and revocation
recovery remain with their existing owners.

Managed profile references now use the same small Rust naming contract as
signing-keys bootstrap. It preserves the raw organization namespace and the
closed issuer/verifier profile choices; registered holder-key naming is separate.
Audit/custody leaf checks share native scope, lifetime and capability checks with
AppRole minting while retaining each caller's policy and canary requirements.

Owner-aware handoff stays with the privileged Python owner and shares its
exclusive writes, install UID/GID and role-specific modes. A replacement is
written and synced as `.new` before old-token revocation. Uncertain revocation
or failed replacement leaves the old and pending files for reconciliation.
Successful replacement is followed by a directory sync; if that final sync
fails, exit 3 reports recovery and the new credential is at the primary path.
No failure cleanup revokes that installed replacement merely because its final
sync could not be confirmed.

Generation assembly reuses the Rust workload identity inventory. It preserves
exact static bytes, active file modes, exclusive creation, distinct scoped tokens
and the separate overlap/retirement ceremonies. Failure removes only files
created by that attempt; an unconfirmed rollback is reported for recovery.
Assembly does not activate a generation or retire the independent release checks.

Replacement-issuer staging and the live authority/token/certificate preflight
also run in Rust. The Python activation, renewal-bootstrap and root-retirement
entrypoints retain their arguments and consume the same closed native checks.
The deployed Python inventory is checked against the compiled operator's actual
preflight traversal in HTTPS acceptance tests; adding a workload or token must
extend both inventories before qualification passes.

`stage-issuer` retains its create-or-resume behavior for workload/Keycloak PKI
versions 2 through 8. It authenticates the scoped CA-rotation identity, verifies
the exact mount lifetime, internal P-256 root profile, mounted-certificate bytes
and 300-day expiry, and writes one exclusively created 0600 public certificate.
Only reviewed 400/404 CA-read responses permit creating a missing issuer;
malformed existing issuer metadata is refused. A post-login failure or uncertain
delivery returns exit 3. Inspect the named mount and output before retrying;
after a lost generation response a validated existing issuer is resumed rather
than regenerated. Remote state is not claimed to be rolled back.

Activation still requires actual version-one signing or JWE-read proofs under
each scoped leaf token, exact policy text and the requested orphan lineage.
It binds both generations' certificates to non-exportable remote keys and the
correct issuer for ordinary renewal, overlap or retirement. Retirement can omit
old-issuer validity checks only while both generations use the replacement
issuer. Compose recreation, deployment ownership checks, rollback and reports
remain in the existing Python owner; no preflight command performs cutover.

After the initial KMS-only installation, use
`scripts/provision_selfhost_renewal_identity.py --mode bootstrap` once with
the existing private generation, HTTPS OpenBao CA, and the bootstrap root
token. Its separate empty 0700 output directory holds a RoleID, SecretID,
and the exact 21-policy receipt. The script requires the current keys,
certificates, and scoped tokens to pass live custody checks before creating
the AppRole and token role. Rust returns the sorted, unique 21-policy inventory
from those same verified token lookups for both renewal and CA bootstrap; it
rejects non-regular entries or missing required tokens before contacting OpenBao.
Other regular generation files remain allowed, and initial bootstrap tokens may
still be children of the installation root. The combined read-only inventory
command has a 600-second deadline, with each HTTPS request bounded to 10 seconds.
Protect and back up these operator-only identity
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
the replacement is written attempts to destroy the newly minted SecretID.
These transactions run in the matching Rust `marty-deploy` operator; the Python
entrypoint and its arguments are unchanged. Exit status 3 means creation,
cleanup, or retirement could not be confirmed: preserve both identity
directories and investigate before retrying. If the SecretID creation response
was lost, the old identity is retained but additional remote authority may
exist without a locally staged replacement. After success,
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
changed certificates and scoped tokens. Its default mode refuses CA rollover.

The signed Rust operator owns Keycloak's five closed policy scopes, token
creation, exact existing-policy selection during renewal, scoped signing/JWE
probes, and actual foreign-key 403 checks. Native Keycloak and AppRole operations
share bounded HTTPS request mechanics; Keycloak retains its own policy profile.
The Python command still owns PKI/Transit CSR orchestration and the seven-file
staging contract: two certificates and five distinct tokens, no overwrite,
initial 0444 files under an owner-private root, and renewal 0600 files. Renewal
does not create or widen policies. Its leaves retain the exact single policy,
7–8 hour remaining lifetime, orphan status, and renewal-role creation path.

Keycloak certificate expiry and the replacement CA's 300-day check use native
expiry-only semantics matching `openssl x509 -checkend`; they do not reject a
future notBefore value. Activation's separate lifetime and chain checks still
enforce current validity. Strict replacement-root validation verifies the exact
kind/version identity, single canonical PEM, critical CA constraints, P-256
public key and self-signature without checking time. Issuer validity is checked
separately. OpenSSL remains the differential test and Windows release oracle.

Failures before token minting remain validation failures. A mint response lost
in transit, failed post-mint qualification, failed token delivery, abnormal
native process exit, or subsequent staging failure returns fixed exit 3:
`Keycloak provisioning requires operator recovery`. No token values appear in
the diagnostic. Existing renewal authority cannot revoke these leaves, so this
refactor does not grant it additional revocation permissions or claim that the
remote changes were rolled back. An operator must reconcile issued tokens and
the partial disposable setup before retrying; preserve the active generation.
Initial provisioning creates its non-exportable foreign test key before minting
so every returned token has already proved denial; that test key may remain if
later provisioning fails. Local file-write cleanup still removes only files
created by that attempt. This stage does not activate a generation.

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
make the new issuers trusted by an installed app. To stage the explicit
trust-overlap generation, supply both replacement producer directories to
`stage_selfhost_renewed_secrets.py` and add `--ca-overlap`. The assembler
requires a single old public CA and a distinct single new public CA, then
creates the exact old-plus-new PEM bundle in `workload_identity_ca_cert`.
Every other static input and mode stays fixed. Do not substitute leaf files
into a live generation by hand.

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
--ca-overlap (flag; only for a replacement issuer generation)
--ca-retire (flag; only for the later public trust-retirement generation)
--workload-pki-mount <workload-pki-v2 through workload-pki-v8; CA change only>
--keycloak-pki-mount <keycloak-pki-v2 through keycloak-pki-v8; CA change only>
--ca-rotation-token-file <private scoped CA-rotation token; CA change only>
--log-dir <absolute empty private 0700 directory>
--report <absolute new file inside log-dir>
```

The command validates the generation, both live token sets, exact scoped
policies and signer/JWE access, current certificate validity, each leaf's
public key against its version-one non-exportable Transit signer, both live
issuers, and the Compose model before changing the
owned project. Certificate lifetime and chain validation run in the signed Rust
operator; activation no longer shells out to OpenSSL. Chain verification retains
purpose-any behavior (both server-only and client-only workload EKUs are valid),
without adding hostname, CRL, or OCSP checks to this preflight. Runtime TLS still
enforces its own peer identity and usage requirements. The verifier checks chain
signatures and validity, CA constraints, signing key usage, path length, issuer
identifiers, critical extensions, and name constraints. Public issuer bundles can
supply intermediate certificates and multiple self-issued roots; a non-self-issued
issuer alone does not become a trust anchor. Additional PEMs in a leaf file do not
supply intermediates, matching the previous command. Inputs are bounded to 64 KiB
per public certificate/bundle and at most 16 issuer certificates. The supported
producers remain OpenBao P-256 roots issuing P-256 workload and RSA-2048 Keycloak
end-entity certificates; this operator is not a general document-CA verifier.
CA-marked targets and legacy issuer certificates without BasicConstraints are
refused even though generic OpenSSL compatibility mode can accept them. The
supported OpenBao producers emit end-entity targets and explicit CA constraints;
differential tests record these deliberate profile boundaries.
Transit custody, version-one key matching, exact mounted trust overlap, and
retirement checks remain separate and mandatory. Generated differential tests use
OpenSSL as the previous verifier's oracle on both native release architectures.
Both generations must contain every file-backed Compose secret,
including secrets from optional profiles, before recreation starts. It recreates
only that project, checks all expected services
and renewed secret mounts, and writes a private result report. On failure
after recreation starts, it attempts to recreate the prior **KMS-only**
generation and reports `rolled_back`; a failed rollback is an incident that
requires operator recovery. The command is not a zero-downtime switch and
does not itself run the issue/present/verify/revoke, session, database custody,
or expiry-crossing checks. Run those independently before accepting the
generation. Do not use an old local-key installation as the rollback target.
Pass the same `--compose-override` to the root-retirement audit when the
installed project uses one; both checks render it with each secret generation.
For an overlap generation, pass `--ca-overlap` and both exact replacement mount
names to the root-retirement audit as well. The audit logs into the already
provisioned CA-rotation AppRole and verifies the old and new live issuers,
each generation's leaf chain, and unchanged version-one Transit signers.
The overlap keeps the old public CA trusted for a bounded rollback. It is not
trust retirement. Once the overlap generation is active, all owned services
mount only new-issuer leaves, and the old-only rollback obligation has ended,
create an empty private output directory and run the same assembler with
`--current <overlap generation> --output <new directory> --ca-retire` (without
`--tls` or `--keycloak`). It copies the generation unchanged except for removing
the old **public** workload CA from its exact two-issuer bundle. Activate that
generation using `--ca-retire`, both replacement mount names, and the scoped
CA-rotation token; the current overlap generation remains the KMS-only rollback
target. The root-retirement audit accepts the same `--ca-retire` mode. The
command checks that both generations' leaves chain to the replacement issuers
and the remote signer versions stay fixed. Complete the separate browser-session
and expiry-crossing checks before accepting trust retirement. Do not wait for
the old leaf certificates to expire before refreshing the active eight-hour
leaves and tokens: a stale active generation will fail this preflight.

## Operator input helper ownership

`selfhost_operator_inputs.py` owns the shared private-file reader, exclusive
credential writer, private-directory check and loopback HTTPS-origin check.
The command modules retain their historical imported names; command-specific
AppRole policies, token checks, policy receipts, staging and rollback remain
with their existing owners. The shared module ships in the self-host bundle
and performs no filesystem or subprocess work at import time. This refactoring
does not change validation rules or broaden snapshot/renewal authority.

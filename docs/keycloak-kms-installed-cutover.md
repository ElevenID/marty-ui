# Installed Keycloak KMS-only cutover

This procedure applies to the non-public `elevenid-beta` and
`marty-selfhost-prod` installations. It is a clean database/realm replacement,
not a migration of Keycloak's locally generated key-provider material. Do not
run it until the exact release images, OpenBao keys, scoped tokens, public
certificates, browser/CIBA probes, and restore rehearsal have qualified.

## Current boundary

Both installed stacks still run stock Keycloak 25.0. Each `keycloak` database
has four `privateKey` and four generated `secret` KeyProvider configuration
rows. The generic `public.component_config` table is required by Keycloak and
must remain. On 2026-10-16, read-only counts found 15 `11id` users and one
master admin in beta, and four `11id` users and one master admin in self-host.
Those local accounts are held in the rollback snapshot; a clean realm import
will not silently claim to preserve their credentials or sessions.

## Required implementation

1. Resolve every image from the exact published release plan by digest. Prove
   the Keycloak image contains the matched remote-key provider and that the
   configured OpenBao RS256, JWE, HMAC, and AES keys are non-exportable and at
   the pinned versions. Confirm public certificates and scoped token files;
   reject private-key file inputs.
2. Acquire the stack's deployment lock, reject another maintenance/release
   mutation, record the exact running image IDs and container settings, and
   stop all application writers and Keycloak. Confirm none remain running.
3. Take a quiesced, checksum-manifested snapshot of the Marty and Keycloak
   PostgreSQL databases, PostgreSQL globals, OpenBao Raft volume, Redis state,
   and applicant state. Keep it outside the database volume. Rehearse restore
   against disposable resources before changing the installed database.
4. Preserve the old Keycloak database by renaming it under a unique cutover
   name while all Keycloak connections are stopped. Create a fresh `keycloak`
   database owned by the Keycloak role. Import the checked-in `11id` realm
   using the matched remote-key image, then run the supported configurator.
   Never import old `component_config` rows or a realm export containing local
   KeyProvider material. This is a clean install; add no row/table migration.
5. Before reopening application traffic, prove both realms have exactly the
   expected remote KeyProvider graph and zero `privateKey`/generated `secret`
   rows with `scripts/sql/keycloak-kms-only-verify.sql`. Run browser login,
   cookie/session refresh, CIBA, token verification/JWKS, and KMS-loss denial
   against the exact installed image and both realms. Verify KMS-only custody
   again after those operations.
6. Recreate the applications from the same release manifest and run the local
   and tunneled installed journeys. Only after acceptance, remove the renamed
   old Keycloak database. Retain the external coordinated backup for the
   defined rollback window. A private-key-bearing database, even one no longer
   used by Keycloak, is not the final KMS-only state.

## Rollback boundary

If any step after the database rename fails, keep traffic closed and writers
stopped. Stop the new Keycloak instance, rename the fresh database aside, and
restore the original database name and exact previous Keycloak/application
containers. If the release has also mutated OpenBao or Marty state, restore
the coordinated PostgreSQL/Raft/Redis/applicant snapshot as one unit before
reopening traffic. Verify the restored services and user counts. This is an
emergency recovery path to the pre-cutover installation, not a permitted
long-term local-key fallback or proof of KMS-only acceptance.

The existing `restore-local-beta-release.ps1` is not yet this rollback path:
its Rust-only image pairing check rejects the currently running beta
Issuance/Gateway images. The cutover implementation must provide and locally
rehearse its own exact-prior-image recovery before installed mutation.

On 2026-10-16, a disposable network-isolated PostgreSQL 15 container proved
the narrow database operation with synthetic `privateKey` data: rename the
old `keycloak` database, create a fresh same-named database, find no old
`component_config` table in the fresh database, rename the fresh database
aside, restore the old name, and recover the synthetic row. The owned
container was removed. This does not yet prove Keycloak startup, coordinated
backup/restore, writer quiescence, or an installed cutover.

On 2026-10-16, a read-only `pg_dump -Fc` of each running installed Keycloak
database was streamed directly into a separately owned PostgreSQL 15 container
with `--network none`; `pg_restore --no-owner --no-acl --exit-on-error`
succeeded in both. Source and restored beta both had 16 users, four
KeyProvider `privateKey` rows and four generated `secret` rows. Source and
restored self-host both had five users and the same four-plus-four key rows.
The stream was not retained as an additional backup and both disposable
containers were removed. This proves the present Keycloak database can be
restored in isolation without mutating the installed database. It does not
prove a quiesced coordinated PostgreSQL/OpenBao/Redis/applicant restore,
Keycloak login, or the clean KMS-only cutover.

The custody SQL now checks all Keycloak component configurations for
private-key field names and PEM markers, and checks the public schema for
private-key-named tables or columns. It still checks generated KeyProvider
secrets separately. A disposable PostgreSQL 15 graph with both required
remote-provider realms passed; an unrelated component's synthetic
`private_jwk` field and a synthetic `private_key_cache` table each caused the
gate to fail. The same revised SQL rejected both installed databases with
four private-key and four generated-secret rows each. No real private key was
created for these tests, and the disposable container was removed.

The revised SQL also passed `probe_keycloak_remote_rs256.py --require-browser`
against disposable local Keycloak/OpenBao images. The probe exercised both
realms' remote RS256 signing, rotated browser cookies, CIBA, token refresh and
JWKS, KMS-loss denial, then ran the SQL against the resulting PostgreSQL
database. Its containers and network were removed. The local images are not
the signed `v1.1.248` release artifacts; that exact-artifact and installed
cutover proof remains separate.

The beta release preflight now invokes this same custody SQL before its backup
and again after Keycloak configuration. This removes the older, narrower
KeyProvider-only count, so an unrelated component's private-key field or a
retired private-key table cannot pass the release preflight. Installed beta
still fails the gate until the clean cutover is executed.

`scripts/beta-keycloak-clean-database.ps1` now provides the database-only
swap/reversal primitive for that cutover. It requires the checksum-verified
quiesced beta backup, the expected running beta PostgreSQL container, unused
validated database names, and zero Keycloak database connections. It renames
the old database and creates a fresh one owned by `keycloak`; reversal retains
the failed fresh database separately and restores the old name. A disposable,
network-isolated PostgreSQL 15 rehearsal proved the old synthetic marker stayed
in the retained database, the fresh database was empty, and reversal recovered
the marker without copying local KeyProvider rows. A tampered backup was
rejected. This primitive is not yet wired into the locked release flow, does
not stop writers or create its own backup, and does not qualify installed
cutover/rollback. The disposable container was removed. The synthetic backup
files remain under the OS temporary directory because automatic approval
review rejected their deletion; they contain no real keys or database data.

The beta Compose Keycloak service already starts with `--import-realm` and a
read-only checked-in realm import mount, so a fresh database can bootstrap the
`11id` realm before the existing configurator runs. The ordinary beta release
also captures a quiesced coordinated backup after stopping writers, but its
preflight migration rehearsal restores only the Marty database; it does not
rehearse restoring Keycloak, OpenBao Raft, Redis, and applicant state together.
The swap primitive must be wired after that quiesced backup, and the emergency
restore path must be extended and rehearsed for the currently installed legacy
Issuance/Gateway image pairing before any live cutover.

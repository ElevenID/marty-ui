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

# Beta Rust startup after the guarded schema migration

The existing local beta deploy and restore scripts deliberately stop at the
passport fence. The aggregate release operator checks the SQL bytes in the
signed migration image against protected source, then applies those SQL files
as the privileged database operator while the app login is closed and the
host mutation marker is active. The issuance SQL first bridges the published
`merge_issuance_heads` beta head through the four later Alembic revisions,
including the event owner backfill. In the same transaction, the operator
creates a fence-owned Rust migration ledger with `SELECT` only for `marty`
and commits the source- and fence-bound native migration receipt. The Rust
`verify-owned-schema` command then checks the exact ledger, final Alembic
head, baseline catalog, OID4VCI objects, and passport objects in a read-only
transaction. After that, the operator appends
`docker-compose.profile.passport-premigrated-beta.yml` **last** in its approved
Compose file list. This selects read-only schema validation in both Rust
services. Ordinary pre-fence beta startup retains the default migration mode.

The postmigration Compose invocation has this shape, with the approved files
in their manifest order and the selected services from the single aggregate
release plan:

```powershell
$composeArgs = @('-p', 'elevenid-beta')
foreach ($path in $approvedEnvFiles) { $composeArgs += @('--env-file', $path) }
foreach ($path in $approvedComposeFiles) { $composeArgs += @('-f', $path) }
$composeArgs += @('-f', (Join-Path $protectedRepo 'docker-compose.profile.passport-premigrated-beta.yml'))
$effective = & docker compose @composeArgs config --format json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'The approved beta Compose plan is invalid' }
if ($effective.services.flow.environment.MARTY_SCHEMA_STARTUP_MODE -cne 'validate' -or
    $effective.services.'issuance-native'.environment.MARTY_SCHEMA_STARTUP_MODE -cne 'validate') {
    throw 'The aggregate beta release would rerun guarded schema DDL'
}
& docker compose @composeArgs up -d @approvedServices
if ($LASTEXITCODE -ne 0) { throw 'The aggregate beta deployment failed' }
```

The protected operator still needs to bind the exact source, images, database
identity, schema verification receipt, and service list before this call. It
must not use the legacy deploy path or run the aggregate Compose command until
those gates pass. Production is outside this beta command.

## Guarded migration ownership gate

The fence transfers both service schemas and the three passport tables to its
NOLOGIN guard owner, while existing non-passport tables retain their `marty`
owner. A rehearsal against a schema-only copy of beta PostgreSQL 15.17 showed
that `marty` cannot run even the issuance OID4VCI migration after the fence:
`CREATE INDEX` requires schema `CREATE`, which the fence revoked. The guard
owner can run the passport SQL migrations only with a temporary database
`CREATE` grant, and cannot run the complete Flow migration because it does not
own the existing non-passport Flow tables. A superuser SQL replay establishes
syntax compatibility but does not establish the intended migration permissions.

The protected migration operator therefore executes the reviewed Rust SQL as
the already-authorized superuser while application login is closed, keeps
the fence ownership and application-role DDL revocation in force, and verifies
the fence again. The newly created
`issuance_service.passport_beta_batch_intents` table also needs
`SELECT, INSERT, UPDATE, DELETE` granted to the beta `marty` application role;
the guard owner otherwise owns it without granting runtime access. The release
gate must check that access using the actual application role before Rust
startup. None of these steps is supplied by the existing Compose overlay.

## Local bridge rehearsal (2026-10-09)

An isolated PostgreSQL database was created from the checked-in Rust issuance
baseline, then the four post-merge schema changes were reversed and its
Alembic head set to `merge_issuance_heads`. The checked-in bridge SQL advanced
that database to `issuance_event_owner`. The live-code-watch Rust binary then
ran `migrate` and `verify-owned-schema` successfully against that isolated
database. Removing the bridge version from its ledger caused
`verify-owned-schema` to fail; the version was restored afterward. This tests
the old-head handoff and ledger rejection without changing the beta database.

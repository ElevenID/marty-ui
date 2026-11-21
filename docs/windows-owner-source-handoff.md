# Versioned Windows owner source handoff

`scripts/package_windows_owner_source.py` creates a reproducible source artifact
for a reviewed Windows owner revision. It is a preparation tool for the
[selected-expired recovery source transition](windows-compose-recovery.md#prepare-an-ordinary-selected-generation-with-expired-certificates).
It creates or verifies one inert archive. It does not install that archive,
execute its code, edit a retained owner, or change a scheduled task.

The separate [Windows source installation and replay tool](windows-owner-source-install.md)
can place the verified archive in a new private versioned directory and replay
the original selection anchor. It preserves the remaining caller-migration and
live admission requirements below.

## Create the exact source artifact

Use the complete 40-character commit from the reviewed change, available in the
trusted tooling repository's object database. The output file must not exist.

```powershell
python scripts/package_windows_owner_source.py create `
  --repository C:/Marty/reviewed-tooling `
  --commit $ReviewedCommit `
  --output C:/Marty/source-handoffs/windows-owner-source.zip
```

The tool reads the catalog and files directly from that commit's Git objects.
Working-tree modifications, untracked files, Git replacement objects, and inherited
Git-directory overrides cannot substitute source bytes. It accepts only ordinary
committed files and refuses symbolic links and submodules in the selected assets.

The archive contains the complete `deploy-config/bundles/selfhost.json` asset set,
including expansions of declared directories. It also carries the catalog itself,
the recovery and task-installation PowerShell wrappers, their direct Python
helpers, and the Windows recovery/renewal documentation. All exported Python
files are parsed to check the catalog's existing static local-import closure
rule against the commit's complete source tree. This check does not import or
execute package code. Installed third-party Python packages and runtime-supplied
custody inputs remain separate prerequisites.

The single archive root contains the full source commit in its name. The canonical
`.marty-windows-owner-source.json` records the source tree, exact catalog digest,
each file's size, executable mode, Git blob identifier and SHA-256, and the local
Python import inventory. ZIP member order, dates, permissions, and storage format
are fixed, so an unchanged commit produces identical bytes.

The JSON result reports the archive and manifest SHA-256, source identity, file
count, payload size, and the qualification boundaries. Retain the result through
the same reviewed channel as the source commit. Existing or partially written
output is never overwritten or automatically removed.

## Verify the transferred artifact

Run the verifier from trusted tooling, supplying the expected digest and full
commit retained separately from the archive:

```powershell
python scripts/package_windows_owner_source.py verify `
  --archive C:/Marty/source-handoffs/windows-owner-source.zip `
  --expected-sha256 $RetainedArchiveSha256 `
  --expected-commit $ReviewedCommit
```

Verification is read-only and performs no extraction. It checks the externally
supplied digest before opening ZIP members, then checks the exact canonical
manifest, member inventory, catalog binding, local import inventory, file bytes,
modes and Git blob identifiers. The manifest filename and its descendants are a
reserved namespace, including case variants. Unsafe Windows paths, case collisions, duplicate
members/JSON keys, links, unexpected members, missing files, changed manifests,
compressed members, and noncanonical ZIP framing refuse. The payload is bounded
to 2,048 files, 4 MiB per file, and 64 MiB overall; the complete archive has a
separate bounded read.

The digest protects a transferred artifact only when its expected value comes
from the trusted creation/review result. An internally consistent manifest or a
Git commit string is not a signed release or authorization to execute source.
Do not derive the expected digest from the received archive and treat that as
independent verification.

## Complete the source transition before live use

All exported result records retain these fields as `false`:

| Field | Work still required |
| --- | --- |
| `release_authenticated` | Authenticate the applicable release and reviewed source through the existing release process. |
| `windows_custody_qualified` | Place the qualified complete source in a new private versioned directory; bind its runner to the exact inventory and verify real NTFS handles, ACLs and namespace behavior. |
| `original_anchor_replayed` | Prove that the new reader resolves the original retained selection anchor and complete predecessor history, with unchanged custody evidence. |
| `active_callers_migrated` | Coordinate every active scheduled caller and supported explicit entrypoint; verify the new bindings and preserve historical inactive readers. |
| `credential_admission` | Perform the existing native authority, candidate credential, publication and renewed-current proofs. |
| `runtime_admission` | Complete the selected owner's activation, health, routing and interruption/recovery qualification. |

Where the selected operation is `passport-role-repair`, its exporter separately
binds retained `custody_sources.exportOwnerSha256` to the admitted module or a
qualified explicit successor. That conditional guard does not apply to ordinary
`selfhost-renewal` exports and is not evidence of a blocker on an ordinary
production installation. In every operation, preserve the original source,
runner, inventories, configuration and evidence, and qualify the selected
reader's actual retained bindings. This tool neither rewrites those inputs nor
bypasses their checks.

The existing managed task installer remains create-only. Exporting its wrapper
does not make it an update command. Likewise, retaining legacy branches of the
recovery wrapper does not supply their deployment-specific configuration or
authorize use against this managed installation. Real Windows tests and isolated
imports qualify the source artifact; they do not prove production replay,
credential recovery, application readiness or a completed website cutover.

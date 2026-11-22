# Install and replay a versioned Windows owner source

`scripts/selfhost_windows_source_install.py` installs an independently verified
[source handoff](windows-owner-source-handoff.md) in a new private directory. It
creates a dedicated runner that can replay the original retained selection
anchor using the new source. Neither operation modifies existing source,
configuration, owner history, scheduled tasks, credentials, or Docker objects.

This is an executable source-placement and compatibility check. A scheduled
renewal caller still requires its separate reviewed migration before the new
selected-expired origin can be emitted on that installation.

## Retain the trusted bootstrap identity

The verifier must be trusted before candidate source is loaded. This tool uses
three fixed bootstrap files from qualified tooling: the installer itself,
`selfhost_windows_inputs.py`, and `package_windows_owner_source.py`. The caller
retains a separate inventory and its digest from the reviewed tooling commit.
The tooling commit may differ from the owner-source commit being installed.

Create the inventory in trusted tooling, directly from the exact Git objects:

```powershell
python scripts/selfhost_windows_source_install.py bootstrap-inventory `
  --repository C:/Marty/reviewed-tooling `
  --commit $ReviewedToolingCommit `
  --output C:/Marty/source-handoffs/reviewed-bootstrap.json
```

The command returns the canonical inventory SHA-256. Retain it independently
with the reviewed tooling revision and the separately reviewed owner-source ZIP
digest. Neither digest may be established merely by hashing an untrusted file
after receiving it. The inventory records the exact size and SHA-256 of each
bootstrap file. Both the tooling and source identities remain visible in the
installation record.

The qualified tooling files must retain their exact Git blob bytes. Windows
line-ending conversion changes those hashes; use a byte-preserving export for
the three bootstrap files instead of revising the reviewed inventory to match
a converted checkout.

## Create a new private installation

The destination parent must already exist on NTFS, be owned by the current
operator, and satisfy the existing private-input ACL policy. The installer does
not create or broaden ACLs. The destination itself must be absent; its name is
exactly `windows-owner-source-<full-source-commit>-<first-16-archive-SHA256>`.
Existing, partial, or linked destinations refuse.

The operator process must also create objects owned by that same current user.
Windows takes [new object ownership](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object)
from the creating token's default owner. An elevated token can default to the
Administrators group, even inside a directory explicitly owned by the user.
Such output does not satisfy this installer's owner policy and refuses. The
installer does not adjust the token, rewrite ownership, or broaden that policy.
The public Windows CI launcher separately scopes the default owner of its
disposable synthetic test process to its actual user, verifies fresh parent and
isolated-child outputs with the unchanged guard, and restores the exact original
default owner before success. That test setup is not a production installer or
caller migration step.

Pass the original retained configuration anchor and its independently observed
digest. Do not substitute the latest generation's configuration or re-adopt a
successor journal. The original anchor preserves access to the existing
predecessor/continuation/product/recovery history.

```powershell
$NewSource = Join-Path $PrivateParent (
  'windows-owner-source-' + $ReviewedSourceCommit + '-' + $ArchiveSha256.Substring(0,16)
)
python scripts/selfhost_windows_source_install.py install `
  --archive C:/Marty/source-handoffs/windows-owner-source.zip `
  --archive-sha256 $ArchiveSha256 `
  --commit $ReviewedSourceCommit `
  --destination $NewSource `
  --anchor $OriginalSelectionAnchor `
  --anchor-sha256 $OriginalAnchorSha256 `
  --project $RetainedComposeProject `
  --tooling-inventory-path C:/Marty/source-handoffs/reviewed-bootstrap.json `
  --tooling-inventory-sha256 $ReviewedBootstrapInventorySha256
```

The installer reads and holds the exact public source/archive/bootstrap inputs
and the private original anchor, validates all external bindings, and checks
the private destination parent before allocating output. Its new directory
contains only these declared entries:

| Entry | Contents |
| --- | --- |
| `source/` | The complete exact source archive inventory, including its source manifest. |
| `source.zip` | The original verified archive bytes, retained for later full reconstruction. |
| `bootstrap/` | The three separately trusted bootstrap source files. |
| `replay-owner.py` | Generated read-only runner bound to those bootstrap hashes. |
| `installation.json` | Canonical installation identity, source/tooling bindings, original anchor and runner hash. |

During creation the final record is named `installation.pending.json`. New
files use exclusive creation; their allocation identity is captured while that
handle is open and bound to the verified private writer. Payload writes are
flushed and checked through the existing NTFS handles. Every source file and
subdirectory receives exact byte/membership/ACL/namespace checks.

All initial handles must close successfully before a separate complete reproof
can promote the pending record through its verified handle. All other private
proof handles, including the installation directory, exit before the rename;
the pending record and namespace handles remain held. This preserves the
directory and ancestor identities while permitting Windows to open the target
directory for the rename. A final complete reproof checks the published state.
Promotion cannot overwrite a destination. Failures retain the partial directory
and any pending record. There is no resume, overwrite, automatic cleanup, or reuse shortcut.
A failure after rename is an uncertain publication requiring inspection; do not
derive a success receipt from the presence of `installation.json` alone.

On success, retain the returned `installation_sha256` independently. The result
reports private source placement at that observation, while
`original_anchor_replayed`, `active_callers_migrated`, `credential_admission`,
and `runtime_admission` remain false.

## Replay the original selection without runtime callbacks

Run the generated reader in a fresh qualified interpreter with both isolation
and bytecode writes disabled:

```powershell
python -I -B "$NewSource/replay-owner.py" `
  --expected-installation-sha256 $RetainedInstallationSha256
```

The runner refuses other operations and missing interpreter isolation. It checks
the fixed trusted bootstrap hashes before executing those in-memory bytes. The
bootstrap then checks the externally retained installation identity and holds
the exact private source, bootstrap, archive, runner, anchor, and complete
directory memberships throughout the operation. An extra source file or
`__pycache__` directory is an error.

Candidate local modules load only from the verified, held byte inventory through
a dedicated finder; source paths are retained as module origins. The runner does
not put the candidate directory on `sys.path`, reuse previously imported owner
modules, or reread executable source through an ordinary import loader. Installed
third-party interpreter dependencies remain part of the separately qualified
Python environment.

The only owner operation is a complete `selected_inputs(original_anchor)` lease.
It follows the retained ancestry, verifies the resolved selected configuration,
generation/environment fingerprints and receipts, and releases the existing
project lock normally. No lease callback is invoked: no Docker inspection,
native authority check, credential renewal, recovery, activation, website
transition, or post-renewal hook runs. An existing caller's lock contention is a
refusal; the runner does not retry or bypass it.

Only after the selection lease and every source/input handle exit successfully
does the runner emit its nonsecret result. It reports the project, local segment
sequence, resolved generation sequence, selected-input digest, source commit and
installation/anchor digests. The resolved generation can exceed the original
journal's last local sequence. That distinction is retained explicitly.

Successful replay sets `original_anchor_replayed=true` for that observation.
It does not prove unexpired credentials, strict live `ForeignContext`, native
authority, application readiness, or a successful production recovery. All
credential/runtime admission and active-caller migration fields remain false.

## Preserve the production caller contract

The generated reader is **not a renewal scheduled-task replacement**. Before any
later source/task handoff, inventory and preserve the actual existing action,
principal, triggers, settings, runner, source hashes, explicit recovery modes,
and post-renewal behavior. A deployment may invoke a private Python runner
directly rather than the repository's PowerShell wrapper. Its pinned follow-up
operations, including an existing Google identity-provider configuration hook,
must remain part of that migration contract.

Keep all historical source and inactive entrypoints. The existing managed task
installer remains create-only. Task migration, explicit recovery-entrypoint
coordination, and any authorized host operation remain separate work; this
source installation does not claim to complete them.

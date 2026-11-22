# Run a qualified Windows owner from its versioned installation

`scripts/selfhost_windows_source_caller.py` is a separate operational caller for
the [versioned source installation](windows-owner-source-install.md). Place its
exact reviewed bytes as `run-owner.py` beside a canonical private `caller.json`
in a new private directory. The caller does not change the installed source,
bootstrap, installation record, original configuration, or historical runner.
It does not install, replace, enable, disable, or verify a scheduled task.

An independently retained profile digest binds the runtime script, qualified
Python path, existing installation identity, enrolled logical TLS project,
existing private diagnostic log, and the existing Google identity-provider
follow-up operation. The initial runtime script must be independently verified
before execution, just as the source installer's initial bootstrap must be.
Hashing an untrusted received script or profile does not establish that trust.

## Prepare the private caller

Retain the actual existing task definition, runner, source/hash inventory,
explicit entrypoints, and post-renewal behavior before preparing a replacement.
This caller preserves a direct Python renewal followed by a fixed Google
identity-provider helper. It does not infer that behavior from a task name or
substitute the repository's PowerShell wrapper for a deployment-specific caller.

The following values are **synthetic examples**, not host settings:

```json
{
  "schema": "marty.windows-owner-source-caller/v1",
  "script_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "python": "C:/Python312/python.exe",
  "installation": {
    "root": "C:/Example/private/windows-owner-source-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-cccccccccccccccc",
    "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  "logical_project": "marty-selfhost-example",
  "log": "C:/Example/private/retained/renewal.jsonl",
  "hook_state": "C:/Example/private/caller-hook-state",
  "hook": {
    "helper": "C:/Example/private/retained/enable-google-idp.py",
    "helper_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "client_id": "C:/Example/private/credentials/google_client_id",
    "client_secret": "C:/Example/private/credentials/google_client_secret",
    "docker": "C:/Program Files/Docker/Docker/resources/bin/docker.exe",
    "image": "python@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "network": "marty-production-example_default",
    "timeout_seconds": 90,
    "success_stdout": "Google IdP and first-broker flow verified in example realm"
  }
}
```

The stored profile uses sorted keys, compact separators, and one trailing
newline, matching `packed()` in the caller. Its externally retained SHA-256 is
over those exact bytes. The schema is closed: unknown or missing keys, duplicate
JSON keys, noncanonical bytes, nonfinite values, malformed digests, unsupported
logical projects, and unsafe path spellings refuse. Paths are canonical local
drive paths with forward slashes; UNC paths, relative paths, reparse points,
alternate streams, reserved Windows names, trailing dots/spaces, control
characters, and Docker mount delimiter injection are refused.
This canonical spelling applies to the stored profile. Explicit CLI paths may
use ordinary Windows backslashes; validation normalizes only those separators
and passes the original argument unchanged to the qualified owner.

The caller directory contains exactly `caller.json` and `run-owner.py`. All
other inputs already exist outside that directory and the immutable source
installation. The caller does not create or relax ACLs. Its private inputs must
pass the same current-user owner/DACL, NTFS, no-reparse, single-link and held-byte
checks as the original owner. The qualified Python and Docker executables are
held as public immutable tool inputs; their installation and interpreter
dependencies remain separately qualified prerequisites.

The separate private `hook_state` directory is enrolled create-only before any
caller invocation. Initially it contains exactly `owner.json` and an empty
`lock` file. Its owner record is the canonical result of
`hook_state_owner(retained_profile_sha256, retained_installation_sha256)`: schema
`marty.windows-owner-source-hook-state/v1`, `profile_sha256`, and
`installation_sha256`. Use the unchanged qualified private writer to create
those exact files; retain the caller profile digest independently. The caller
does not initialize, reset, repair, overwrite, or clean up this directory.
Its path must not alias, contain, or fall beneath any caller, installation, log,
helper, credential or qualified executable path.

Use the retained profile digest in every invocation:

```powershell
& $QualifiedPython -I -B 'C:/Example/private/caller/run-owner.py' `
  --expected-profile-sha256 $RetainedCallerProfileSha256 --check-only
```

Isolation and disabled bytecode writes are mandatory. Optimized Python (`-O`)
refuses. The current interpreter must match the exact qualified profile path.
The caller requires CPython 3.12 or later before reading inputs or dispatching an
operation; a different interpreter/version still requires separate qualification.

## Check source and original history without runtime callbacks

`--check-only` is exclusive. It verifies the profile and runtime bytes, complete
caller directory, independently pinned installation, all three original
bootstrap files, original archive, complete source inventory, and original
selection anchor. Bootstrap bytes are hash-checked before they execute. Candidate
modules load through the unchanged installer's held-byte `VerifiedFinder`; the
caller neither adds a source path to `sys.path` nor accepts preloaded owner
modules.

The check holds the exact Google helper and existing client input files and
checks the existing log's private placement. It replays the original anchor
through `selected_inputs()` and reports the local sequence, cumulative generation
sequence, and selected-input digest. It invokes no lease callbacks, Docker
commands, credential work, hook, task change, or diagnostic-log append.

Success is emitted only after the complete source, caller, namespace and owner
leases exit successfully. It proves the observed bindings and retained history;
it does not prove current native authority, live readiness, hook execution,
periodic triggers, task migration, or completed production recovery.
An unresolved hook intent refuses check-only before owner replay; a successful
check must not imply that an operationally blocked caller is ready to enroll.

## Preserve ordinary renewal and its follow-up hook

With no operational arguments, the caller invokes the existing
`renew_once(original_anchor, logical_project)` owner. It requires the actual
`renewed-and-selected` result, a local sequence of at least two, and a cumulative
generation sequence at least as large as that local sequence.

It then reacquires `selected_inputs(original_anchor)`. Before running the hook,
the selected project, local/cumulative sequences, journal, original selected
intent, returned configuration hash, renewed environment and secret directory,
Compose identity, Docker pipe and engine must match that renewal result. A newer
or different selection cannot borrow the earlier result to authorize the hook.
This check and the hook occur within the same selected-owner lease.

Before preparing the hook intent, an owned, bounded read-only Docker `info`
request through the exact qualified executable and the lease's explicit named
pipe must report the lease's exact engine ID. Check-only never performs this
probe. The hook also uses that explicit `--host` and `--pull never`, preventing
a default context or implicit image pull from redirecting this operation.

The only follow-up mutation is the retained Docker invocation: `run --rm`, the
exact project default network, four ordered read-only bind mounts, the fixed
Python entrypoint, the pinned `python@sha256:...` image, and
`/run/secrets/google_helper.py`. The mounts carry the selected generation's
`keycloak_admin_password`, existing `google_client_id`, existing
`google_client_secret`, and the exact hash-pinned helper. No caller-supplied
command or arbitrary argument list is accepted.

The helper and all three private inputs remain held through the command. The
existing owned-process job contains the CLI and its descendants, continuously
bounds its output, and enforces the fixed 90-second timeout. Success requires
exit zero and the exact retained success line after whitespace trimming. Helper
output and secret values are never forwarded.

The job controls the CLI process tree. Docker daemon work can outlive a failed
or timed-out CLI, and `--rm` is not evidence of daemon quiescence. Failure is an
uncertain operation requiring inspection; the caller never retries the hook,
removes a container, rolls back credentials, or fabricates completion evidence.

### Retain an unresolved hook across future scheduled invocations

Every invocation holds the separate empty private lock exclusively, including
through source and caller exit checks. Before any owner or Docker callback, it
verifies the exact state directory, owner record, and contiguous canonical
`NNNNNN.intent.json`/`NNNNNN.complete.json` pairs. Existing records remain held.
Unknown entries, holes, corrupt/partial records, wrong profile or installation
bindings, and an unpaired intent refuse; the caller never deletes or relabels
those records. The finite bound is 4,096 attempts, after which new ordinary
renewal refuses before it starts. A new bounded journal requires a separately
reviewed enrollment, not an automatic reset.

After successful renewal and matched selection, and after the read-only engine
probe, the unchanged qualified installer writer exclusively creates, flushes
and rechecks a new intent before the Google helper can run. It binds the profile,
installation, original anchor, selected input digest, local/global sequences,
project, engine, pipe, journal, helper and previous completion digest.

Only after the helper succeeds and every source, caller, original-anchor and
selected-owner scope exits successfully may the same create-only writer publish
a completion binding the exact intent and typed hook result. The state lock and
namespace outlive those source scopes. The completion and state guards must then
exit successfully before logging or output. A timeout, callback error, or late
source/input proof failure leaves the intent unresolved and blocks later
ordinary renewal, explicit recovery and check-only invocations. No automatic
hook retry or generic guard-clear command exists. A partial or uncertain record
publication requires inspection; its presence alone is not a success receipt.

## Explicit expired-current operations

The explicit interface retains paired arguments and the existing managed
configuration schema. The private managed wrapper must still point at the exact
original anchor in the pinned source installation. It cannot retarget the caller
to another owner or replace the original anchor with a later configuration.

| Phase | Additional required arguments |
| --- | --- |
| `inspect` | None |
| `prepare-selected` | `--attempt-directory`, `--logical-project` |
| `stage` | `--attempt-directory`, `--logical-project` |
| `reconcile-stage`, `retire-unused-stage`, `publish`, `activate` | `--attempt-directory` |
| `select`, `retire-helpers`, `finalize` | `--attempt-directory`, `--source-journal` |

Every explicit invocation also requires `--configuration` and
`--expired-current`. The optional `--operator-successor-file` remains available
for the existing phases that support it; `inspect` and `prepare-selected` refuse
it. `prepare-selected` and `stage` require the exact enrolled logical project
from the profile. Duplicate, unknown, missing, extra, odd or mixed-mode arguments
refuse before owner dispatch.

For example, after all source/caller handoff prerequisites and live operation
authorization have been satisfied:

```powershell
& $QualifiedPython -I -B 'C:/Example/private/caller/run-owner.py' `
  --expected-profile-sha256 $RetainedCallerProfileSha256 `
  --configuration $OriginalManagedConfiguration `
  --expired-current prepare-selected `
  --attempt-directory $QualifiedEmptyAttemptDirectory `
  --logical-project $EnrolledLogicalTlsProject
```

Explicit operations dispatch only to the reviewed owner's existing
`selfhost_windows_recovery.main()`. They never invoke ordinary renewal or the
Google hook. All existing owner checks, strict `ForeignContext`, native
authority, certificate observations, publication, activation and recovery guards
remain in force. The caller adds no retry, stop/quiesce shortcut or receipt
promotion capability. The owner's canonical JSON is bounded to 65,536 bytes and
forwarded only after every outer source/input exit succeeds.

## Diagnostic summaries and failure handling

Successful operations append only a bounded nonsecret summary to the existing
private log after all owner/source/input and hook-state exits. The established
`utc`, `result`, and renewal sequence fields remain. Explicit success retains
`explicit-recovery-phase-completed`. Failures append a generic
`operator-reconciliation-required` summary when its trusted log binding is
available, with only a bounded exception class name. Check-only never appends.
The log is diagnostic; it never clears or admits the authoritative hook state.
No raw exception, command output, helper
output, token, key, or client credential enters these summaries.

The append opens the existing file with a single no-write-sharing handle and
proves its NTFS identity, single link, current-user owner and unchanged private
ACL. It bounds and preserves the complete old prefix, writes at the verified
end, flushes, and verifies the exact final bytes and identities. It never creates
or truncates a log. A partial write, failed flush or failed close remains
uncertain; there is no second append attempt to hide that result.

Preparing this caller does not migrate active callers. Preserve and separately
qualify every active scheduled and supported explicit entrypoint before emitting
a selected-expired origin that historical readers cannot consume. Retain the old
source, runner, task definition, configuration, and evidence. A successful caller
check must not be presented as completed task migration, credential recovery,
website activation, periodic/logon behavior, or host reboot qualification.

# Windows candidate credential renewal adapter

`scripts/selfhost_windows_renewal.py` implements an isolated candidate transaction
using the existing Compose, rootless-migration, readiness and secret-mount owners.
The POSIX activator's platform/project checks are unchanged. This is a library;
there is no operator CLI, unattended task, production admission or reboot claim.
Signed release verification and publication/cutover approvals remain separate.

The managed candidate must have the complete declared service closure. Both KMS
initializers remain absent and opt-in. Managed OpenBao, its unseal helper and the
successful completed TLS initializer remain unchanged. Only roles that mount
generation secrets are recreated, with `--no-deps --no-build --pull never`.
Images must be digest pinned, published ports must be loopback only, and active
tunnel connectors, host networking and privileged roles are refused. Writable
storage overlap with any other Compose consumer, including read-only consumers,
is refused. Known Docker/WSL Windows-drive spellings are resolved through real
Windows identities (including junction targets and ancestor identities). Only
default-root local Docker volumes without driver options have a native volume
identity, including legacy inspect records whose Source is the volume name. A bind
of the exact volume root shares that identity. Native bind subpaths require fresh
kernel mount metadata from a trusted network-disabled helper sharing the existing
container's verified private/default PID namespace. It reads only filtered declared
destinations and their mount ancestors from `/proc/1/mountinfo`, with no data
volumes mounted and no added capabilities. Exact container/start identity, unique
destinations, visible parent chains without ancestor overmounts, decoded normalized roots, a pinned Docker Desktop VM root prefix,
ext4 filesystem type and a device number anchored by an ordinary named-volume
mount are required. Whole-volume classification is conservative. A same-project
zero-exit historical job with the exact same Source may reuse that live witness
as a metadata inference; this never authorizes restarting it. Unknown evidence,
inaccessible metadata, other filesystems or ambiguous mounts remain refused.

The caller supplies a private configuration with the exact retained Compose hash,
current/renewed env and generation paths, local Docker pipe/engine identity and
the already release-verified Linux operator identity. The transport rechecks its
digest and embedded source/tag identity while holding the NTFS binary and CA.
The scoped renewal control volume is mounted read-only. Native authority,
generation, orphan token, certificate/key/chain and lifetime checks are mandatory.
Both native mirrors must match the held Windows bytes exactly. Native checks then
use private mode0700/0600 snapshots materialized from those held bytes in isolated
tmpfs, so later changes to shared staging mirrors cannot change the checked data.

`selfhost_windows_renewal_native.export_generation(config, mirror)` provides the
read-only byte transport needed by the recurring producer/export path. The caller
holds the existing selected-generation lease and supplies its retained transaction
configuration and a normalized generation-directory URI below `/control`.
The adapter holds and hashes the Compose model and derives the exact inventory
from its secret declarations. It checks the existing project control volume,
then uses the pinned helper with network disabled and the volume mounted read-only.
Its Docker log driver is disabled so private chunks are not retained as daemon logs.
It neither mounts the Bao/database volumes nor exports enrollment/session files.

The helper checks private root/file modes, root ownership, regular single-link
files, no-follow opens and stable file identities. Data must be bounded UTF-8,
with empty files preserved. Held no-follow ancestor directory descriptors anchor
all relative file opens; all files stay open through the final identity and
namespace rechecks. Its manifest and each 12,000-byte chunk bind the same
whole-payload hash. Responses stay below the existing owned runner's bounded
output tail; the Windows caller checks exact indices, lengths, inventory and the
final payload hash before returning any byte map. The limit is 512 files of at
most64KiB each and8MiB for the complete encoded payload. A ten-minute fetch budget
is checked again after final decoding and held-input exit. Engine inspection and
the owned runner's separate bounded cleanup remain existing dependencies; this
is not a newly qualified hard whole-call or unattended timing guarantee. Failed
owned-process failures become fresh fixed-message uncertainty exceptions carrying
only the process-cleanup flag and empty tails; their original private chunk frames
and exception chains do not propagate. Parser/UTF-8 failures likewise become a
fixed refusal without retaining private exception payloads.

Export returns private bytes to its caller, never host stdout. It writes no
Windows files, mints no credentials, selects no generation and grants no native
admission. A producer must retain its durable attempt evidence, materialize the
result under the existing private Windows input owner, and pass the unchanged
native generation/token/certificate checks before registered activation. This
transport alone does not implement producer scheduling or expired-leaf recovery.

The private project lock and output files must already exist. The lock is named
`.<project>.renewal.lock` beside the generation directories. `intent`, `result`,
`new_log` and `rollback_log` must be distinct empty private files in one separate
output directory. The transaction does not create files, weaken ACLs, overwrite
a prior receipt or modify either generation/env file. Existing intent makes an
ambiguous or interrupted transaction an operator recovery case, not a blind retry.

The adapter holds the lock, retained Compose/env files and both complete secret
generations through native checks, durable intent, recreation and mount/readiness
verification. Writable Windows data-source names are also held while their normal
application writes remain permitted. Data mounts and image identities must remain
unchanged. Running roles must match retained Compose config hashes; the preserved
zero-exit historical TLS initializer requires an exact container/image/hash receipt.
Ancestor names cannot be replaced while held. Unselected container
identities, state, restarts and mounts must remain unchanged, including a fresh
all-container check immediately before intent. An ordinary failure
recreates the prior generation and verifies it. Failure of rollback, held-input
exit checks or final receipt writing preserves the intent and requires recovery.
An activation result is written only after the held-input exit checks pass.

Qualification must include real NTFS locking and sharing, native preflights,
isolated Docker activation/rollback, then the owned application's authentication
and KMS journeys. A successful return establishes candidate readiness and mounts;
it does not establish production release admission, credential retirement,
continuous availability or automatic engine/logon/host recovery.

Returned Compose invocations that leave a role in `created`, paused or another
nonprogressing state fail promptly rather than polling for a first start that
Docker will not perform. A mutating CLI timeout is an uncertain outcome: preserve
its bounded diagnostics and intent, and do not launch automatic rollback. The
Windows mutation runner uses an unnamed noninheritable kill-on-close Job Object
with no breakaway flags. Its isolated Python helper waits for an input gate before
launching Docker; job assignment precedes every command byte. Output drains into
bounded tails. Normal completion requires zero active job processes and bounded
reader completion. Timeout, surviving descendants or containment failure preserve
uncertainty even after owned-process termination. Synthetic Windows tests cover
nonzero exits, large output, gate-assignment failure, timeouts and surviving
grandchildren. Dependency-layer and real Docker containment qualification remain
blockers to exposing a CLI or unattended lifecycle. Job termination does not prove
Docker daemon operation quiescence. See [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

Before intent, the entire active dependency graph is validated for normalized
conditions, required closure, health/completion contracts and cycles. Selected
roles are recreated in dependency layers. Each role appears in one invocation;
the preserved foundation and completed layers must be ready before advancing.
Ordering is projected from the full active graph, preserving paths through
unchanged roles. Dependency restart cascades are refused before intent.
A transient health failure therefore cannot leave all downstream layers created
by an earlier bulk invocation. Readiness/completion is refused after the600-second
phase deadline, including when a status read or receipt flush crosses it. The
shared read-only Compose status transport has its separate60-second inspection
timeout; this is not a hard600-second process wall-clock guarantee.

The caller must preallocate `step_receipts`, one object per computed layer, with
exact keys `new_started`, `new_completed`, `rollback_started`, `rollback_completed`.
Each value names a distinct existing empty private file beside the four main
outputs. The durable intent retains the layer plan and receipt paths. A started
receipt is flushed before each mutating invocation, and a completed receipt only
after readiness. Rollback uses the same validated ordering with the old env.
Never replay an interrupted layer from these records without reconciliation.

The generation-selection owner can call `preflight_current` for a read-only
current-custody and minimum-one-hour lifetime check. It verifies both native
mirrors against held bytes, materializes private snapshots and delegates scoped
authority, orphan-token and certificate/key/chain/lifetime decisions to the signed
native operator. This separate entry point does not verify a changing-generation
transition. `preflight` still requires distinct mirrors and changed renewable
inputs, including the native generation verifier.

Native requests now use the existing owned Win32 job runner's bounded binary
stdin pipe. Private payloads are absent from command arguments. Command arguments,
private input, encoded gate request and output tails each have separate bounds;
every owned command inherits a private pipe or DEVNULL rather than the gate stdin.
Durable selection/reconciliation and recovery integration remain separate work.

`selfhost_windows_selection.py` adds a candidate selection journal beside its
generations, at `.<project>.generation-selection`. It uses the same existing
exclusive project lock, private NTFS proofs and immutable model/engine/operator
binding. Records are append-only, sequence/parent-linked and bounded; secret
values are never stored in them. Original transaction configs, intents and results
remain unchanged.

The library exposes these bounded operations:

- `adopt(config_path)` proves an existing successful activation, then selects its
  renewed inputs. Interrupted initial metadata adoption can resume after proof.
- `prepare(next_config_path)` proves the selected current inputs and writes the
  pending intent before activation. An initialized owner makes unregistered or
  changed activation requests fail before mutation.
- `complete(config_path)` verifies the durable activation/rollback result and
  current runtime before appending selection. `reconcile=True` never replays
  Docker: an empty original intent permits only the unchanged old selection;
  otherwise the terminal phase needs every durable started/completed boundary.
  Incomplete or uncertain commands remain operator recovery cases even when a
  snapshot looks healthy. Original empty result files stay empty.
- `status(config_path)` reports journal state, not live readiness. Pending,
  malformed, partial or extra records never silently fall back to older inputs.
- `selected_inputs(config_path)` holds the project lock, selected metadata,
  model/env and complete generations for a recovery consumer. Its immutable lease
  exposes paths and a current-proof callback, no secret bytes; the callback refuses
  use after the context closes.

Read-only proofs may use a fresh scoped authority token file without rewriting
historical configs. Native authority/lifetime decisions remain mandatory. Existing
Linux generation owners and Windows Compose/native validators are reused; this
library starts no services and installs no task. PowerShell startup integration,
producer scheduling, expired-credential recovery and engine/logon/host-reboot
qualification remain required before unattended operation. Process-interruption
controls do not claim power-loss durability qualification.

The legacy Windows recovery wrapper refuses a default-active `openbao-tls-init`
in either its product or OpenBao Compose inventory before any service mutation,
including in check-only mode. Combined `up` and dependency traversal can replay
that completed job. A retained managed candidate therefore needs the selected-
generation recovery integration; passing paths to the legacy wrapper is unsafe.
Existing standalone shapes without that initializer retain their recovery path.

The selected-input lease now offers `recover_existing(output_dir, authority_file)`
as a library callback. It holds the same project lock, original receipts and
complete generations throughout recovery. The output directory must already be
empty/private and named `windows-recovery-*` beside the generations. Missing,
paused, invalid or failed completed jobs refuse before mutation. Only existing
IDs may start; completed migrations and the TLS initializer never start again.
Bao and its unseal helper start as a foundation group, then the native owner must
admit the selected credentials before application roles start in dependency order.
The full final readiness, storage, identity and native proof remains mandatory.

A shared recovery marker blocks renewal, selection changes and new recovery after
an interrupted/uncertain attempt. No failure path clears it or rolls back daemon
operations. Preserve the marker, attempt receipts and generations for operator
reconciliation. The callback returns a provisional result; only a clean exit from
the entire selected-input context publishes success and clears the exact marker.
Receipt tampering, a caller exception or a failed held-input exit leaves the marker.
The marker remains authoritative even if a result file was written before a final
publication-lock exit failure. Never interpret that result independently. Admission
uses no-follow namespace checks: dangling marker/selection links and metadata errors
must not fall back to an installation without an owner.
The existing PowerShell wrapper can dispatch the managed CLI with an explicitly
supplied trusted interpreter; see [managed configuration](windows-compose-recovery.md#retained-managed-openbao-candidate).
It installs no scheduled task and never automatically removes an uncertain marker.
Producer scheduling and broader interruption recovery remain required before
unattended recovery is qualified.

An explicitly coordinated planned stop may retain a separate
`.<project>.recovery-preparation.json` marker. It blocks every new admission just
like the recovery marker, including dangling entries. Only the already-held lease
can call `recover_existing(..., preparation_sha256=...)` to hand it off. The
private completion receipt must bind the exact preparation hash, returned stop
CLI, all stopped IDs and retained completed-job IDs. Model/engine/selection/data
identity, actual stopped state and protected observations are rechecked. Unknown,
incomplete, mismatched or changed stop records never authorize startup.

The owner flushes the normal recovery intent and marker before unlinking the
preparation marker. Both exist during transfer; interruption leaves at least one
authoritative marker. The original preparation and completion evidence remains
linked by hashes in the recovery intent. This supports controlled planned-stop
handoff; it does not automatically reconcile an uncertain stop or interrupted start.

`reconcile_existing(config_path, authority_file=...)` is a separate read-only
terminal operation. Use it only after verifying the original recovery owner has
finished. It requires the exact guarded intent, registered selection, model-derived
layers, current IDs, all matching started/completed command boundaries, and fresh
native readiness/custody/lifetime proof. Missing or uncertain boundaries refuse
even when containers appear healthy. A preparation marker also refuses this path.
No workload command is issued. Original result bytes remain unchanged, including
an empty original result; a separate deterministic `reconciliation.json` records
the current proof. All original receipts and directory membership are rechecked
before the marker clears, after lease and publication-lock exit checks. A prior
valid reconciliation record can be retained during a fresh proof after publication
interruption. This does not resume an unfinished start, prepared stop or expired
generation, and it is not automatic logon recovery.

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

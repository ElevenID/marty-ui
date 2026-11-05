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
storage overlap with another Compose project is also refused.

The caller supplies a private configuration with the exact retained Compose hash,
current/renewed env and generation paths, local Docker pipe/engine identity and
the already release-verified Linux operator identity. The transport rechecks its
digest and embedded source/tag identity while holding the NTFS binary and CA.
The scoped renewal control volume is mounted read-only. Native authority,
generation, orphan token, certificate/key/chain and lifetime checks are mandatory.
Both native mirrors must match the held Windows bytes exactly.

The private project lock and output files must already exist. The lock is named
`.<project>.renewal.lock` beside the generation directories. `intent`, `result`,
`new_log` and `rollback_log` must be distinct empty private files in one separate
output directory. The transaction does not create files, weaken ACLs, overwrite
a prior receipt or modify either generation/env file. Existing intent makes an
ambiguous or interrupted transaction an operator recovery case, not a blind retry.

The adapter holds the lock, retained Compose/env files and both complete secret
generations through native checks, durable intent, recreation and mount/readiness
verification. Ancestor names cannot be replaced while held. Unselected container
identities, state, restarts and mounts must remain unchanged. An ordinary failure
recreates the prior generation and verifies it. Failure of rollback, held-input
exit checks or final receipt writing preserves the intent and requires recovery.
An activation result is written only after the held-input exit checks pass.

Qualification must include real NTFS locking and sharing, native preflights,
isolated Docker activation/rollback, then the owned application's authentication
and KMS journeys. A successful return establishes candidate readiness and mounts;
it does not establish production release admission, credential retirement,
continuous availability or automatic engine/logon/host recovery.

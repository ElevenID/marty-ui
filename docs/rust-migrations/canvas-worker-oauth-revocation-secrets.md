# OAuth revocation secret-resolution composition

Qualification update: df3ed290b19a2cd8e82ef21bfa83355cb2c62a83 passed all 98
configured entries in CI34076998603 (2085.34s). All six native zero-request markers,
the real schema-rejection test and native empty-token regression were inspected.
The separate four-test worker database suite passed in 96.39s; all applicable
exact-head checks passed. This supersedes historical pending status below, not
the distinctions between schema, process and counting-provider evidence.

The actual published standalone worker now has six frozen observations for
unavailable access-token references. Each starts from the official published
schema with encrypted secrets and the existing isolated HTTPS owner:

- No access reference.
- Current-tenant prefix with an empty secret ID.
- Current-tenant prefix with a nested secret ID.
- Current-tenant reference to a missing secret.
- Current-tenant reference to a disabled secret.
- Current-tenant reference whose secret ID exists only under another tenant.

All six actually schedule one retry with `canvas_oauth_revoke_rejected`, release
their lease, reach idle and make zero provider requests. They preserve all three
ciphertexts, secret ownership/enabled state, unused markers, access/refresh
references, platform state and issued rows. The stored retry deadline remains
within the existing first-attempt range. No row mutation, request, counter or
secret lookup result is inferred from the case name.

The first capture passed in 33.82s. Independent permanent regeneration plus
the real schema-rejection test passed in 42.92s; the third top-level Windows
entry returned early and is not native HTTPS qualification. Frozen canonical LF
SHA256: `14366ca93da14c695f3fdb94e616739b8f944851db9acdb972a3d5a0fa6aa621`.
The immutable image owner and actual module source hashes retain provenance.
This older transport source is not the separately hardened privacy reference.

Native whole-process replay is implemented through the existing worker binary,
real repository/vault and HTTPS parent. It compares every frozen field, including
the complete secret-state map. Integrity controls reject unexpected HTTP requests
even when zero are expected, missing/duplicate cases, failed/timed-out children,
changed tenant references and changed secret usage. Existing fixtures, matrix
loading, database owner and process protocol are reused.

## Schema rejection is not worker execution

Inspection of actual `pg_constraint` definitions confirmed that a different
tenant prefix is rejected for client, access and refresh references. The permanent
test requires SQLSTATE 23514 and the exact tenant-reference constraint for each
update, preserving the complete connection row, all ciphertexts and issued rows.
It passed again with those preservation assertions in 3.66s. No constraints were
disabled to manufacture an unreachable worker input.

An attempted empty-plaintext seed was rejected by the actual published
`save_integration_secret` API with ValueError before any worker ran (4.48s).
It is recorded as an input-validation boundary, not silently relabeled as one
of the six worker observations. No claim about arbitrary corrupt ciphertexts or
all secret write API behavior is made by this corpus.

## Reviewed native empty-token correction

The lower-level native vault accepts encryption of an empty string, while the
published worker explicitly treats an empty token as unavailable. Native worker
inspection found the missing non-empty guard. A real native cycle/repository/vault
regression with a counting provider reproduced unwanted dispatch (one call when
zero were required, 3.58s). The provider performs no network activity.

Adding `!token.is_empty()` to the existing revocation branch fixes that behavior;
the regression then passed in 4.07s. It asserts zero dispatches, returned success/
retry counters 0/1, exact durable retry state and unchanged ciphertexts/issued rows.
The guard does not trim or rewrite non-empty tokens. Encryption, secret-write APIs
and the other worker's crypto code are unchanged. The actual cycle constructor is
shared with the counter replay; the counting provider is explicitly a test double,
not native HTTPS parity evidence or a published empty-secret worker capture.

The mandatory hosted suite now registers 94 entries. Strict all-target Clippy
passed after the runtime correction. Native six-case process qualification,
the previous queue/lease/counter additions and whole-worker cutover still require
fresh exact-head hosted evidence. No consumer, feature or Python implementation
has been removed; production and persistent deployments remain unchanged.

Final local regressions: 334 issuance library tests passed in 15.74s, all 24
behavior tests passed in 0.01s, and 1,005 Python tests passed with one existing
opt-in skip in 43.22s. Strict all-target Clippy, shell syntax, Python lint and
patch-integrity checks passed. These local results do not replace the required
native Linux process gate.

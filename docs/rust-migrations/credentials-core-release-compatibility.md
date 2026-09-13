# Credentials/Core release compatibility — 2026-09-08

Status: release blocked on concrete dependency behavior, not release-workflow
permission. The user authorized workflow activation. Production is unchanged.

User sequencing decision on 2026-09-08: finish the feature-preserving DIDComm
Rust consumer migration first. KMS-layer corrections are explicitly deferred in
Credentials `docs/rust-migrations/didcomm-kms-outstanding.md` (`DIDCOMM-KMS-001`,
[PR #273](https://github.com/ElevenID/marty-credentials/pull/273)). This release
compatibility gap must not be used to block the Rust port itself. It still
prevents claiming compatibility with a new artifact that lacks required APIs.

## Verified release failure

Credentials preparation [34236062000](https://github.com/ElevenID/marty-credentials/actions/runs/34236062000)
passed and created immutable `v0.1.73` at
`9bd2747f040f203188529758ec38f0a5dce5ac5f`.
Release [34236090229](https://github.com/ElevenID/marty-credentials/actions/runs/34236090229)
finished **failed**. All artifact-build jobs and Rust tests passed, but its
Python test job had 1,689 passes, two skips and three failures. Draft publication
was skipped; do not move or reuse the tag to repair source.

The failing assertions reject a private holder JWK before remote signing and
reject malformed ES256 signatures (three bytes and an all-zero 64-byte value).
Keep those assertions. Release installs the exact checksum-pinned Core 0.1.60
wheel (`dce4fb99016dfcb3801fbfb9dcab9e8b0f74bd4f`); main CI instead builds
Core source `08a0d435390f13186cb6f6278b9a15f9020067a7` with compatibility features.
Core [PR #308](https://github.com/ElevenID/marty-core/pull/308), merged as
`72d4f214c8e71b4ed41b7d60cdbb638231c112a6`, already fixed these security behaviors.
The latest public Core release observed was 0.1.61, also predating those fixes.

## Why a pin change alone is insufficient

Core main `1ae5b71e53ebfd2bad29b2e7c23c3d048461245c` declares **0.2.0**.
Its release binding profile uses `kms-only` with no default features. Do not
downgrade that reviewed version to 0.1.62 or restore removed private-key APIs
as a shortcut.

| Credentials capability | Verified downstream use | Current Core release boundary |
| --- | --- | --- |
| `didcomm_encrypt` | Default anonymous encrypted delivery, preflight and final envelope | Native optional `didcomm-encrypted-envelope` feature exists but is absent from the default release wheel. |
| `didcomm_encrypt_authcrypt` | Documented authenticated delivery selected by issuer policy, both issuance and explicit delivery routes | No KMS-backed replacement port found. The raw-private-key implementation is incompatible with the KMS-only profile. |
| `didcomm_decrypt` | Wrapper and startup requirement; no repository route/demo/test caller found | Intentionally absent. Treat as a potentially stale requirement only after owner confirmation, not as permission to remove live encryption. |

At credentials `9bd`, `services/issuance/application/rust_integration.py` lists
all three as required startup capabilities. Preflight and final delivery use
the same frozen sender/recipient inputs and prohibit authcrypt-to-anoncrypt
fallback. `services/issuance/infrastructure/api/routes.py` calls the delivery path from issuance
and `/v1/issuance/didcomm/deliver`; `docs/CONFIGURATION.md` documents issuer policy.
All six inspected local credentials branches retained the same integration-file
blob; their Python consumer has not been replaced. The user confirmed that the
crypto worker is not editing Credentials. A substantial native consumer already
exists in marty-ui's `rust/services/issuance/src/initiation_didcomm.rs`; reuse and
qualify that owner rather than adding another implementation. Its existing
Core `ec307b6edd0450c558869fd587215e72cd46e9d1` pin supports Rust anoncrypt and
authcrypt without restoring deleted Python APIs. This existing local-key path
is not KMS-only and does not authorize an unqualified dependency update.

## Required repair and release evidence

1. Preserve the confirmed ownership boundary: this lane owns the Credentials
   consumer migration; other-worker Core changes remain separate and untouched.
2. Preserve both delivery modes, recipient resolution, issuer policy, sender
   binding, preflight/final-context consistency and no-fallback behavior through
   the existing canonical Rust owner. Do not merely delete startup capability
   checks. The future KMS boundary belongs to the deferred follow-up.
3. Freeze language-neutral behavior and test the actual replacement Rust ports,
   including failure ordering, durable effects, public behavior and actual
   consumers. Secret-key exclusion and opaque KMS operations remain explicit
   outstanding security work, not a claimed property of the current Rust port.
4. Qualify the **actual release-profile wheels** with credentials, not only
   source-built compatibility wheels. Keep the three failed security regressions
   and add main-CI evidence that exercises the production dependency profile.
5. Publish a compatible, reviewed Core artifact through its governed release
   path, update credentials' immutable dependency record, and prepare a new
   credentials version after exact-main gates pass. Never retag v0.1.73.
6. Verify the resulting issuance image and its own migration CLI before changing
   the aggregate lock, then complete beta-only deployment and acceptance.

This is a required release dependency repair within the existing migration goal,
not a reason to delete DIDComm functionality or relax release tests. Independent
Canvas parity and proven-unused Python retirement can continue meanwhile.

# Marty UI pull-request reconciliation

The review began with 44 open pull requests. PRs #1888 and #1889 were opened
while reconciliation was in progress and are included in this disposition map.
Original source branches and pull-request commit histories are retained.

## One candidate for the reviewed changes

PR [#1881](https://github.com/ElevenID/marty-ui/pull/1881) is the integration
candidate for the following 21 source PRs. It uses the existing human-authored
branch so normal private-fork and protected-merge checks apply. The dependency
bot security policy, required checks and merge queue are unchanged.

| Source PRs | Intended changes preserved |
| --- | --- |
| #764, #817, #824, #1088, #1089, #1090, #1835, #1855, #1856, #1857 | Explicit Node, UI, browser-test, Python and GitHub Action updates; coherent npm/Bun locks; MSW 3 migration. See [the dependency preservation map](dependency-backlog-reconciliation.md) for exact versions and the deliberately narrower monthly transitive refresh. |
| #1456, #1524, #1690 | Correct current authorization guidance, retained OpenBao assertions, shared REST/startup input validation, bounded installation-directory input and escaped diagnostic output. The actual eight seeded roles replace the stale role matrix. |
| #1791 | Allow the authenticated application-settings source/selection pair before initial ACME enrollment while retaining all other ownership and lifecycle refusals. |
| #920, #925 | Preserve the reserved digital-passport candidate, its eight-step contract and future D-13/MIP beta reservation. Unsupported create, patch, activation and execution remain explicitly blocked; current public MIP 0.5 does not advertise the candidate. |
| #1793 | Optional native Keycloak passkey login and account enrollment, same-subject session/PKCE/state/nonce checks, opt-in configuration, profile controls and matching Helm assets. Existing KMS/custody qualification remains required. |
| #1881 | Authenticate prerequisite-owner responses through bounded, fixed-origin, operator-CA HTTPS and optional remote-key listeners. Repair the standalone Rust-probe lock for the added HTTPS dependencies. |
| #1886, #1888 | Correct Kubernetes JSON-patch transport to `/dev/stdin`; retain the exact payload, preconditions, private evidence and single attempt. Raise only the existing release-contract job timeout from 35 to 45 minutes after the observed timeout, preserving every test and gate. |
| #1889 | Refuse private Helm configuration values and nonboolean worker activation, stop on failed secret-file reads, validate UI startup metadata, refuse another tenant's retained default revocation profile transactionally, and resolve manual preflight environment values through the actual Compose model. |

The combined tree preserves the independently reviewed component changes.
Overlapping workflow and authentication-test files were reconciled explicitly:
the passkey qualification and action pins both remain, and cookie/cache options
are asserted on the real fetch call under MSW 3. The review does not treat
ancestor status alone as proof that a feature remains in the final tree.
The concurrently opened installation hardening PR #1889 adds 18 distinct paths;
its complete file changes merge without modifying the prior combined source.

All source heads are retained as commit ancestors of the published candidate.
Closing an original PR means its work moved into this candidate; it does not
mean a passing local component check independently established a main merge.
The protected hosted checks and queue qualify the final combined source.

## Superseded or unnecessary PRs

| Closed PR | Existing disposition and preservation evidence |
| --- | --- |
| #1575 | Canonical organization/DID/purpose/format/algorithm key references landed through #1763 (`b615ba8b4`); main also contains subsequent IACA and negative-test additions. |
| #1678 | MDOC configuration overlays, successor verification and exact journal receipts landed through #1732 (`7bb393833`); later runtime improvements remain intact. |
| #1715 | The custom orchestration was replaced by native Compose in #1716 (`70f5eac44`). Main retains rootless ownership/storage checks, `init: true`, healthy Signing Keys ordering and exact saved-project cleanup scope. |
| #1531 | Its unique additions were six CI timing labels and parser allowlists. All six actual timeout/lease-expiry cases and assertions remain in main; the extra measurements are unnecessary. |

## Three distinct unfinished features retained as drafts

### #1710: installer VM and rootless custody qualification

Published preservation head `1ca9f970cec2fea8fc779b373b214e031664062f`, tree
`95d2558264fbef129126434468739ab1869b32cd`, retains all original heads from
#1672, #1675, #1676, #1680, #1682, #1694, #1699, #1701, #1702, #1703, #1704,
#1706, #1707 and #1710. The 13 subordinate PRs are consolidated here.

The package admission, rollback-copy/checkpoint/resume, fixed package transfer
and host-UID custody fixture remain. Main now uses a different resource-profile
and rootless cloud-init API; this draft's separate setup-Engine/offline-package
fixture needs deliberate adaptation. Actual isolated VM, package and rollback
qualification is still required. No live fixture or product activation is
authorized by source preservation.

### #1683: receipt diagnostics and dormant purge preparation

Published preservation head `7091bb49874522a6b78e668b26ea02a1813adba4`, tree
`b439f94769bf7581d2fef69d82608058ad52933b`, retains all original heads from
#1639, #1640, #1657, #1662, #1677 and #1683. The five subordinate PRs are
consolidated here.

Receipt identity validation, sanitized doctor diagnostics, read-only complete
planning, root census, foreign-owner reader qualification and dormant
confirmation/ledger work are preserved. The newer selected receipt/planner
parents were retained when older rebased branches were combined. Adaptation to
the current native Compose lifecycle and actual rootless-reader qualification
remain open. This draft adds no purge execution authority.

### #1783: public verification experience

The original head `c44bdf35112c965b1d64a6c0874f0baf34987c5c` remains the
canonical source for the default-off public `/verify` catalog, signed fictional
example, independent-wallet lane, quotas and retention lifecycle.

Its protobuf configuration-digest field numbers conflict with newer typed
`PolicyRevision` fields, its SD-JWT binder predates opaque authenticated query
evidence, and its finalization path predates full-record compare-and-swap and
durable receipts. Reconciliation must preserve those newer security controls
and repeat the positive/negative provider and wallet qualification. The feature
is unique and is retained rather than silently discarded or prematurely merged.

## Validation boundaries

Independent source reviews cover each component and their integration. Local
tests include dependency migrations, UI/authentication/profile/manifest
interactions, installer contracts and the real Kubernetes subprocess transport.
The original dependency full-suite run exposed three further MSW assertion
differences; those were corrected and both complete affected test files passed.

Local native Rust execution could not fetch the private SSI fork with the
available terminal credentials. Browser/physical passkey and deployed-runtime
qualification are not claimed. The final protected hosted checks remain the
merge gate; optional capabilities retain their existing activation controls.

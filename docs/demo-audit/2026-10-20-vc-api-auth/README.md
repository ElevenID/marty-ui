# Beta VC-API authentication repair

Beta now serves `beta-v259-vc-api-auth-1e6d88b82163`, manifest SHA-256
`7f4965015a6c0dff5575d62d1cf756ba89785a1768a26b96450dbfa112a5bf15`.
The deployed Gateway and UI source is `1e6d88b82163f1de19a4b9e948c3415a5cb707e5`.
Gateway verification now uses the existing policy-service authentication override.
The focused Gateway cases pass, including a requirement on the actual outgoing
policy request's service header. Two synthetic model cases verify deployment scope
and rejection of production, inconsistent binding, and newer unreviewed lineage.

Two fresh real beta probes each issued a governed Data Integrity credential (200),
verified it (200, allow), and rejected a changed proof (422, not verified). Their
attempt IDs and credential hashes differ. Each reads the active template and
checks exact release/component/image bindings before and after the operations.
The separate postcheck reconciles public release/manifest/UI metadata, container
identities, OCI labels, and maintenance preflight. It initially received a 403 with
Python's default user agent; the existing browser-style probe user agent passed.
No source or credential assertion was relaxed to address that transport failure.

These are unrecorded VC-API companion checks. A separate program reconciled the
reports and Git bytes; no independent human or worker review is claimed. The
primary/legacy demo portfolio is still unqualified. Earlier primary pairs remain
historical; current full recorder runs, independent wallets, Canvas, and final
editorial acceptance are still required. No recordings or publications were made.

The lifecycle integration also incorporates the actual deployed beta history.
Conflicts retain exact session-result matching, request cancellation, and native
authenticated disclosure inventory. Filtered policy claims are not presented as
the complete mdoc disclosure inventory. A shared result reader serves QR polling
and history, and the UI client uses the canonical VC-API routes. All 41 focused
result/history/QR/client tests pass with reused local dependencies. The first
merged fixture lacked authenticated disclosures and was corrected to use the
native contract; the negative filtered-claim test remains. No clean local UI build
is inferred; hosted checks remain required.

Operational entry points remain in the governed workspace:
`audits/beta-release-20261018/direct-vc-auth-overlay.py`, its scope tests and
postcheck, plus `audits/demo-audit-20261018/launch-direct-vc-di-functional.py`.
The active probe is now reviewable source at
`tests/scripts/audit-beta-direct-vc-api.js`. The old workspace probe is historical.
Overlay rollback, connector-reference custody, current-model hashes, and the
global beta operation lock are reused. Unselected beta identities are protected;
unrelated projects can change independently and are not a stability invariant.

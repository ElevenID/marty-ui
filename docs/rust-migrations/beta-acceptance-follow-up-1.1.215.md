# Beta acceptance follow-up: v1.1.215

## Why a new release

Immutable `v1.1.214` was qualified, published and deployed successfully to beta
at source `24f5d5dc0bb47d3dadb118b4dbe45191c5cf71b1`. Deployment markers and
health checks passed, and all 29 production container invariants were unchanged.
These checks did not prove complete UI startup or demo acceptance.

The release-bound KMS recording passed authentication and the custom ElevenID
Keycloak theme, but production CSP blocked WebAssembly compilation and prevented
organization state restoration. The failed recordings remain evidence; no
successful final recording is claimed. A browser-only candidate-header diagnostic
confirmed the correction but does not qualify the released artifact.

## Required protected changes

- `#781`: invoke the exact-image Rust verifier migration during restored-backup
  rehearsal and live beta cutover, before application startup. Official images
  remain digest-bound; local builds are pinned to their immutable image ID.
- `#782`: permit WebAssembly compilation under the production CSP while retaining
  JavaScript eval/inline restrictions and existing allowed origins. The browser
  CI gate executes the configured policy and a negative control.

Both corrections are merged in protected source
`f20f3e0f5071fdf94078a9222b517188cdd82a82`. Reviewed-file equivalence and the
exact four-path `#782` merge delta were independently verified before bringing
this activation branch onto that source.

The selected `v1.1.215` live lock changes only the release coordinate. Every
component pin, the `eligible` release-state contract, the held example, verifier
comparison, provenance gate and production configuration remain unchanged.
Integration `v1.2.80` remains the separately verified static pin to `v1.1.214`;
the aggregate continues to use its existing `v1.2.79` qualification harness.

The recorder dependency correction separately merged through recorder PR `#38`
at `88079b1b91bd7dc4771fde6a5e672323a57689a3`, with 163 Node and three narration
tests passing, protected-main CI success and zero reported npm vulnerabilities.
Its only change is the transitive `qs` lock entry. Bind subsequent recordings to
that verified recorder source; all scenarios and assertion contracts are intact.

Preliminary read-only checks on 2026-09-05 found no `v1.1.215` Git tag or GitHub
release, no version tag on any of the three release images, and no recent claim
for this coordinate. The protected claim workflow must repeat its authoritative
absence and exact-main checks; this document is not a reservation or clearance.

## Required completion evidence

1. Merge both corrections and this activation through protected review/queue
   gates. Bind the claim to the exact protected-main commit; do not reuse a
   claimed coordinate after source changes.
2. Build, attest and qualify the aggregate through the normal digest-first
   release transaction. Independently verify published assets and exact image
   provenance. Resume a failed observation or transient qualification against
   its existing immutable checkpoint; do not rebuild merely because a poll ends.
3. Use the source-bound beta deployment runner, restored-backup migration
   rehearsals and before/after production invariants. Keep production unchanged.
4. Run full browser/credential acceptance and release-bound KMS/provider-switching
   recordings without response overrides, forced UI state or relaxed assertions.
5. Collect and evaluate the governed 7-day event-stream and 14-day revocation
   evidence for the accepted source. A single health/soak sample is insufficient.
6. Reconcile the static integration pin and roadmap with the actual published
   release; clean only owned, proven-merged worktrees and branches. Retain beta
   backups, failed recordings, release transactions and other workers' work.

This follow-up does not activate the standalone Rust Canvas worker or authorize
deleting reachable Python. Its whole-worker, PostgreSQL, configuration,
readiness and all-consumer parity gates remain part of the active migration goal.

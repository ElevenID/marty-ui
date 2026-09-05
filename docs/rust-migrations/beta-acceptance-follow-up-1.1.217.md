# Beta acceptance follow-up: 1.1.217

## Scope and status

This draft selects a new immutable aggregate coordinate, not a release claim,
publication, deployment or acceptance pass. It is based on reviewed UI793 head
`d43161c7dcd640f8bf1c4c388f5522cb910ac0fc`; wait for that prerequisite's protected
merge and content equivalence before making this activation ready.

Published/deployed216 at `89c66b07aceb937366390ae194e75ff09fd528b2` remains the
actual beta release. Its KMS switching recording and theme checks pass, but full
lifecycle, all demos, external device evidence and soak do not. Preserve every
original receipt, failed browser trace and recording without relabeling them.

Included forward fixes are UI789 complete checksum coverage, UI790 browser
installation ordering, UI791 feature-preserving CSP origins, UI792 native
deployment evidence transport, and UI793 checked private qualification plus
accurate recorder provenance labels. Recorder39/41 are already merged privately.
Local tests and local13-scenario qualification are not hosted acceptance evidence.

## Feature-preservation boundary

Only `release/stack-lock.json`'s aggregate coordinate changes in this activation,
along with its exact test assertion and current roadmap/evidence documentation.
Retain all component versions, sources, digests and qualification pins, Python
issuance0.1.72, integration qualification1.2.79 and calendar VERSION2026.08.0.
Do not route the standalone Rust Canvas worker or delete any reachable Python
worker, processor, webhook, integration or UI/demo capability. Other-worker
crypto commits are not implicitly selected; preserve their worktrees.

## Gates before and after release

1. Recheck absence of the candidate Git tag, GitHub release/draft and all three
   versioned OCI image tags. Preliminary absence is not reservation or authority
   to reuse a coordinate later. Finish exact-head maintainer review/tests, then
   merge793 and this activation through normal protected checks and merge queue.
2. Claim the exact protected source once; retain the transaction/claim identity.
   Do not change claimed source, restart a live run because a poll times out, or
   overwrite existing release/tag/registry evidence. Publish normally only after
   all existing release/qualification gates pass.
3. Independently verify the annotated tag/source, complete checksum subjects,
   all release asset bytes and signatures/provenance, all exact OCI image digests
   and source-bound attestations, and the release transaction.
4. Use the official beta wrapper from a fresh clean released worktree and fresh
   artifact/attempt paths. Select a reviewed recorder revision after terminal green
   checks and verify it is current recorder main. The private plan cannot enforce
   branch protection; remote-main equality alone is not governance proof.
5. Preserve databases/backups and compare production's exact before/after state
   against the post-host-reboot baseline. No production deployment, restoration
   or destructive state reset. Keep the Python Canvas consumer active until its
   whole-worker/routing gates pass.
6. Pack the original three deployment evidence files using the released native
   utility. Send the bundle only to private recorder intake, wait on its exact
   run handle, and require successful live portfolio qualification. Then supply
   the completed run, exact reviewed recorder SHA and original receipt hash to
   public lifecycle; retain the signed stack hash as an independent expectation.
7. Run the unchanged full browser/CSP, credential primitive, issuance/login,
   verification/renewal/revocation and public-demo acceptance gates. Record fresh
   release-bound demos, including the canonical KMS switching scenario, without
   replacing real behavior with mocks or deleting recently added UI capabilities.
8. Obtain genuine release-bound external wallet/device recordings and signed
   request/native handoff evidence. Complete the governed7/14-day acceptance soak
   and reconcile the Integration static release pin only after the new aggregate
   meets its gates. No green unit test, short health sample or qualification
   report substitutes for any of these requirements.

See [private intake and public lifecycle](private-demo-qualification-lifecycle.md).
Standalone Canvas worker configuration/loop/database/OAuth/error-phase parity,
CSCA lifecycle manager/monitor follow-up623 and feature-preserving dirty branch
cleanup remain part of the broader active goal, not completion claims of this
release-coordinate patch.

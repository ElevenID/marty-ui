# Held passport Rust qualification coordinate: 1.1.218

The stack lock selects `marty-ui@1.1.218` with `release_state=hold`.
This is a source and dependency review coordinate, not a release claim or beta
deployment. The prior 1.1.217 release predates the reviewed passport aggregate
and cannot supply the exact Rust images for protected disposable acceptance.

Before changing the lock to `eligible`, merge the aggregate passport correction
and deployment/restore writer fence through protected `main`. Record that exact main SHA and
confirm every pinned component artifact and revision still matches the source.
Recheck that the tag, GitHub release, and all three public image coordinates are
absent. In a separate reviewed change, make the lock eligible and pass protected
checks; then use `prepare-stack-tag.yml` and `cd.yml` on the same exact main
commit as described in [Beta releases](../BETA_RELEASES.md). Do not create a
tag or release by hand.

The resulting immutable Rust images can qualify the **pre-deletion** packaged
and protected disposable gates in
`contracts/passport-rust-only-retirement-behavior.json`. A release is not a
deployment. The required base Compose, selfhost Compose, and independent
Kubernetes proofs must exercise the Rust nine-route flow, Marty simulator,
KMS-backed issuer profile and certificate chain, signed same-job callback,
batch behavior, job restart/resume, and production isolation. Separately,
attest a durable passport-scoped write fence and the real beta cutover drain
against the exact source; a failed drain blocks cutover and must preserve every
existing job and artifact. The current beta Python `issuance` container also
serves unrelated routes, so stopping the whole container would lose those
features. Credentials PR #305 currently requires that whole writer to be
stopped; its gate and the missing protected producer must be revised together
to verify a passport-scoped fence. The deployment/restore mutex alone does not
fence live passport writes. Independent
review must resolve regression findings before Python passport deletion.

Once those gates pass, verify the exact head of the prepared
[Credentials deletion PR](https://github.com/ElevenID/marty-credentials/pull/305),
implement its missing protected final cutover producer, and pass its later
beta drain attestation and post-cutover CI on that head. Resolve review
findings before merging the deletion. The producer and receipts are currently
absent, so this gate is not yet achieved. Claim a
final immutable aggregate release from
the post-deletion source, then perform **one beta-only deployment** and
acceptance soak. A different unused coordinate will be needed if 1.1.218 was
already claimed for pre-deletion qualification. A failed post-deployment probe
halts new beta passport writes and calls for a reviewed Rust fix and retest;
it does not select a Python passport owner. Production remains unchanged.

The lock's current Credentials issuance component is a pinned aggregate
dependency. Its Python image is not a passport rollback requirement. Review
and update every final release pin when Python passport code is deleted.

# Passport Rust qualification coordinate: 1.1.219

This coordinate was claimed in run `36942611050` and stopped before promotion
in stack-release run `36942661031`. The public-stack smoke used the pinned
integration harness `v1.2.79`, which started retained Python issuance without
the native DIDComm owner and exited when the retired encryption callables were
absent. The tag, release, and versioned images were not published. Do not reuse
this claim or coordinate. The reviewed harness correction was released as
`marty-integration-tests@v1.2.81`; continue with the
[1.1.220 qualification coordinate](passport-predeletion-release-1.1.220.md).

The stack lock selects `marty-ui@1.1.219` with `release_state=eligible` only
after the reviewed aggregate, the pre-promotion guard, the two release-gate
repairs, and Rust build audit #1022 reach protected main.
The [1.1.218 claim](passport-predeletion-release-1.1.218.md)
was tombstoned after qualification failed and cannot be reused. This
eligibility is not a release claim or beta deployment. The prior 1.1.217 release
predates the reviewed passport aggregate and cannot supply the exact Rust images
for protected disposable acceptance.

Record the exact protected-main SHA and confirm every pinned component artifact
and revision still matches the source. Recheck that the tag, GitHub release,
and all three public image coordinates are absent. Once this separate eligibility
change passes protected checks, use `prepare-stack-tag.yml` and `cd.yml` on
the same exact main commit as described in [Beta releases](../BETA_RELEASES.md).
Do not create a tag or release by hand.

The resulting immutable Rust images can qualify the **pre-deletion** packaged
and protected disposable gates in
`contracts/passport-rust-only-retirement-behavior.json`. A release is not a
deployment. The required source-bound protected disposable run must prove six
owned Rust service images, all nine routes, tenant isolation, the managed KMS
CSCA/DSC chain and SOD signing, the two-job Marty simulator batch, signed
same-job callbacks, job restart/resume, and production isolation. The separate
base Compose, selfhost Compose, and Kubernetes live consumer fixture remains
optional later work in #944. Separately,
attest a durable passport-scoped write fence and the real beta cutover drain
against the exact source; a failed drain blocks cutover and must preserve every
existing job and artifact. The current beta Python `issuance` container also
serves unrelated routes, so stopping the whole container would lose those
features. Credentials PR #305 now calls for a passport-scoped fence; its
protected producer is implemented, while exact-head runtime receipts remain missing. The
deployment/restore mutex alone does not fence live passport writes.
Independent review must resolve regression findings before Python passport
deletion.

Once those gates pass, verify the exact head of the prepared
[Credentials deletion PR](https://github.com/ElevenID/marty-credentials/pull/305),
run its protected final cutover producer, and pass its later beta drain
attestation and post-cutover CI on that head. Resolve review findings before
merging the deletion. The runtime receipts are currently absent, so this gate
is not yet achieved. Claim a
final immutable aggregate release from
the post-deletion source, then perform **one beta-only deployment** and
acceptance soak. A different unused coordinate will be needed after 1.1.219 is
claimed for pre-deletion qualification. A failed post-deployment probe
halts new beta passport writes and calls for a reviewed Rust fix and retest;
it does not select a Python passport owner. Production remains unchanged.

The lock's current Credentials issuance component is a pinned aggregate
dependency. Its Python image is not a passport rollback requirement. Review
and update every final release pin when Python passport code is deleted.

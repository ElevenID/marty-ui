# Beta aggregate coordinate proposal: 1.1.218

Signing Keys aggregate #913 merged to protected main at
`c70aa64492f135d3ffd54dc10c8a9867fc39528f`. This local hold proposal is
rebased on passport aggregate #919, which is still awaiting protected gates and
merge. The proposal has no protected-main release authority. After the final
intended passport wave merges, record the exact main SHA and verify that it
contains the reviewed aggregate behavior before merging this coordinate. No
tag, claim, image, release, deployment, or acceptance is created here.

The lock selects `marty-ui@1.1.218` but keeps `release_state=hold`. The claim
workflow requires `eligible` and therefore cannot claim this proposal even if
it is merged early. A separate reviewed eligibility change is required after
the final aggregate source is on protected main. The lock already pins
Credentials issuance 0.1.78 at commit
`efd5da1e2d41419ce93721f98d314c7b911e6b5e` and OCI digest
`sha256:e7bb482120837c68af6cec2f6d1d5276488de440b93fc811987860b7b99b4657`.
That release matches the three frozen Python passport route source hashes. The
published 1.1.217 stack instead contains Credentials issuance 0.1.72 and a
different UI source; its manifest cannot qualify this rollback plan.

On 2026-09-27, read-only checks found no `v1.1.218` Git tag or GitHub release,
including drafts, and no `1.1.218` registry manifest for any of the `ui`,
`services`, or `migrations` images under `ghcr.io/elevenid/marty-ui-oss`.
Absence is provisional and must be checked again by the protected claim workflow.

After the final aggregate and this proposal merge, review an eligibility patch
that changes only `release_state` to `eligible`, along with its exact assertion.
Once that patch passes protected checks and merges, record the new protected
main SHA and verify it includes the final aggregate. Then run the documented
sequence in `docs/BETA_RELEASES.md`: dispatch `prepare-stack-tag.yml` with
`tag=v1.1.218` and that exact main `source_sha`; retain the successful claim
run ID; then dispatch `cd.yml` with that `claim_run_id` on the same source.
The claim requires the configured merge-group checks and absence of all public
coordinates. The release workflow builds and attests the three UI images, runs
public-stack and verifier qualification, and requires `stack-release` environment
approval before publication. It writes a signed, checksummed aggregate manifest
only after the gates pass. Do not manually create a release draft or reuse a
tag if any coordinate appears before the claim.

This coordinate patch does not approve a beta deployment, passport cutover,
Python deletion, or production change. The disposable Rust-to-Python rollback,
issuer-profile/KMS and provider inputs, protected beta lifecycle, and aggregate
soak retain their separate runtime gates.

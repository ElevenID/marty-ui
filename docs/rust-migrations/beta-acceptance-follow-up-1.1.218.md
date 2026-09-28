# Beta aggregate coordinate proposal: 1.1.218

Signing Keys aggregate #913 merged to protected main at
`c70aa64492f135d3ffd54dc10c8a9867fc39528f`. Passport aggregate #919
merged to protected main at `2cbbab9f37ab0fe7c17dcfd4c69212dc46eb9e3d`.
This local hold proposal has no protected-main release authority. After the
remaining digital handoff and Rust migration work merges, record the exact main
SHA and verify that it contains the reviewed aggregate behavior before making
this coordinate eligible. No
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

After the remaining digital and Rust wave merges, review every held-lock
component pin against the final protected source and its immutable artifacts;
refresh stale pins in a separate reviewed patch while `release_state` stays
`hold`. Only after that patch passes protected checks should an eligibility
patch change `release_state` to `eligible`, with an exact assertion that all
pins and acceptance gates still match. Once it merges, record the new protected
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
Python deletion, or production change. The current passport Python retirement
requires the disposable Rust-to-Python rollback, KMS-backed CSCA/DSC issuer
profiles, exact native two-job simulator batch with signed same-job callback,
nine-step Flow, D-12 recording, protected beta lifecycle, production-isolation
proof, and aggregate soak. The later digital handoff adds its managed delivery
destination, exact encrypted package, and independent review gates. External
physical paperwork is outside Marty and neither route claims a real booklet.

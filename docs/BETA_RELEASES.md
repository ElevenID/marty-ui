# Beta stack releases

Marty beta delivery is an aggregate, immutable Rust stack release. The former
per-repository Python-wheel beta process is retired. Do not publish or install
Python MMF beta packages and do not recreate `release-beta.yml` workflows.

## Release sequence

1. Merge every coordinated component through its protected default branch and
   record each exact revision in the stack inputs.
2. Dispatch **Prepare stack tag** on exact protected `marty-ui/main`. It checks
   the configured merge-queue and code-scanning results, creates the annotated
   `v*` tag in an evidence bundle, and records its exact object and source SHA.
   The accountable maintainer verifies and imports that bundle, publishes the
   previously unused tag through a temporary scoped tag-rule bypass, restores
   the rule immediately, and lets the tag event start
   `.github/workflows/cd.yml` at the immutable tag.
3. Allow that workflow to validate the coordinated revisions, build the Rust
   service plane, publish immutable OCI images, SBOMs, attestations, checksums,
   and the atomic release manifest, and retain rollback evidence.
4. Deploy the manifest's exact image digests to beta as one aggregate change.
   Production deployment is a separate decision and is not part of this gate.
5. Dispatch **MIP 0.4 Beta Credential Lifecycle** from
   `.github/workflows/e2e-tests.yml` with the successful stack-release run ID,
   release version, exact Marty UI and Marty Protocol revisions, beta source
   snapshot, audit organization, and beta origin.
6. After the lifecycle passes, dispatch **MIP 0.4 Wallet Conformance And
   Release Attestation** from `.github/workflows/wallet-conformance.yml` with
   the immutable release and lifecycle run IDs plus the protected device-lab
   evidence URL and SHA-256.

## Protection and evidence requirements

The three workflows fail closed through the repository's shared release-
environment preflight. `stack-release`, `beta-lifecycle`, and
`wallet-conformance` must disallow administrator bypass, restrict deployment
branches or tags, and require the named accountable maintainer review. This
repository currently has one active maintainer, so `burdettadam` may approve
their own deployment after the governed pull request and required status checks
pass; an alternate identity must not be used to manufacture independence.

The accepted evidence set must bind every result to the same release version,
source commit, stack-release run, beta source ID, and deployed image digests.
Retain the last known-good beta images, release manifest, SBOMs, signature
bundles, checksums, lifecycle report, and wallet attestation until a newer
aggregate release completes the same gates.

## Recovery dispatch

The **Stack release** workflow re-downloads the completed preparation evidence.
It rejects branches, lightweight tags, tags not on the exact protected `main`
commit, tag objects that differ from the preparation bundle, failed preparation
runs, and tags with an existing release. A lost tag event is recovered by
dispatching `.github/workflows/cd.yml` at that same immutable annotated tag.

Do not use a branch workflow dispatch as a substitute for an immutable release,
and do not mix independently built component versions in beta.

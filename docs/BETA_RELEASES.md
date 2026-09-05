# Beta stack releases

Marty beta delivery is an aggregate, immutable Rust stack release. The former
per-repository Python-wheel beta process is retired. Do not publish or install
Python MMF beta packages and do not recreate `release-beta.yml` workflows.

## Release sequence

1. Merge every coordinated component through its protected default branch and
   record each exact revision in the stack inputs. The coordinated set includes
   the Rust verifier and the demo recorder because their executable behavior is
   part of release qualification even though they are not service images.
2. In a separate reviewed change, set the exact absent stack coordinate to
   `eligible`, then dispatch **Prepare stack release claim** on that exact
   protected `marty-ui/main` commit. It checks the configured merge-queue and
   code-scanning results, release environments, component attestations, and
   absence of every public coordinate before writing a durable claim artifact.
   Preparation creates no tag, image, release, or deployment.
3. Dispatch **Stack release** from `.github/workflows/cd.yml` on the same exact
   protected-main commit with the successful claim run ID. It authenticates the
   claim and pinned integration source, builds and attests content-addressed
   Rust images, runs the public-stack and verifier gates against those exact
   digests, and retains resumable transaction checkpoints. Only after every
   qualification gate passes may it promote the version tags, create the
   annotated source tag, publish the GitHub release with exact SBOMs,
   attestations and checksums, and seal the terminal transaction.
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
complete component revision map, stack-release run, beta source ID, and deployed
image digests. Local aggregate deployment refuses dirty coordinated worktrees;
the live Rust gateway publishes the same exact component map for recorders and
acceptance gates to compare.

After the live markers match, the local beta runner creates a hashed
`deployed-demo-manifest.json` evidence artifact. Its
`DEPLOYED_PENDING_EVIDENCE` state binds exact revisions and image digests while
truthfully leaving recording timestamps and evidence hashes empty. Recorders use
that artifact; only a later evidence-finalization step may claim completed
recordings or publication readiness. This avoids embedding an image's own final
digest inside that same immutable image.

Run the public demo acceptance gate with `REQUIRE_LIVE_DEMO_BINDING=1` and
`DEPLOYED_DEMO_MANIFEST_PATH` set to that artifact. The gate requires the
public manifest to remain an unbound `PENDING_DEPLOYMENT` template, then
compares every component revision and image digest in the separately stored
post-deployment artifact with the live Rust release marker. The protected
lifecycle workflow instead supplies its already validated release version,
beta source ID, and Marty UI revision as independent dispatch inputs.

Retain the last known-good beta images, release manifest, SBOMs, signature
bundles, checksums, lifecycle report, and wallet attestation until a newer
aggregate release completes the same gates.

## Official release deployment on the beta host

Use the official-stack mode for a release produced by `.github/workflows/cd.yml`.
It is intentionally separate from the non-promotable local-worktree snapshot
mode. The official mode accepts only the downloaded `stack-manifest.json` and
its exact `SHA256SUMS` entry, an annotated release tag at the executing commit,
and the explicitly selected current `marty-demo-recorder/main` revision. It verifies the
manifest attestation, pulls every runtime image by digest, verifies OCI version
and revision labels, and records registry digests in deployment evidence. It
does not rebuild released images.

Select that recorder SHA only after maintainer review and terminal green checks.
The recorder repository's current GitHub plan does not enforce branch protection;
the wrapper verifies remote-main equality, not protected-branch governance. New
receipts label this input `explicit-recorder-revision`, never an unverified claim
of protection. Preserve historical receipts byte-for-byte rather than relabeling
them. See the [private qualification/lifecycle sequence](rust-migrations/private-demo-qualification-lifecycle.md)
for the checked acceptance prerequisite and private evidence handling.

Create a clean detached worktree at the published tag. Keep the release bundle
under that worktree's ignored `tests/artifacts` directory and reference the
host's existing beta environment files explicitly:

```powershell
$releaseTag = "v1.1.205"
$releaseWorktree = "C:\beta-release-worktrees\marty-ui-$releaseTag"
$releaseArtifacts = Join-Path $releaseWorktree "tests\artifacts\$releaseTag-official"
# Replace with the exact revision already reviewed after its checks passed.
$recorderRevision = "REVIEWED_RECORDER_40_CHARACTER_SHA"

git fetch origin --tags
git worktree add --detach $releaseWorktree $releaseTag
New-Item -ItemType Directory -Force -Path $releaseArtifacts | Out-Null
gh release download $releaseTag --repo ElevenID/marty-ui --dir $releaseArtifacts

& (Join-Path $releaseWorktree "scripts\deploy-canvas-oss-beta.ps1") `
  -ArtifactDir $releaseArtifacts `
  -AuditPath (Join-Path $releaseArtifacts "beta-deployment-audit.json") `
  -OfficialStackRelease `
  -RecorderRevision $recorderRevision `
  -TunnelEnvFile "C:\beta-runtime\.env.tunnel.beta.local" `
  -GeneratedEnvFile "C:\beta-runtime\.env.beta.generated.local"
```

The runner validates every release and source input twice, with the final check
immediately before the maintenance window. It retains the existing preflight
backup, isolated migration rehearsal, quiesced backup, supervised rollback,
runtime-marker, public-origin, and self-host-production invariant gates. A
`-PlanOnly` invocation of the lower-level runner performs no artifact writes;
the governed Canvas wrapper intentionally performs the actual maintenance-window
deployment and audit.

## Recovery dispatch

The **Stack release** workflow re-downloads either the original claim or one
explicit later checkpoint. Supply `resume_run_id` and `resume_artifact`
together; the checkpoint allowlist, transaction identity, claim run, source
SHA, stack-lock digest, state, image digests and attestations must all still
match. Rerunning the original workflow run retains its exact source. A new
dispatch is accepted only while protected `main` still equals the claimed
source SHA, so current trusted workflow code is never selected from transaction
data.

If exact-source completion is no longer possible, publish a conflict tombstone
through `.github/workflows/tombstone-stack-release.yml`; never retarget or reuse
the claimed coordinate. Do not create a tag or release by hand, substitute a
different branch dispatch, or mix independently built component versions in
beta.

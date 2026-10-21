# Beta stack releases

Marty beta delivery is an aggregate, immutable Rust stack release. The former
per-repository Python-wheel beta process is retired. Do not publish or install
Python MMF beta packages and do not recreate `release-beta.yml` workflows.

## Developer validation

Use isolated working branches and local builds for developer testing. Do not
wait for hosted CI, an aggregate release tag, or published images to exercise
a candidate feature. Combine related repairs into larger reviewable commits.
Run a focused behavioral check for the concrete change; broaden testing when a
failure or an affected boundary warrants it. Full release qualification remains
part of publication and promotion, rather than a prerequisite for each experiment.

For UI work, reuse installed dependencies and run `npm run build` from `ui` with
`DISABLE_PRERENDER=1` when testing application behavior. This checks TypeScript
and bundles the application without the unrelated marketing prerender step.
Record the exact source and distinguish local results from deployed-beta results.
Use beta-only guarded local build/overlay paths for runtime experiments, preserving
backup, recovery, credential custody, and production isolation. A local candidate
does not acquire official release status from a successful developer run.
`create_local_release_manifest.py` accepts clean branch commits for this local
path, snapshots the coordinated sources, and binds their exact commits and bytes.
Its recorded `origin/main` revision is informational; verification does not wait
for those branch commits to merge. Dirty or changed sources and any claim that
the local snapshot is promotion-eligible or release-ready remain rejected.

For separately prepared developer runtime images, `-UsePreparedLocalImages`
accepts the local `elevenid-local/services`, `db-migrate`, and `ui` tags for the
snapshot's release label. The runner resolves each tag to an immutable image ID,
checks Linux/amd64 and exact source/version labels through that ID, and reuses
the shared service selectors. It skips image builds while retaining source
verification, rehearsal, backups, maintenance fencing, and recovery. This option
cannot be combined with `-OfficialStackRelease`.
`-PlanOnly` checks the current passport fence boundary, prepared image inputs,
and paired DIDComm/passport configuration; execution repeats those checks under
the deployment lock. DIDComm uses the existing native HTTPS custody validator
for the current TLS/Raft profile, including when encrypted delivery is disabled.

`scripts/generate_local_runtime_dockerfiles.py --source <checkout> --output <directory>`
derives service, migration, and public UI runtime recipes from the production
Dockerfiles. It preserves their runtime stages and replaces only compiler/asset
inputs with named `local_binaries` and `local_assets` contexts. Linux binaries are
copied with executable permissions even when their context is on a Windows drive.
The generator checks the service executable inventory against the shared build
script; it does not build or qualify images. Supply freshly built UI assets with
the snapshot's `marty-ui-release.json`. The prepared-image runner checks that
served marker as well as image labels before starting maintenance.

Use `scripts/smoke_local_beta_ui.py --image <image-id> --source-manifest <manifest>`
for a quick local UI component check. It starts an owned loopback-only container,
checks the homepage, console shell, served marker and local script MIME types,
requires the UI alone to refuse stack readiness, and removes its container.
This is component validation, not an authenticated demo or full-stack qualification.

The shared Compose graph waits for organization health before starting
revocation-profile. Native TLS startup eagerly connects to that gRPC service;
starting both together can exhaust the health retries and abort dependent
application startup even though organization becomes healthy moments later.
Keep the dependency in the shared graph instead of weakening the health check.
If a prior rollout already completed migrations and stopped during application
startup, inspect the retained artifacts and use the guarded
`complete-local-beta-startup.ps1` path. Do not replay migrations to restart
already prepared application containers.

After an authorized beta database reset, a host passport-fence marker can still
refer to the retired PostgreSQL cluster. Use
`reconcile-reset-beta-passport-fence.ps1 -PostgresContainer <full-id>` to inspect
that condition without mutation. The tool requires the running beta PostgreSQL
container, no current passport fence schema, an intact installation receipt, and
different old/current container and PostgreSQL system identities. With `-Apply`
and a new `-OutputPath`, it acquires the deployment lock, rechecks the evidence,
archives the original marker beside itself and retains a reconciliation receipt.
It changes no database state. A live fence, same-cluster restart, incomplete
intent, changed receipt, or production target remains rejected. Never delete a
marker merely because a local deployment is blocked.

State-volume names are resolved from the actual beta PostgreSQL, Redis, applicant
and OpenBao mounts. The shared plan requires exact project/resource ownership,
records each volume's creation identity, and rejects foreign/shared attachments
except stopped successful beta OpenBao initializers. Deployment pins those
existing volumes as external resources, so a reset-specific name is preserved
and a missing volume cannot be silently created. Backups retain the plan;
restore checks it before stopping services or writing data. A historical backup
without explicit volume bindings requires investigation before restore.
Backup directories restrict access to the current user, SYSTEM and local
administrators on Windows (mode 0700 elsewhere). OpenBao backup uses its native
Raft snapshot command with credentials kept inside the node; the separate static
custody archive excludes the live Raft directory. Database restore preserves the
running OpenBao state; disaster recovery of its retained snapshot is separate.
Rehearsal readiness uses argument arrays and captures expected native startup
errors without changing the caller's failure policy. Its temporary OpenBao CA
is read through `exec` and accepted only as a public PEM certificate; Docker's
archive API cannot retrieve that tmpfs file on the beta host.

For a failed cutover whose application state is unchanged,
`recover-unchanged-local-beta.ps1` can inspect the retained quiesced backup and
the exact prior container set. It holds the host deployment mutex, checks volume
identities and backup hashes, compares both databases with native dumps while
preserving SQL/data bytes, and checks the applicant store. With `-Apply` it starts
only those stopped prior containers, verifies their health and original local/
tunneled API/UI bindings, then clears the pending marker. It restores no database
and modifies no KMS state. A changed database, image, owner, volume or active job
requires investigation and forward repair instead. Keep the original failed
cutover and recovery receipts; recovery is not an updated-beta qualification.

An update of an already initialized beta uses the production ordinary-migration
contract: KMS/DID initialization is disabled, the initialization token is absent,
and only the Notification envelope token and public CA are mounted. The separate
initialization role's short-lived token is not a signing-key rotation mechanism.
Native database, issuance and revocation migration jobs use frozen image IDs with
their build definitions removed. Rehearsal and live migration run the same normal
migration entrypoint, including Notification schema migration. An existing Raft
node is checked for readiness rather than rerunning its fresh-only initializer.
The durable configuration includes every initializer script and policy; missing
bind sources cannot become empty directories that falsely report success.

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
`wallet-conformance` disallow administrator bypass and restrict deployment
branches or tags. The protected `stack-release` environment has no required
reviewer, so a qualified release can continue without a manual deployment
approval. `beta-lifecycle` and `wallet-conformance` still require their named
accountable maintainer review.

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

For the post-deletion Rust passport aggregate, follow the
[passport aggregate acceptance checklist](rust-migrations/next-aggregate-beta-acceptance.md)
and use `scripts/run-passport-beta-aggregate-deploy.ps1` with the final signed
manifest and protected fence, maintenance, and native migration receipts. Its
public acceptance soak completes the cutover. The `deploy-canvas-oss-beta.ps1`
path below calls `deploy-local-beta-release.ps1`, which still invokes Python
migrations; reserve that path for earlier non-passport beta deployments.

The procedure below uses the official-stack mode for an earlier non-passport
release produced by `.github/workflows/cd.yml`.
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
  -TunnelTokenEnvFile "C:\beta-runtime\private\connector-token.env" `
  -GeneratedEnvFile "C:\beta-runtime\.env.beta.generated.local"
```

`TunnelTokenEnvFile` must contain only `TUNNEL_TOKEN=<active token>` and stay in a
private, unlinked file outside OneDrive. Use the existing protected connector
input from the last completed rotation; never copy an old token from a repository
environment file. The runner verifies its access controls and exact match to the
running beta connector, then binds the file fingerprint and container identity
through the final pre-maintenance check. Missing, stale, changed or foreign
credentials fail before maintenance. Planning reads these inputs but writes no
override. Actual deployment adds a public-path-only Compose override that removes
the old inline value and resolves the protected input file. Connector commands
use the token environment rather than a secret argument. This does not rotate a
token or restart the existing connector.

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

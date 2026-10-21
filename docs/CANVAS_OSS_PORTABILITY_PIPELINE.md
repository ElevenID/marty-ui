# Unmodified Canvas OSS portability pipeline

This lane runs a source-pinned, unmodified Canvas LMS against the deployed Marty development system at `https://beta.elevenidllc.com`. Canvas is publicly reachable at `https://canvas-test.elevenidllc.com` through the beta stack's existing Cloudflare tunnel.

It is intentionally separate from `docker-compose.profile.canvas-real.yml`, the packaged Rust Canvas demo seeder, and the Canvas sandbox. Those tools remain useful for deterministic development, but their Rails-runner bootstrap, localhost metadata bridge, synthetic AGS event path, and Canvas Credentials receiver are not portability evidence.

## Current implementation boundary

The upstream source image build runs on a disposable GitHub `ubuntu-24.04` VM;
it does not need the beta Docker socket, tunnel, credentials, or WSL runner.
`prepare_canvas_source_builder.py` removes only a fixed inventory of unrelated
preinstalled SDK directories on that hosted VM, then requires at least 80 GiB
free on the actual Docker backing filesystem and 12 GiB Docker memory. It
rejects local/self-hosted invocation before Docker access or SDK removal. Hosted
capacity is measured, never assumed: insufficient capacity fails the source
build. GitHub advertises only 14 GB standard-runner storage; SDK reclamation is
an attempted workaround, not a guaranteed capacity allocation.

Default-branch publication, the protected `canvas-oss-image-publish` environment,
pristine upstream source, immutable base-image conversion, SBOM and keyless
provenance remain required. A published digest still needs review and lock-file
promotion. This does not qualify Canvas or relax the separate local beta
portability runner's Docker integration and physical capacity checks.

References: [GitHub runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and [Ubuntu hosted image inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md).

The stock source image was published by [run 39527943630](https://github.com/ElevenID/marty-ui/actions/runs/39527943630), pulled locally, and promoted to `published` in the lock after registry hashes, source labels and GitHub attestation verification. The [review receipt](canvas-oss-image-review-20261020.json) records the immutable digest and verification inputs. This completes image acquisition; it does not qualify the Canvas runtime or D07/D08.

The harness has an executable `readiness_only` mode. Recheck the actual host's Docker backing capacity, memory, integration and beta network/tunnel bindings before starting it; earlier host observations are not current readiness evidence. The local stock Canvas bootstrap, public LTI navigation, wallet operations and fresh negative/recovery contract still require real execution. No successful nightly or portability run is claimed.

After the dedicated distro, runner binary, reviewed image digest, and coordinated beta release exist, `readiness_only` starts the honest topology, verifies the deployed beta capability and public Canvas route, and emits `status=readiness_only`; it cannot be promoted or used by the demo recorder as portability proof.

The scheduled and default manual mode is `full`. It fails closed until the `canvas-contract` Docker Compose one-shot runs `tests/scripts/run-canvas-oss-standard-contract.js` against the real standard flow. Chromium, Playwright, API driving, and video capture stay inside that service; no browser or demo process runs natively in Windows or WSL. The driver must create sanitized `observations.json` from real Canvas UI, LTI 1.3/LTI Advantage, documented Canvas REST APIs, and a real wallet/KMS badge claim. A missing driver, case, environment value, video, container provenance record, or observation fails rather than becoming a skip.

## Reproducible Canvas image

The reviewed lock is [canvas-oss.lock.json](../deploy-config/catalog/canvas-oss.lock.json). It pins:

- upstream repository `instructure/canvas-lms`;
- official annotated tag `release/2026-05-06.409` (tag object `116bf6129f2658f0c292f6242f966b19c1117309`), peeled commit `b6932922d0d06cef2667820a4dd6560b667e2bef`, and source tree `63f3a4528a7daaccc057eb4e2acac93af89d3c92` (`stable/2026-05-06`);
- upstream `Dockerfile.production`;
- an immutable GHCR digest after it has been built and reviewed.
- immutable Postgres, Redis, Mailpit, and edge-proxy dependency digests;
- the upstream `instructure/ruby-passenger:3.4-jammy` index and Linux/amd64 child digests used by `Dockerfile.production`;
- the locked Linux/amd64 Playwright base-image digest, dedicated contract Dockerfile, Playwright-only package lock, zero-high/critical npm audit gate, Compose service identity, and secret-file transport.

Run **Canvas OSS Source Image** manually from reviewed `main` on its disposable
GitHub `ubuntu-24.04` VM. The source builder reclaims its fixed hosted SDK inventory
and requires measured Docker backing capacity before building; it does not use
the local WSL runner. That runner is required separately for beta portability.

The source workflow checks out the annotated upstream tag, verifies its tag
object, peeled commit and Git tree, rejects a dirty worktree, verifies the locked
upstream base-image manifests, and applies the reviewed BuildKit source policy
without editing the Canvas Dockerfile. It publishes SBOM/provenance and
release/ref/base labels plus the source-policy digest in a fixed image manifest.
Base verification fetches the locked index and Linux/amd64 child by digest,
hashes their raw bytes, and checks the exact platform-to-child binding. A later
change to the upstream tag does not select a new base or invalidate the pinned one.
Review that manifest, then update `image.digest` and set `image.digest_state` to
`published` in the lock. Acceptance rejects a manifest whose tag, source/tree SHA,
base image, source policy, labels or output digest differs from that reviewed lock.

Create the `canvas-oss-image-publish` GitHub environment with a custom deployment
branch policy allowing only the `main` branch. The source image publication
environment has no required-reviewer gate, as authorized by the maintainer;
manual dispatch from reviewed main authorizes building and publishing the pinned
image. A successful publication still requires manifest review and lock-file
promotion before portability acceptance. The image workflow admits only a manual
run from `ElevenID/marty-ui` `main`; all third-party Actions in the image,
portability, and hosted-Canvas workflows are pinned to reviewed full commit SHAs.

## Local runner and beta prerequisites

For local development with the reviewed Canvas image already pulled, use
`scripts/run-local-canvas-runtime.ps1 -ArtifactDir <new-output-directory>
-BetaDeploymentManifest <actual-local-deployment-manifest>`. It checks the exact
published digest, upstream/base labels, Linux/amd64 platform, beta source and
Compose ownership, and physical free space on the Windows volume containing
Docker Desktop's actual VHDX. Runtime reserves the larger of20GiB or twice the
present image size; upstream source builds retain the80GiB prerequisite. The
runtime mode cannot compile a Canvas source image or substitute an unreviewed
image. It uses the existing Windows `desktop-linux` endpoint, so a WSL socket
pointing at another daemon cannot silently select a different environment.

Add `-Bootstrap` to run the existing approved stock lifecycle and start its
isolated services. The wrapper holds the Docker runner and beta deployment
locks. Canvas, databases, the contract browser and continuity monitor remain
Compose containers. Source/image bindings, actual contract unit results, stock
bootstrap audit, public login, beta continuity and the self-host production
invariant are retained. Private operator keys/passwords remain under
`~/.codex/private`. Learner/API-key inputs are deliberately empty until real
full-contract authority is configured; unit results and bootstrap never qualify
D07/D08. This path neither registers a GitHub runner nor claims GitHub labels.

The required labels are `self-hosted`, `linux`, `x64`, and `canvas-oss-wsl2`. The overnight window is 02:00-06:00 `America/Denver`. GitHub schedules both 08:07 and 09:07 UTC and admits only the trigger that is 02:07 in Denver, so daylight-saving changes do not shift the local window. The job timeout leaves time for teardown before 06:00.

The timezone gate runs first on `ubuntu-latest`, so the out-of-window UTC trigger never consumes the one-job local runner. Scheduled admission also requires repository variable `CANVAS_OSS_NIGHTLY_ENABLED=true`; it must remain absent/false until runner setup and a dry run succeed. Once provisioned, the WSL runner is ephemeral: it registers with `--ephemeral` for one job using a fresh short-lived GitHub registration token. A Windows Scheduled Task must bring it online; a workflow cannot create an offline local runner.

One-time setup (partially completed on the current host):

1. From an elevated PowerShell prompt, obtain the current Linux x64 archive URL and SHA-256 checksum from **Settings -> Actions -> Runners -> New self-hosted runner**, then run:

   ```powershell
   .\scripts\setup-canvas-oss-runner.ps1 `
     -InstallUbuntuIfMissing `
     -RunnerArchiveUrl 'https://github.com/actions/runner/releases/download/vX.Y.Z/actions-runner-linux-x64-X.Y.Z.tar.gz' `
     -RunnerArchiveSha256 '<checksum shown by GitHub>'
   ```

   The setup fails closed if Ubuntu 24.04/WSL2, a non-root default user, `gh`, `jq`, `node`, `python3`, Docker Compose v2, the Docker Desktop socket, 80 GiB free disk, 12 GiB Docker memory, `elevenid-beta-network`, or the existing beta tunnel is unavailable. Tunnel services are discovered by the `elevenid-beta` Compose project and `nginx-proxy`/`cloudflared` service labels; both must be unique, running and attached to the exact network ID. Historical container names do not establish ownership. If WSL installation requires a restart or first interactive launch, it reports that boundary and must be rerun. Enable Docker Desktop integration for `Ubuntu-24.04`; do not install a second Docker daemon inside WSL.
2. Authenticate Windows GitHub CLI as an account or GitHub App installation able to administer repository runners: `gh auth login`. The setup script installs the WSL `gh` binary used by workflows, but it does not register a runner.
3. Run `.\scripts\register-canvas-oss-runner.ps1` interactively once. It requests a fresh short-lived GitHub registration token, registers `--ephemeral`, verifies server-side `self-hosted`, `linux`, `x64`, and `canvas-oss-wsl2` labels, and accepts one job in the foreground. Confirm GitHub removes it afterward.
4. Only after that dry run succeeds, register the daily local-time task:

   ```powershell
   $script = 'C:\Users\maree\OneDrive\Glthub\marty-workspace\marty-ui\scripts\register-canvas-oss-runner.ps1'
   $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
   $trigger = New-ScheduledTaskTrigger -Daily -At '1:50 AM'
   $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 5) -MultipleInstances IgnoreNew
   Register-ScheduledTask -TaskName 'ElevenID Canvas OSS one-job runner' -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest
   ```

The task follows the Windows `America/Denver` local clock. After its dry run, set repository variable `CANVAS_OSS_NIGHTLY_ENABLED=true`; until then scheduled triggers exit on GitHub-hosted infrastructure without queueing the absent local runner. An idle permanent runner is neither created nor expected; the repository normally returns to zero registered Canvas runners after each job.

The runner is orchestration only. Marty, Canvas, PostgreSQL, Redis, workers, mail capture, edge routing, the Playwright contract browser, video recording, and the beta continuity monitor all remain Docker Compose services on the existing Docker Desktop daemon and `elevenid-beta-network`; no application, browser, demo, or data-plane service is installed natively in Windows or WSL, and no second Docker daemon is permitted. The runner does not stop Docker Desktop, start another tunnel connector, or touch a `marty-selfhost-prod` workload. It records and temporarily stops only:

- `marty-canvas-real`;
- `marty-canvas-sandbox`;
- `marty-issuance-canvas-localhost-bridge`.

It restores entries that were running before the job. `retain_failed_state=true` retains only named Canvas data volumes; it removes Canvas containers and runtime configuration and restores the prior beta experiments.

The native WSL Actions runner remains an orchestration boundary, not part of the demonstrated stack. Its access to `/var/run/docker.sock` is root-equivalent control of the shared Docker Desktop daemon; running the agent itself in a container would not create a security boundary. The workflow must therefore remain dispatch/schedule-only, protected by the `canvas-oss-beta` environment, read-only GitHub permissions, and the explicit beta/self-host invariants. A future Compose-hosted runner also requires daemon-visible workspace paths or named volumes: Docker-outside-of-Docker cannot bind a path that exists only inside the runner container. The current WSL workspace and artifact/config/secret directories must remain bind-mountable by Docker Desktop.

The already-running beta deployment—not the GitHub job environment—must be healthy and configured in both `marty-issuance` and `marty-canvas-sync-worker` with:

```text
CANVAS_PORTABLE_INTEGRATION_ENABLED=true
CANVAS_PILOT_ORGANIZATION_IDS=<exact pilot organization ID; no wildcard>
CANVAS_LTI_EXPERIENCE_BASE_URL=https://beta.elevenidllc.com
CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST=https://canvas-test.elevenidllc.com
CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID=<system signing organization>
CANVAS_LTI_TOOL_ISSUER_DID=did:web:beta.elevenidllc.com:orgs:marty
CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS=<separate credential issuer profile inventory>
CANVAS_LTI_TOOL_ACTIVE_KID=<issuer DID>#<active verification-method fragment>
CANVAS_LTI_TOOL_PUBLIC_JWKS=<compact public-only RSA/RS256 JWKS>
CANVAS_LEGACY_EVENT_INGEST_ENABLED=false
```

`CANVAS_PRIVATE_ORIGIN_ALLOWLIST` remains separate and is not needed for this public hostname. `check_canvas_beta_capabilities.py` inspects the deployed container configuration without writing values to artifacts, requires the worker to run the same coordinated issuance image, and compares the configured public JWKS with the public beta endpoint. A job-level variable cannot satisfy this gate. The later binding readiness response must still pass `rollout_allowlist`, `worker_heartbeat`, `kms_issuer_configuration`, and `kms_did_sign_verify_challenge` plus every other blocking check; this preflight does not substitute for a live KMS sign/verify challenge.

The public runtime marker must match an explicit reviewed source ID and a coordinated full `local-deployment-manifest.json` plus sibling `source-manifest.json`. The manifest must bind `marty-gateway`, `marty-issuance`, and `marty-canvas-sync-worker` image IDs to the same release marker and snapshot. The current UI-only 20260714 manifest has `backend_images_reused=true` and is intentionally rejected.

Configure the protected `canvas-oss-beta` GitHub environment with:

- variable `CANVAS_OSS_IMAGE_BUILD_RUN_ID`;
- variable `CANVAS_OSS_EXPECTED_BETA_SOURCE_ID`;
- variable `CANVAS_OSS_BETA_DEPLOYMENT_MANIFEST` (absolute WSL path);
- variables `CANVAS_OSS_ADMIN_EMAIL`, `CANVAS_OSS_ORGANIZATION_ID`,
  `CANVAS_OSS_APPLICATION_TEMPLATE_ID`, and
  `CANVAS_OSS_CREDENTIAL_TEMPLATE_ID` (the exact active Open Badge pair approved
  for this lane);
- secrets `CANVAS_OSS_ADMIN_PASSWORD`, `CANVAS_OSS_MARTY_API_KEY`, `CANVAS_OSS_LEARNER_EMAIL`, and `CANVAS_OSS_LEARNER_PASSWORD`.

Missing core values fail every run; missing flow credentials fail full mode.

The Actions checkout contains only `marty-ui`, while the coordinated release build requires sibling repositories. The workflow therefore has no automated beta-deploy switch. Before acceptance, an operator runs `scripts/deploy-canvas-oss-beta.ps1` from the real Windows source workspace against a newly created full local-release artifact. That wrapper performs backup, rehearsal, live migration, and coordinated application/UI recreation; it does not drop beta databases or volumes. Point the protected environment at the resulting full deployment manifest. A destructive beta reset remains an operator action until its exact database/volume boundary and restore procedure are encoded; it must never touch `marty-selfhost-prod` state.

### Coordinated beta runbook

Run this only after every coordinated worktree is stable. Creating the manifest
freezes tracked and unignored source from all required repositories; any edit
afterward causes both the pre-build or post-build verification to fail. The
deployment wrapper itself admits only `02:00` through `05:59`
`America/Denver`.

```powershell
# Existing private beta TUNNEL_TOKEN file. Migrate legacy argv connectors first
# using docs/beta-connector-credential-migration.md.
$protectedBetaConnectorEnvFile = "C:\beta-runtime\private\connector-token.env"
$release = "canvas-oss-beta-local-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))"
$artifact = Join-Path $PWD "tests\artifacts\$release"
$snapshots = Join-Path $artifact "source-snapshots"
$manifest = Join-Path $artifact "source-manifest.json"
$audit = Join-Path $artifact "canvas-oss-beta-deploy-audit.json"

New-Item -ItemType Directory -Force -Path $snapshots | Out-Null
python .\scripts\create_local_release_manifest.py `
  --workspace .. `
  --release-version $release `
  --output $manifest `
  --snapshot-dir $snapshots
python .\scripts\create_local_release_manifest.py `
  --workspace .. `
  --verify-manifest $manifest

# Non-mutating plan review; this is safe before the maintenance window.
& .\scripts\deploy-local-beta-release.ps1 `
  -ArtifactDir $artifact `
  -EnablePortableCanvas `
  -CanvasOrigin "https://canvas-test.elevenidllc.com" `
  -PilotOrganizationId "00000000-0000-0000-0000-000000000001" `
  -TunnelTokenEnvFile $protectedBetaConnectorEnvFile `
  -PlanOnly

# Execute only inside the approved Denver maintenance window.
& .\scripts\deploy-canvas-oss-beta.ps1 `
  -ArtifactDir $artifact `
  -TunnelTokenEnvFile $protectedBetaConnectorEnvFile `
  -AuditPath $audit

python .\scripts\check_canvas_beta_capabilities.py `
  --organization-id "00000000-0000-0000-0000-000000000001" `
  --output (Join-Path $artifact "beta-capability-preflight.json")
```

An operator may run an explicitly authorized deployment outside that window by
adding `-AllowOutsideMaintenanceWindow`. The audit records that override; all
beta backup, migration rehearsal, and self-host production invariant checks
still apply.

After the deploy, set the protected workflow's expected source ID to
`marty_ui_sha` from this exact `source-manifest.json` and its deployment
manifest path to the sibling `local-deployment-manifest.json` as seen inside
the WSL runner. Do not reuse an older manifest or the local, non-published
Canvas image digest.

## Honest bootstrap boundary

Before Canvas web/jobs start, the lifecycle runner invokes exactly:

```text
bin/rails db:create
bin/rails db:migrate
bin/rails db:initial_setup
bin/rails brand_configs:generate_and_upload_all
```

Canvas's documented environment variables make `db:initial_setup` non-interactive. Runtime YAML contains only ephemeral operator configuration and generated test LTI keys; no Canvas source file is changed or mounted. After web startup the acceptance driver receives no database address or credentials. Rails runner/console, direct SQL, custom plugins, Canvas patches, the localhost metadata bridge, custom event ingestion, and synthetic AGS events are prohibited.

Passwords, learner identity, and the Marty API key are materialized with mode `0600` under the runner's ephemeral directory and mounted through Docker Compose secrets. The contract service receives only `/run/secrets/...` paths; those values do not appear in `docker inspect` environment output. The Canvas database configuration reads its password from the mounted secret file, and the one-shot lifecycle exports the Canvas bootstrap password only inside its process.

Before bootstrap, the workflow removes containers, volumes, and orphans only
from the `canvas-oss-portability` Compose project. It then proves that no
project resource remains, the external tunnel network has the same identity
and membership, and every previously running non-project container is still
running. The continuity monitor is the only service allowed to be running when
the stock lifecycle begins.

The edge adapter joins the existing tunnel network as `canvas-real:3000`, which is the upstream expected by the beta nginx configuration. All Canvas paths—including `/.well-known/openid-configuration`—are proxied to stock Canvas. The proxy does not synthesize platform metadata.

## Evidence and demonstration contract

The single canonical result is:

```text
tests/artifacts/canvas-oss-portability/portable-attestation.json
```

It is exported to recorders as `CANVAS_PORTABILITY_ATTESTATION_PATH`. A promotable result has the checked-in nested schema, `status=passed`, `run.mode=full`, exact Canvas/Marty origins, exact source/image/release provenance, and passed `oss_required` cases. Instructor Deep Linking must use the installed stock Canvas assignment chooser, and both instructor and learner resource launches must open that assignment through the stock course UI; the full contract contains no sessionless API launch. The evidence proof reads the exact current head for every typed requirement and validates its source, logical key, revision and payload hashes, verification status, timestamps, and pinned AGS line item. The claim proof races two administrator approvals and requires one reserved transaction, zero issued credentials before wallet claim, and exactly one afterward. Post-issuance downgrade must open one review without changing credential status, and recovery must automatically resolve it.

Full mode also requires:

```text
tests/artifacts/canvas-oss-portability/video/canvas-oss-portability.webm
```

The artifact audit rejects HAR files, trace ZIPs, browser storage, cookie/session dumps, raw claims, and token-like fields. Screenshots and video must be sanitized by the standard-flow driver. The legacy `record-canvas-employer-demo.js` and Canvas sandbox recording are never accepted as OSS portability evidence.

New Quizzes is `hosted_required`; the open-source Canvas runtime cannot honestly provide the separate hosted New Quizzes service. Canvas Credentials projection is `outside_gate` because it is optional and not part of the portable production milestone.

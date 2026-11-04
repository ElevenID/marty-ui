# Independent website releases and retained-slot deployment

The marketing website can be built and promoted independently of the login,
consoles, backend, and OpenBao. The two existing production producer workflows
remain the entry points. Each has three operations:

| Operation | Builds or selects | Prerequisites | Result |
| --- | --- | --- | --- |
| `combined` (default) | Existing combined production UI | Exact stable backend from the same public source and version | Existing legacy package, plus signed application compatibility evidence |
| `website` | Marketing website only; pricing is included by the private producer | Exact protected-main source and locked frontend dependencies | Digest-pinned website with original producer receipt |
| `compose` | Already published website, combined application, and stable backend | Exact successful original producer run IDs and attempts | Signed composition containing unchanged original evidence |

`website` never requires a new stack release, stack claim, or backend build.
`compose` never builds an image. These operations publish artifacts; they do not
change a running installation. The customer/selfhost full and tester contracts
remain separate from production marketing.

## First cutover

The reviewed code lands before live qualification of the new producer identities.
Before merge, complete the source/build/contract checks and required repository
checks. Merge the public PR before its private companion. The workflows retain
`combined` as their default; merging does not activate split routing on a host.
Protected-main admission is required for live signed production artifacts, so do
not make that post-merge qualification a prerequisite for merging the code.
Website activation still requires the real host and application/billing checks
below; a source merge is not evidence that those checks passed.

1. Merge the public frontend/producer/edge changes and the private adapters and
   producer changes. The private producer explicitly selects a public main-lineage
   commit containing these shared helpers. It does not execute code from a
   downloaded release artifact.
2. Produce and qualify a **combined** application from the new code, with its
   corresponding stable backend. The existing product deployment process installs
   this release and its digest pins. The website tool does not install or upgrade
   the product.
3. Keep the original combined producer run ID and attempt. Its image must contain
   `/marty-web-routes.json`, and its signed receipt must include
   `application-web-compatibility.json`. An older combined image without this
   evidence is rejected. The backend edge must support the optional website
   include and independent `/edge-healthz`.
4. Produce a website, compose it with that application and backend, and rehearse
   promotion and rollback on the actual hosting configuration before production
   cutover. Qualify the login/callback/console journey and, for the private full
   audience, the real pricing-to-checkout/payment journey separately.

The slim `application` Docker target is available for later work. This migration
accepts only signed **combined** application compatibility evidence. Activating a
slim application requires a separately qualified cutover; changing a marker value
does not authorize it.

## Produce a website

For public marketing, dispatch the existing public workflow on `main`:

```sh
gh workflow run production-web-release.yml --repo ElevenID/marty-ui --ref main \
  -f mode=website
```

For the full marketing/pricing surface, dispatch the existing private workflow:

```sh
gh workflow run production-ui-release.yml --repo ElevenID/marty-subscriptions --ref main \
  -f mode=website -f ui_source_sha="$reviewed_public_sha"
```

Use a full 40-character public commit SHA from main lineage. The private workflow
also binds the exact private dispatch commit. Omit `stack_release_tag` in website
mode. Public revisions use the public SHA; full revisions use
`PUBLIC_SHA-PRIVATE_SHA`. Publishing different bytes under an already retained
revision is rejected by the host, so a source change receives a new revision.

The dedicated image coordinates are:

- Public: `ghcr.io/elevenid/marty-ui-oss/website@sha256:…`
- Full: `ghcr.io/elevenid/marty-subscriptions/website@sha256:…`

The existing combined coordinates and manifest schemas remain unchanged. Private
builds stage committed frontend blobs only, scan every final image layer, and push
the exact inspected archive by digest. Private intermediate caches, build records,
source archives, and billing backend code are not exported.

The small `web-website-RUN_ID-ATTEMPT` artifact contains exactly five files:

```text
website-release.json
website-release.json.sigstore.json
website-release.json.provenance.jsonl
image.provenance.jsonl
web-surface-routes.json
```

A new combined release also publishes the small
`web-application-RUN_ID-ATTEMPT` artifact: the original legacy manifest and its two
proofs, the additive compatibility receipt and its two proofs, and the original
image provenance. Existing `production-web-VERSION-RUN-ATTEMPT` and private
`production-full-VERSION-RUN-ATTEMPT` artifacts are retained for combined mode.

## Compose with an existing product

Select successful original **website** and **combined** runs in the same producer
repository. The two sources can differ; their route contracts and production
audiences must match. The selected application determines the original stable
backend source and tag.

```sh
gh workflow run production-web-release.yml --repo ElevenID/marty-ui --ref main \
  -f mode=compose \
  -f website_run_id="$website_run" -f website_run_attempt="$website_attempt" \
  -f application_run_id="$application_run" -f application_run_attempt="$application_attempt"
```

For full production, use `production-ui-release.yml` in
`ElevenID/marty-subscriptions` and also supply `ui_source_sha` for the reviewed
public **tooling checkout**. That tooling source is explicit; a receipt cannot
select executable code. The private run's own source signs the composition, while
the original private/public sources, run IDs, and attempts remain in their
unchanged receipts.

Intake checks the hosted API's repository ID, workflow, main ref, source, success,
run, and attempt. It selects one exact artifact name, checks its byte size and
digest, accepts only the fixed inert receipt files, and verifies the original
keyless signatures and source-bound hosted-runner certificates. Stable backend
verification uses the existing installer verifier. The composer repeats original
verification while packaging; the host repeats it before deployment.

Download the resulting `web-composition-RUN_ID-ATTEMPT` artifact from the selected
successful composition run into a new owner-private directory. It contains:

```text
web-composition.json
web-composition.json.sigstore.json
web-composition.json.provenance.jsonl
web-composition.zip
web-composition.zip.sigstore.json
web-composition.zip.provenance.jsonl
```

Review the manifest's website revision, application digest, backend tag, product
image map, OpenBao pin, and original producer identities. Keep all six files
together. The host authenticates both outer subjects before bounded extraction,
then checks every embedded original subject. It never executes an archive script.

## Prepare the existing host

This implementation owns websites on an ordinary, separately managed Compose
deployment. It is **not** an upgrade operation for a native-installer-owned
installation. Keep product provisioning, migrations, secrets, backups, and
OpenBao initialization in their existing owner workflows.

Use a trusted, reviewed checkout of these Python helpers, Python 3.12, the pinned
dependencies in `scripts/selfhost-preview-tools.requirements.txt`, and a reviewed
Docker Compose installation. Local model tests use Compose 5.4.0. The host must
use Linux containers and the existing ingress, origin, ports, and networks.

Supply the complete existing ordered Compose file list, including the combined
application override such as `compose.production-ui.yml`, and its existing env
file. Every product role and all four separate OpenBao roles must be digest
pinned. Snapshot validation renders **all profiles**, including one-shot
bootstrap roles, without starting them. It checks actual installed container
ownership, configured digest references, and installed image IDs; absent or
unhealthy product containers do not block website startup.

The website overlay adds three bounded website slots and a read-only directory
mount to the existing edge. Real Compose rendering must show no changes to any
product role, ingress port, existing volume, network, or secret. Only public UI
runtime settings and the existing public analytics/site-verification files are
copied to website services. There are no website host ports or product health
dependencies.

Provision checksum-reviewed `gh` 2.103.2 and `cosign` 3.1.4 binaries. Linux CI uses
the exact size/SHA-256 pins in `scripts/install_web_verifiers.sh`; it is a Linux
installer, not a Windows package installer. On Windows, provision the corresponding
reviewed Windows binaries and record their approved checksums during host
qualification. Configure registry read access and verifier network access under
the deployment account. Never substitute a moving `latest` download or an
executable supplied by the composition archive.

Keep the stack's `.marty-website` directory, downloaded composition, tools, and
retained receipts writable only by the deployment owner. POSIX mode checks are
enforced; Windows requires equivalent account ACLs. Use a trusted CA bundle with
`--ca-file` if the existing ingress uses a private CA. TLS verification remains
enabled and redirects are not accepted for the public revision probe.

## Deploy on Windows with the existing ingress

Adapt these paths to the existing installation. In particular, preserve the
existing Compose file ordering and project names. The example keeps product and
OpenBao Compose files under the same existing stack project directory.

```powershell
$ErrorActionPreference = 'Stop'
$MartyStack = 'C:\Marty\production'
$MartyTools = 'C:\Marty\reviewed-release-tools'
$Python = 'C:\Marty\release-python\Scripts\python.exe'
$Gh = 'C:\Marty\tools\gh-2.103.2\bin\gh.exe'
$Cosign = 'C:\Marty\tools\cosign-3.1.4\cosign-windows-amd64.exe'
$Composition = 'C:\Marty\releases\selected-web-composition'
$WebsiteTool = Join-Path $MartyTools 'scripts\deploy_website.py'
$Common = @(
  '--stack-dir', $MartyStack,
  '--project', 'marty-selfhost-prod',
  '--compose-file', (Join-Path $MartyStack 'docker-compose.yml'),
  '--compose-file', (Join-Path $MartyStack 'compose.production-ui.yml'),
  '--env-file', (Join-Path $MartyStack '.env.selfhost.production.local'),
  '--openbao-compose-file', (Join-Path $MartyStack 'docker-compose.selfhost.openbao.yml'),
  '--openbao-env-file', (Join-Path $MartyStack '.env.selfhost.production.local'),
  '--openbao-project', 'marty-selfhost-openbao',
  '--public-origin', 'https://elevenidllc.com',
  '--gh', $Gh, '--cosign', $Cosign
)
& $Python $WebsiteTool @Common --composition-dir $Composition
if ($LASTEXITCODE -ne 0) { throw 'Website deployment failed; inspect its recovery message.' }
```

The command takes a host lock, authenticates the composition and originals,
compares current product pins, and stages the unused slot. It checks the website's
actual metadata and health, validates the merged Compose model and Nginx config,
switches the route include, reloads the edge, and verifies the homepage and
metadata through the existing public origin. Both responses must identify the
selected revision. A final product snapshot must still match before state commits.

The same command and flags work on a Linux host with its existing absolute paths
and a Python virtual environment. Do not pass the generated website overlay as a
base `--compose-file`: the website owner manages that extra overlay itself.

## Rollback, product upgrades, and recovery

Website rollback uses retained original evidence and preserves the **current**
adopted product configuration and pins:

```powershell
& $Python $WebsiteTool @Common --rollback
if ($LASTEXITCODE -ne 0) { throw 'Website rollback failed.' }
```

Only the active and immediately previous revisions are promised to old browser
tabs. Their `/_website/REVISION/` assets route to their own slots. A third physical
slot stages the next candidate without overwriting either retained revision.
After another promotion, older assets return a real 404; those tabs must reload.
HTML and `/_website/runtime-config.js` select the active website. Missing static
assets never become application HTML.

An independent product upgrade changes the product baseline and must be adopted
explicitly. First qualify/install the new product through its existing process,
keeping the website overlay in any product recovery command. Compose the current
website with the new qualified application/backend and then run:

```powershell
& $Python $WebsiteTool @Common --adopt-current-product --composition-dir $Composition
if ($LASTEXITCODE -ne 0) { throw 'Product adoption failed.' }
```

Adoption authenticates the new composition and the retained active/previous
receipts, checks route and audience compatibility, verifies the actual current
product pins and resolved configuration, and updates only the baseline. It does
not change website slots or start/recreate a product container. Subsequent website
rollback keeps the upgraded backend, application, and OpenBao pins. Unexplained
configuration or image drift fails closed rather than silently becoming a new
baseline.

Adoption also checks that the retained website overlay still matches the new
resolved product model. Changing the copied public environment, public secret
mounts, or edge network membership is a **website configuration migration**, so
adoption refuses it before updating either state or overlay. Successful adoption
therefore remains compatible with `--start-current`.

If such a change was incidental, use the product owner to retain the prior
website-facing configuration and retry adoption with the upgraded image pins.
If the new wiring is required, use the planned combined backout below, qualify
the new configuration, and establish a fresh website cutover from an authenticated
composition. Preserve the archived receipts; this explicit new cutover resets
the old-tab retention window. Do not manually edit host state to bypass the
compatibility check or expect adoption to move live retained slots across networks.

If activation fails, the owner restores the previous routes and overlay, verifies
the prior website when one exists, and stops only the staging candidate. A durable
transaction remains if restoration cannot be verified. After resolving the
reported host issue:

```powershell
& $Python $WebsiteTool @Common --recover
if ($LASTEXITCODE -ne 0) { throw 'Website transaction still needs recovery.' }
```

Recovery restores the last committed selection or finishes cleanup after a
committed activation. It does not guess through changed product state. A stale
`deploy.lock` is removed only after confirming the recorded process is no longer
running and no operator owns the deployment. Keep the transaction and original
receipts; deleting them is not a rollback procedure.

Receipt and journal contents are flushed before Docker mutation. POSIX also
flushes directory entries after rename/removal. Windows replacements request
`MoveFileExW` write-through. A state rename that succeeds before a flush error is
treated as crossing the commit boundary, so old routing is not restored while new
state remains selected. Actual Windows power-loss behavior still requires host
qualification.

## Reboot and product recovery

Restore the website and edge independently, before waiting on backend/OpenBao:

```powershell
& $Python $WebsiteTool @Common --start-current
if ($LASTEXITCODE -ne 0) { throw 'Retained website startup failed.' }
```

This authenticates the retained receipts and configuration, starts only the
active/previous website services and the existing edge, and checks the homepage
and metadata through the **local edge**. It does not require public TLS/tunnel
ingress to have recovered yet. After the existing ingress owner has recovered:

```powershell
& $Python $WebsiteTool @Common --check-current
if ($LASTEXITCODE -ne 0) { throw 'Public website revision check failed.' }
```

The existing repository-hosted `scripts/recover-marty-after-reboot.ps1` detects
split state, runs these checks around its existing recovery sequence, and retains
the recorded website overlay in subsequent product Compose operations. For that
script, configure `MARTY_WEBSITE_PYTHON`, `MARTY_WEBSITE_GH`, and
`MARTY_WEBSITE_COSIGN` under the recovery account to the reviewed executable paths.
Without split state, provide the complete retained Compose invocation; see
[Windows Compose recovery](windows-compose-recovery.md). Beta recovery is opt-in. For separately installed
bundle hosts, configure equivalent commands using the exact saved `$Common`
arguments and trusted tooling checkout.

After the website owner releases its lock, product recovery uses
`recover_product_services.py` to read the exact invocation's active service list.
It refuses failed, empty, malformed, or duplicate inventories, removes the edge
and all three website slots, and passes an explicit nonempty product list with
`--no-deps` to Compose. Inactive initialization profiles stay inactive. An unlocked
product recovery therefore cannot recreate a website-owned container from a stale
overlay during a concurrent website promotion.

Every operator or scheduled product `docker compose up` must include
`.marty-website/compose.website.json` **after** the existing product file list once
the website split is active. Omitting it during an edge recreation removes its
website route mount. Keep external TLS/tunnel startup in its existing owner and
perform the public check after that ingress is available. `/edge-healthz` means
the edge is alive; `/ready` and `/health/ready` retain product readiness and may
fail while marketing remains available.

The supported signed backend role closure does not include the legacy
`cloudflared` additions. Public TLS/tunnel ingress must therefore be independently
supervised outside the product/OpenBao readiness chain. The reboot wrapper does
not restore that external ingress owner; its final probe checks the public path
after local recovery. Qualify the actual supervisor ordering on the host. Local
website/edge startup is independent of product readiness; public availability also
requires the separately owned ingress to be available.

## Qualification and backout

Before first production activation, rehearse the following on the real Windows
Docker/Nginx host and its actual public origin:

- Promote two revisions, keep a page from each open, stage a third, and verify
  active/previous assets, cache headers, and real errors for expired/missing assets.
- Verify `/resources` belongs to marketing while `/resources/…` remains a protocol
  route. Verify login/error/callback, consoles, API docs, and protocol metadata
  continue through their existing owners with path/query/hash handoffs intact.
- Stop the product services on a disposable host and cold-start the retained
  website/edge. Check marketing locally before ingress recovery, then publicly.
  Product readiness must still report failure while those services are down.
- Exercise failed candidate startup, failed edge validation/reload, failed public
  revision checks, interruption/recovery, and host reboot. Compare actual product
  pins before and after website rollback and explicit product adoption.
- Execute the authenticated application journey and full private billing/payment
  journey against the intended compatible backend. Compiled page availability is
  not a payment qualification result.

Local Python tests cover contracts, provenance boundaries, real Compose model
merging, product/profile snapshots, retained-slot transitions, and persistence
failure injection. `tests/test_website_edge_runtime.py` can run against a local
Nginx binary with `MARTY_TEST_NGINX_EXECUTABLE`; it checks real edge routing and
marketing availability while product listeners are absent. These checks do not
claim Windows Docker bind-mount, registry/signing-service, power-loss, or billing
qualification. Signed composition fields explicitly remain
`runtime_tested: false` and `billing_journey_tested: false`.

For a planned return to the combined website, first qualify the currently
installed combined application's marketing pages and product readiness. Restore
the saved product Compose invocation without the website overlay and recreate
**only the edge**, then verify the original public origin and handoffs. Retain
the website state/receipts as archived recovery evidence and remove the split
startup task only after that backout is verified. Do not use a website rollback
to install an older product, erase OpenBao state, or switch to an unqualified slim
application.

During that planned backout, serialize host operations and move the retained
`.marty-website` directory to a distinct archive path after successful verification
and startup-task removal. Leaving active split state at the original path tells
the recovery owner to restore that website on the next boot.

Implementation owners: `website_release.py`, `website_provenance.py`,
`web_release_intake.py`, `web_producer_evidence.py`, `package_web_composition.py`,
and `deploy_website.py` under `scripts/`. The shared route contract is
`contracts/web-surface-routes.json`; source/build boundaries are documented in
`ui/README.web-surfaces.md`.

API references used by the implementation:
[GitHub workflow-run attempts](https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run-attempt),
[GitHub artifact metadata](https://docs.github.com/en/rest/actions/artifacts),
[Compose configuration rendering](https://docs.docker.com/reference/cli/docker/compose/config/),
and [Windows write-through file replacement](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).

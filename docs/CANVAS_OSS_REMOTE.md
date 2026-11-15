# Stock Canvas on one remote host

This bounded profile runs unmodified stock Canvas on a dedicated remote host.
AWS provisioning, certificate/DNS authority and local migration stay with the
operator. Keep the active `marty-ux-20261110` k3s host and its capacity intact.

Use a dedicated Linux **x86_64** host, Docker Compose v2, Python3 and Node20+.
Execute bootstrap as the root deployment operator (`sudo`); state/config/secret
directories are0700. The unchanged generator creates individual config files
as0644. Each config/Compose-secret file is mounted separately read-only, so the
nonroot Canvas process can read its mounted file without traversing the host's
private parent directory. Password files are0644 inside0700 host-only parents
for the same file-bind reason; TLS private key remains0600, read by nginx root.
No entire private state directory is mounted into Canvas. Named files/log
volumes inherit the stock image directory ownership on first empty-volume mount;
actual UID/file-read/writability is still a bootstrap verification requirement.
The published upstream-stock image and every dependency come from
`deploy-config/catalog/canvas-oss.lock.json`; there is no build stage, Canvas
source mount, patch or plugin. Reuse the existing runtime-config generator and
four-command pre-start lifecycle owner. Do not run Rails or direct DB setup after
bootstrap. The remote Compose excludes the browser/contract/monitor workloads;
existing synthetic-fixture adapters run separately and keep their ownership,
OAuth/LTI, cleanup, recording and editorial requirements.

All six steady services restart unless explicitly stopped; the lifecycle
one-shot is excluded. Actual bootstrap and workload checks must still account
for OOM/restart/generation observations rather than treating a restart as a pass.

The pilot applies **real** RAM hard caps: web3GiB, one jobs process1GiB,
Postgres512MiB, Redis128MiB, mail64MiB, edge64MiB; steady total4.75GiB.
The separate lifecycle cap is4GiB, run before web/jobs start; bootstrap total
4.6875GiB. Passenger min/max workers are1 using the base image's documented
environment controls; the stock delayed-job configuration has one worker.
Both phases require6GiB available physical RAM, including unchanged1GiB host
reserve and at least256MiB cushion, on an8GiB dedicated host. Require2GiB host
usable swap; allocate an extra actual page for the swap header (2GiB+4KiB
file bytes for a4KiB page). Swap is not physical-RAM credit. Limits are explicit. This is an
unqualified capped trial, not a demonstrated irreducible minimum or throughput
claim. A bootstrap/OOM/workload failure must be preserved for review, without an
automatic retry or cap increase. The existing reviewed larger profile remains
unchanged. A1GiB micro is not suitable; the active8GiB UX host's observed5GiB
available also does not admit this profile or imply permission to share it.

The maintained prebuilt-image owner requires **20GiB free after pulling** the
actual host-reported Canvas image plus dependencies. Root's AWS prefetch
observed Docker image size6,625,029,490 bytes, with config/image ID
sha256:054fdb1cc20714b1159538d6b02b9a741afc0cc514a4c8bdfac12f2c4c59faea
and the unchanged pinned registry manifest digest70745c55... . Do not use the
historical local3.06GB estimate or equate Image.Id with a registry manifest
digest. The maintained guard uses max(20GiB,2*actual image size);20GiB still
dominates this observation. Total EBS size depends on AMI, swap, Docker layers
and data;30GiB is not a guaranteed fit.
Choose the smallest reviewed volume that still passes the actual post-pull
20GiB free-space check. Logs rotate at10MiB*3 per container; uploads, database and
security/LTI configuration persist. Budget EBS/publicIPv4/egress independently;
free-credit eligibility is account/region-specific and not established here.

Use one public subnet/Internet Gateway and one host/public IP, **no NAT Gateway,
ALB, RDS or Redis service**. Only80/443 are published. Postgres/Redis/mail/web/jobs
stay on a private Compose bridge. Restrict SSH to the operator or use the
account's supported existing session path. Inbound443 must serve real publicly
trusted TLS;80 is only ACME HTTP-01 and redirect. Egress needs registry/package
fetches, DNS, time and HTTPS to beta. No network attachment to the local beta
Docker network is needed.

Keep `https://canvas-test.elevenidllc.com`: domain, secure SameSite=None sessions,
LTI issuer and current adapters deliberately bind this origin. Root must review
the current DNS/tunnel route before any switch; do not add a remote connector
under the existing beta tunnel or repoint live traffic automatically. Obtain a
real certificate only after hostname/DNS authority is settled; prepare a private
TLS directory containing regular `fullchain.pem`/`privkey.pem` files (key0600),
and an ACME public webroot. The existing pinned nginx image terminates443 and
preserves Host/forwarded HTTPS; it also exposes only an internal3000 healthcheck.
Renew certificates through the chosen owner, replace files in the mounted TLS
directory and reload only the owned edge after successful validation.

Connectivity must work both ways: beta workers/browser to Canvas REST/OAuth and
Canvas to beta's LTI JWKS/launch/auth endpoints. Existing callback is
`https://beta.elevenidllc.com/v1/integrations/canvas/oauth/callback` and tool JWKS
is `/v1/integrations/canvas/lti/jwks`. Recreate only fresh owned synthetic Canvas
users/course/developer keys/LTI installation and Marty binding through existing
stock APIs/adapters; local numeric IDs, access tokens, issuer keys and callbacks
are not portable resource proof. Preserve local Canvas and its same-three
restore duty until an explicit later migration/retirement decision.

After Root verifies AWS access, credits/eligibility, instance/AMI/volume/egress
cost and dedicated ownership, install the host prerequisites through that
approved host owner. The bootstrap defaults to a file-only plan:

```sh
python3 -B scripts/deploy_canvas_oss_remote.py
```

After separate certificate, engine and effects review, the concrete command is:

```sh
sudo python3 -B scripts/deploy_canvas_oss_remote.py --execute \
  --engine-id EXACT_APPROVED_REMOTE_ENGINE_ID --admin-email OWNED_SYNTHETIC_ADMIN_EMAIL \
  --tls-directory /srv/canvas-tls --acme-directory /srv/canvas-acme-public
```

The new state directory must be absent. It generates fresh admin/database
secrets in owned private files and current operator configuration, pulls only
locked images and validates image source/base labels, then invokes the existing
lifecycle. It refuses an engine containing any containers, including stopped
ones; do not use it on the active UX host. No `down`, volume deletion, AWS CLI,
app/API credential copy or local-stop command is provided. A controller timeout
does not prove the remote lifecycle container terminal: preserve the recorded
state and inspect its exact Compose-owned identity before any cleanup/resume.
Bootstrap success is still not LTI/worker/full-demo/release qualification.

The current native engineering owner still observes Desktop's
`marty-selfhost-prod` and `canvas-oss-portability` as protected local contexts
(`canvasOwnedNativeEngineering.js::protectedEngineeringContext`). Keep those
guards for the retained local baseline. They do not establish AWS container or
volume identity. Before a full remote-Canvas engineering claim, bind the remote
engine/image/source/limits/created-container and persistent-volume observation
through the existing runtime-evidence owner and verify it again after the run;
do not relabel Desktop inspections as remote evidence or waive stock invariants.

Primary references: [Canvas production prerequisites](https://github.com/instructure/canvas-lms/wiki/Production-Start)
recommend8GB for a single host; [Instructure base-image controls](https://raw.githubusercontent.com/instructure/dockerfiles/master/ruby-passenger/README.md)
document Passenger worker limits; [AWS Free Tier account split](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-free-tier-usage.html)
must be checked against the actual account. No ongoing-free claim is made.

## Keep the existing Cloudflare route with a local origin relay

The existing local nginx edge can relay to AWS while the browser continues to
use the same Cloudflare-trusted Canvas origin. Root-owned DNS/tunnel changes are
not a prerequisite for this variant. The origin certificate may use an explicitly
approved private CA: only its public certificate moves to the relay; origin
private keys remain on the remote host.

Prepare a reviewed nginx configuration that listens on port3000, connects only to
the approved origin IP on port443, sets SNI/Host to canvas-test.elevenidllc.com, requires
`proxy_ssl_verify on`, and trusts the approved CA at
`/etc/nginx/canvas-remote-ca.pem`. Retain the canonical forwarded HTTPS headers.
Freeze its actual SHA256 and the public CA SHA256 before rendering. The renderer
consumes these operator files; it generates no certificate, key or per-IP config.

`scripts/derive_canvas_oss_edge_relay.py` takes `--inputs FILE --output FILE`.
The JSON input keeps `project: "canvas-oss-portability"` and hash-bound file refs
named `canonical`, `lock`, `compose`, `relayConfig`, `publicCa`. Each ref supplies
`path`, a lowercase64-hex `sha256` and optional exact `bytes`; `sourceRevision` and
`gitBlob` may retain provenance. `canonical` is the exact reviewed canonical
`docker-compose.canvas-oss-acceptance.yml`, `lock` the existing stock lock, and
`compose` the approved Compose executable. The CA file accepts public certificate
PEM blocks only. Supply real inputs, with no dummy database/admin fixture values.

```sh
python3 -B scripts/derive_canvas_oss_edge_relay.py \
  --inputs /private/relay-inputs.json --output /private/edge-relay.json
# After reviewing these exact inputs, source-render only:
python3 -B scripts/derive_canvas_oss_edge_relay.py \
  --inputs /private/relay-inputs.json --output /private/edge-relay.json --render
```

Default is a file-only plan. Render invokes only Compose config with no
interpolation/path resolution, projects the actual canonical edge and resolves
only the locked edge image plus two real read-only file binds. Compose may ignore
service filtering with no interpolation; projecting the returned source model
keeps the result to exactly one service. The existing project/container/health port3000
and canvas-real alias stay canonical. The web dependency is removed, RAM is
actually64MiB, and both networks are retain-or-fail external references. No
unrelated services, global volumes, secrets or fixture variables are emitted.
The output and `.source-check.json` receipt must be fresh; no old model is
overwritten. This receipt proves source derivation, not TLS or runtime identity.

Root must separately verify current engine/old edge/network/image/config/CA
identities, admit a new edge generation and observe origin/relay/public health,
login and both-direction REST/LTI connectivity. Keep stopped local web/jobs,
all volumes and production/beta unchanged. Never remove orphans, enable
COMPOSE_REMOVE_ORPHANS or run down against this intentionally selected model.
Use the existing lifecycle owner with retained before/rollback evidence; the
renderer performs no service or mount operation. Reconcile the original same-three
restore duty explicitly rather than claiming a changed edge is the old spec.

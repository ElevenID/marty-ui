# UI live reload on an isolated K3s development node

This optional Helm values overlay runs Vite beside the existing UI Nginx
container. The installation's HTTPS origin serves the browser, API, Keycloak
and HMR WebSocket. It adds no Service, Ingress, public port or credential mount.
Backend services still use their installed images and existing TLS/auth setup.
The default chart continues to serve the installed static UI image.

Use a dedicated single-node development installation with the normal K3s,
OpenBao, workload certificates, Keycloak and native services already healthy.
The overlay is for editing and browser exploration; it does not certify a
release artifact. Check the AWS account's current Free Tier eligibility and
retain the development node's agreed automatic stop time.

Use a node with at least 8 GiB of memory. The development container has a 4 GiB
memory limit for Vite and its existing TypeScript/ESLint checkers, including the
temporary overlap while Vite prepares a replacement configuration. A 2 GiB limit
was exceeded during an observed reload, causing a container restart and a
temporary gateway error. Monitor the node's available memory when running
additional workloads.

Development UI upgrades use `Recreate`: the old UI Pod stops before its
replacement starts, so two 4 GiB Vite containers do not overlap. The UI is
unavailable while the replacement installs dependencies and becomes ready.

The postinstall hook also applies a version- and digest-checked lifecycle repair
to `vite-plugin-checker` 0.14.5. Its original forced worker termination left the
native TypeScript 7 watcher running after configuration reloads. The repair waits
for startup, stops and reaps that worker's own native child, then acknowledges
cleanup before terminating the worker. TypeScript and ESLint remain enabled.
Unknown dependency versions or contents stop installation for review; revisit
this patch when upgrading the checker. Cleanup failures are logged explicitly.

## Enable

Put the working checkout on the K3s node, for example `/opt/marty-ux`. Its `ui/`
and `contracts/` directories must be readable by UID/GID 1000. Keep secrets and
credentials outside those directories. Only these two source directories are
mounted, read-only; the Node process gets separate ephemeral dependency and
temporary directories. Edits on the node remain visible to the watcher.

Keep the original installation values, image pins and namespace. Set
`publicOrigin` in those installation values to the browser's **exact** existing
HTTPS origin, including a port such as `https://dev.example.test:8443`.

Run from the node's checkout, adapting the installation-specific values:

```sh
set -eu

MARTY_DEV_RELEASE=marty
MARTY_DEV_NAMESPACE=marty-dev
MARTY_DEV_VALUES=/opt/marty-install/installation-values.yaml
MARTY_DEV_CHECKOUT=/opt/marty-ux

test -d "$MARTY_DEV_CHECKOUT/ui"
test -d "$MARTY_DEV_CHECKOUT/contracts"
test ! -L "$MARTY_DEV_CHECKOUT/ui/node_modules"
mkdir -p "$MARTY_DEV_CHECKOUT/ui/node_modules"

helm upgrade "$MARTY_DEV_RELEASE" ./deploy/helm/marty \
  --namespace "$MARTY_DEV_NAMESPACE" --reset-then-reuse-values \
  -f "$MARTY_DEV_VALUES" \
  -f ./deploy/helm/marty/values-ui-development.yaml \
  --set-string "ui.development.checkoutPath=$MARTY_DEV_CHECKOUT" \
  --wait --timeout 15m

kubectl -n "$MARTY_DEV_NAMESPACE" logs deployment/ui -c ui-dev-install
kubectl -n "$MARTY_DEV_NAMESPACE" logs deployment/ui -c ui-dev --tail=40
kubectl -n "$MARTY_DEV_NAMESPACE" rollout status deployment/ui --timeout=300s
```

Use the chart from this checkout: the overlay requires its development
templates and Vite origin helper. `--reset-then-reuse-values` loads new chart
defaults and then retains installed settings, including the dependency-resource
settings of `values-k3s-dev.yaml`. Use Helm 3.14 or newer for that option.
Do not replace existing installation values with example image digests.

Create the real `ui/node_modules` directory before rollout: it is the mountpoint
for the writable dependency volume inside the read-only source mount. A linked
local dependency directory must not be copied to this checkout. The empty host
mountpoint is hidden by the container's dependency volume.

Repeat this preparation for **every new checkout**, including an isolated
worktree selected when resuming an existing installation. An earlier checkout's
directory does not supply the new checkout's mountpoint. If the UI Pod reports
`CreateContainerError` while mounting `/workspace/ui/node_modules` on a read-only
filesystem, check the selected checkout on the node and create that empty
directory with the commands above. Keep the source mount read-only; dependencies
remain in their separate writable volume. Then watch the UI rollout for startup
and readiness.

The pinned official Node 24 image runs `npm ci --include=dev` against the checked
in lockfile. The init container needs outbound access to the package registry
and the released ElevenID package archives referenced by that lockfile. It
does not receive registry, AWS, OpenBao or Kubernetes credentials. Its normal
install output is available in the init-container log. A restart recreates
the dependency directory and installs afresh; no host `node_modules` is used.
The project's postinstall patch writes only beneath that dependency directory.
The explicit npm cache uses `/tmp/npm-cache`; the image's home is unchanged.

Vite binds only to the pod's loopback port 3000. `VITE_API_URL` stays empty so
browser API requests remain same-origin. `VITE_DEV_PUBLIC_ORIGIN` comes from
the installation origin and sets the exact HMR hostname, TLS scheme and port.
Nginx preserves the installed image's `/runtime-config.js` and sends backend
and Keycloak traffic through their existing routes.

## Verify the watcher in the browser

Open the existing HTTPS deployment, log in and visit the organization console.
The browser should fetch `/@vite/client` from that same origin and connect its
HMR WebSocket with `wss` on the same external port. The Vite log should show a
ready server, without a fallback direct connection to port 3000.

Make a small visible change to a label on the page in the node checkout. Save
it and verify that the open page changes while the login session remains
active. Restore the label and verify the second update. Then apply the real UX
fixes in that checkout and repeat the affected interactions. This verifies
the source watcher, proxy WebSocket, React refresh and authenticated route
together. Keep the final diff free of temporary labels.

Changes to `ui/src/` and styles refresh directly. Vite restarts for its own
configuration changes. After changing `package.json`, `package-lock.json`, or a
postinstall patch, restart this deployment so the init container installs and
patches fresh dependencies. This also clears any watchers from an older install:

```sh
kubectl -n "$MARTY_DEV_NAMESPACE" rollout restart deployment/ui
kubectl -n "$MARTY_DEV_NAMESPACE" rollout status deployment/ui --timeout=600s
```

Keycloak themes and backend services retain their existing deployment
lifecycle; this overlay watches the UI checkout only.

In development mode, Nginx readiness checks `/edge-healthz` and the `ui-dev`
container independently checks Vite's `/@vite/client`. This keeps the frontend
available to explain an authentication/backend outage and offer a retry. It
does **not** make a ready UI pod evidence that the API or an OB3 journey works.
The static release UI retains its existing gateway-dependent `/health/ready`
readiness probe. Use the strict backend preflight below in development mode.

## Run the development resume preflight

From an operator shell with Python 3.10+, OpenSSL, kubectl and AWS CLI, run the
read-only checker against the existing installation. The shell must already
have its intended AWS identity and Kubernetes access. Select the context and
the actual certificate owner explicitly; the application and certificate
namespaces can differ. For example, replace these synthetic identifiers with
the retained installation's values:

```sh
python3 scripts/check_kubernetes_dev_resume.py \
  --context retained-development-context \
  --namespace marty-active-dev \
  --release marty \
  --instance-id i-0123456789abcdef0 \
  --region us-east-2 \
  --origin https://192.0.2.20 \
  --certificate-namespace marty-certificate-owner \
  --certificate marty-public \
  --tls-store-namespace marty-certificate-owner
```

This command supports the existing Linux AWS/K3s IPv4 profile. It neither
starts EC2 nor changes Kubernetes, Helm, cert-manager, OpenBao or retained
bootstrap state. It requires `ec2:DescribeInstances` and read access to the
selected release's Deployments/StatefulSets, `marty-config`, Ingress,
Certificate, Issuer and TLSStore. Existing Secret `get` access is needed for
public certificates: Kubernetes RBAC does not grant access to individual
Secret fields, but the checker asks kubectl to emit only the selected public
leaf field. It never captures a Secret manifest, token or private key and
never prints subprocess stderr or HTTP bodies. Do not grant broader access
solely to make this check pass; run it with the established operator access.

The stages distinguish conditions that can otherwise look like a successful
resume:

| Stage | Required observation |
| --- | --- |
| Current address | A fresh EC2 read identifies the requested running instance and its IP matches the exact HTTPS origin. |
| Public certificate owner | The existing Certificate requests that IP, `Ready=True` observes its current generation, its Issuer is Ready and the designated default TLSStore uses its Secret. |
| Actual HTTPS | The remote peer passes normal chain, validity and IP SAN verification, and its leaf fingerprint matches that owner's public leaf. No TLS bypass or redirect is accepted. |
| Application origin | `PUBLIC_API_URL` and `KC_HOSTNAME` match the exact public origin. Existing Keycloak client redirects still need their separate readback. |
| Workloads | The selected release's required Deployments and postgres/redis StatefulSets exist, and every selected workload is fully ready at its current revision. |
| Public workload leaves | The actual Secret mounts selected by workload TLS paths, Keycloak signing-certificate paths and Redis are present and have sufficient public certificate lifetime remaining. Private-key access and token validity are outside this stage. |
| Backend readiness | `/health/ready` returns the gateway's JSON contract and healthy core dependencies. An HTML page, generic health response, redirect or missing dependency does not pass. |

The default budget is 120 seconds overall, with each command or HTTPS request
bounded to 10 seconds and response sizes capped. Use `--timeout-seconds` and
`--request-timeout-seconds` for a slow but understood connection, up to a
600-second total budget. A timeout is a failed observation, never a readiness
result. `--minimum-validity-seconds` defaults to 3600; choose enough time for
the planned manual test. `--format json` produces a sanitized structured report.

Exit `1` means a blocking check failed and includes its next diagnostic action;
exit `2` means invalid input. Exit `0` means **ready to attempt an authenticated
check**, with any warnings still visible. The report always says
`demoQualified: false`: it does not authenticate to OpenBao, prove a running
process reloaded its credentials, verify Keycloak client redirects, resolve
the preserved issuer DID, or issue/present an OB3 credential. A generic OpenBao
metadata error is not proof of an expired token. Follow the applicable retained
credential lifecycle and inspect current service evidence; do not fresh-bootstrap
an existing installation in response to a failed preflight.

Complete login, the intended OB3 issuance/presentation path and the visible HMR
round trip separately after the blocking checks pass. Keep the agreed node stop
deadline in force throughout the test.

## Resume an existing development installation

Inspect current deployment readiness, pod state and relevant service logs first.
Historical credential or reload failures do not establish a current failure;
keep healthy services running and investigate current authentication evidence
before forcing credential reloads or restarts. Verify that the node's agreed
automatic stop guard is still active, and retain its existing deadline.

Record the mounted checkout's branch, status and diff before replaying a review
branch. Preserve any local edits by creating a new isolated worktree for that
revision, then set up its real `ui/node_modules` mountpoint as described above.
Switch `ui.development.checkoutPath` to it in a separate, reviewed source replay;
do not reset, clean or switch branches in another session's mounted checkout.

Keep private evidence under a restrictive `umask 077`, but run Git and source
checkout operations in a separate subshell with `umask 022`. Otherwise new
root-owned source files can become unreadable to the UID 1000 watcher and crash
its checkers. Before reload, verify that UID 1000 can traverse and read `ui/`
and `contracts/`. If repair is needed, correct only tracked public source files
to `0644` (or `0755` for tracked executables) and their source directories to
`0755`; do not recursively change ownership or permissions on the installation,
private evidence, or credential directories.

For an origin-only replay with unchanged backend images and schemas, retain
private backups of the installed Helm values, manifest and certificate resource.
Use the exact chart contents from the installed release, including its existing
live-reload support; a matching chart version alone is insufficient. Render the
installed values with that chart and compare with the stored release manifest
before changing values. Resolve unexplained differences before proceeding.

Set both `migrations.enabled=false` and `keycloak.configurator.enabled=false`
in the development values. These are ordinary setup Jobs, so `--no-hooks` alone
does not disable them. Both values default to `true`; retain these overrides
and review them before a later runtime upgrade. Keycloak itself continues to
run. Keep existing credentials, organization settings and image pins, and do
not rerun bootstrap or the full configurator, which reapplies the initial
operator password even for an existing user.

If the public IP changed, preserve the currently installed `MARTY_ISSUER_DID`
from `marty-config` as an explicit `organization.did`, then update `publicHost`
and the exact `publicOrigin`, including its port. Check explicit `config`
overrides for stale public URLs. Preview the desired manifest: it must contain
no setup Jobs, retain every image reference, and limit other changes to the
approved public-origin fields and derived configuration checksums.

Locate the certificate actually serving HTTPS by following the installed
TLSStore or Ingress reference to its TLS Secret and owning Certificate. The
public Certificate may be in a different namespace from the application;
match the resource and its current SAN before editing. Update that existing
Certificate's IP SAN, preserving its issuer and Secret reference. Wait for
`Ready=True` for the new generation and verify the served certificate's new
SAN; an earlier generation's Ready condition is insufficient.

For the public-IP profile, keep the existing automated Let's Encrypt production
issuer, ACME account and `shortlived` profile shown in
[`ip-certificate.yaml.example`](../deploy/k3s/ip-certificate.yaml.example).
Retain its HTTP-01 challenge route and certificate renewal configuration.
Check the issued leaf's validity dates and the Certificate's next renewal time,
then verify HTTPS with normal certificate validation. When an IP client does
not send SNI, the ingress controller's default TLSStore must reference that
same issued Secret. Reconcile the certificate owned by this installation;
running a different retained single-installer installation does not update
the K3s ingress certificate.

### Use one public certificate owner

Traefik uses its `default` TLSStore for a connection without SNI or without a
matching certificate. That Secret must be in the TLSStore's own namespace;
the application namespace does not need a copied Secret when the Ingress uses
this default. Retain one discoverable default TLSStore and one cert-manager
Certificate owner for that default leaf. See Traefik's
[TLSStore reference](https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/crd/tls/tlsstore/)
and [Ingress TLS configuration](https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/ingress/#tls).

The default chart behavior continues to require `ingress.tlsSecretName` for
controllers/installations that load a certificate from the application
namespace. On this existing Traefik profile, a separate, reviewed chart update
can explicitly select the default-store mode instead:

```yaml
ingress:
  className: traefik
  useDefaultCertificate: true
  tlsSecretName: ''
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: 'true'
```

This option enables the TLS router explicitly and omits the per-ingress
`spec.tls` Secret reference. It creates no Certificate, Issuer, TLSStore or
Secret, and it does not copy certificate bytes or alter renewal policy. The
chart refuses a simultaneous Secret name, another ingress class, TLS disabling,
or cert-manager/ACME ownership annotations. Unrelated annotations are retained.
The existing Traefik deployment must already discover the owner namespace.
Validate actual served HTTPS before and after the change; chart rendering cannot
establish the live default store's visibility or certificate trust.

An old copied Secret can differ from the default leaf while a normally verified
IP connection succeeds. The preflight reports that difference as a delivery
warning, alongside the actual served-certificate result. Removing the Ingress
reference prevents that obsolete copy from being loaded by this Ingress. Review
other consumers before separately deleting any old Secret; this option does
not delete it. Do not introduce a second issuance or copying controller.

This new option requires a chart that contains it. Keep its adoption separate
from the same-chart origin-only replay below: compare the exact installed and
proposed manifests, preserve all unrelated settings/image pins and keep both
setup Jobs disabled. Confirm the intended Ingress and any separately approved
UI probe change are the only additional differences. Resume certificate renewal
through the existing cert-manager owner, then rerun the preflight and browser
journey.

### Replay only the existing public origin

For this same-chart origin-only update, reuse the installed values and apply
only the reviewed origin overrides, including the two disabled Jobs:

```sh
helm upgrade "$MARTY_DEV_RELEASE" "$MARTY_DEV_INSTALLED_CHART" \
  --namespace "$MARTY_DEV_NAMESPACE" --reuse-values \
  -f "$MARTY_DEV_ORIGIN_VALUES" --no-hooks --wait --timeout 15m
```

Here `MARTY_DEV_INSTALLED_CHART` is the verified installed chart directory or
archive, and `MARTY_DEV_ORIGIN_VALUES` is the minimal reviewed override file.
This replay does not need the new-default loading used when first enabling
the overlay. Configuration checksum changes trigger the affected rollouts;
inspect their completion before adding any manual restart.

Reconcile only the existing `marty-ui` Keycloak client's `redirectUris`,
`webOrigins` and `attributes.post.logout.redirect.uris` through the existing
Admin CLI/API. Preserve all other client fields and attributes, including its
PKCE requirement. Authenticate with existing administrator credentials inside
the Keycloak container. Keep authentication output, CLI state and admin-operation
evidence in distinct private files with restricted permissions; keep sanitized
public-field receipts separate, and clean up temporary CLI sessions on exit.
Read back those three public fields and the preserved PKCE setting.

Finish by checking HTTPS, deployment readiness and the stop guard, then perform
the authenticated browser and visible HMR round trip described above. Record
those outcomes separately from the certificate, Helm and client-update checks.

This preserves the issuer DID and its existing records. A DID or issuer profile
that still names the previous address remains unsuitable for an issuance or
credential-login qualification at the new origin. This UI replay does not renew
the eight-hour workload identities or extend the node's agreed stop time.

## Return to the installed static UI

```sh
helm upgrade "$MARTY_DEV_RELEASE" ./deploy/helm/marty \
  --namespace "$MARTY_DEV_NAMESPACE" --reset-then-reuse-values \
  --set ui.development.enabled=false --wait --timeout 10m
```

This removes the Node containers and source mounts and restores the original
static Nginx routes. Stop the development node at the end of the authorized
window; preserve its source diff or push the review branch first.

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

Run from the node's checkout, adapting the three installation-specific values:

```sh
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

## Return to the installed static UI

```sh
helm upgrade "$MARTY_DEV_RELEASE" ./deploy/helm/marty \
  --namespace "$MARTY_DEV_NAMESPACE" --reset-then-reuse-values \
  --set ui.development.enabled=false --wait --timeout 10m
```

This removes the Node containers and source mounts and restores the original
static Nginx routes. Stop the development node at the end of the authorized
window; preserve its source diff or push the review branch first.

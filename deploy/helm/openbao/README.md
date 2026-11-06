# OpenBao for the single-node Kubernetes development milestone

This directory contains a values profile for the **official OpenBao Helm chart
0.30.6**, not a chart fork. `upstream.json` pins the upstream archive and its
SHA-256. The chart's default server image is deliberately replaced by the
authenticated Marty `openbao-didcomm` image, which includes OpenBao 2.5.5, the
DIDComm plugin, and the existing `selfhost-tls-init` executable. Both the server
and its TLS init container use that same image digest.

The profile provides one Raft member, a retained 4 GiB PVC, an HTTPS listener,
native static-seal auto-unseal, and ordinary Kubernetes health probes. It requests
100 mCPU and 256 MiB of memory, with limits of 750 mCPU and 512 MiB. It requires
Kubernetes 1.30 or later and a default StorageClass. K3s's `local-path` StorageClass
is suitable for this development milestone. A single member and local storage
provide persistence across a normal restart; they provide no node redundancy.

## Fresh bootstrap

Run from the repository checkout on a Linux x86-64 operator host with Python 3,
PyYAML (for example, Ubuntu's `python3-yaml` package), `kubectl`, Helm 3, the
pinned release verifier tools, and the complete installer
release asset directory. The kubeconfig must authorize the selected development
namespace. The state directory must be a new absolute path under an existing
private operator directory. An existing namespace may contain the HTTPS ingress
Secret or registry credentials, but must have no application workloads, PVCs, or
Marty credentials.

Fetch the pinned official archive with Helm:

```sh
helm pull openbao \
  --repo https://openbao.github.io/openbao-helm \
  --version 0.30.6 \
  --destination /path/to/chart-packages
```

Then run the transport adapter with the selected, independently obtained release
identity. Replace each example path or identity with the actual installation
inputs:

```sh
python scripts/bootstrap_kubernetes_openbao.py \
  --kubeconfig /path/to/kubeconfig \
  --context development-context \
  --namespace marty-dev \
  --state-dir /private/operator/marty-dev-bootstrap \
  --assets /private/operator/release-assets \
  --gh /path/to/pinned/gh \
  --cosign /path/to/pinned/cosign \
  --helm /path/to/helm \
  --chart-package /path/to/chart-packages/openbao-0.30.6.tgz \
  --runtime-source-sha RELEASE_SOURCE_SHA \
  --chart-source-sha CHART_SOURCE_SHA \
  --release-tag RELEASE_TAG \
  --build-run-id RELEASE_BUILD_RUN_ID \
  --build-run-attempt RELEASE_BUILD_RUN_ATTEMPT
```

Add `--image-pull-secret NAME` for each existing same-namespace registry Secret
when the selected images require authentication. Keep downloaded release payloads
in the private modes required by the release verifier. The adapter copies the
verified native operator to its own executable file; do not change the downloaded
operator artifact's mode to make it executable.

The adapter calls the existing release verifier again before any cluster write.
It checks the complete signed artifact inventory, signatures, provenance,
selected source/tag/build identity, operator build identity, and the pinned
OpenBao chart archive. Generated `marty-images.json` and `openbao-images.json`
are installation configuration, not independently signed authorization.

The bootstrap uses existing tools for each operation:

1. Kubernetes creates the separate immutable `marty-openbao-seal` Secret. Helm
   installs the official chart with the authenticated image override.
2. The existing signed `selfhost-tls-init` executable creates the listener
   identity inside the Raft PVC. The native `bao operator init` command initializes
   the fresh static-sealed server exactly once.
3. The unchanged `docker/openbao-init.sh` from the authenticated installer bundle
   registers the DIDComm plugin and application policies. The native `bao` CLI
   creates scoped application tokens.
4. A bounded, disposable Pod runs the signed image's
   `marty-passport-tls-bootstrap` and the verified native operator's
   `operator keycloak-provision` command. Its private inputs arrive through exec
   stdin and live in a memory-backed temporary volume. The Pod is deleted after
   the producers finish.
5. The native operator's `kubernetes-secrets` command publishes the existing
   application Secret catalog. Standard `kubectl --from-file` inputs add the
   notification TLS Secrets and the initial operator password Secret.

Successful completion creates `bootstrap-complete.json` in the private state
directory. Install the application chart with that directory's
`marty-images.json` and the site-specific values. The application chart uses
`https://openbao:8200` in the same namespace and the existing Secret references;
it does not initialize OpenBao or receive its root or recovery authority.

## Credential and persistence contract

The OpenBao seal key is mounted read-only from `marty-openbao-seal` and is not
stored on the Raft PVC. The TLS init container receives only the PVC, not the
seal Secret. The native OpenBao process performs auto-unseal on subsequent starts.
The OpenBao service account has no automatically mounted Kubernetes API token,
and the profile installs no injector, operator, or auth-delegator binding.

The private state directory contains the static key, native initialization
response with root/recovery material, a scoped kubeconfig, and application
credential files. Keep that directory private and preserve it with operator
recovery material. These files must not be committed, attached to ordinary
diagnostics, put into Helm values, or copied into application containers. The
adapter prints no credential values. Failures retain diagnostics in that private
directory.

The application login uses `marty-operator` Secret key `password`; its private
operator-side file is `credentials/marty_org_admin_password`. This password is
different from the Keycloak master administrator password. The application
chart's existing Keycloak configurator creates the requested organization user.

This is a **short-lived development profile**. Workload TLS certificates and
scoped credentials expire after eight hours. The migration bootstrap credential
expires after two hours. Complete the initial migration and the planned
two-hour acceptance/reboot test within those windows, then stop the environment.
No credential renewal is installed by this milestone. Rebooting the node does
not extend certificate or token lifetimes. A continuously running installation
requires a separate reviewed renewal flow using the existing native producers.

## Restart and recovery checks

After the application is healthy, record the OpenBao cluster ID and check a
normal Pod restart or the planned whole-node reboot. The public native status
command uses the persisted listener CA and needs no root token:

```sh
kubectl --kubeconfig /path/to/kubeconfig --context development-context \
  --namespace marty-dev exec openbao-0 -- bao status -format=json
```

Require the same cluster ID, `initialized: true`, `sealed: false`,
`type: static`, and `storage_type: raft`, then check application readiness and
the intended login/demo flow. The PVC and the separate seal Secret must survive.
The chart retains PVCs on scale-down and deletion; Helm uses an `OnDelete`
StatefulSet strategy, so a deliberate Pod restart is needed to apply a later
Pod-template change.

Bootstrap refuses to adopt an existing installation or reuse a state directory.
If an initialization request times out, preserve both the namespace and private
state and inspect the native status and recorded initialization response. Do not
replay initialization, replace the static seal key, delete the PVC, or rerun with
a fresh state path to hide an uncertain result. Standard OpenBao recovery and
operator custody apply after the first initialization.

## Local validation

Render or lint the official chart with this profile and the generated digest
override:

```sh
helm lint /path/to/chart-packages/openbao-0.30.6.tgz \
  --values deploy/helm/openbao/values-k3s-dev.yaml \
  --values /private/operator/marty-dev-bootstrap/openbao-images.json

helm template openbao /path/to/chart-packages/openbao-0.30.6.tgz \
  --namespace marty-dev \
  --values deploy/helm/openbao/values-k3s-dev.yaml \
  --values /private/operator/marty-dev-bootstrap/openbao-images.json
```

This verifies Kubernetes manifest generation. A fresh-cluster installation and
restart test are still required to qualify runtime behavior.

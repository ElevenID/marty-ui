# Kubernetes development milestone

This target packages Marty with standard Kubernetes and Helm. It is an opt-in,
single-node development path. Its runtime provenance comes from the existing
signed installer inventory; it does not inherit the Compose installer's runtime
qualification or admit a release to the consumer installation channel.

## Ownership

| Responsibility | Implementation |
| --- | --- |
| Node and container runtime | K3s `v1.36.6+k3s1`, installed with its official installer |
| Application installation | Helm 3 `v3.22.1`, `deploy/helm/marty` |
| HTTPS routing | K3s's packaged Traefik, ordinary Ingress and TLS Secret |
| Public certificate enrollment and renewal | Official cert-manager `v1.21.3` chart |
| OpenBao server and Raft volume | Official OpenBao Helm chart `0.30.6` with the authenticated Marty plugin image |
| Database, Redis and applicant storage | StatefulSets/PVCs and a single-writer applicant Deployment |
| Migration and Keycloak configuration | Kubernetes Jobs and the existing application commands |
| Workload signing keys, certificates and scoped tokens | Existing native Marty producers and the OpenBao CLI |
| Release verification | Existing inventory validation, pinned `gh` and `cosign` verifiers |
| Trial shutdown | A systemd timer with an absolute UTC deadline |

There is no new operator, controller, package manager, cloud orchestrator, or
certificate client. `prepare_kubernetes_helm_values.py` projects an authenticated
inventory into Helm values. `bootstrap_kubernetes_openbao.py` transports the
existing native provisioning commands over `kubectl`; it never retries an
uncertain initialization or adopts an existing store.

## Development envelope

Use an isolated Linux amd64 node with **2 vCPU and 8 GiB RAM**. The first AWS
trial uses an eligible `m7i-flex.large`, Ubuntu 24.04, and a 40 GiB encrypted gp3
root disk. Confirm the account's active Free plan, remaining credits, instance
eligibility, and AMI eligibility before starting each trial. This is a credit
funded experiment, not a promise of permanently free Kubernetes hosting.

The AWS profile reuses an existing network and instance profile. It does not
create an EKS cluster, NAT gateway, AWS load balancer, domain, or paid account
upgrade. HTTP-01 uses port 80; operator HTTPS uses port 8443. Keep the Kubernetes
API and SSH behind the established private administration path. K3s ServiceLB
is node software; its `LoadBalancer` Service does not request an AWS ELB.

Fill the absolute stop deadline in
[`cloud-init.yaml.example`](../deploy/k3s/cloud-init.yaml.example) before launching.
Set EC2's instance-initiated shutdown behavior to `stop`. Verify the timer is
active before deploying application workloads. The deadline is fixed across a
reboot. Stopping a VM ends its compute usage; retained EBS storage remains a
resource that requires an explicit retention or deletion decision.

K3s local-path PVCs are bound to this node. They survive an ordinary reboot, but
are not replicated storage or a backup. The OpenBao seal key is kept separately
from the Raft PVC and also retained in the private bootstrap directory. Preserve
both the seal material and Raft state when planning recovery.

## Prepare the cluster

The cloud-init example pins and verifies the K3s binary, official install script,
and Helm archive before execution. It enables Kubernetes Secret encryption at
rest and keeps the host kubeconfig mode `0600`.

On the node, using its existing privileged administration session:

```sh
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
systemctl list-timers marty-dev-stop.timer --no-pager
kubectl get nodes
kubectl get pods -A

helm upgrade --install cert-manager \
  oci://quay.io/jetstack/charts/cert-manager \
  --version v1.21.3 --namespace cert-manager --create-namespace \
  --set crds.enabled=true --wait --timeout 5m
kubectl create namespace marty-dev
```

The application chart accepts an existing TLS Secret. For a raw public IPv4
trial, use [`ip-certificate.yaml.example`](../deploy/k3s/ip-certificate.yaml.example)
after choosing the CA account and accepting its subscriber agreement. Contact
email is optional for the selected CA; remove the placeholder if no contact is
being supplied. Replace `PUBLIC_IPV4` with the current instance address.
cert-manager's `shortlived` profile handles the IP certificate. The separate
Traefik TLSStore provides the default certificate for IP clients that omit SNI.
For DNS hosting, use a normal hostname certificate and Ingress host.

Do not expose the application until the certificate is Ready. A pending ACME
order is not successful HTTPS startup. Do not bypass certificate validation to
make acceptance pass.

## Authenticate the runtime and bootstrap OpenBao

Obtain a complete signed installer artifact set for an explicitly selected
runtime source, release tag, producer run, and attempt. These identities must be
chosen from the release/tag and workflow evidence, not inferred from an
unverified inventory. Keep each of these five subjects and its `.sigstore.json`
and `.provenance.jsonl` sidecars together in a private directory:

- `installer-inventory.json`
- `install.sh`
- `marty-deploy-linux-amd64`
- `prepared-selfhost-bundle.zip`
- `prepared-selfhost-images.json`

Use the existing installer verifier pins from `install.sh`. The adapter checks
the `gh` and `cosign` executable hashes again. Directories must be `0700`, input
artifacts `0600`, and verifier executables `0700`. Install the repository's
existing PyYAML dependency (`python3-yaml` on Ubuntu).

Download the official OpenBao chart archive; the bootstrap validates its exact
checksum against [`upstream.json`](../deploy/helm/openbao/upstream.json):

```sh
helm pull openbao --repo https://openbao.github.io/openbao-helm \
  --version 0.30.6 --destination /root/marty-k3s
```

Run `python3 scripts/bootstrap_kubernetes_openbao.py --help` for the explicit
paths and identities. Supply an **unused** private state directory, the selected
kubeconfig and context, a dedicated namespace, the authenticated artifact set,
the two pinned verifiers, Helm, and the pinned chart archive. The bootstrap
performs the full shared verification again before writing to the cluster.

The output contains `marty-images.json` and `openbao-images.json`. The Marty
output preserves the signed `ui-selfhost` image and the signed PostgreSQL/Redis
references. Runtime source and chart source are recorded separately. The
OpenBao override selects the signed plugin image using `tag@sha256`, as required
by the official chart's image template; the digest determines the bytes.

Root and recovery material stay in the private operator directory. Applications
receive public certificates, scoped KMS credentials, and distinct service
credentials through Kubernetes Secrets. The initial application operator has a
separate generated password in the `marty-operator` Secret. It does not reuse
Keycloak's bootstrap administrator password.

If bootstrap stops, retain its namespace and private state and diagnose the
reported step. Do not rerun initialization with a new output path against the
same store. Reconcile the existing attempt or deliberately start a new isolated
trial after preserving the failed attempt's evidence.

## Install the application

Create an installation values file with the actual public origin, organization
identity and TLS Secret. For the bounded development trial, the existing native
installer's `operator@localhost` identity avoids using an external mailbox.
Keep the generated password private and use it only in the selected test system.
Do not put passwords, root tokens, or private keys in Helm values.

```yaml
publicHost: YOUR_PUBLIC_IPV4
publicOrigin: https://YOUR_PUBLIC_IPV4:8443
organization:
  id: YOUR_ORGANIZATION_UUID
  slug: marty-dev
  adminEmail: operator@localhost
  did: YOUR_ORGANIZATION_DID
ingress:
  tlsSecretName: marty-public-tls
```

Render and validate before installation:

```sh
helm lint --strict deploy/helm/marty \
  -f deploy/helm/marty/values-k3s-dev.yaml \
  -f /root/marty-k3s/bootstrap/marty-images.json \
  -f /root/marty-k3s/installation.yaml

helm template marty deploy/helm/marty --namespace marty-dev \
  -f deploy/helm/marty/values-k3s-dev.yaml \
  -f /root/marty-k3s/bootstrap/marty-images.json \
  -f /root/marty-k3s/installation.yaml \
  | kubectl apply --dry-run=server -f -

helm upgrade --install marty deploy/helm/marty --namespace marty-dev \
  -f deploy/helm/marty/values-k3s-dev.yaml \
  -f /root/marty-k3s/bootstrap/marty-images.json \
  -f /root/marty-k3s/installation.yaml \
  --wait --wait-for-jobs --timeout 20m
```

Regular Jobs avoid a pre/post-install-hook readiness deadlock with the database
and schema-validating services. Kubernetes bounds and retries the migration
containers. Native issuance starts after the organization and credential
template services have seeded their initial data. The selected graph retains
the gateway's full readiness dependencies and uses native issuance exclusively.

## Acceptance and limits

Helm lint and rendered manifests establish packaging behavior only. Qualify the
actual isolated installation with all of the following evidence:

1. The exact runtime artifact set passes signature, provenance and image binding.
2. Database/credential bootstrap and migration/configuration Jobs complete.
3. Every required workload is Ready; gateway readiness checks its complete core.
4. HTTPS validates for the actual public origin, UI login succeeds, and a native
   credential issuance demonstration completes.
5. Reboot the same node; verify the same OpenBao cluster and PVC identities,
   automatic unseal, full application readiness and retained application data.
6. Record actual memory/CPU, pod restarts, events and shutdown status. Do not
   interpret resource requests as observed capacity.

The current native development workload identities last **eight hours**. The
migration-only bootstrap token lasts **two hours**. This milestone does not
install unattended application identity renewal; cert-manager renews the public
ingress certificate separately. Extending the application lifetime requires the
existing native renewal operation to be integrated and qualified. Do not extend
credentials or disable their checks to hide expiration.

Reboot testing here establishes recovery on the same single node. It does not
establish high availability, node replacement, backup restoration, multi-node
scaling, EKS compatibility, or production release admission.

## Upstream references

- [K3s architecture](https://docs.k3s.io/architecture)
- [K3s packaged Traefik customization](https://docs.k3s.io/networking/networking-services)
- [OpenBao official Helm chart](https://github.com/openbao/openbao-helm/releases/tag/openbao-0.30.6)
- [OpenBao 2.5 static seal](https://openbao.org/docs/2.5.x/configuration/seal/static/)
- [cert-manager supported versions](https://cert-manager.io/docs/releases/)
- [cert-manager ACME profiles](https://cert-manager.io/docs/configuration/acme/)
- [Let's Encrypt IP certificates](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)
- [AWS Free plan](https://aws.amazon.com/free/free-tier-faqs/)

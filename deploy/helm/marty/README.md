# Marty Helm chart

This chart installs the current Marty services, UI, remote-key Keycloak,
PostgreSQL and Redis into an existing Kubernetes cluster. It uses native
Deployments, StatefulSets, PVCs, Jobs, Services, NetworkPolicies and Ingress.
There is one native issuance owner (`issuance-native`). The current Rust graph
uses event-stream and durable outboxes, so it does not install RabbitMQ.

Use **one release per dedicated namespace**. Stable short Service names retain
the existing application and workload-certificate contract. The namespace and
StorageClass are portable; this chart does not provision a cluster or cloud
resources.

## Prerequisites

1. Kubernetes with a default StorageClass (or `persistence.storageClass`), a
   NetworkPolicy-capable CNI, and an Ingress controller. The K3s development
   profile selects Traefik and its `websecure` entry point. For another
   controller, set `ingress.className`, annotations and
   `networkPolicy.ingressNamespace` to the controller's namespace.
2. The existing release-verification workflow must authenticate the release
   inventory and exact images. Supply full immutable references in
   `images.services`, `images.ui`, `images.migrations`, `images.keycloak`,
   `postgres.image` and `redis.image`. The chart checks digest syntax; it does
   **not** verify signatures. Preserve the inventory's exact repositories,
   including the UI's `ui-selfhost` repository when present. No build runs on
   the target node. `imagePullSecrets` accepts normal Kubernetes pull Secrets.
3. OpenBao is a **separate, pinned official Helm release** using the signed
   Marty plugin image, TLS, persistent Raft storage, and an explicit unseal
   mechanism. `openbao.address` must resolve from the application namespace
   and match the OpenBao certificate. Bootstrapping keys, policies, identities,
   certificates and scoped tokens is completed before installing this chart.
4. Existing Kubernetes Secrets in this namespace must follow
   `deploy-config/catalog/kubernetes-secrets.json`. Their names can be changed
   through `existingSecrets`; their keys and projected filenames retain the
   catalog contract. This chart never accepts credential values in Helm
   values, creates replacement credentials, or initializes OpenBao.
5. An existing `kubernetes.io/tls` Secret, from cert-manager or another
   certificate issuer, supplied as `ingress.tlsSecretName`. Set `publicHost`
   and the operator's `organization.adminEmail`. `publicOrigin` can
   specify a non-default HTTPS port. Domain ownership, certificate issuance
   and firewall configuration remain external prerequisites.
6. A Redis TLS Secret with `tls.crt`, `tls.key` and `ca.crt`, named by
   `existingSecrets.marty-redis-tls` (default `marty-redis-tls`). The server
   certificate must include the DNS SAN `redis`. For the K3s development
   profile, the standard cert-manager resources in
   `deploy/k3s/redis-certificate.yaml` create a private CA and server certificate:

   ```sh
   kubectl --namespace marty-dev apply -f deploy/k3s/redis-certificate.yaml
   kubectl --namespace marty-dev wait --for=condition=Ready \
     certificate/marty-redis-tls --timeout=120s
   ```

Redis exposes verified TLS only. Its server private key is mounted only in
Redis; Marty containers receive only `ca.crt`. A small init container combines
the signed image's public CA bundle with this CA, and `SSL_CERT_FILE` selects
the resulting trust bundle for Rust Redis clients and migration commands.
Public HTTPS trust remains available. No local development environment or TLS
verification bypass is used. Certificate rotation requires restarting Redis
and the application pods so they reload their certificates and trust bundle.

Two notification Secrets supplement the older Kubernetes catalog:

| Secret name (configurable) | Required keys | Existing bootstrap outputs |
| --- | --- | --- |
| `notification-workload-tls` | `tls.crt`, `ca.crt` | `NOTIFICATION_WORKLOAD_SERVER_CERT`, `MARTY_WORKLOAD_IDENTITY_CA_CERT` |
| `notification-tls-kms` | `token`, `ca.crt` | `NOTIFICATION_TLS_KMS_TOKEN`, `OPENBAO_TLS_CA_CERT` |

An additional `marty-operator` Secret (also configurable through
`existingSecrets`) has a `password` key for the initial organization
administrator. The configurator reads it using `secretKeyRef` as
`MARTY_ORG_ADMIN_PASSWORD`; keep that generated credential in the bootstrap
credential store. This avoids importing a shared demo password or requiring
SMTP before the operator can first sign in.
For an isolated development milestone, the existing installer identity
`operator@localhost` is supported; use an owned email address for a normal
deployment.

The default key is `workload-tls-notification-server`, version `1`, consistent
with the existing self-host bootstrap. Applications use `DATABASE_SYNC_URL`
from `marty-secrets`, which must contain a URL-escaped `postgresql://` connection
string. The older catalog's `DATABASE_URL` Python driver scheme is not used.

The first milestone keeps the canonical `11id` Keycloak realm and KMS key
filenames. The packaged realm is derived from `config/keycloak/11id-realm.json`:
known demo-password users are removed before import, the service-account role
mapping is retained, and the API client secret is resolved from its Kubernetes
Secret. The existing strict configurator and theme are packaged unchanged.
Optional social login defaults to disabled. Enable
`config.KEYCLOAK_SOCIAL_LOGIN_ENABLED: 'true'` only after providing both Google
client credentials through the existing `marty-secrets` contract.

## Install

Keep the authenticated release image values and non-secret installation inputs
in separate values files. For example, an installation file contains:

```yaml
publicHost: marty.example.org
organization:
  adminEmail: operator@example.org
openbao:
  address: https://openbao:8200
ingress:
  tlsSecretName: marty-edge-tls
```

Then use Helm directly:

```sh
helm lint --strict deploy/helm/marty \
  -f deploy/helm/marty/values-k3s-dev.yaml \
  -f verified-release-values.yaml -f installation-values.yaml

helm upgrade --install marty deploy/helm/marty \
  --namespace marty-dev --create-namespace \
  -f deploy/helm/marty/values-k3s-dev.yaml \
  -f verified-release-values.yaml -f installation-values.yaml \
  --wait --wait-for-jobs --timeout 35m
```

Create the namespace and bootstrap its Secrets before the install. The
`--create-namespace` flag is harmless when it already exists. Retain a failed
release and Job logs for diagnosis before retrying; automatic uninstall on
failure would discard useful evidence.

The migration Job runs existing binary commands as ordered init containers:
revocation-profile, shared/notification bootstrap, organization,
credential-template, flow, device-registration and verification. Bounded curl
retries then wait for the organization and credential-template runtimes to
seed their catalogs before the native issuance migration runs. This prevents
fresh issuance from permanently seeding an empty application-template catalog.
The Job has a deadline and retry limit. It is a regular Job, so `helm --wait`
can observe the schema-validating applications and migration completion
without a post-install-hook deadlock. Kubernetes may restart application
containers while their prerequisites initialize.

For an IP endpoint, set `publicHost` to the raw IP and `publicOrigin` to, for
example, `https://192.0.2.20:8443`. The chart omits the Ingress rule host and TLS
hosts, because Kubernetes does not allow IP literals there. The certificate
must contain that IP SAN. For clients which omit TLS SNI, configure the
Ingress controller's default certificate separately (Traefik uses a
`TLSStore`); a portable Ingress cannot select that default. Normal DNS names
produce a host-specific rule and TLS host.

## Development capacity and persistence

`values-k3s-dev.yaml` keeps one replica per service, bounds CPU/memory requests,
and caps the configurable database pools at five connections. The applicant
JSON store always uses one replica with a `Recreate` strategy and a writable
directory PVC. PostgreSQL and Redis use persistent StatefulSets; Redis has
append-only persistence. StatefulSet PVCs survive Helm uninstall, and the
applicant PVC has Helm's `keep` policy. Delete data only as an explicit reset.

The development profile requests **875 millicores and 2336 MiB** for its steady
workloads, leaving room on a 2 CPU / 8 GiB node for K3s, the Ingress controller,
OpenBao and setup Jobs. Requests are a
scheduling budget, not a measured peak or production sizing guarantee. Measure
actual usage and reboot survival on the target. K3s local-path storage remains
tied to its node; this profile provides no failover or backup guarantee.

The UI's readiness checks gateway readiness. Keycloak startup/liveness use the
private management port `9000`; readiness checks the imported realm's OIDC
discovery document on `8080`. Internal peers keep the existing KMS-backed TLS
and scoped-token authentication. NetworkPolicies restrict private workloads
to the namespace and UI ingress to the configured controller namespace. Egress
is available for supported external integrations. The Canvas worker has no
HTTP health endpoint; Kubernetes observes its process exit, as in the existing
runtime. Set `canvasWorker.enabled=false` if that integration is not selected.

## Inspect and qualify

```sh
helm status marty -n marty-dev
kubectl get pods,jobs,pvc,ingress -n marty-dev
kubectl logs job/marty-migrate-1 -n marty-dev --all-containers
kubectl logs job/marty-keycloak-1 -n marty-dev
kubectl get events -n marty-dev --sort-by=.metadata.creationTimestamp
kubectl top pods -n marty-dev
```

Job names contain the Helm release revision. Existing Secrets are not hashed
into chart metadata: after rotating startup-read credentials, use the normal
`kubectl rollout restart` operation for affected workloads. Application
configuration overrides belong in the string-valued `config` map; credentials
belong in Secrets. Do not change schema, namespace, provider or key identity
under an existing data set without a reviewed migration.

Before claiming milestone acceptance, test a fresh isolated install, exact
image IDs, HTTPS and OIDC readiness, existing issuance/verification/wallet demo
journeys, and a full node reboot with persistent state and OpenBao unsealed.
`helm lint` and rendered-manifest tests do not establish those runtime results.
Upgrade/rollback and production availability remain separate qualification
work.

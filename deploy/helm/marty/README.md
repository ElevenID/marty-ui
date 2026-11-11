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
The existing migration bootstrap and signing-keys runtime both use Redis
database 2 for their managed signer registry.
Flow also receives the existing signer's public CA in its trust bundle and
calls the signer's HTTPS listener directly at `https://signing-keys:8018/internal`.
This keeps its startup health check independent of gateway readiness.

The native Kubernetes catalog publishes both Notification TLS Secrets:

| Secret name (configurable) | Required keys | Existing bootstrap outputs |
| --- | --- | --- |
| `notification-workload-tls` | `tls.crt`, `ca.crt` | `NOTIFICATION_WORKLOAD_SERVER_CERT`, `MARTY_WORKLOAD_IDENTITY_CA_CERT` |
| `notification-tls-kms` | `token`, `ca.crt` | `NOTIFICATION_TLS_KMS_TOKEN`, `OPENBAO_TLS_CA_CERT` |

The development bootstrap requires an authenticated native operator whose
`kubernetes-secrets-contract` output matches the checkout's exact compiled
publication contract (`marty.kubernetes-secret-publication/v1`). It checks this
before cluster access and uses the native publisher for these Secrets along
with the other catalog entries. Older operators without this contract are
refused before initialization. The bootstrap publishes default catalog names;
chart `existingSecrets` overrides still require the caller to provision the
corresponding names and keys.

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

`publicHost` accepts a DNS hostname or a raw IPv4 address, without a scheme,
port or path. `publicOrigin` defaults to `https://<publicHost>` and must use
that same host. Rendering fails before installation for a mismatched host,
invalid address or unusable port. Host comparison ignores DNS casing, while
the selected origin and its port spelling are preserved so an update does not
change the default issuer DID. That same origin supplies the default application
URLs, Keycloak callbacks, CORS and the development UI. An
explicit `organization.did` is preserved; retain it when changing the origin
of an existing installation. IPv6 public endpoints are not supported by this
chart and are rejected instead of producing an invalid default URL.

For an IPv4 endpoint, set `publicHost` to the raw IP and `publicOrigin` to, for
example, `https://192.0.2.20:8443`. The chart omits the Ingress rule host and TLS
hosts, because Kubernetes does not allow IP literals there. The certificate
must contain that IP SAN. For clients which omit TLS SNI, configure the
Ingress controller's default certificate separately (Traefik uses a
`TLSStore`); a portable Ingress cannot select that default. Normal DNS names
produce a host-specific rule and TLS host.

An explicit `ingress.host` may select a different DNS name or wildcard DNS rule
when an external reverse proxy rewrites the Host header. It does not change the
public application origin. IP literals, ports and malformed DNS rules are
rejected in this field.

SMTP credentials remain in the existing `marty-secrets` Secret, using its
`SMTP_PASSWORD` key; `existingSecrets.marty-secrets` may rename that Secret.
Do not put `SMTP_PASSWORD` or `KEYCLOAK_SMTP_PASSWORD` in `config`: these keys
are rejected so a credential cannot be written into the ConfigMap or
Helm values history.

The same boundary applies to the other private catalog values, including
database passwords and credential-bearing database URLs, API keys, webhook
secrets, OpenBao tokens and the initial administrator password. Rendering
refuses their scalar environment names and runtime aliases in `config`,
including aliases for catalog entries that accept only file inputs. This also
covers the OIDC client secret and the private verification governance registry.
The guard applies even when the Keycloak configurator is disabled and does not
print the supplied value. Provide private values through the existing
Kubernetes Secrets contract.
`config` is distributed as a nonsecret ConfigMap; use it for customer policy,
public endpoints, SMTP usernames, KMS key names/versions and mounted file paths.
The packaged private-key list is checked against the source secret catalogs.

Set `canvasWorker.enabled: false` as a YAML boolean to omit the Canvas sync
worker when the installation does not use that integration. The chart rejects
quoted strings such as `'false'` instead of treating them as enabled. This
switch does not disable the application APIs or other installation workloads.

The generated ConfigMap also sets the Canvas worker's `ISSUER_BASE_URL` to the
installation origin and `CANVAS_OAUTH_COMPLETION_REDIRECT_URL` to that origin
plus `/console/org/deploy/canvas`, preserving a configured HTTPS port. Explicit
values for these keys in `config` take precedence over the generated defaults.

## Direct issuance and persistence acceptance

Once the required workloads and setup Jobs are ready, run
`tests/scripts/run-kubernetes-acceptance.cjs` from a machine that can reach the
public HTTPS origin. It uses the existing browser `AuthHelpers` and OID4VCI
`receiveAndVerifyCredential` helper. Install Node 24 or newer and the locked
test dependencies, including Chromium:

```sh
npm --prefix tests ci
tests/node_modules/.bin/playwright install --with-deps chromium
```

The four arguments `--origin`, `--issuer-did`, `--password-file` and
`--state-dir` are required. Use the actual HTTPS origin without a trailing
slash, the matching managed `did:web` issuer, and absolute private file paths.
The password must be an existing regular file with no group/other permissions.
Choose a new state directory beneath an existing private parent; the driver
creates it with mode `0700` and its files with mode `0600`.

```sh
node tests/scripts/run-kubernetes-acceptance.cjs --phase accept \
  --origin https://marty.example.org:8443 \
  --issuer-did did:web:marty.example.org%3A8443:orgs:marty-dev \
  --password-file /private/marty/bootstrap/credentials/marty_org_admin_password \
  --state-dir /private/marty/acceptance
```

The default login is `operator@localhost`, the organization is
`00000000-0000-0000-0000-000000000001`, and the source credential template is the
built-in Marty badge `50000000-0000-0000-0000-000000000040`. Override them with
`--email`, `--organization-id` and `--credential-template-id` when needed.
`--repo` defaults to the checkout containing the script; an override must be
an absolute checkout path. The source template is discovered and validated
through the authenticated API before use.

The `accept` phase logs in normally, ensures the requested issuer identity
exists, and, when needed, creates and activates a new version of the source
template with that issuer. It initiates one synthetic credential directly
through the native issuance API, redeems the offer, verifies the issuer's
signature and holder binding, and reads back the exact transaction and issued
credential hash. It does not require an application approval workflow.

After the planned reboot, run the same command with `--phase resume` and the
same arguments. Resume requires the successful acceptance receipt, performs a
fresh login, verifies the retained credential against the live issuer DID
document, and checks the same persisted IDs and hash. It creates no new offer.
Record the node/PVC/OpenBao restart evidence separately; this driver verifies
application continuity and does not reboot or inspect the cluster.

Only non-secret receipts are printed. Passwords, offers and credential bodies
remain private; state files are capped at 1 MiB and HTTP failure diagnostics at
64 KiB. A failed run retains its partial state and exits nonzero. Diagnose that
attempt before starting another; the driver refuses to reuse an acceptance
directory and does not replay uncertain writes or issuance. Normal browser and
Node TLS verification remain enabled throughout.

## Development capacity and persistence

`values-k3s-dev.yaml` keeps one replica per service, bounds CPU/memory requests,
and caps the configurable database pools at five connections. The applicant
JSON store always uses one replica with a `Recreate` strategy and a writable
directory PVC. PostgreSQL and Redis use persistent StatefulSets; Redis has
append-only persistence. StatefulSet PVCs survive Helm uninstall, and the
applicant PVC has Helm's `keep` policy. Delete data only as an explicit reset.

Redis uses `noeviction` because it stores signing identities, published DID
documents and one-use signing-grant markers as well as cache entries. At its
configured memory limit it refuses new writes while retaining existing keys;
evicting either permanent records or unexpired replay markers is unsafe. Watch
Redis memory and rejected commands during capacity testing. The existing
memory cap and pod limits remain bounded; a full Redis instance needs operator
attention and can make application writes unavailable.

Single-replica application Deployments use `Recreate`. This keeps the
development node within its existing no-surge budget and makes Helm wait for
the application's one Ready pod. With `RollingUpdate` and
`maxUnavailable: 1`, Helm 3.22.1 can otherwise consider a one-replica
Deployment ready with zero Ready pods. Recreate causes a service interruption
during a rollout; this development target does not promise uninterrupted
updates. When `apps.replicas` is greater than one, applications retain the
existing rolling strategy with one unavailable replica and no surge; applicant
remains a single writer. Upgrade and multi-replica qualification remain
separate work.

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

The development bootstrap's application AppRole and native generation commands
prepare ordinary-token replacement candidates in private operator state. A
staged candidate does not update this chart's Secrets or restart workloads.
Use the [Kubernetes lifecycle guide](../../../docs/kubernetes-first-milestone.md#stage-ordinary-application-credentials)
for the fixed 11-input replacement scope, retained identity and recovery
boundary. Fresh bootstrap also enrolls the existing Renewal AppRole for
[private TLS and Keycloak candidate staging](../../../docs/kubernetes-renewal-staging.md).
The [Renewal activation command](../../../docs/kubernetes-renewal-activation.md)
uses conditional updates to the existing Secrets, Deployment controllers and
private delivery checks. Authenticated workload acceptance, automatic renewal
and live upgrade qualification remain separate requirements.

Before claiming milestone acceptance, test a fresh isolated install, exact
image IDs, HTTPS and OIDC readiness, existing issuance/verification/wallet demo
journeys, and a full node reboot with persistent state and OpenBao unsealed.
`helm lint` and rendered-manifest tests do not establish those runtime results.
Upgrade/rollback and production availability remain separate qualification
work.

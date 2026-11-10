# Configure a Kubernetes development installation

Use this guide with the [Kubernetes development milestone](kubernetes-first-milestone.md)
on the existing isolated AWS/K3s node. The signed Linux/Compose installer has a
separate [hosting file](installer-hosting.md) and typed
[application settings file](installer-application-settings.md).

For a complete customer example, use the
[Canyon Skills Academy scenario](customer-deployment-scenario.md). It supplies
separate customer, optional email and synthetic credential-claim inputs, plus
checks for a customer UUID and issuer identity rather than the default tenant.

## Keep one source for each setting

| Setting | Source | Check before installation |
| --- | --- | --- |
| Runtime images | Authenticated `marty-images.json` from bootstrap | Keep the signed repositories and immutable digests |
| Registry access | Bootstrap `--image-pull-secret`, repeated as needed | Each existing Secret is in the selected namespace and has a Kubernetes registry type |
| Public URL, organization and login policy | One nonsecret `installation.yaml` | Host, origin, TLS certificate and callback identity agree |
| Passwords and provider credentials | Existing Kubernetes Secrets and private bootstrap storage | Use the catalog keys and selected Secret names; never put credentials in `config` |
| Cluster and namespace | Explicit kubeconfig, context and dedicated namespace | Use the same selections for bootstrap, Helm and kubectl |
| Persistent data and credential lifecycle | Original bootstrap state, PVCs and retained generation receipts | Preserve identity across a reboot; check expiry before resuming |

Bootstrap checks the Helm 3 executable before creating its state directory.
After authenticating runtime artifacts and selecting the explicit Kubernetes
context, it checks registry Secret names and types before creating the namespace,
seal Secret or OpenBao release. A failed prerequisite should be corrected before
attempting provisioning. A later partial bootstrap still requires investigation;
do not retry initialization against an existing OpenBao store.

The validated registry selection produces both `openbao-pull-secrets.json` and
`marty-pull-secrets.json`. The first is consumed by OpenBao bootstrap. Include the
second when rendering or installing the Marty chart so the same registry
references reach application workloads. Both files contain names, not registry
credentials. An empty selection produces an empty list for public images.

## Select the public origin and initial login policy

A DNS installation values file can contain:

```yaml
publicHost: identity.example.org
publicOrigin: https://identity.example.org
organization:
  slug: marty-dev
  adminEmail: operator@localhost
ingress:
  tlsSecretName: marty-public-tls
config:
  KEYCLOAK_USER_REGISTRATION_ENABLED: 'true'
  KEYCLOAK_VERIFY_EMAIL: 'false'
  KEYCLOAK_RESET_PASSWORD_ENABLED: 'false'
  KEYCLOAK_SOCIAL_LOGIN_ENABLED: 'false'
  ORGANIZATION_CREATION_ENABLED: 'false'
```

Replace the hostname and select the actual organization identity. The isolated
development profile permits `operator@localhost`; use an owned address for a
normal installation. Organization creation is an explicit product policy, not a
requirement for the initial organization administrator to sign in.

For the AWS direct-IP trial, replace the two public fields with the current
address, for example:

```yaml
publicHost: 192.0.2.20
publicOrigin: https://192.0.2.20:8443
```

`publicHost` is a DNS name or raw IPv4 address without a port. `publicOrigin` is
an HTTPS origin with the same host and an optional valid port; it has no path,
credentials, query or fragment. IPv6 is not supported by this chart's current
public endpoint contract. Helm rejects conflicting or malformed inputs before
installation. Explicit valid origin spelling is retained because the derived
issuer DID can depend on those exact bytes.

The certificate must cover the chosen name or IP. The IP path also requires the
controller's default TLS certificate, as described in the milestone guide.
Leave `ingress.host` unset for ordinary direct hosting. A separate DNS/wildcard
Ingress override is available for an operator-managed reverse proxy; that proxy
must route the canonical public origin correctly. This does not create another
issuer or automatically configure DNS, certificates or external login providers.

Preserve `organization.did` and the retained organization identity when changing
an existing development endpoint. An EC2 public-IP change is not permission to
silently replace the issuer DID or reinitialize accounts.

Select the initial tenant through `organization.id` and `organization.slug`.
Use the lowercase canonical UUID spelling; the chart refuses uppercase UUIDs
because some service records use exact string keys. Inspect retained tenant
records before correcting an existing installation rather than silently
changing its identity.
Conflicting `config.MARTY_ORG_ID` or `config.MARTY_ORG_SLUG` aliases are rejected
because callbacks and the default issuer DID are derived from the canonical
values. Set its display name with `config.MARTY_ORG_NAME`. The runtime must
contain the customer bootstrap corrections described in the scenario guide;
changing Helm values does not rename or transfer an existing organization.

The packaged login realm is `11id`. The chart rejects a different
`KEYCLOAK_REALM` because its imported realm and readiness checks use that name.
Login policy flags reject invalid spellings rather than falling back to a
different policy. Quote values such as `'false'` in the string-valued `config`
mapping. The existing setup-script boolean spellings remain supported.

## Enable Keycloak mail explicitly

Default installation does not require an SMTP service. Password reset defaults
to disabled. Enable reset or email verification only after configuring and
testing a real provider. Add nonsecret settings to `installation.yaml`:

```yaml
config:
  KEYCLOAK_SMTP_HOST: smtp.example.org
  KEYCLOAK_SMTP_PORT: '587'
  KEYCLOAK_SMTP_FROM: identity@example.org
  KEYCLOAK_SMTP_USERNAME: identity-mailer
  KEYCLOAK_SMTP_STARTTLS: 'true'
  KEYCLOAK_SMTP_SSL: 'false'
  KEYCLOAK_VERIFY_EMAIL: 'true'
  KEYCLOAK_RESET_PASSWORD_ENABLED: 'true'
```

This explicit reset-password selection also matters when upgrading an existing
installation: if its working mail flow relied on the old implicit `true`
default, set `KEYCLOAK_RESET_PASSWORD_ENABLED: 'true'` before running an enabled
Keycloak configurator with this chart.

Merge those keys into the existing `config` mapping; do not duplicate the YAML
key. Store the provider password under `SMTP_PASSWORD` in the existing
`marty-secrets` Secret, or its `existingSecrets.marty-secrets` override, using the
installation's private credential-management procedure. Preserve all unrelated
keys. When both an SMTP host and username are configured, the configurator
requires that key through its `secretKeyRef`; a missing key prevents the Job
from starting. The reference remains optional for a mail-free installation or
an upgrade preserving stored realm SMTP. A configured host without a username
selects an unauthenticated relay; the Job supplies an empty password so a
retained provider Secret cannot silently enable authentication on that relay.
Never place `SMTP_PASSWORD` or `KEYCLOAK_SMTP_PASSWORD` in Helm `config`; the chart
rejects both without echoing their values.

A fresh installation with an enabled configurator must supply an SMTP host
before enabling verification or reset. Configured mail requires a valid port
and sender; SSL and STARTTLS cannot both be enabled, and authenticated mail
requires one encrypted transport. A Helm upgrade may preserve an SMTP provider
already stored in the realm by leaving its host unset. Preview that upgrade
with `helm template --is-upgrade` or `helm upgrade --dry-run=server`, so the
preview uses the same installation-versus-upgrade behavior as the real command.
These checks establish configuration requirements; only a real delivery test
can establish provider authentication and working verification/reset links.

This configures Keycloak account-verification and password-reset email. It does
not enable application notification email; that adapter remains unavailable.
Google login separately requires both existing Google credential inputs and its
provider callback configuration.

## Render the complete selection before writing it

Complete the milestone's artifact verification, namespace/bootstrap and TLS
steps first. Use the same generated registry-reference file in every Helm
command. For example, with the explicit context already selected in a private
`KUBECONFIG` and the variables below set to the intended installation:

```sh
helm lint --strict deploy/helm/marty \
  -f deploy/helm/marty/values-k3s-dev.yaml \
  -f "$BOOTSTRAP_STATE/marty-images.json" \
  -f "$BOOTSTRAP_STATE/marty-pull-secrets.json" \
  -f "$INSTALLATION_VALUES"

helm template marty deploy/helm/marty --namespace "$MARTY_NAMESPACE" \
  -f deploy/helm/marty/values-k3s-dev.yaml \
  -f "$BOOTSTRAP_STATE/marty-images.json" \
  -f "$BOOTSTRAP_STATE/marty-pull-secrets.json" \
  -f "$INSTALLATION_VALUES" \
  | kubectl --context "$MARTY_KUBE_CONTEXT" --namespace "$MARTY_NAMESPACE" \
      apply --dry-run=server -f -
```

Both commands must succeed. Helm validation and Kubernetes server dry-run do not
prove a registry login, valid external provider credentials or a healthy
application. Use the milestone's `helm upgrade --install` command with these
same values files and explicit context, then check Jobs, workload readiness,
HTTPS, login and acceptance.

## Resume a stopped development node

Keep the AWS Free plan/credit checks and absolute shutdown timer from the
milestone guide. Reuse the retained node, namespace, OpenBao store and private
bootstrap evidence. Check the current public IP and certificate before access.

Development workload credentials have an **eight-hour absolute lifetime** and
the initial migration token a **two-hour lifetime**. Stopping the node does not
pause expiry. cert-manager's public certificate renewal does not replace
application, workload-TLS or Keycloak credentials. There is no automatic
application renewal schedule in this profile.

Before expiry, use the existing ordinary-token and TLS/Keycloak staging and
activation commands. After expiry, use only the recovery procedure applicable
to that retained installation; the
[legacy recovery guide](kubernetes-legacy-credential-recovery.md) documents its
specific admitted legacy generation. Fresh bootstrap is not a resume command.
Helm's `deployed` status alone does not establish readiness or extend credentials.

## References

- [Kubernetes image pull Secrets](https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod)
- [Helm 3 lint](https://helm.sh/docs/v3/helm/helm_lint/)
- [Helm 3 template](https://helm.sh/docs/v3/helm/helm_template/)

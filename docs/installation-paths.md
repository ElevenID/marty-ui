# Installation paths and configuration ownership

Choose the path that matches the installation you are creating or maintaining.
An artifact being published, a model rendering successfully, and an application
being ready are separate observations. Use each path's documented checks before
handing the installation to a customer.

## Entry points

| Situation | Entry point | Configuration owner | Current scope |
| --- | --- | --- | --- |
| Fresh signed Linux candidate | [Linux tester quickstart](linux-installer-tester.md), exact release `install.sh --candidate-test TAG` | Private typed hosting and application-settings JSON; authenticated package and retained installer journal | Linux amd64, regular user, existing rootless Docker; experimental candidate. Normal channel/version installation requires separate signed admission. |
| New single-node AWS/K3s development installation | [Kubernetes configuration](kubernetes-installation-configuration.md) and [development milestone](kubernetes-first-milestone.md) | Helm values for nonsecret customer policy; authenticated image values; separately provisioned Kubernetes Secrets | Dedicated development namespace on the documented 8 GiB node. Helm success does not qualify credential lifetime, browser login or production capacity. |
| Existing manual self-host Compose installation | [Production Compose configuration](../deploy-config/compose/selfhost-production/README.md) | Selected environment file, external secret files, exact reviewed Compose file order and project | Operator-managed lifecycle and release verification; source configuration alone grants no signed-installer admission. |
| Existing legacy Kubernetes manifests | `scripts/deploy-kubernetes.sh --help` | Clean reviewed manifest checkout, signed operator and release inputs, operator-owned shell environment file | Maintenance of the selected manifest tree. Default `k8s/oracle` manifests target `marty-prod` and `ocir-secret`; flags do not rewrite that manifest identity. Use the Helm path for a new AWS/K3s installation. |
| Retained Windows Docker Desktop installation | [Windows recovery](windows-compose-recovery.md) and [retained product adoption](windows-renewal-activation.md) | Retained ordered Compose files, environment file, Docker context and reviewed private deployment evidence | Recovery/adoption of retained candidates. This is not a fresh Windows bootstrap; Windows execution and reboot qualification require the actual Windows host. |
| Local application development or beta experiments | [Development quickstart](../README.md#local-development-recommended) and [deployment catalog](../deploy-config/README.md) | Development/beta environment and its named Compose project | Development and release engineering. Do not layer development Compose infrastructure into production. |

The POSIX public bootstrap refuses macOS, Windows and unsupported architectures
before staging or downloads. A source-checkout command or platform-specific
recovery script does not expand its support matrix.

## Hosting and application choices

For the signed Linux candidate, [hosting configuration](installer-hosting.md)
owns the canonical HTTPS origin, host listener, public-entry alias, TLS source,
webpage sections and optional Cloudflare connector. Local, direct and external
proxy modes use the same authenticated application topology. DNS, provider port
mapping, firewall rules and frontend trust remain explicit host prerequisites.
An IP landing-page alias does not replace the canonical DNS issuer identity.

[Application settings](installer-application-settings.md) own the permitted
registration, mail, organization display name and integration choices. Imported
optional credentials retain their separate private-file custody. Managed
OpenBao is the default; an explicitly selected external foundation has its own
prerequisites. Selecting AWS hosting does not select AWS KMS.

For Helm, keep customer values separate from authenticated release-image
selection. The [Canyon Skills Academy scenario](customer-deployment-scenario.md)
supplies a customer organization, canonical DNS origin and optional authenticated
mail configuration. It exercises tenant bootstrap and refuses inconsistent
aliases or incomplete mail prerequisites. The same display-name scenario is
also checked through the native source package and Compose hosting models.

## Shared datastore behavior

The PostgreSQL initialization script is shared by the source Compose paths and
the packaged Helm chart. Customer passwords are read from the selected secret
source and passed to `psql` through its environment. PostgreSQL quotes values and
identifiers; punctuation is not interpreted as SQL. Existing role passwords are
preserved when initialization is repeated. Password rotation requires its
separate supported operation, not rerunning first-install initialization.

The shared service loader expands the catalog's `${MARTY_DB_PASSWORD}` slot in
`DATABASE_URL_TEMPLATE` as a URI component. Reserved characters, literal percent
signs and UTF-8 bytes are encoded without changing the raw password. Template
text is data: additional shell variables and command substitutions are refused.
The double-dollar spelling used by Compose source files is also accepted.
A complete `DATABASE_URL` remains caller-encoded and is unchanged when no
template is selected; an explicitly selected template retains its precedence.
The native Kubernetes publisher applies the same component encoding to the
database and legacy AMQP URI fields while preserving their scalar Secret values.
Existing secret-file handling still removes CR bytes and trailing LF bytes;
it is not a mechanism for binary passwords or NUL bytes.

Redis contains retained signing and identity configuration and short-lived
one-use grant markers as well as cache-like data. The shared instance therefore
uses `noeviction`: memory pressure refuses new writes instead of discarding
existing keys. Existing expiry, persistence and memory ceilings remain in place.
Investigate an out-of-memory refusal and the documented retention/cleanup owner;
changing back to an eviction policy can lose identity or replay-protection state.
AOF persistence does not replace a backup or make Redis highly available.

## Diagnostics and recovery

Use `status`, `doctor`, `trust-info` and `validate` on the retained signed
installation after startup, then perform the documented browser and application
journey checks. An ACME-pending result may exit zero before the application has
started; continue the retained order using the reported operation. Do not start
a new bootstrap to recover an existing installation.

The legacy Kubernetes wrapper now reports failure when a required image update,
resource read or rollout fails. `status` does not require an image registry or
release credential, and its explicit command-line namespace overrides values in
the selected environment file. A failed update may already have changed earlier
Deployments: inspect current state before retrying. It does not perform an
automatic rollback.

The Kubernetes development profile has bounded credential lifetimes. Stopping a
node does not pause expiry. Use its documented renewal or recovery owner and
preserve existing credentials and evidence. Re-running fresh OpenBao bootstrap
against an existing store is not recovery.

## Verification boundaries

The source checks deliberately cover different layers:

| Check | What it establishes |
| --- | --- |
| Helm schema, lint and rendered-manifest tests | Customer value validation, resource shape, Secret references and datastore configuration |
| Native packaged-source Compose tests | Configuration propagation across hosting variants, restart and generation models, and preservation of unrelated runtime fields |
| Nightly source-bundle integration | Selected renderer and tools, deterministic input environment, real ZIP creation, receipt and descriptor consistency |
| Disposable PostgreSQL and Redis tests | Actual scalar and loader/publisher URI password authentication, repeat initialization, memory-pressure refusal, key retention and AOF restart |
| Legacy shell execution tests | Argument precedence, literal callback configuration and nonzero failure propagation without cluster mutation |

These checks do not substitute for a newly authenticated release on the target
host, a fresh browser login, or a complete issue/present/revoke journey. Keep
those deployment outcomes explicit when reporting customer readiness.

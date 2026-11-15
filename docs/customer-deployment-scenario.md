# Customer deployment scenario: Canyon Skills Academy

## Customer and acceptance goal

Canyon Skills Academy is a fictional workforce training provider. Assume one
academy administrator, two credential issuers and a pilot cohort of 25 adult
learners. Staff approve completion of a practical skills course, issue an Open
Badges 3 credential in VC-JWT format and let the learner receive it through
OID4VCI. These are scenario assumptions, not measured capacity or customer data.

The academy controls account creation and organization membership. A credential
must not silently create a new login account. The first installation works
without email delivery; email verification and password recovery are a separate
optional configuration. Managed issuer signing and workload TLS use the
installation's existing OpenBao integration. No Canvas credentials or external
LMS are required for this direct issuance rehearsal.

| Input | Scenario value or requirement |
| --- | --- |
| Organization ID | `750e8400-e29b-41d4-a716-446655440001` |
| Organization slug | `canyon-skills` |
| Organization name | `Canyon Skills Academy` through `config.MARTY_ORG_NAME` |
| Test administrator | `admin@canyon-skills.example`; a synthetic login identity, not a mailbox |
| Intended customer origin | `https://credentials.canyon-skills.example`; reserved example DNS |
| DNS issuer DID | `did:web:credentials.canyon-skills.example:orgs:canyon-skills` |
| Credential contract | Organization-owned active Open Badges template, VC-JWT, managed ES256 issuer |
| Trial topology | One K3s development node, persistent PostgreSQL/Redis/applicant storage, separate OpenBao chart |
| External access | HTTPS through the UI ingress; database and internal service endpoints stay ClusterIP |

The nonsecret profile is
[`customer-education.yaml`](../deploy/helm/marty/examples/customer-education.yaml).
The optional email policy is
[`customer-education-smtp.yaml`](../deploy/helm/marty/examples/customer-education-smtp.yaml).
Neither file includes image digests, passwords, tokens or a functioning external
provider. The synthetic DNS and SMTP names must be replaced for a live customer.
The nonsecret
[`customer-education-claims.json`](../deploy/helm/marty/examples/customer-education-claims.json)
fixture supplies fictional learner name Avery Morgan, academy name and
Workplace Safety Foundations achievement text for the credential rehearsal.

## Keep the installation inputs separate

Use the same installation and credential-production path as
[the Kubernetes development milestone](kubernetes-first-milestone.md), with a
**new namespace and fresh private bootstrap state for this customer scenario**.
Changing the organization values of a retained deployment does not transfer its
existing templates, memberships, signer registry or credentials to a new
customer. Do not initialize an existing OpenBao store again.

Apply values in this order:

| Layer | Source and purpose |
| --- | --- |
| Development resources | `deploy/helm/marty/values-k3s-dev.yaml` |
| Verified runtime and infrastructure images | `marty-images.json` emitted by the authenticated release/bootstrap path |
| Checked registry references | `marty-pull-secrets.json` from that same bootstrap state |
| Customer choices | `deploy/helm/marty/examples/customer-education.yaml` |
| Optional login email policy | `customer-education-smtp.yaml`, only after mail prerequisites are available |
| Actual installation endpoint | A separate operator-created values file with the real host, exact HTTPS origin and TLS Secret name; override the administrator email here when appropriate |

The chart deliberately fails to render the example without the image layer.
The render tests use synthetic digests in temporary test files only. They are
not release artifacts and must never be copied into an installation.

For the DNS customer path, provision the actual DNS record and a valid matching
certificate. For a disposable AWS trial, set the endpoint layer's `publicHost`
to the node's current IPv4 address and `publicOrigin` to its exact HTTPS origin,
including the externally reachable port. Select the matching existing TLS
Secret with `ingress.tlsSecretName`. The chart renders a hostless ingress rule
for an IP endpoint because a Kubernetes Ingress host is a DNS name.

The base profile leaves `organization.did` unset. A **fresh** trial therefore
derives a DID from the actual endpoint, escaping a port as `%3A`; the path stays
`:orgs:canyon-skills`. This is a separate laboratory issuer identity. It does
not establish that the customer's DNS or customer DID is operational. Retained
issuers must preserve their existing explicit DID and published resolution;
changing a node address is not a credential identity migration.

For a new isolated scenario, set these variables to the actual private state,
explicit context, namespace and endpoint values file before rendering:

```sh
: "${BOOTSTRAP_STATE:?fresh customer bootstrap state}"
: "${MARTY_KUBE_CONTEXT:?explicit customer cluster context}"
: "${MARTY_NAMESPACE:?new customer scenario namespace}"
: "${CUSTOMER_ENDPOINT_VALUES:?actual endpoint values file}"

helm lint --strict deploy/helm/marty \
  -f deploy/helm/marty/values-k3s-dev.yaml \
  -f "$BOOTSTRAP_STATE/marty-images.json" \
  -f "$BOOTSTRAP_STATE/marty-pull-secrets.json" \
  -f deploy/helm/marty/examples/customer-education.yaml \
  -f "$CUSTOMER_ENDPOINT_VALUES"

helm template marty deploy/helm/marty --namespace "$MARTY_NAMESPACE" \
  -f deploy/helm/marty/values-k3s-dev.yaml \
  -f "$BOOTSTRAP_STATE/marty-images.json" \
  -f "$BOOTSTRAP_STATE/marty-pull-secrets.json" \
  -f deploy/helm/marty/examples/customer-education.yaml \
  -f "$CUSTOMER_ENDPOINT_VALUES" \
  | kubectl --context "$MARTY_KUBE_CONTEXT" --namespace "$MARTY_NAMESPACE" \
      apply --dry-run=server -f -
```

After both commands succeed, use the milestone's bounded
`helm upgrade --install --wait --wait-for-jobs` invocation with **these same
layers** and the explicit context/namespace. Include the optional SMTP layer in
all three invocations if it is being qualified. Do not count a Helm `deployed`
status as application acceptance.

## Configuration audit and release prerequisites

The custom organization exercises code paths that a default `marty` install
cannot test. This audit identified the following release requirements:

- Native organization startup must consume `MARTY_ORG_NAME` and
  `MARTY_ORG_SLUG` when creating its first organization, alongside
  `MARTY_ORG_ID`. Previously it accepted a custom ID while creating the name
  `Marty` and slug `marty`; Keycloak independently accepted the customer name.
- Native issuance's fresh application-template seed must select templates,
  construct deterministic IDs and save records under the configured
  organization. Its previous hardcoded default UUID left a custom customer's
  application catalog unseeded.
- Every organization-owned login deployment seed must use the configured
  organization ID. Its referenced presentation policy, trust profile and
  built-in login/issuance flows must use that same ID. Previously the
  presentation-policy catalog and historical Flow seed selected the default
  organization independently of the customer configuration. Validate these
  ownership links at runtime; a direct issuance pass does not exercise them.
- Flow's migration command and read-only schema validator must receive the
  configured organization ID. Fresh built-in flow definitions and their
  bootstrap instance belong to that ID, and the default deployment can receive
  the login-flow reference only when it has the same owner. Retained fixed-ID
  policies, flows, instances and deployment profiles keep their existing
  owner; conflicting configuration must stop rather than reassign them.
- The fixed default revocation profile must belong to the configured customer.
  Native startup checks the retained owner in its migration transaction. A
  conflict rolls back pending schema and status-list URL migrations; a
  same-owner restart preserves the customer's profile settings and timestamps.
- The chart must reject conflicting identity aliases and invalid mail-dependent
  login configuration before Kubernetes changes are applied.

These are application/runtime requirements. A locally corrected Helm chart
does not make an older signed image contain the Rust corrections. Select and
verify a signed runtime containing those changes before declaring the fresh
customer deployment qualified. Record `release.runtimeSourceSha`, image digests
and the chart source with the acceptance evidence. Startup must preserve a
retained organization record rather than rename or reassign it automatically.

The production profile's credential catalog seeds its existing membership
badge with the configured organization ID on a fresh database. Its stable
template ID is `50000000-0000-0000-0000-000000000040`. On a retained database,
that ID can belong to the prior organization; the acceptance driver correctly
refuses to use a template outside the selected organization.

For the supported Open Badges rehearsal, read these ownership links back from
the actual installation. Identical UUIDs in different services name different
records; each customer-owned row must belong to the configured organization.

| Record | Stable identifier | Expected scope |
| --- | --- | --- |
| Open Badges credential template | `50000000-0000-0000-0000-000000000040` | Customer |
| Login trust profile | `60000000-0000-0000-0000-000000000001` | Customer; configured issuer DID remains pinned |
| Revocation profile | `70000000-0000-0000-0000-000000000001` | Customer |
| Open Badges presentation policy | `50000000-0000-0000-0000-000000000004` | Customer; references the badge and trust profile above |
| Login deployment profile | `70000000-0000-0000-0000-000000000001` | Customer; references the presentation policy above |
| Built-in login flow | `71000000-0000-0000-0000-000000000001` | Customer |
| Built-in badge issuance flow | `72000000-0000-0000-0000-000000000040` | Customer |
| Open Badges compliance profile | `10000000-0000-0000-0000-000000000003` | Shared system profile with no tenant owner |

## Run the real deployment acceptance

The existing driver
[`run-kubernetes-acceptance.cjs`](../tests/scripts/run-kubernetes-acceptance.cjs)
reuses the normal browser authentication and OID4VCI verification helpers. It
requires a healthy installed application, an existing administrator and an
active organization-owned Open Badges/VC-JWT template. It does not create the
customer organization or its template catalog.

Before running it, require both migration/configurator Jobs to complete, all
required deployments and StatefulSets to be Ready, full gateway readiness,
valid public HTTPS, and usable workload/OpenBao credentials. Read the customer
organization back through the authenticated application and check its exact
ID, name and slug. Check the template and login deployment profile belong to
that ID. Use the milestone's bounded readiness procedure and preserve failed
observations as failures.

Use the fresh membership template for the infrastructure rehearsal with the
customer claims fixture below. The driver permits the fixture to set only
`given_name`, `family_name`, `organization_name`, `achievement_name` and
`achievement_description`. The organization ID still comes from the CLI, the
member ID and email from the authenticated operator, the role remains
`applicant`, and the issuance time is current. Avery Morgan is descriptive
synthetic data; this test delivers to the authenticated test operator rather
than provisioning a separate learner account. A separate academy course-badge
template, its achievement criteria and the staff approval journey need their
own product acceptance.

The scenario file is validated before evidence-directory creation, browser
launch or an API mutation. It is bounded to 8 KiB and a flat object of nonempty
descriptive strings with per-field length limits. The successful receipt
retains the supplied claims and their SHA-256 over canonical JSON. This binds
the requested scenario to its evidence; JSON formatting/key order may differ
without changing that binding. Runs without a scenario file keep the existing
generic milestone claims and receipt format.

Set `CUSTOMER_ORIGIN` and `CUSTOMER_ISSUER_DID` from the **actual rendered
configuration**, and `CUSTOMER_ADMIN_EMAIL` from the effective organization
administrator setting. `CUSTOMER_PASSWORD_FILE` must be an absolute path to
the private operator password file, with no group/other permissions.
`CUSTOMER_ACCEPTANCE_STATE` must be a new absolute directory path whose parent
exists; the driver creates the directory with mode `0700` itself.

```sh
node tests/scripts/run-kubernetes-acceptance.cjs \
  --phase accept \
  --repo "$PWD" \
  --origin "${CUSTOMER_ORIGIN:?actual HTTPS origin}" \
  --issuer-did "${CUSTOMER_ISSUER_DID:?actual managed did:web issuer}" \
  --organization-id 750e8400-e29b-41d4-a716-446655440001 \
  --credential-template-id 50000000-0000-0000-0000-000000000040 \
  --scenario-claims-file "$PWD/deploy/helm/marty/examples/customer-education-claims.json" \
  --email "${CUSTOMER_ADMIN_EMAIL:?actual administrator login}" \
  --password-file "${CUSTOMER_PASSWORD_FILE:?absolute private password file}" \
  --state-dir "${CUSTOMER_ACCEPTANCE_STATE:?new absolute evidence directory}"
```

The acceptance mutates the disposable scenario: it can create a managed ES256
issuer identity, create/activate a new template version when its issuer needs
to match, and issue one synthetic credential. The driver records these steps
privately and stops on failure. It verifies:

1. A real administrator login and authenticated account readback.
2. Exact organization ownership of the active template and managed issuer.
3. DID resolution at the selected HTTPS origin, OID4VCI offer redemption,
   VC-JWT issuer signature and holder binding.
4. Persisted transaction and credential records with the same organization,
   template, credential hash and expected issued/active statuses.

Retain the private credential and request files on the node; share only the
redacted receipt. A stopped attempt is not a pass. Inspect retained evidence
before deciding whether another issuance is appropriate; do not repeatedly
replay an uncertain mutation.

After a same-node restart and restored readiness, run the same command with
`--phase resume` and the original state directory. Resume requires a successful
accept receipt and the same scenario claims. A changed, omitted or newly added
scenario is rejected before launching the browser or making an API call. It
verifies the original credential's hash, current DID
signature verification and persisted records without creating another
issuance. Development workload identities have an **eight-hour absolute
lifetime**, and the initial migration token has a **two-hour lifetime**. This
profile has no automatic application-credential renewal schedule. Public
certificate renewal does not renew the workload or Keycloak credentials.
Stopping an EC2 node does not pause expiry. Keep the milestone's absolute
shutdown timer, and use the retained installation's admitted renewal/recovery
procedure before expecting resume acceptance to succeed.

## Optional email and operational boundaries

The SMTP overlay enables email verification and password recovery while
keeping public registration disabled. It selects authenticated SMTP on port
587 with STARTTLS, explicit sender identity and a nonsecret account name. Put
the actual password in `SMTP_PASSWORD` on the existing application Secret;
never put `SMTP_PASSWORD` or `KEYCLOAK_SMTP_PASSWORD` in Helm `config`.

The chart requires the SMTP password Secret key when a host and authenticated
account are configured; the base no-mail profile keeps that reference optional.
Rendering the overlay cannot prove that the password exists or authenticates.
Before enabling it for a customer, validate
the actual SMTP endpoint, TLS negotiation, sender authorization, password
reset email and verification-link return to the same HTTPS origin. This
overlay configures Keycloak login email; it does not claim notification-service
mail delivery or an external provider integration has been tested.

NetworkPolicy enforcement depends on the cluster's network implementation.
The profile limits incoming traffic to internal pods to this namespace and
allows the ingress namespace to reach the UI. It does not enforce an egress
allowlist. Default K3s storage is local to the node; the PostgreSQL 10 GiB,
Redis 1 GiB and applicant 1 GiB requests are scenario inputs, not a backup,
high-availability or capacity claim. OpenBao's separate persistent volume and
the node's other storage must also fit the actual disk. Preserve the existing
AWS Free-plan eligibility/credit checks and bounded shutdown procedure.

## Automated checks and evidence scope

Run the reusable configuration checks with Helm 3 on `PATH`, or set
`MARTY_HELM_BIN` to the verified Helm executable:

```sh
python -m pytest -q tests/test_customer_deployment_scenario.py
node --test tests/scripts/run-kubernetes-acceptance.test.cjs
```

The tests exercise Helm's real values-layer merge and strict lint. They check
DNS and IP/port origin consistency, organization and DID propagation, closed
registration, external private Secret references, required ConfigMap/volume/
Service references, managed KMS wiring, native issuance, storage persistence
and namespace network rules. The optional SMTP test verifies policy and
credential references. Neither test contacts DNS, AWS, SMTP, a registry or an
application server.

The Node contract tests execute the real OID4VCI proof/signature helper against
local mocked HTTP boundaries. They verify the customer issuance request and
receipt binding, unchanged default behavior, refusal of identity overrides
before browser/API actions, and read-only resume with exactly matching claims.
These tests do not establish a live browser login or deployed issuance result.

A deployment report should list the exact source/images, observed readiness,
runtime organization readback, successful acceptance receipt and optional
resume receipt separately from these local checks. Mark DNS/SMTP and any
customer-specific course workflow as untested until their own live evidence
exists.

| Evidence level | What a pass establishes | Required next evidence |
| --- | --- | --- |
| Local Helm lint/render | Values merge, chart guards and generated resource references | Kubernetes server admission and usable prerequisites |
| Kubernetes server dry-run | The selected API server admits the resources without persisting them | Actual installation, completed Jobs and ready workloads |
| Normal HTTPS probe | The selected endpoint's certificate and response status at that moment | Authenticated login and organization readback; a valid certificate can accompany an unhealthy application |
| Acceptance `accept` | Real login, owned issuer/template, signed credential receipt and database readback | Resume check and the customer's course/email workflow |
| Acceptance `resume` | The previously issued credential and its records still verify after recovery | Operational renewal, backup and availability qualification |

If a retained laboratory deployment has expired workload credentials or failed
readiness, record the precise block. Server admission of this fixture and a
normal TLS probe remain useful evidence, but a full customer deployment and
login/issuance acceptance must remain unqualified until the application is
healthy and the customer scenario is actually installed.

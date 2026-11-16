# Stage Kubernetes workload TLS and Keycloak renewal

The Kubernetes development bootstrap enrolls the existing native Renewal AppRole.
An explicit staging command uses that scoped identity to create one private
workload TLS and Keycloak credential candidate. It reuses the signed TLS producer,
native Keycloak producer, OpenBao authority checks, immutable generation commands,
Kubernetes transport pod and current-generation lock.

Successful staging retains a verified candidate and confirms retirement of its
transient Renewal session. It does not publish the candidate, select it as current,
restart workloads or extend the lifetime of credentials currently in use.

## Fresh bootstrap and compatible runtime

Use a new successful bootstrap with a signed runtime that implements
`kubernetes-renewal-contract`, `operator kubernetes-renewal-enroll` and
`operator kubernetes-renewal-stage`. Bootstrap compares the public compiled
capability before selecting a Kubernetes context or creating resources. A runtime
with different inputs, lifetime limits or operation support is refused.

Renewal enrollment occurs once during the initial authenticated root ceremony,
after the original TLS and Keycloak credentials exist. Native code validates the
current live inventory and enrolls the existing closed Renewal policy and token
role. It retains these three private identity files unchanged from the generic
native AppRole contract:

- `renewal-role-id`
- `renewal-secret-id`
- `renewal-leaf-policies.json`

The separate `renewal-binding.json` receipt fixes the namespace, namespace UID,
OpenBao cluster ID, original workload project and original producer nonce. The
native wrapper derives that nonce from the retained workload project. A later
transport pod's random name never replaces the original TLS or Keycloak identity.

The bootstrap completion receipt includes `renewalAuthority` and the authenticated
`renewalContract`. Keep the identity, binding, initial enrollment evidence and
entire original bootstrap directory on private encrypted operator storage.
Routine staging opens no retained root initialization, seal key or root-token
file. An older bootstrap without completed Renewal enrollment is refused; this
command does not retrofit enrollment by reopening retained root authority or
substituting a newer unsigned operator.

## Scope of one candidate

| Existing producer | Changed files | Preserved identity |
|---|---:|---|
| Workload TLS producer, `selfhost-renew` profile | 16 certificates and 16 signer tokens | Existing workload project, signing keys and workload CA |
| Native Keycloak producer, renewal mode | 2 certificates and 5 scoped tokens | Existing PKI mount, realm keys and original producer nonce |
| Generation staging and verification | Exactly 39 total changes | Every other selected file, its bytes and mode |

There are 40 renewable inputs: the 39 replacements and unchanged
`workload_identity_ca_cert`. The complete Kubernetes generation can contain more
than 40 files. Staging preserves the selected generation's ordinary application
credentials, migration inputs, passwords and additional regular files. It uses
the current selection after a completed ordinary application activation, rather
than silently returning to bootstrap credentials.

The native checks require the exact enrolled 21-policy inventory and closed
Renewal authority. New leaf tokens are scoped orphan tokens and cannot inherit
broader policies. Live verification checks token lifetime and creation role,
remote key version, certificate lifetime, issuer and public-key identity. Current
credentials must retain at least 3,600 seconds of valid lifetime; the wrapper
reserves additional time for its remaining validation and cleanup. Begin well
before expiry. This path does not recover expired credentials, change a CA,
rotate remote keys or rerun the Keycloak realm/client/admin configurator.

## Stage a candidate

Use the exact runtime source, release tag, build run, build attempt and chart
source from the original bootstrap. Retain the original complete signed artifact
closure and pinned verifiers. Choose a new operation directory whose existing
parent is private operator storage; do not place it inside a retained generation
or authority identity.

```sh
python3 scripts/stage_kubernetes_renewal_credentials.py \
  --state-dir "${BOOTSTRAP_STATE:?}" \
  --operation-dir "${NEW_RENEWAL_OPERATION_DIR:?}" \
  --assets "${ORIGINAL_ASSETS:?}" \
  --gh "${PINNED_GH:?}" --cosign "${PINNED_COSIGN:?}" \
  --runtime-source-sha "${RUNTIME_SOURCE_SHA:?}" \
  --chart-source-sha "${CHART_SOURCE_SHA:?}" \
  --release-tag "${RELEASE_TAG:?}" \
  --build-run-id "${BUILD_RUN_ID:?}" \
  --build-run-attempt "${BUILD_RUN_ATTEMPT:?}"
```

The command holds the existing private state-directory lock, resolves the
selected generation and refuses any pending application activation. It
reauthenticates the original signed artifacts and compiled contracts before
cluster access, then observes the namespace and OpenBao identity before uploading
authority and again before native issuance. Inputs and the selected generation
are checked again before completion.

Kubernetes runs the existing signed producer image as UID 10001 with no service
account token, a read-only root filesystem and a memory-backed temporary volume.
The pod has the existing fixed 1,200-second active deadline. One shrinking
900-second operation budget covers cluster observations, native work, export and
cleanup; separate subprocesses cannot restart that budget. Native code owns the
TLS child process group and the transient AppRole session. It attempts to revoke
every known session on post-login failure and requires a denied lookup to prove
retirement before reporting success.

The candidate is verified natively before export and again with the same signed
operator on private local storage. The whole generation and all file modes must
match the expected preservation rules. Completion additionally requires retained
private evidence, an unchanged selected generation, and successful transport-pod
cleanup.

## Completion and interrupted attempts

The operation directory retains `candidate/`, the copied bound identity and
original signed operator, private snapshots, native evidence and
`renewal-stage-requested.json`. Only a completed operation receives
`renewal-stage-complete.json` with status `candidate-staged-not-activated`.
Its `activation` and `caChanged` fields remain false. The current-generation
selector is unchanged, and Kubernetes Secrets and Deployments are untouched.

Treat every native token, certificate/token archive, AppRole identity and failure
capture as private credential material. Do not attach these files to PRs, issues
or public logs. Public status should contain only fixed names, counts and opaque
identifiers.

Preserve a failed operation at its original absolute path. An existing operation
directory is not a retry target. Login can issue a token before a response is
lost; a failed or malformed response does not prove that no authority exists.
Known-session retirement failure also prevents completion. Newly created orphan
leaf tokens intentionally survive retirement of the transient session; this
wrapper does not add leaf-token revocation privileges or discard partial
evidence to make a retry appear safe.

An uncertain native command or failed private export retains the original pod
for its remaining lifetime and records `transport-pod.json`. A captured archive
can be only a snapshot while remote work continues. The deadline is never
extended, and pod memory is not durable recovery storage. Recover available
evidence promptly within that original window and investigate the retained
attempt before any further issuance.

## Remaining deployment work

Use the [Renewal activation command](kubernetes-renewal-activation.md) to publish
the verified replacements to their existing Kubernetes Secret owners and verify
the selected Deployment rollouts and private credential delivery. The staging
success receipt does not establish those results. Authenticated runtime acceptance, automatic renewal,
expired-credential recovery, production upgrades and a live AWS/Kubernetes
acceptance trial also remain separate qualification steps.

Public ingress and Redis certificate management remain owned by the existing
cert-manager resources described in the
[Kubernetes development guide](kubernetes-first-milestone.md). Ordinary token
activation continues through the existing
[application activation command](kubernetes-application-activation.md).

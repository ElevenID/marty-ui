# Activate ordinary Kubernetes application credentials

The explicit activation command completes the ordinary-token staging flow for
the retained Kubernetes development installation. It reuses the existing signed
native operator, OpenBao AppRole, Kubernetes Secret API and Deployment
controllers. It updates one existing Secret and then selects a verified private
credential generation for the next staging cycle.

This remains a development adapter. Workload TLS and Keycloak renewal, recovery
after credential expiry, scheduling, production upgrades and authenticated
application acceptance are separate work. Updating ordinary tokens does not
extend the original TLS or Keycloak lifetime.

## Prerequisites

- A successful retained bootstrap with its bound application identity and the
  original signed artifact closure, pinned verifiers and private kubeconfig.
- A signed runtime that implements `kubernetes-application-activation-contract`,
  `operator application-token-verify`, and
  `operator kubernetes-application-publication`. An older runtime cannot be
  upgraded by substituting a new local operator into its retained bootstrap.
- A completed application staging operation for the currently selected
  generation. Current tokens must still pass OpenBao lookup. Candidate tokens
  need at least 1,800 seconds of remaining lifetime when the native verification
  operation returns.
- An installed application with the expected Helm ownership, signed images,
  ordinary credential references and a completed matching migration Job. An
  absent, active or failed migration Job is not proof of completion. The chart's
  migration Job TTL can remove old evidence; this adapter refuses when its
  required completion evidence is unavailable.
- Linux and private, caller-owned operator directories on encrypted storage.
  Staging and activation share an advisory directory lock. All cooperating
  writers must use it; manual concurrent edits are outside this single-writer
  contract. Observed custody or content changes cause refusal.

The namespace, namespace UID, OpenBao cluster, workload project, Kubernetes
context, runtime identity and chart identity come from the retained bootstrap.
There are no command-line overrides for these bindings or for the lifetime cap.

## Activate one staged candidate

Use the original release values from the bootstrap receipt. Choose an unused
activation directory whose parent already exists on private operator storage.
Keep this directory separate from the original credentials, selected generation,
application identity and staging operation.

```sh
python3 scripts/activate_kubernetes_application_credentials.py \
  --state-dir "${BOOTSTRAP_STATE:?}" \
  --stage-dir "${COMPLETED_STAGE_DIR:?}" \
  --operation-dir "${NEW_ACTIVATION_DIR:?}" \
  --assets "${ORIGINAL_ASSETS:?}" \
  --gh "${PINNED_GH:?}" --cosign "${PINNED_COSIGN:?}" \
  --runtime-source-sha "${RUNTIME_SOURCE_SHA:?}" \
  --chart-source-sha "${CHART_SOURCE_SHA:?}" \
  --release-tag "${RELEASE_TAG:?}" \
  --build-run-id "${BUILD_RUN_ID:?}" \
  --build-run-attempt "${BUILD_RUN_ATTEMPT:?}"
```

The command authenticates the same original artifacts and compares the compiled
activation capability before cluster access. It copies the staged candidate to
the private activation directory and verifies the complete generation, including
unchanged files and modes. It records intent before any application mutation.

The existing bounded producer pod obtains fresh native proof through the retained
non-root AppRole. The native operation checks exact token policy bundles,
creation routes, lifetime caps and identity binding. It creates only its own
bounded verification session and retires that session. It does not mint another
candidate or revoke the old application tokens.

## Kubernetes changes and proof

Native code builds one private JSON Patch for `marty-secrets`. The patch tests
the original Secret UID and resourceVersion, replaces exactly the 11 ordinary
token keys, and sets an opaque activation marker. Other Secret data and existing
annotations are preserved. Stale preconditions cause refusal; the command does
not refresh a conflicting Secret and overwrite it.

| Deployment | Ordinary token keys |
|---|---|
| `signing-keys` | `SIGNING_KEYS_OPENBAO_TOKEN`, `DIDCOMM_ISSUANCE_OPENBAO_TOKEN`, `SIGNING_KEYS_GRANT_VERIFY_TOKEN` |
| `notification` | `NOTIFICATION_OPENBAO_TOKEN` |
| `gateway` | `GATEWAY_SIGN_GRANT_MINT_TOKEN`, `GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN` |
| `flow` | `FLOW_SIGN_GRANT_MINT_TOKEN` |
| `issuance-native` | `ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN`, `ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN`, `ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN`, `ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN` |
| `canvas-sync-worker`, when present | Reuses `ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN` |

For signing-keys, the environment variable `OPENBAO_SERVICE_TOKEN` receives the
`SIGNING_KEYS_OPENBAO_TOKEN` key. The legacy Secret key `OPENBAO_SERVICE_TOKEN`
and migration-only `OPENBAO_BOOTSTRAP_TOKEN` remain outside this update.

The command changes a pod-template annotation with each Deployment's observed
identity and version preconditions. Kubernetes performs the rollout using the
existing strategy, selectors and readiness probes. The adapter pins the observed
rollout revision and independently checks Deployment, ReplicaSet and Pod
ownership, generation and readiness. A status-only resourceVersion change may
be observed before an undispatched Deployment update only when its saved desired
specification and ownership still match; a Secret precondition is never refreshed.

Every selected Pod also undergoes a bounded, read-only credential delivery check.
Expected values travel on private stdin and are compared inside the container
against the fixed environment alias or projected file. Only a fixed success
marker is returned. Competing signing-keys and Notification credential sources
are refused, including sources introduced through `envFrom`. The command then
verifies the same Pod identities and
revisions again. This establishes delivery to those containers; it does not
exercise every authenticated application operation or prove an application's
in-memory credential cache behavior.

The verification and post-verification phase has one 900-second monotonic budget.
Each verifier pod has a fixed 1,200-second lifetime. Reconciliation obtains a new
native proof in a new bounded verifier pod and starts a new 900-second budget.
It never extends an existing pod's deadline or any credential's absolute expiry.

## Current selection and interrupted attempts

The bootstrap directory retains `application-activation-pending.json` while an
activation is incomplete. Fresh staging refuses this condition. This prevents
a later staging command from silently returning to bootstrap credentials after
the Secret changed but local selection did not finish.

After Secret, rollout, private delivery and final identity checks succeed, the
command records `application-activation-verified.json`, atomically replaces the
private `application-current.json` selector under the held lock, and durably
records completion. It removes the pending marker only after verifying both the
selector and completion receipt. Original and candidate credential directories
are retained. The next staging command resolves the selected generation through
the same custody-checked helper.

If an attempt stops after recording pending intent, preserve all its private
files and reconcile that same activation directory:

```sh
python3 scripts/activate_kubernetes_application_credentials.py \
  --reconcile \
  --state-dir "${BOOTSTRAP_STATE:?}" \
  --operation-dir "${EXISTING_ACTIVATION_DIR:?}" \
  --assets "${ORIGINAL_ASSETS:?}" \
  --gh "${PINNED_GH:?}" --cosign "${PINNED_COSIGN:?}" \
  --runtime-source-sha "${RUNTIME_SOURCE_SHA:?}" \
  --chart-source-sha "${CHART_SOURCE_SHA:?}" \
  --release-tag "${RELEASE_TAG:?}" \
  --build-run-id "${BUILD_RUN_ID:?}" \
  --build-run-attempt "${BUILD_RUN_ATTEMPT:?}"
```

Reconciliation reauthenticates the original runtime and obtains fresh token
proof. It observes the already-requested Secret result rather than repeating
the Secret patch. It can observe this attempt's dispatched rollouts and start
only proven, previously undispatched remaining rollouts. A foreign marker,
changed workload, stale Secret, missing evidence, expired token or unproven
unchanged mutation outcome remains a refusal requiring operator investigation.
There is no automatic rollback, old-token revocation or replacement issuance.

If interruption occurred after selector publication, the same retained intent
and immutable verification evidence allow completion to be reconciled. An exact
interrupted prefix of the expected completion record is retained privately
before repair; a conflicting record is not replaced. A completed operation can
be recognized without another cluster mutation.

All raw Secret observations, patch bodies, candidate files, AppRole material,
native response captures and transport failure output are private credentials.
Do not attach them to an issue, PR, public log or recovery report. Public status
contains counts, fixed names and opaque operation identifiers only. Retain the
same absolute directory paths while an operation is pending.

Kubernetes owns the concurrency and rollout behavior used here:
[API update and JSON Patch semantics](https://kubernetes.io/docs/reference/using-api/api-concepts/)
and [revision-pinned rollout status](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_rollout/kubectl_rollout_status/).

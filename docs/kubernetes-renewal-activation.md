# Activate Kubernetes workload TLS and Keycloak renewal

The explicit activation command installs a completed [Renewal candidate](kubernetes-renewal-staging.md)
into the existing Kubernetes Secrets and uses Deployment controllers to replace
their workloads. The native operator owns fresh credential verification and the
restricted JSON Patch payloads. Kubernetes owns resource concurrency, Secret
projection and workload replacement. The adapter retains one private attempt and
updates the selected generation only after every destination and rollout is verified.

This operation renews existing identities. It does not change a CA, rotate remote
keys, rerun the Keycloak realm/client/admin configurator, or replace cert-manager's
ownership of public ingress and Redis certificates. Completion establishes private
credential delivery. Authenticated application/Keycloak acceptance, automatic
scheduling, expired-credential recovery and production upgrade qualification are
separate requirements.

## Prerequisites

- A completed fresh Kubernetes bootstrap that enrolled the existing Renewal
  AppRole, with its original signed artifact closure, operator, namespace/OpenBao
  binding and producer nonce retained on private encrypted storage.
- A signed runtime implementing `kubernetes-renewal-activation-contract`,
  `operator kubernetes-renewal-verify` and
  `operator kubernetes-renewal-publication`, in addition to Renewal staging.
  An older signed operator without these capabilities is refused; this path does
  not substitute an unsigned binary or reopen retained root authority.
- A completed staging operation made from the exact currently selected full
  generation. The candidate contains 39 replacements across 40 renewable inputs
  and preserves ordinary credentials, the workload CA, additional inputs and modes.
- Still-valid current and candidate authority. Fresh native verification demands
  at least 4,500 seconds of valid lifetime to retain a 3,600-second floor through
  the bounded 900-second activation. Begin well before expiration.
- Existing supported Helm-owned Deployments, the original signed image identities,
  completed migration/configurator evidence and the expected Secret projections.
  Concurrent Helm upgrades, configuration changes and other lifecycle writers
  must not run during the operation.

The chart sets a default 86,400-second completion TTL on both the migration Job
and the Keycloak configurator Job. Kubernetes can therefore remove required
evidence after 24 hours; this adapter refuses activation if either matching
completed Job is absent. A retained standard-Job policy or authenticated durable
completion evidence remains necessary for repeated long-running operation.
Do not rerun migration or configuration solely to recreate this evidence.

Ordinary application activation and Renewal activation use the same private
directory lock, current-generation selection and pending-operation guard. A
pending operation blocks fresh staging and activation in either domain. Selection
retains separate ordinary and Renewal activation markers so the next operation
preserves the other credential family's identity.

## Activate one candidate

Choose a new absolute operation directory whose existing parent is private
operator storage. It must not overlap retained credentials, either AppRole identity,
the staging directory or the selected generation. Keep the exact runtime/chart
source and release/build identity from the original bootstrap.

```sh
python3 scripts/activate_kubernetes_renewal_credentials.py \
  --state-dir "${BOOTSTRAP_STATE:?}" \
  --stage-dir "${COMPLETED_RENEWAL_STAGE:?}" \
  --operation-dir "${NEW_RENEWAL_ACTIVATION_DIR:?}" \
  --assets "${ORIGINAL_ASSETS:?}" \
  --gh "${PINNED_GH:?}" --cosign "${PINNED_COSIGN:?}" \
  --runtime-source-sha "${RUNTIME_SOURCE_SHA:?}" \
  --chart-source-sha "${CHART_SOURCE_SHA:?}" \
  --release-tag "${RELEASE_TAG:?}" \
  --build-run-id "${BUILD_RUN_ID:?}" \
  --build-run-attempt "${BUILD_RUN_ATTEMPT:?}"
```

The adapter reauthenticates the retained signed operator and compiled contracts
before cluster access. It binds the namespace UID and OpenBao cluster, copies the
candidate privately, and verifies that the complete selected generation matches
the staging predecessor. A bounded non-root Kubernetes pod uses the retained
Renewal identity for fresh native authority, token and certificate checks. It
issues no replacement credentials. Success requires retirement of its transient
session, denied lookup and retained private evidence before Secret mutation.

## Conditional Secret publication and adoption

The compiled publication catalog maps the candidate into **33 existing Secrets**:
32 single-field TLS certificate/token destinations and seven fields in
`keycloak-kms`. Each private JSON Patch tests that Secret's UID and resourceVersion,
updates only its selected fields and records the attempt's Renewal marker.
Unrelated data, annotations and unchanged CA fields are preserved. Controller-owned
or immutable destinations are refused.

These are separately conditional Kubernetes updates. Kubernetes does not make the
33-object operation atomic. Every request has durable private intent before it is
sent. A failed or interrupted attempt can leave a verified prefix installed; the
shared pending record prevents another lifecycle operation from treating that
mixed state as a completed generation.

Only after all destinations show the intended candidate does activation request
the existing Deployment rollouts. Workload identity, Helm ownership, signed images,
specifications, ReplicaSet revisions and Pod UIDs stay pinned throughout admission
and completion. The Keycloak restart reloads its same-key certificate into provider
state; the existing configurator is not rerun. Additional projected readers are
included in the closed workload graph.

Private delivery checks compare the bytes projected into the selected containers,
including multiline certificates. They use the existing publication normalization
(remove carriage returns and trailing line feeds), while preserving raw generation
files. Projected credential bytes are captured and compared privately, never placed
in command arguments or public status output. Ready Pods and matching files alone do not establish that
every authenticated credential operation has been exercised.

## Completion and reconciliation

A successful operation retains `renewal-activation-verified.json` and
`renewal-activation-complete.json` and selects the immutable candidate as current.
The completion status is `renewal-generation-selected`. It records
`credentialDeliveryVerified: true` and `credentialConsumptionVerified: false`.
Retain the entire original operation, predecessor, proof and authority directories;
selector history depends on that private evidence.

The same activation deadline covers final selection and completion durability.
If final pending cleanup or its history verification exceeds that deadline, the
adapter restores the original pending intent under the shared lock and refuses
completion. The published candidate and completion evidence stay available for
reconciliation of that exact attempt.

After interruption, preserve the original absolute operation path and reconcile
that same attempt:

```sh
python3 scripts/activate_kubernetes_renewal_credentials.py \
  --state-dir "${BOOTSTRAP_STATE:?}" \
  --operation-dir "${ORIGINAL_RENEWAL_ACTIVATION_DIR:?}" \
  --reconcile \
  --assets "${ORIGINAL_ASSETS:?}" \
  --gh "${PINNED_GH:?}" --cosign "${PINNED_COSIGN:?}" \
  --runtime-source-sha "${RUNTIME_SOURCE_SHA:?}" \
  --chart-source-sha "${CHART_SOURCE_SHA:?}" \
  --release-tag "${RELEASE_TAG:?}" \
  --build-run-id "${BUILD_RUN_ID:?}" \
  --build-run-attempt "${BUILD_RUN_ATTEMPT:?}"
```

Reconciliation reauthenticates the same inputs and obtains fresh bounded proof.
It never replays a Secret request already recorded as dispatched. Such a request
must be observed as the exact candidate; an unchanged or conflicting outcome
requires investigation of the retained attempt. A destination with no recorded
request can proceed only from its exact original preconditions. Remaining
Deployment rollouts retain the same request and revision guards.

Do not delete a pending record, restore an old selector, start a new attempt,
extend credentials or rerun issuance to make uncertainty disappear. An uncertain
native command or failed evidence export retains its original pod only for the
remaining fixed deadline; pod memory is not durable recovery storage. Keep raw
Secret observations, patch payloads, credential archives and AppRole material
private. Live signed-runtime application and AWS acceptance remains required
before claiming deployment support is fully qualified.

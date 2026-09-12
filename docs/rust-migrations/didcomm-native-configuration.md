# Native DIDComm configuration ownership

This configuration prepares selective native delivery and selects beta Flow's
qualified initiation RPC consumer. It does not switch gateway routes, change
production, remove Python, or qualify KMS-only custody.

The beta `issuance-native` service now receives the same resolver and endpoint
policy expressions as legacy `issuance`:

| Variable | Default |
| --- | --- |
| `UNIVERSAL_RESOLVER_URL` | Empty; native resolution remains available |
| `DIDCOMM_DID_WEB_INTERNAL_BASE_URL` | `http://gateway:8000` |
| `DIDCOMM_ALLOW_PRIVATE_IPS` | `false` |

These are operator configuration, never request-controlled selectors. The
private-address override is not enabled by default. No production Compose file
is changed. Native Rust also supports the explicit
`DIDCOMM_UNIVERSAL_RESOLVER_URL` environment override, but this beta composition
mirrors the existing legacy resolver variable rather than introducing different
resolver precedence between the two services.

## Initiation consumer configuration

Beta Flow uses `ISSUANCE_GRPC_TARGET=issuance-native:9005`. Its existing
`ISSUANCE_SERVICE_URL=http://issuance:8005` remains inherited from base: that
separate HTTP provider serves physical-document operations, not this RPC.
Base/self-host profiles and Envoy's shared issuance gRPC cluster are unchanged.
Native issuance explicitly retains its enabled port 9005 and the same service
token as Flow and legacy issuance. Existing health and published-migration
dependencies remain; rendered checks verify configuration, not live readiness.

Native initiation's organization, template and revocation gRPC targets and
template HTTP URL now explicitly equal the legacy Compose bindings. These are
fixed service addresses, matching the previous Rust defaults; this does not add
new interpolation precedence. `VCDM_RELATED_RESOURCE_URLS` forwards the exact
legacy `${VCDM_RELATED_RESOURCE_URLS:-}` expression. Empty stays fail-closed;
operator-authorized resource URLs must not disappear for ordinary issuance or
the gateway VC-API adapter, which also calls `/v1/issuance/initiate`.

This selection relies on the actual keyed Flow provider gate (ordinary creation,
recovery/conflict, pure/mixed DIDComm rejection) and the separate ten-case
unkeyed native RPC gate. Flow keeps its idempotency keys; this does not make
current Flow requests perform unkeyed DIDComm push. Gateway initiation selection
is separate. No additional Core or KMS behavior is introduced.

Python retirement remains a published-consumer boundary: standalone base,
self-host and Kubernetes manifests still select the external Python issuance
image. Beta routing alone does not make their direct/automatic DIDComm endpoints
unreachable. Preserve those consumers or migrate their supported routing before
removing reachable helpers/startup capabilities from their future image. Unused
Python decrypt/unpack wrappers can be reviewed separately; canonical Rust
capabilities and language-neutral reference fixtures remain.

## Explicit overlays

`docker-compose.profile.didcomm-native-authcrypt.yml` requires an existing
`issuance-native` service and `DIDCOMM_ENCRYPTION_POLICY_DIR`. It mounts only that
exact directory read-only at `/run/secrets/didcomm-authcrypt`, with automatic
host-path creation disabled. `DIDCOMM_ENCRYPTION_POLICY_FILE` points to
`didcomm-encryption-policy.json` there. No gateway or unrelated service receives
this material. Preserve the same issuer-specific policy used by legacy delivery:
absent policy means anoncrypt, but a configured policy with an absent issuer or
invalid authcrypt key must fail closed, never silently choose anoncrypt.

`docker-compose.profile.didcomm-native-conformance.yml` additionally requires the
existing project-isolation conformance overlay. It is for disposable tests only:
it trusts the generated `${OIDF_TLS_CERT_DIR}/root-ca.pem` through an exact
read-only file mount, enables private wallet endpoints, and provides
`host.docker.internal:host-gateway` only to native issuance. It neither creates a
standalone native service nor isolates an entire project by itself.

Both native overlays are explicit additions. Existing legacy authcrypt and
conformance overlays retain their standalone behavior. The beta release runner's
`-EnableDidcommAuthcrypt` switch selects both legacy and native authcrypt profiles;
it never selects conformance networking or a private CA. Without that switch the
selected profile list stays empty. The legacy conformance launcher is unchanged.

## Beta deployment pairing gate

An optional overlay alone is not downgrade prevention. The beta runner now uses
`scripts/beta-didcomm-configuration.ps1` to pair both profiles and calls the shared
stdlib validator in `scripts/validate_beta_didcomm_configuration.py`. It validates
the actual complete rendered model, including the generated image override,
before image pulls, builds, backups or service mutations, then revalidates before
entering maintenance. Local release metadata/runtime-file staging precedes this
gate; it does not stop or recreate services.

Validation rejects selected-but-missing policies, legacy-only configuration,
unexpected policy configuration without explicit opt-in, different policy
sources, writable native mounts, automatic native host-path creation, and the
same policy source mounted into unrelated services. Policy file contents are
never read by this gate. Compose output stays in process memory with a 30-second
timeout and an 8 MiB accepted JSON limit; errors and success output contain no
model or environment values. `-PlanOnly` reports the boolean and profile names,
explicitly marking configuration as unvalidated without invoking this validator.

This enforces ownership/configuration pairing through the beta runner, not the
contents of an issuer policy. Runtime tests must still prove missing issuers and
invalid authcrypt keys fail closed, and direct manual Compose invocations do not
receive runner enforcement automatically. This change does not switch routes or
perform a deployment.

Native CA startup/error/rotation parity is separately qualified in
[`didcomm-consumer-cutover-readiness.md`](didcomm-consumer-cutover-readiness.md);
the configuration gate itself does not execute the Rust service. DIDComm KMS corrections
remain deferred under `DIDCOMM-KMS-001`. Compatibility policy files can contain
local sender private keys and are not a KMS-only solution.

## Read-only qualification

Run `python scripts/test_didcomm_native_compose.py` with Docker Compose available.
The gate uses `compose config` only: no daemon operations, pulls, builds, or
deployments. It compares complete merged models, preserving every unrelated
service and resource; checks synthetic resolver/mount/related-resource bindings,
Flow-only RPC selection, shared token/control-plane/health ownership and missing-input
rejection; rejects an unpaired authcrypt configuration; and verifies legacy
conformance still does not introduce a native service. CI runs this gate with
the existing pinned Compose renderer before image builds.

Merge tests deliberately disable interpolation and configuration consistency to
inspect exact source expressions. Separate synthetic binding tests exercise
interpolation without reading deployment environment files. Neither replaces
real packaged native delivery, startup, tenant/authentication, or acceptance gates.

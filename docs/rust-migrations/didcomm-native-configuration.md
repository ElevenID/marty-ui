# Native DIDComm configuration ownership

This configuration prepares selective native delivery; it does not switch gateway
routes, change production, remove Python, or qualify KMS-only custody.

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

Native CA startup/error/rotation parity is a separate outstanding qualification;
the configuration gate does not execute the Rust service. DIDComm KMS corrections
remain deferred under `DIDCOMM-KMS-001`. Compatibility policy files can contain
local sender private keys and are not a KMS-only solution.

## Read-only qualification

Run `python scripts/test_didcomm_native_compose.py` with Docker Compose available.
The gate uses `compose config` only: no daemon operations, pulls, builds, or
deployments. It compares complete merged models, preserving every unrelated
service and resource; checks synthetic resolver/mount bindings and missing-input
rejection; rejects an unpaired authcrypt configuration; and verifies legacy
conformance still does not introduce a native service. CI runs this gate with
the existing pinned Compose renderer before image builds.

Merge tests deliberately disable interpolation and configuration consistency to
inspect exact source expressions. Separate synthetic binding tests exercise
interpolation without reading deployment environment files. Neither replaces
real packaged native delivery, startup, tenant/authentication, or acceptance gates.

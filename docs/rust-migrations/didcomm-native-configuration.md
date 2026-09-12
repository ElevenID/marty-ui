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
conformance overlays retain their standalone behavior. Neither the beta release
runner nor the legacy conformance launcher selects the new overlays implicitly.

## Required cutover integration still outstanding

`scripts/deploy-local-beta-release.ps1` currently owns a closed `ComposeFiles`
array and has no DIDComm authcrypt selector. An optional native overlay alone is
**not** downgrade prevention: a caller could select legacy authcrypt without
configuring the native owner. Before routing DIDComm to native delivery, the
deployment owner must pair both exact policy overlays or reject the final
rendered configuration. The reusable `assert_native_policy_pairing` assertion in
`scripts/test_didcomm_native_compose.py` rejects legacy-only policy configuration,
different policy sources, writable mounts, and automatic host-path creation.
It is exercised by CI, but is not yet called by the deployment runner. No claim
of deployment-time pairing enforcement is made by this configuration slice.

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

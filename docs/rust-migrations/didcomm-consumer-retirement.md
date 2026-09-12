# DIDComm consumer retirement gates

Source audit: UI `79b2e3645`, Credentials protected main `ddd6b4e4383fe1000e3255f3e4237dc5b6020a2a`.
This is a source inventory, not deployed configuration or acceptance evidence.
DIDComm KMS corrections remain deferred. Production is unchanged.

The eight Canvas operations and standalone initiation/direct-delivery selection
do not establish that every supported consumer has left Python. Renewal admission
is being implemented separately; see [its frozen evidence](credential-renewal-retirement.md).

| Consumer | Remaining retirement gate |
| --- | --- |
| Beta gateway | Qualify and select renewal only after native admission, both encryption modes and durable finalization pass. |
| Base Compose | Add a qualified native service/profile and explicit gateway native URL; inventory direct legacy HTTP/gRPC loopback-port consumers. |
| Self-hosted | Qualify native image/binary, secret-file loading, database readiness and service configuration without replacing the partial legacy service wholesale. |
| Kubernetes | Add distinct native Deployment/Service, probes, image, schema, secrets and control-plane configuration before selective routing. |
| Flow | Beta initiation gRPC is already native. Move base/self-hosted initiation targets only after qualification; retain legacy physical-document HTTP. |
| Envoy | Qualify exact initiation RPC and annotated HTTP routing, authentication and response projection while retaining eleven sibling RPCs. |
| Conformance | Select native overlays explicitly with paired policy/CA mounts and rendered-model gates; preserve legacy reference execution. |

Gateway `config.rs` deliberately aliases the native service URL to legacy when
`ISSUANCE_NATIVE_SERVICE_URL` is absent. That is static configuration, not a
runtime retry fallback. A native route name alone does not prove Rust selection.
Base, self-hosted and Kubernetes already launch the Rust Canvas worker; historical
Python launch recognizers do not establish an active Python worker.

## Envoy boundary

The canonical RPC is
`/marty.ui.issuance.v1.IssuanceService/InitiateIssuance`; its annotation is
`POST /v1/issuance/initiate`. With the existing transcoder's
`match_incoming_request_route: true`, both exact routes need qualification before
their respective legacy prefixes. Use a separate native cluster, not a wholesale
replacement of `issuance_grpc`. Keep all eleven other methods on their current
owner until separately qualified.

Native management initiation requires `x-service-token`. Public bearer tokens or
API keys are not substitutes; do not inject a service token into unauthenticated
traffic. Current Envoy and native tonic transport are plaintext within the
configured internal boundary; unrelated workload certificate mounts do not prove
issuance mTLS. Qualify actual transport requirements before activation.

The transcoder returns the protobuf response, including `pre_auth_code`; it does
not execute gateway privacy projection. Test its existing supported surface
separately with the intended Envoy image and descriptor, native and legacy
observed upstreams, missing/invalid/valid authentication, exact and lookalike
paths, ordinary idempotent recovery/conflict and keyed DIDComm rejection. Preserve
all sibling routes, and bind the qualified configuration through the deployment's
actual runtime configuration root.

## Source configuration findings

- Kubernetes Flow omits `ISSUANCE_GRPC_TARGET`, whose Rust default is
  `issuance:9006`, while the configured legacy issuance service exposes 9005.
- Self-hosted uses `DIDCOMM_ALLOW_PRIVATE_ENDPOINTS`; both retained Python and
  native Rust consume `DIDCOMM_ALLOW_PRIVATE_IPS`. Defaults remain restrictive.

Reviewed source repair `5a4d2abae` sets the explicit legacy Flow target to 9005
and the recognized private-IP setting to literal `false`. It also removes one
byte-identical duplicate gateway secret reference without changing the surviving
reference. Parsed positive/mutation and existing configuration regressions passed
(147 author checks; 40 independently repeated). These are source repairs, not
rendered deployment, observed failure recovery or native activation evidence.

Do not delete active Python encryption, policy or startup requirements until all
intended consumers above have passed their gates. The unused decrypt/unpack
adapter retirement in Credentials PR #275 does not authorize further deletion.

## Explicit native conformance selection

The conformance launcher retains `--issuance-owner legacy` as its default.
`--issuance-owner native` adds a distinct native service and gateway URL, paired
read-only CA mounts, and paired authcrypt policy mounts when `--didcomm-authcrypt`
is selected. Native mode pairs the service token across the existing thirteen
Rust/legacy clients and peers; it does not change Flow or Envoy targets. Missing
required configuration, ambiguous mounts, token mismatches or legacy URL aliases
fail validation. There is no automatic legacy fallback.

Beta and conformance share `docker-compose.service.issuance-native.yml` at the
repository root. The former beta definition is frozen at `cb1a01656703896ce552bff42c140f154a97026a`
in `tests/fixtures/issuance-native-compose-before-extraction.yml`. Full rendered
beta equality covers unset, empty and custom optional values, including exact
required-variable failure text (Compose's map/list diagnostic location is not
part of that behavior). The service file is required alongside the Compose files
in the source checkout; it is not a runtime bind asset and must not be copied
into the self-host runtime-asset directory. Existing beta deployment uses its
source-verified full checkout. Self-host release bundle selection is unchanged.

Released native `up` additionally requires `--stack-manifest`, `--stack-checksums`
and `--release-ui-revision`. It reuses the official release input validator and
existing `gh attestation verify ... --repo ElevenID/marty-ui` trust, then reads
the authenticated UI source's coverage contract from the local Git object store.
The closed floor requires initiation, direct DIDComm delivery and renewal native
ownership; an older services digest that merely contains the binary is rejected.
The tooling checkout need not equal the authenticated source revision. Exact
RepoDigest and OCI source/revision/version labels are cross-checks, not signatures.

The executable/linker probe uses an exact-owned, networkless, read-only container
without secret mounts; cleanup verifies the random ownership label and exact ID.
It is not route or behavioral acceptance. `--local-build` is explicitly source
evidence, checks the same coverage floor, and cannot substitute for release
attestation. Actual runtime conformance remains required and must fail on missing
routes. Current artifacts without selected renewal are intentionally ineligible.

Qualification commands: `python -m pytest tests/test_conformance_native.py
tests/test_prepare_official_beta_release.py` and
`python scripts/test_conformance_native_compose.py`. The latter performs only
read-only Compose rendering with synthetic values: released/local source images
crossed with anoncrypt/authcrypt, full existing-model preservation except the
closed native auth/selection delta, and beta extraction parity. No native stack
has been deployed or accepted by these configuration gates; Python retirement,
KMS corrections and production remain outside this change.

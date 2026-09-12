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

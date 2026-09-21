# DIDComm consumer retirement gates

Source audit: UI `79b2e3645`, Credentials protected main `ddd6b4e4383fe1000e3255f3e4237dc5b6020a2a`.
This is a source inventory, not deployed configuration or acceptance evidence.
DIDComm KMS corrections remain deferred. Production is unchanged.

Current integration checkpoint: UI `2455701b8`. The original audit and proposed
batches below are historical requirements, not a claim that their configuration
work is still absent. Base and self-host native owners and the Rust self-host
packager are integrated; Flow base opt-in/self-host selection has rendered
loader/provider-factory qualification. Kubernetes configuration is integrated at
`97ff18e48`, with model and closed deployment-command tests, not cluster
acceptance. Envoy routing is integrated at `b26eb71c8`, with actual-image
validation and local configuration/contract tests; its complete Linux business
gate remains pending. Flow actual-main acceptance and the QR retry timestamp fix
are integrated at `cff3a4aa1`; combined Windows actual-main, retained PostgreSQL,
rendered-selection and process-cleanup gates passed at `854844bb591`. These are
not release-image, gateway JWT, callback-delivery or self-host TLS acceptance.
Kubernetes signing/auth dependencies are integrated at `fc64b0026`; the resolved
runtime adapter is still under qualification. No new deployment is claimed.
See the [current roadmap](../CONSOLIDATED_RUST_MIGRATION_ROADMAP.md) and each
linked qualification record for the precise evidence and remaining runtime gates.

Selected beta and explicit native consumer compositions now also bind the retained Python service to the
native owner explicitly. This preserves callers that still reach the legacy
port: initiation and direct DIDComm delivery are forwarded as whole authenticated
requests before Python state or crypto work, with no runtime fallback. Self-host
production remains legacy until a compatible immutable Credentials image is
released and pinned. The
language-neutral ownership contract is
`contracts/didcomm-native-consumer-ownership.json`. Standalone Credentials still
defaults to its legacy owner, so source deletion remains gated on an explicit
decision about that supported surface; KMS correction remains separate.

The eight Canvas operations and standalone initiation/direct-delivery selection
do not establish that every supported consumer has left Python. Renewal admission
is being implemented separately; see [its frozen evidence](credential-renewal-retirement.md).

| Consumer | Remaining retirement gate |
| --- | --- |
| Beta gateway | Direct delivery and initiation select Rust; remaining gates are coordinated artifacts and aggregate beta deployment/acceptance. |
| Base Compose | Native remains explicit opt-in and delegates retained direct callers; decide the supported standalone legacy surface before deletion. |
| Self-hosted | Production remains legacy; require a compatible immutable Credentials image and runtime qualification before activation or retirement. |
| Kubernetes | Selected renderer adds the native owner and direct delegation; keep the unselected production source unchanged until deployment approval and acceptance. |
| Flow | Native compositions select initiation gRPC; retain legacy physical-document HTTP and complete aggregate acceptance. |
| Envoy | Exact initiation RPC and annotated HTTP routing are selectively native; retain eleven sibling RPCs and complete deployed response/authentication acceptance. |
| Conformance | Native overlay is explicit with paired policy/CA mounts and direct delegation; preserve legacy reference execution. |

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

### Token-rate configuration follow-up

The pre-extraction beta native definition omitted `TOKEN_RATE_LIMIT` even though
base legacy issuance forwards `${TOKEN_RATE_LIMIT:-30}` (`docker-compose.base.yml:899`)
and native `config.rs:873-878` consumes it. The shared native definition now
forwards that exact expression. This is an explicit one-field repair to beta,
not unchanged beta behavior; the frozen pre-extraction fixture is unmodified.
The whole-model gate permits only the added native capacity field, derived from
the independently rendered legacy owner. All other beta fields and required
input failures remain checked unchanged.

Real Compose tests cover unset/empty values becoming `30`, explicit `30`, `1200`,
and `0` across beta and all four conformance modes. Model guards reject missing
or mismatched capacities. These tests prove configuration forwarding, not runtime
limiter acceptance. Credentials `ddd6b4e4383fe1000e3255f3e4237dc5b6020a2a`,
`services/issuance/infrastructure/api/routes.py:769-791`, uses Python `int` and
rejects requests when hit count is at least the configured capacity. Native
`token_rate_limit.rs:58-59` uses the same comparison for nonnegative capacities;
its existing zero-capacity unit test explicitly checks reject-all behavior.

The grammar gap found by that historical audit has since received a separate
[Rust parser and runtime parity implementation](token-rate-config-parity.md).
Current configuration uses shared `PythonConfigInteger`; the limiter preserves
negative/zero rejection, unbounded positive thresholds and exact window/header
behavior against the frozen 40-case Python reference. This is not the old
`usize`/`FromStr` implementation. Raw empty environment values still fail numeric
parsing, while Compose's `:-30` maps empty input to the normal default before
startup. Final integrated hosted and deployment acceptance remain required;
the original configuration-only forwarding repair does not supply that proof.

## Remaining consumer implementation batches (source audit only)

Audit: base/self-host/Envoy and gateway configuration sources at UI `f78aceff4`
were byte-identical to conformance branch `4f435d4c6`. These are proposed batches
and required acceptance gates, not executed migrations or deployments. Production,
Core, KMS and legacy features remain unchanged.

### Routing inventory and correction boundary

Base `docker-compose.base.yml:859` defines only the immutable Python issuance
service. Gateway `:360` supplies only `ISSUANCE_SERVICE_URL`; gateway
`config.rs:145-147` consequently aliases `issuance-native` to that legacy URL.
A distinct native service plus explicit `ISSUANCE_NATIVE_SERVICE_URL` corrects
this without changing `ISSUANCE_SERVICE_URL` or deleting unselected HTTP routes.
Gateway `issuance_native.rs:27-81` selects exact methods/paths from the embedded
coverage contract and leaves absent operations on legacy.

The URL correction affects **all 73 selected HTTP entries at this audited
revision**, not just DIDComm/initiation: 53 integration/Canvas, nine issuance,
eight discovery, health, credential-schema and internal entries. Renewal adds
its own entry after separately reviewed activation. Test the complete selected
configuration surface when adding a general deployment owner.

Base Flow `:811` still uses `issuance:9005`. Legacy loopback ports at `:935-936`
expose 8005 and 9005 directly, bypassing gateway owner selection. Self-host
`docker-compose.selfhost.prod.yml:485` likewise defines only Python issuance;
gateway `:263` lacks a native URL and Flow `:870` selects legacy gRPC. Auth,
applicant, presentation-policy and Flow retain direct legacy issuance HTTP URLs
in both models. Self-host contains no Envoy service. These are independent
consumers; changing the gateway alone does not retire them.

### Batch 1: general base native profile

Configuration-only checkpoint: the opt-in base profile, neutral structural
runtime extraction, shared immutable-image overlay and paired explicit policy
profile are implemented in the isolated follow-up. See
[the complete inventory and qualification boundary](base-native-issuance-profile.md).
The default base, Envoy, legacy loopback ports and unselected HTTP consumers remain
unchanged. Flow's opt-in/self-host gRPC target has since received
[rendered loader/provider-factory qualification](flow-native-consumer-selection.md).
This is not packaged runtime acceptance or authorization to delete
Python; the required runtime gates below remain outstanding.

- Add a distinct native owner and explicit gateway URL in a general opt-in
  profile. Do not reuse conformance's private-IP allowance or synthetic CA.
- Bind the actual executable, complete build/image selection, HTTP 8005/gRPC
  9005, readiness and issuance-migration dependency. Pair DB, issuer URL,
  API/HMAC/integration/signing secrets, organization 9002, template 9003,
  revocation 9013 and their existing HTTP endpoints.
- Preserve deployed Canvas, token-rate, TTL, resolver and discovery settings;
  the beta-specific shared definition is not a substitute for that inventory.
  If token authentication is enabled, pair all thirteen existing clients/peers
  identified by the conformance validator, not only the three native targets.
- Keep legacy loopback ports, Envoy targets and all unselected HTTP routes.
  Flow initiation selection is covered by its separate qualification above.
  Authcrypt remains explicitly opt-in with paired owner-only read-only mounts;
  no conformance trust configuration becomes a production default.

Required gates: complete before/after model comparison with closed intentional
deltas and negative binding tests; actual packaged native main and gateway using
the rendered configuration; token/discovery/Canvas regressions plus ordinary,
anoncrypt/authcrypt initiation and renewal. Missing/unavailable native must not
retry against legacy. Use actual PostgreSQL, signing and wallet decryption for
durability claims, with controlled peers clearly identified.

### Batch 2: self-host native owner and package

- Add a separate owner using existing `*_FILE` aliases and the same
  `grpc_service_token` secret as current clients/peers. Gateway and native signing
  already have the intended shared issuance-key file identity; preserve it.
- Exercise `services/entrypoint.sh` and `scripts/load-secrets-env.sh`, which load
  secret aliases, unset consumed file selectors and expand `DATABASE_URL_TEMPLATE`
  from the database password. Preserve the issuance migration prerequisite.
- Do not blindly extend the current beta service definition: it interpolates
  required raw beta secret variables and references `marty-network`, while
  self-host uses file-only secrets and its default network. Extract a neutral
  executable/readiness/dependency definition with exact beta regression guards,
  then give self-host an explicit native environment/secret allowlist.
- Do not copy the legacy BAO token into native merely because it appears beside
  other issuance secrets. Native signing uses its existing signing service owner;
  this is not a KMS migration.
- Add native image/`SERVICE_NAME`/build-reset handling to the self-host bundle
  override using the qualified services artifact. Any newly referenced Compose
  files must be included in `deploy-config/bundles/selfhost.json` assets. Preserve
  all existing API/migration artifacts and unselected consumers.

Required gates: actual packaged secret-loader/main with synthetic secret files;
missing, unreadable and conflicting direct/file inputs fail closed; correctly
expanded SQL URL, paired keys, default network and migration readiness. Render
and exercise the packaged bundle without access to the source checkout. Reuse the
real PG/signing/wallet graph for the actual selected native operations and prove
legacy HTTP siblings remain available.

### Batch 3: Flow initiation gRPC only

After the native owner graph passes, change only `ISSUANCE_GRPC_TARGET` to
`issuance-native:9005` in each qualified model. Keep `ISSUANCE_SERVICE_URL` on
legacy for physical-document and other unselected HTTP behavior. Flow's actual
`grpc_providers.rs:522` calls `InitiateIssuance` with its service authentication.

Required gates: reuse `didcomm_flow_grpc_admission.rs` and the native gRPC fixture
with actual candidate process configuration and token files. Cover ordinary
idempotent recovery/conflict, fresh keyed DIDComm rejection, anoncrypt/authcrypt,
refused wallet delivery and missing holder. Prove full responses, HTTP/2/protobuf
transport, durable state and no extra sends; retain physical-document HTTP tests.

### Batch 4: Envoy exact initiation routes

`config/envoy/envoy.yaml:69-73` and `:136-140` currently send both the entire
issuance RPC prefix and `/v1/issuance/` to `issuance_grpc`, whose endpoint at
`:331-355` is legacy port 9005. Add a separate native HTTP/2 cluster and health
check. Insert exact **POST** routes for the canonical `InitiateIssuance` RPC and
`/v1/issuance/initiate` before those prefixes. Pass existing `x-service-token`;
never inject it into unauthenticated traffic.

Keep the eleven sibling RPCs on legacy: ExchangeToken, IssueCredential, GetOffer,
ListTransactions, GetTransaction, RevokeCredential, SuspendCredential,
ReinstateCredential, GetCredentialStatus, StreamCredentialEvents and HealthCheck.
Native service-level health alone does not establish that those methods migrated.

Required gates: actual intended Envoy image and descriptor, exact methods and
lookalike paths, all siblings, missing/invalid/valid service authentication,
protobuf and transcoded HTTP bodies including `pre_auth_code`, ordinary recovery
and conflicts plus DIDComm delivery behavior. Gateway privacy projection must not
be substituted for the actual protobuf surface. Mount both configuration and
descriptor through `MARTY_RUNTIME_CONFIG_ROOT` in the intended deployment model.
Current source uses `marty-envoy:latest` and `envoyproxy/envoy:v1.29-latest`; record
and qualify the actual image digest instead of claiming an immutable released
artifact already exists. No image-pin or deployment change is authorized by this
audit alone.

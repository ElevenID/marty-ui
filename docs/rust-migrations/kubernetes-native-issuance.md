# Kubernetes native issuance: intermediate source qualification

This is an explicit opt-in composition, not a deployed cutover or permission to
delete Python. No cluster, registry, Secret value, or production state was read
or changed for this checkpoint. Resolved Kubernetes runtime acceptance and the
remaining direct consumers in [consumer retirement](didcomm-consumer-retirement.md)
still gate retirement. DIDComm KMS corrections remain out of scope.

## Selection and image ownership

`scripts/deploy-kubernetes.sh` retains its disabled/default behavior when
`K8S_ISSUANCE_NATIVE_ENABLED` is unset or exactly `false`. Selecting exactly `true`
requires an already-built `kubernetes-native-issuance` executable and
`MARTY_SERVICES_IMAGE`. No automatic build, image pull or image-source inference
occurs. Build the host tool from the reviewed source with:

```text
cargo build --locked --release --manifest-path rust/Cargo.toml -p marty-release-evidence --bin kubernetes-native-issuance
```

The default tool path is `rust/target/release/kubernetes-native-issuance`;
`K8S_NATIVE_ISSUANCE_BIN` supports an explicit reviewed installation/target path.
This document deliberately provides no deployment invocation: final acceptance
and release provenance remain outstanding.

The source-only `07a-issuance-native.yaml` and `07b-signing-keys.yaml` templates
must never be applied directly. Both must be present in the selected manifest
directory, including custom `--k8s-dir` distributions. The Rust tool composes
them with the actual envsubst-rendered complete
`07-microservices.yaml`, returning a Kubernetes List. The shell captures and
validates that complete model before its first deployment write. The tool has
no network client and reads only declared non-secret selector/settings variables;
unrelated environment is not enumerated. Diagnostics use a fixed refusal without
echoing input. Documents are capped at 1 MiB, each selected variable at 64 KiB,
and their aggregate at 256 KiB. Duplicate mappings, resource identities, owner
containers and environment entries are refused.

New resources are the distinct `issuance-native` Deployment and ClusterIP Service
(HTTP 8005, gRPC 9005), `issuance-native-config`, and the existing Rust
`signing-keys` owner's Deployment and ClusterIP Service (HTTP 8017). They do not share the
legacy `app: issuance` selector. The packaged services entrypoint receives
`SERVICE_NAME=issuance_native`. Native has no host ports, host namespace flags,
init containers, extra containers, or automatic service-account token mount.
The existing `marty-app` service-account name and `ocir-secret` pull reference
are reused; no new credentials are created. Before selecting a private GHCR
image, the approved registry workflow must ensure that the referenced pull
Secret actually authorizes that registry/image. Its historical `ocir-secret`
name and the syntax validator do not establish GHCR authentication; no Secret
contents were inspected here. `/health` probes prove listener
health only, not database/schema, control-plane, wallet or signing readiness.
No existing NetworkPolicy is supplied by this manifest set; ClusterIP/selector
separation is not claimed as network-policy enforcement.

The opt-in gateway gains `ISSUANCE_NATIVE_SERVICE_URL=http://issuance-native:8005`,
`SIGNING_KEYS_SERVICE_URL=http://signing-keys:8017`, and its existing source-derived
readiness roster plus the native member. The common gateway manifest explicitly
sets `AUTH_GRPC_TARGET=auth:9001`, repairing its prior localhost default across
pods. Its
`ISSUANCE_SERVICE_URL` remains legacy. The gateway's existing reviewed operation
selector decides ownership; this is not an all-route switch. Flow still addresses
`issuance:9005`, Envoy is unchanged, and all sibling services remain intact.

The legacy Deployment and issuance migration Job retain their separate
`MARTY_ISSUANCE_IMAGE` and published Python schema authority. Existing RP, UI and
issuance migration ordering is unchanged. Native is deliberately not added to
the global app image catalog, whose per-service tags do not describe the shared
services artifact.

`MARTY_SERVICES_IMAGE` requires a canonical immutable
`ghcr.io/<lowercase-path>/services@sha256:<64-lowercase-hex>` reference. This new
selector is intentionally stricter than the old release formatter: the frozen
[eight reference cases](../../contracts/kubernetes-native-image-reference.json)
record its acceptance of a trailing slash, mixed-case path and other
noncanonical spellings that the new selector rejects. Normal reviewed immutable
references remain accepted. Image syntax validation is **not provenance**:
the external issuance stack lock does not authenticate the UI services artifact.
Final deployment still requires the approved release's services digest and
source/evidence binding.

## Complete selected-native configuration inventory

The authoritative, test-enumerated sets are `INHERITED_SETTINGS`,
`OPTIONAL_SETTINGS`, `SECRET_SETTINGS`, `SHARED_BINDINGS` and `NATIVE_SETTINGS` in
`rust/crates/release-evidence/src/kubernetes_native.rs`. The repo-local inventory
guard compares them with every literal production config input; unexplained
new inputs fail the guard. These are explicit categories, not a generic
"defaults" exclusion:

| Category | Source and behavior |
| --- | --- |
| Fixed identity/listeners | `SERVICE_NAME`, HTTP/gRPC enablement and ports above. Native binds its existing listener host; no host-network override is forwarded. |
| Existing control-plane owners | `ORG_GRPC_TARGET=organization:9002`, `CT_GRPC_TARGET=credential-template:9003`, `RP_GRPC_TARGET=revocation-profile:9013`, `SIGNING_KEYS_INTERNAL_URL=http://gateway:8000/internal/signing-keys`. |
| Existing common references | `ENVIRONMENT`, `UI_BASE_URL`, credential-template/revocation-profile HTTP URLs and universal resolver; `ISSUER_BASE_URL` refers to existing `PUBLIC_API_URL`. |
| Existing Canvas common references | Experience/redirect URLs, organization/issuer identity, portable/pilot/legacy-ingest flags, private/self-managed origin lists, readiness/evidence ages, provider/API base/issuer/badgeclass/assertion scope. Each exact name is enumerated in `INHERITED_SETTINGS`. |
| Paired optional business settings | Offer TTL, token limit/window, issuer display/CORS; VCDM resources/size/timeout; DIDComm resolver/internal-web/private-IP policy; Canvas experience/state/JWKS TTLs, deep-linking issuer, private/localhost policy; provider signature tolerance, publish/status URLs, API origin list, base/validate/revoke aliases and publish/status timeouts. All 27 exact names are enumerated in `OPTIONAL_SETTINGS`. |
| Existing Secret key references | `DATABASE_URL`, `ISSUANCE_API_KEY`, `TOKEN_HMAC_KEY`, `INTEGRATION_SECRET_MASTER_KEY`, `SIGNING_KEYS_INTERNAL_API_KEY`, `GRPC_SERVICE_TOKEN`, `CANVAS_CREDENTIALS_SHARED_SECRET`, all in `marty-secrets`. |
| Optional provider token | `marty-secrets/CANVAS_CREDENTIALS_API_TOKEN`, optional reference. Setup does not fabricate this provider token; an integration needing it must already provision it through the authorized secret workflow. |
| Native-only metadata/logging | Explicit `MARTY_RELEASE_VERSION`, `MARTY_UI_SHA`, `ISSUANCE_NATIVE_RUST_LOG` (mapped to `RUST_LOG`). Never copied to legacy. The two release identity fields also reach the selected signing owner; native-specific logging does not. |
| Explicit file mounts | The two existing-policy/CA selectors below; no raw file value, host path or custody variable is copied. |

Precedence is preserved at Kubernetes's actual environment boundary. Legacy
explicit environment entries win; matching supported entries are copied verbatim
to native, including valueFrom and optionality. Without an explicit legacy entry,
an explicitly supplied optional business input is added to the shared ConfigMap
for both owners. Without either override, native refers optionally to the same
existing `marty-config` key as legacy, then uses its existing runtime default if
absent. Empty values remain empty; the runtime remains responsible for parsing.
Unknown extra legacy envFrom sources are refused instead of guessing precedence.
In particular, selection does not inject `DIDCOMM_ALLOW_PRIVATE_IPS=false` over an
existing operator `true`; when absent everywhere, the existing secure false
runtime default remains unchanged. The 16-case effective-value matrix covers
absent/empty/custom input, common ConfigMap canaries and explicit legacy canaries.

Custom `--k8s-dir` sources also preserve the seven explicit shared Secret entries,
an optional explicit provider-token reference, issuer base and ORG/CT/RP/signing
targets. The provider-token entry remains optional when legacy has none.
A missing required shared Secret entry
refuses before writes rather than silently restoring a different canonical
credential reference. The management-key identity remains the approved existing
`marty-secrets/ISSUANCE_API_KEY`. When legacy has no explicit `RP_GRPC_TARGET`,
native keeps `revocation-profile:9013`: this matches both its existing config
default (`config.rs:369`) and the existing Python HTTP/gRPC callers
(`routes.py:1886`, `infrastructure/adapters/grpc_adapter.py:576`). Custom Secret,
database, issuer and dependency canaries check exact entry equality; no Secret
values are read or compared.

Native does not broadly inherit `marty-config`, BAO/custody settings, RabbitMQ,
physical-document or legacy mirror-publication options. Their existing legacy
fields remain untouched. The actual owner analysis for provenance URL, recipient
hashing, duplicate awards and static Canvas profile/JWKS exports is retained in
[the base profile inventory](base-native-issuance-profile.md#base-only-fields-retained-on-their-actual-legacy-owner).
Those settings are not falsely labeled dead or removed.

The remaining config classifications are deliberate: `APP_ENV` is superseded by
explicit existing `ENVIRONMENT`; local Canvas admin fallback and its token are
not enabled in this production profile. Secret `*_FILE` aliases are not also set
beside Kubernetes Secret environment references (including aliases supported by
the shared secret helper). `INTEGRATION_SECRET_MASTER_KEY_ENV` is fixed to the
existing named key rather than selecting arbitrary secret-variable names.
`MARTY_ISSUANCE__` layered runtime overrides are not implicitly forwarded;
`CARGO_PKG_VERSION` remains build metadata. Existing dependency timeout/pool limits
are unchanged, not new operator settings.

## Optional compatibility policy and trust

`K8S_DIDCOMM_POLICY_SECRET` names an existing Secret containing `policy.json`.
`K8S_DIDCOMM_CA_SECRET` names an existing Secret containing `ca.pem`. Each supplied
name is validated and mounted to both owners read-only, with explicit items,
mode 0444 and `optional:false`, under `/run/marty-didcomm-policy` or
`/run/marty-didcomm-ca`. The existing file target/schema/policy loader is reused.
No host directory, secret generation, BAO copy or private-IP allowance is added.
The CA setting is a supported native trust extension, not a claim that Python
gained a new CA loader. Default selection has neither mount. This preserves the
existing anoncrypt/authcrypt compatibility choices without implementing
`DIDCOMM-KMS-001` or copying operator key material during rendering.

The preexisting management credential is now explicitly referenced by gateway,
legacy issuance and native issuance. This is the same
`marty-secrets/ISSUANCE_API_KEY`, not a newly generated replacement.

## Image updates and qualification

Before any image write, selected update-images captures native and legacy
issuance Deployments, gateway, signing Deployment, both selected Services and
shared ConfigMap. The Rust
guard checks both complete closed selected pod models while allowing only enumerated
Kubernetes admission defaults; allocated Service addresses are not mistaken for
source drift. The legacy check fences only supported paired environment/secret
references and policy/CA mounts, leaving its independent image and unrelated
topology alone. Missing map/key/policy refuses before writes. This is a snapshot,
not a concurrency lock or a substitute for release authorization.

Selected image updates set and await signing first, then native, propagating
failure before later image writes. Both use the same reviewed immutable services
image. Full deploy also requires signing, native and gateway
rollouts. Existing unrelated legacy update behavior is preserved. No automatic
rollback or production action is introduced.

The preceding opt-in source checkpoint (before the dependency closure below):
all 30 release-evidence tests passed, including
nine K8s tests (1.83 seconds); strict all-target Clippy (0.84 seconds) and package
format checks passed. Review identified and repaired empty-selector inconsistency
and custom-source binding divergence before this final run. The update-shell test invokes
the actual extracted functions, actual envsubst and actual Rust executable, but
uses named closed kubectl/catalog/Canvas-guard doubles. Thirteen cases cover selected
success, five paired-field removals, native rollout failure, missing binary,
invalid image, unset/explicit-false compatibility and empty/invalid refusal.
Five full-deploy/apply cases invoke actual extracted functions to prove invalid
templates, absent shared Secret refs and invalid selectors cause no API/setup
call, while successful apply sends exactly the previously captured complete
model even if shell image input changes afterward. These closed command controls
do not run a successful cluster deploy or migrations. Full-model/realistic-API mutation and
actual CLI argument tests are separate. The final 164 existing/new Python source,
reference, closed-shell and CI prerequisite guards passed (13.54 seconds);
the prerequisite step runs before the normal complete workspace Rust suite. Bash/envsubst are
mandatory rather than silently skipped. The Unix-only non-Unicode environment
case is not claimed executed by the Windows checkpoint.

## Resolved-runtime dependency closure: source-qualified checkpoint

Inspection for the executable acceptance adapter found two real missing
dependencies; the fixture must not hide either with listener rewrites. The
gateway lacked its cross-pod auth target, and Kubernetes had no signing owner or
gateway signing URL despite native issuance using the existing internal signing
client. The opt-in `07b` template reuses the already-supported Rust service from
base/self-host Compose, not a replacement signer or new custody design.

The signing environment is a closed seven-entry source inventory: service name,
port 8017, Redis database 2, internal signing key, `BAO_ADDR`,
`OPENBAO_SERVICE_TOKEN`, and `PUBLIC_DOMAIN`. The token is the existing supported
alias of `BAO_TOKEN`; the existing deployment secret setup already owns it.
The internal key entry is derived verbatim from the matching gateway and legacy
issuance entries and is shared with native issuance. Matching custom Secret
references remain valid; disagreement refuses before writes. No Secret contents
are read. Explicit release version/revision are appended to both native owners.
The native issuance pod itself remains custody-free.

`BAO_ADDR` is an existing external dependency supplied by `marty-config`; the
production example uses `https://vault.example.com`. This is a placeholder, not
evidence of a reachable or authorized provider. There is no assumed local OpenBao
Deployment. Real provider access, configured key capability, Redis readiness and
registry pull authorization remain operator/release acceptance prerequisites.
Signing `/health` proves the listener after initial Redis setup, not an actual
OpenBao encryption/signature operation. Existing migration ordering is retained;
the signing service uses its existing Redis stores and adds no SQL migration.

The second, identical `MARTY_ORG_ID` mapping in the common ConfigMap was removed.
A frozen original-source hash and whole-map comparison prove this is a
duplicate-key cleanup only; the Rust parser still rejects the historical
duplicate. No organization value was changed. The operational renderer emits
bounded JSON, avoiding serde_yaml's feature-unified JSON-number representation;
modified-manifest fixtures now use JSON documents too and require a successful
custom-source render, not merely a refusal that could hide an encoder failure.

Kubernetes assets are distributed with the repository/manifest directory and
the existing Rust CLI. This does not add Kubernetes assets to the separate
self-host bundle. New source/model tests cover exact signing configuration,
custom/mismatched identity, missing signing owner/service/auth/key, closed pod
topology, release metadata and signing-before-native rollout failures. The
executable shell controls remain closed doubles, with no cluster reads/writes.
The refreshed Windows checkpoint passed all 32 release-evidence tests, including
11 K8s tests (2.86 seconds). The complete 32-test suite also passed with
`serde_json/arbitrary_precision` enabled (11 K8s tests, 2.70 seconds), followed by
strict all-target feature-unified Clippy (1.44 seconds), package formatting and
Bash syntax checks. The six full-deploy/apply cases and 19 update cases use the
actual operational functions and renderer with closed command doubles. Both
selected owners are checked against enumerated realistic API defaults.
All 365 broader Python deployment/consumer/Canvas/source guards passed in 20.01
seconds. These counts supersede the preceding checkpoint for this changed source.

Initial runner failures were resolved before the final evidence: explicit Rust
1.95.0 replaced the unsupported default 1.93 invocation; the frozen-source test
normalizes only CRLF to its declared UTF-8/LF representation; the established
`marty_common` test dependency path was restored; and the exact consumer inventory
now includes the approved gateway auth target. No runtime/frozen behavior was
relaxed. The resolved executable Kubernetes adapter remains pending.

Still required: final integrated hosted tests, authenticated image provenance,
resolved Kubernetes configuration/runtime acceptance (both DIDComm modes,
ordinary/token/discovery/Canvas, initiation/renewal, real dependencies and no
legacy fallback), and remaining direct HTTP/RPC consumers. No Python deletion,
cluster acceptance, release-image boot or completed K8s migration is claimed by
these model and command-boundary tests.

Any later real Kubernetes gate must use an explicitly owned ephemeral cluster
and namespace. Merely finding `kubectl` does not authorize using the current
kubeconfig/context; no context or cluster API was inspected for this slice.

# Default Envoy native issuance

The canonical source now selects the complete migrated twelve-method issuance
gRPC surface. The historical renderer evidence below began with initiation and
remains useful provenance. This does not deploy anything, remove Python, change
authentication policy, or certify an immutable release artifact. Canonical
`config/envoy/envoy.yaml` targets `issuance-native:9005`; Python remains in the
default Compose model for its eleven HTTP-only routes.

## Configuration owner

The existing Rust deployment-tooling crate still provides
`render-envoy-native-issuance BASE_YAML PROTO_DESCRIPTOR`. It emits bounded
JSON-compatible YAML on stdout; the caller owns output publication. Inputs must
be regular files, are limited to 1 MiB, and malformed/ambiguous source topology or
a descriptor differing from the tool's compiled source is rejected. Output is
also bounded. JSON encoding deliberately preserves scalar numbers under Cargo
feature unification with `serde_json/arbitrary_precision`; cross-serializing
JSON values directly with the YAML serializer did not do so. The renderer now
validates an already-native canonical model idempotently, while preserving its
ability to upgrade a reviewed historical legacy model. It requires one native
HTTP/2 cluster at `issuance-native:9005` and the exact gRPC/transcoded issuance
prefixes; ambiguous clusters, shadowing matchers, weakened HTTP/2/health
configuration, or a legacy endpoint under the native name fail closed. Generic
health/reflection routing, filters, timeouts, access logging and unrelated
clusters remain unchanged. No service token is injected: existing caller
`x-service-token` authentication remains required by the native owner.

Deployment-specific generated files may still be selected through
`MARTY_ENVOY_NATIVE_CONFIG` and
`docker-compose.profile.envoy-native-issuance.yml`. The override changes only
Envoy's read-only config bind
(`create_host_path: false`) and adds native readiness as a dependency. It retains
the canonical descriptor mount, legacy dependency, image, ports and environment.
Missing/empty selectors fail Compose rendering. Compose model checks do not
establish file availability inside a deployed release or runtime correctness.

Deployment-specific generated-file staging and authenticated Envoy artifact
release evidence remain separate work. The source image/Dockerfile still use
mutable tags; local runtime checks inspect the actual built immutable image ID
and do not describe that as signed provenance.

## Qualification boundaries

The descriptor contract independently decodes the checked-in protobuf descriptor:
all twelve methods, annotations, streaming flag and complete initiation request
and response field inventory. The descriptor SHA-256 is
`3093b95919ce8a34d3308f0aff7eb2852357e47ec552871ff9664fe0d823af0c`.
That source binding is not a substitute for actual Envoy validation.

`envoy_actual_image_validates_candidate` uses the actual inspected Linux Envoy
image, runs its configuration validator, starts both baseline and candidate
instances, and checks exact-owned cleanup. It can run from Windows with a Linux
Docker daemon. It does **not** exercise the native Linux service or establish
business acceptance. The first single-candidate run exposed and qualified the
numeric serialization repair. The expanded baseline/candidate image gate passed
on Windows against image ID
`sha256:cca6fa4ce9ac716ed475673cc2c07215f6839e9e561010c599af42de742c7c17`;
both actual validators and checked container/file cleanup passed. Six pure
controls also passed. These results do not qualify the full Linux business gate.

The mandatory Linux `base_profile_envoy_composition_isolated` gate reuses the
existing real native-main, gateway, PostgreSQL, Redis, Core signing and wallet
decryption graph. It retains the existing ordinary/token/nonce/discovery/Canvas
and renewal assertions. Automatic anoncrypt/authcrypt requests additionally cross
actual Envoy HTTP transcoding; ordinary keyed initiation/recovery/conflict crosses
actual tonic gRPC and gRPC-web. Native unavailability must not fall back to legacy.
This full Linux composition cannot be claimed from Windows compilation or the
supplementary image-only gate; hosted execution remains required.

The derived legacy reference and auth-health endpoints are explicitly counted
transport controls, not product ownership. All twelve RPCs and their annotated
HTTP endpoints must reach native in the candidate; the stream requires its first
message and successful terminal status. Baseline/candidate
comparisons cover method, lookalike/encoded path and CORS boundaries using whole
response bytes, relevant headers and request-attempt vectors. If actual Envoy
normalizes an encoded URL into initiation, its decoded baseline request identifies
that alias; the candidate is compared to the exact native operation, not to the
legacy control's empty business response. Known/repeated query binding likewise
uses the actual unchanged transcoder's observed accept/reject behavior.

Binary gRPC-web checks decode actual protobuf message and terminal trailer frames,
including missing/wrong service-token failures. Generic health requests prove the
unchanged auth-cluster destination. Rejected requests and no-fallback paths compare
complete lossless snapshots of all four owned issuance tables and peer side effects.

Fixture-only socket projections are closed and reversed in full-model tests:
native `127.0.0.1:9005`, legacy control `127.0.0.1:19005`, auth-health control
`127.0.0.1:19001`; baseline alone uses listener/admin ports `19000/19901` instead
of `9000/9901`. Both sidecars share the exact-owned PostgreSQL network namespace,
without host publications or Docker-socket mounts. Three exact read-only files
per sidecar carry hashes; normal cleanup verifies both container and file absence,
and panic cleanup retains ownership checks. Primary execution and cleanup failures
are reported together. The 30-second validator polling budget is distinct from
the shared bounded per-command setup/cleanup budgets.

## Required gates

- `cargo test -p marty-release-evidence --test envoy_config_contract --test envoy_descriptor_contract`
- Issuance `canvas_published_schema_contract`: feature-unified external YAML scalar
  check, sidecar ownership/cleanup/projection controls and gRPC-web frame negatives.
- Configured `envoy_actual_image_validates_candidate` and full Linux outer/child
  composition, registered in the mandatory published-database runner.
- Existing configured fresh/native/DIDComm regressions and strict affected-target
  Clippy, plus workspace formatting.
- `pytest tests/test_envoy_native_configuration.py`; source-disconnection negatives
  reject ignored, missing or optional runtime/image/Compose gates.
- `python scripts/test_envoy_native_compose.py`: actual three-mode complete Compose
  model comparison and missing/empty selector failures, registered in required CI.

No KMS, Core API/pin, crypto implementation, production deployment or Python
retirement is included in this slice.

Local checkpoint (2026-09-12): 26 release-evidence tests and strict crate Clippy;
strict issuance contract-target Clippy; six Envoy controls plus the cleanup-error
combination control; both-image validation; existing rendered-native and
fresh-main two-mode gates; all 19 selected DIDComm regressions; 17 Python guards
and the three-mode actual Compose gate passed. All 29 recorded container IDs
from the final native/DIDComm regression sequence were independently absent.
The full Linux Envoy business composition is registered but has not been executed
on this Windows host; it remains required before acceptance or activation.

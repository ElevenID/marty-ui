# Self-host executable acceptance: staged qualification

Stage A connects the existing real directory/ZIP packager gate to a closed
runtime configuration adapter. It does not boot services, load operator secrets,
or qualify a released image. Later stages below remain required for consumer
retirement. DIDComm KMS, Core changes, deployment and Python deletion are outside
this slice.

## Stage A: actual extracted bundle, raw runtime settings

The existing mandatory
`actual_cli_packages_and_renders_extracted_bundle_with_contained_asset_references`
test still owns real CLI invocation, ZIP extraction, complete asset/file equality,
reference closure and rejected replacement. It now passes that same extracted
bundle to `tests/support/resolved_selfhost_runtime.rs`. There is no second archive
implementation, loader or operational configuration parser.

The adapter renders both the actual source Compose pair and extracted
`docker-compose.yml` with the same closed synthetic inputs through the existing
bounded packager renderer. It requires explicit
`MARTY_SELFHOST_BUNDLE_TEST_COMPOSE`, version 5.4.0; Linux additionally checks the
already-used renderer SHA-256. This strengthens this executable test's prerequisite,
not the packager CLI's retained optional standalone-renderer interface. Existing
CI exports the pinned executable to this exact variable.

Full models must match after only classified bundle-local bind/config/secret
file paths are relocated. No substring replacement of business values, ignored
services, deleted fields or broad model pruning is allowed. Source hashes remain
unchanged throughout rendering; a complete model digest fences subsequent adapter
use. Existing ZIP/output/extracted membership and byte checks remain intact.
Both renderings use the project name read from the source model. This is the
default self-host profile, not qualification of custom project-name overrides:
flattening materializes network and secret resource names. An initially invented
fixture project rename was removed, rather than ignoring those resource fields.

The prerequisite operator-bind correction is documented in
[the packager boundary](selfhost-bundle-packager.md). The new interpolated gate
exposed it; after its separate reviewed repair, no path-escape normalization or
full-model pruning was needed.

Native, gateway and Flow keep `ENVIRONMENT=production`, their selected image and
dispatcher identities, every raw `_FILE` selector, TLS file path, shared secret
identity, readiness member and Redis database selection. Native remains free of
BAO settings and retains `DIDCOMM_ALLOW_PRIVATE_IPS=false`. Its signer still goes
through gateway; gateway explicitly selects the separate signing owner. Flow's
native RPC and legacy physical-document HTTP owners remain distinct.

The adapter returns `RawComposeRuntime`: three complete raw Compose-serialized
environment maps plus exact declared
secret-mount identities. It does not read or generate secret material. An empty,
fresh owned external-secret directory supplies only Compose path identities.
The source/serialized `$${MARTY_DB_PASSWORD}` escape is retained in
`DATABASE_URL_TEMPLATE`; no precomputed database URL or dollar replacement is
substituted. These maps are **not ready-to-pass process/Docker environment**.
Only the exact source database address suffix is changed. The actual
Compose-to-container escape consumption and packaged loader/password result
remain an explicit later gate. Existing Flow rendered tests check URL shape and
absence of `${`, but do not connect that configured database URL or assert the
password; they are not proof of this secret-expansion boundary.

Endpoint mapping accepts a closed typed role roster and unique nonzero ports,
constructing only loopback endpoints. It can change only the enumerated owner
addresses and listener ports, database host/port and Redis address. All unmapped
fields are compared unchanged. Database user/database remain the source's `marty`;
later runtime fixtures must provision that synthetic identity rather than hide
the packaged database contract. Stage A does not claim these example ports are
bound or that loopback mappings prove Compose DNS.

Negative controls cover missing/loopback/wrong-owner signing URL, changed native
and physical targets, production/private-IP changes, loader bypass, database
template loss, missing readiness members, wrong secret paths/targets/key identity,
TLS path changes, unrelated legacy mutation, raw-plus-file inputs and
missing/zero/duplicate role ports. Exact test-call/registration/renderer/CI
disconnection guards keep this connected to real extracted output.

Final Windows qualification used Rust 1.95.0 and actual Compose 5.4.0 with a new,
task-specific build directory: all 21 packager tests passed, including all three
executable gates (1.77s) and the Stage A completion marker. Strict package Clippy
passed (2.94s); all 133 self-host Python source/render/registration guards passed
(0.85s), with Ruff and package formatting clean. The Windows malformed-path
control ran; the Unix-specific control and Linux renderer digest check await
Linux CI. An earlier shared-cache apparent pass was excluded after its executable
was found not to contain this adapter; the final evidence compiled the actual
source afresh (8.14s).

Both native and Flow mapped templates are compared exactly, including the two
dollar signs; jointly changed single-dollar models are refused. Image-default
command/entrypoint values may be absent or null, but empty-list and explicit
overrides are refused for gateway and Flow. Path conversion rejects invalid
Unicode rather than silently replacing it. No containers, service images or
secret material were created. All results remain configuration and packaging
evidence only, even though real executables perform the rendering.

## Later mandatory stages (not implemented here)

1. **Public services-image and permissions.** Use an exact-head source build of
   the existing `services/Dockerfile`, inspected at UID/GID `10001:10001`. Launch
   its baked `/app/services/entrypoint.sh` and `/app/load-secrets-env.sh`; do not
   mount replacement scripts/binaries or substitute dedicated-image entrypoints.
   Qualify readable files, CRLF handling, template expansion and actual PG access;
   missing/nonregular/unreadable/conflicting inputs and invalid required values
   must fail at their real owner boundary without secret disclosure or admission.
   Never add a root fallback or alter operator permissions. The dedicated gateway
   image bypasses this loader and is not equivalent evidence.
2. **Native and gateway executable composition.** Reuse existing issuance named
   peers and renewal/base gateway/ordinary/DIDComm/Canvas graph assertions through
   a narrow service-endpoint launch seam. Preserve both encryption modes,
   explicit private-IP refusal/opt-in, real PG/Core/HTTPS effects, authorization,
   owner GETs, forbidden legacy POSTs, ordinary/token/nonce/discovery behavior,
   gateway-cache versus native replay distinctions and all readiness members.
   Existing full Canvas lifecycle gates remain separate; read checks alone are
   not full Canvas parity. Use existing exact-owned namespace/Redis/bounded Docker
   owners, with no service host ports, Docker socket or operator mounts in the
   coordinator. A new closed sidecar handoff must be source-reviewed first.
3. **Packaged Flow production workload TLS.** Reuse Flow startup peers and public
   behavior assertions with real synthetic CA/URI-SAN material. The actual Flow
   main must connect to presentation-policy with mTLS and serve its own TLS
   listener. Qualify a real provider RPC and allowed inbound workload method,
   plus wrong SAN/token, absent certificate and untrusted CA failures with no
   admission effects. Production applies workload mTLS only to the policy
   provider; ordinary authenticated native issuance RPC remains unchanged.
   Existing lazy provider/config tests do not prove these handshakes.

Prerequisites for later stages: mandatory same-head public services-image build,
Linux test/packager artifacts, existing pinned Compose, owned published-schema PG
and Redis fixtures, and existing wallet/Core/OpenSSL support. Keep image/script/
binary and extracted-source identities linked, and verify exact cleanup even on
failure. Missing artifacts must fail rather than skip.

Even those synthetic source-image gates will not prove released-image provenance,
registry access, real OpenBao/provider capability, complete self-host deployment
and soak, external callback delivery or permission to retire remaining Python
consumers. Those require their separately governed acceptance steps.

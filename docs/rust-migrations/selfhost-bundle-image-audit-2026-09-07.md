# Selfhost bundle image and dispatch audit - 2026-09-07

Scope: read-only source and actual Compose-merge inspection in the owned UI
worktree at HEAD `6914387e563d1043948aaea7a5cc514be6055038`, including the parent's
then-uncommitted issuance inheritance repair. This is not an exact-head hosted
qualification, an image execution test or a deployed-selfhost health report.

## Inspected sources and rendering boundary

- `docker-compose.selfhost.prod.yml` and
  `docker-compose.selfhost.bundle.override.yml`: complete merged service launch
  definitions, image families, build removal and runtime selectors.
- `services/Dockerfile` and `services/entrypoint.sh`: shared Rust binary copies,
  default launch command and selector-to-executable dispatch.
- `rust/services/Dockerfile.ci`: dedicated-image entrypoints and defaults,
  including `SERVICE_NAME=issuance_native` for the native issuance image.
- `scripts/load-openbao-token-and-start.sh`: inherited issuance wrapper behavior.
- `.github/workflows/cd.yml`: shared release image is built from
  `services/Dockerfile`, with `SERVICE_NAME=gateway` as its image default.
- `scripts/test_canvas_worker_compose_render.py`,
  `tests/test_canvas_worker_deployment.py` and
  `tests/test_issuance_rust_candidate.py`: preservation checks and the remaining
  whole-issuance cutover boundary.

Both base and merged models were independently rendered with `docker compose
--env-file NUL`, the fixed Compose paths, and `config --no-interpolate
--no-env-resolution --no-path-resolution --no-consistency --format json` on
Windows. No image digest resolution, pull, build, container launch or deployment
occurred. Required image expressions remain unexpanded; model consistency and
actual operator configuration are deliberately not qualified by this check.
Rendered environment fields can be arrays or mappings; selectors were checked
from their actual rendered representation without printing secret contents.

## Corrected issuance boundary

Before the local repair, the bundle selected the Rust-only shared image for
`issuance` while retaining its Python Uvicorn command and OpenBao wrapper. It
also selected unsupported `SERVICE_NAME=issuance`. Resetting only the command
would therefore not repair dispatch. Switching the entire API to
`issuance_native` would bypass the existing path-split cutover boundary.

The parent removed only that bundle override. Independent fresh renders now
show **complete definition equality** between base and bundle for `issuance`,
`issuance-migrations` and `canvas-sync-worker`. They retain the immutable
`MARTY_ISSUANCE_IMAGE` expression, original commands, wrappers, secret bindings,
dependencies and other runtime fields. The shared comparator and field-mutation
tests guard whole definitions, not only image names. No blocking finding was
identified in that repair. It preserves the currently required Python runtime;
it does not close whole-API or worker cutover gates.

## Sixteen shared-image service checks

Every service below has no remaining build definition or Compose-level command
or entrypoint override after merging. Its selector matches a dispatcher branch,
and the selected executable is copied into `services/Dockerfile`'s runtime.

| Rendered service | Normalized selector | Rust executable |
| --- | --- | --- |
| `applicant` | `applicant` | `marty-applicant` |
| `auth` | `auth` | `marty-auth` |
| `compliance-profile` | `compliance_profile` | `marty-compliance-profile` |
| `credential-template` | `credential_template` | `marty-credential-template` |
| `deployment-profile` | `deployment_profile` | `marty-deployment-profile` |
| `device-registration` | `device_registration` | `marty-device-registration` |
| `event-stream` | `event_stream` | `marty-event-stream` |
| `flow` | `flow` | `marty-flow` |
| `gateway` | `gateway` | `marty-gateway` |
| `notification` | `notification` | `marty-notification` |
| `organization` | `organization` | `marty-organization` |
| `presentation-policy` | `presentation_policy` | `marty-presentation-policy` |
| `revocation-profile` | `revocation_profile` | `marty-revocation-profile` |
| `revocation-profile-migrate` | `revocation_profile` | `marty-revocation-profile` |
| `trust-profile` | `trust_profile` | `marty-trust-profile` |
| `verification` | `verification` | `marty-verification-service` |

No further source/render launch incompatibility was found in this set. Dedicated
CI image defaults are not substitutes for these shared-image checks. Source
copies and dispatch matches do not prove the contents of an already-published
image, service startup, database compatibility or full behavior.

## Remaining packaging-only omission

`signing-keys` is absent from the bundle override. Its merged model retains
`build.dockerfile=services/Dockerfile`, build argument
`SERVICE_NAME=signing-keys`, and no published image. This is a confirmed gap in
the bundle's published-images selection, **not a demonstrated launch failure**:
the local image source contains and dispatches the correct Rust binary.

Separate next action: coordinate with the active crypto owner, then add the
shared image anchor and runtime `SERVICE_NAME=signing_keys`, preserving all
base runtime wiring. Verify the merged image, absence of a local build, correct
binary selection and unchanged secrets/dependencies/healthcheck. No signing,
key-custody or other security implementation changes are required by this
packaging repair. No such implementation change or deployment occurred here.

## Existing coverage and minimal DRY follow-up

`tests/test_shared_rust_service_image.py` already owns an 18-selector Rust
allowlist, the one-build/all-binaries copy checks and closed-dispatch checks.
Service-specific cutover tests additionally check source dispatch and selected
base/CI definitions. Signing-key tests cover selfhost secret-file wiring, but
not its actual merged bundle image. The existing Compose-render gate protects
the inherited issuance family; it does not yet assert the complete converted
service set. Tests that only enumerate services already using the shared image
would miss an omitted override such as `signing-keys`.

Recommended small extension, without another hard-coded service inventory:

1. Reuse the existing two rendered models. Derive expected converted services
   from the base's `services/Dockerfile` build argument/environment selector, or
   its `rust/services/Dockerfile.ci` target for dedicated Rust services.
2. For every derived service, require the shared published image, no local
   build, the expected normalized selector, and compatible command/entrypoint.
   Verify the selector's own dispatch stanza selects a copied binary; mere
   independent string presence would not catch swapped branch bodies.
3. Normalize rendered environment mappings/arrays once, then compare remaining
   base runtime fields after only the intended image/build/pull-policy/selector
   changes. Keep the issuance-family equality checks separate and unchanged.
4. Add focused mutation controls for a missing override, wrong or absent
   selector, wrong selected binary, inherited Python launch, surviving build,
   and lost runtime binding. Reuse existing allowlist expectations rather than
   copying the eighteen-name table into another test.

This is a test/packaging follow-up, not a reason to re-port already retained
features or relax native cutover gates. Production remains unchanged.

## Packaging follow-up in the owned UI worktree

The follow-up adds only `signing-keys` to the shared-image bundle anchor, with
`SERVICE_NAME=signing_keys`. Its existing Rust binary and dispatcher already
exist in the shared image source. All implementation, key-custody, secret
configuration and crypto-owner files remain untouched. This isolated packaging
change does not adopt another worker's unlanded crypto changes or qualify a
published signing service.

The mandatory Compose-render gate now derives the expected converted service
set from the base build definitions, including dedicated Rust CI-image targets.
It compares each entire service model after only the intended image, build,
pull-policy and normalized-selector changes. Environment lists and mappings
share one normalization helper; secret values are not resolved or printed.
This avoids a second hard-coded service inventory and detects missing overrides.

The expanded actual renderer failed specifically on the omitted `signing-keys`
definition before repair, then passed all **17 converted Rust service models**
afterward, alongside the unchanged issuance API, migrations and worker models.
Independent mutation and dispatcher-binding tests passed all 40 focused cases,
including swapped dispatch bodies, missing overrides and lost runtime fields.
The complete Python suite subsequently passed 1,156 tests with one existing
skip in 58.55 seconds. Independent review also re-rendered and compared every
signing-keys runtime field. The rendered result remains source configuration
evidence, not runtime acceptance.

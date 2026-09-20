# Self-host native issuance owner — qualification in progress

This source change adds a distinct native owner for the already-selected gateway
routes. It does not deploy a persistent self-host or production environment, retire
Python, or correct DIDComm KMS. All direct legacy HTTP consumers remain unchanged.
Flow initiation now has a separately qualified native target and repaired existing
secret bindings; see [its precise qualification boundary](flow-native-consumer-selection.md).

The shared issuance application environment preserves the original service's
entire resolved definition. Nine settings remain exclusively on legacy: BAO
address/token, the three unconsumed static Canvas key/profile exports, three
legacy Canvas publication options, and legacy authentication-session TTL. Native
uses the same existing file identities for database, issuance/signing key,
integration key, token HMAC, Canvas bridge and gRPC token. It receives no BAO
token. Existing loader ownership, database-template expansion, default network
and restrictive DIDComm private-IP setting remain intact.

Native extends the environment/network-neutral runtime and adds the existing
database migration prerequisite. The bundle override selects the shared services
image with a service-local build reset; the neutral source file is included in
the asset descriptor for flattening. The Rust packager must remove build-bearing
source Compose inputs after flattening, not weaken its output validation.

## Configuration input inventory

The gate exhaustively partitions every uppercase input read by native `config.rs`.
Seven values come from the existing file loader: database URL, Canvas bridge
secret, gRPC token, integration key, issuance key, signing key and token HMAC.
The database value uses the existing password/template expansion. Policy and
custom CA files require explicit mounts; neither is silently enabled here.
Cargo package version and the native nested configuration prefix are metadata.

All remaining unforwarded inputs are enumerated in the gate's `UNFORWARDED` set:
Canvas admin fallback/API token and endpoint overrides, timing/TTL/signature
tolerance settings, display/CORS/resolver overrides, token rate/window, related
resource settings and release metadata. None was bound by the frozen self-host
legacy composition. "Unforwarded" does not mean unsupported: these retain native
defaults or require an explicit deployment overlay. The custom-host test supplies
canaries for these values and raw loader outputs to prove ambient configuration
does not unexpectedly override the file-only bindings. This inventory does not
claim every native default has received packaged behavioral qualification.

The shared runtime exports organization/public URL/event-stream context unchanged;
those are not mistaken for new native business inputs. Legacy-only Canvas
publication settings stay on the actual legacy publisher. Gateway readiness is
checked against the source default roster plus native, not an unrelated list.

Source-reviewed defaults (not packaged runtime evidence):

| Unforwarded setting | Effective native default / source |
| --- | --- |
| Token limit/window | 30 requests / 60 seconds; `config.rs:343-387` |
| CORS/display | `http://localhost:3000` / `ElevenID LLC`; same default layer |
| Related resources | Empty URLs, 2,000,000-byte limit, 10-second timeout; same layer |
| DIDWeb internal URL/policy/custom CA | Absent; resolver uses the forwarded universal URL if supplied; same layer and legacy adapter |
| Canvas signature/state/JWKS | 300 seconds / 10 minutes / 1,440 minutes; `config.rs:499-544` |
| Experience code/session/deep-link issuer | 60 seconds / 30 minutes / absent; same section |
| Canvas operator API token and template overrides | Absent; tenant-owned provider configuration remains available; `config.rs:572-607` |
| Publish/status/validation timeout | Publish 20 seconds; status inherits publish and also controls validation; `config.rs:610-625`, `canvas_credentials_protocol.rs:13-24` |
| Local admin fallback | Disabled by production environment, even if requested; `config.rs:630-645` |
| Build/logging | Package version (currently 0.1.0), unknown revision; `config.rs:352-355`; `RUST_LOG` falls back to info in `main.rs:126` |

The literal-input guard does not pretend to discover dynamic names. Native
`secret_value` constructs a corresponding `_FILE` selector, and the integration
key's alternate-variable selector defaults to `INTEGRATION_SECRET_MASTER_KEY`.
Those mechanisms remain supported; the profile chooses its explicit existing
file aliases and does not introduce arbitrary host-variable bindings. The
existing loader reads and clears consumed selectors before native startup.
`RUST_LOG` is an executable logging input outside the `config.rs` inventory and
is intentionally unforwarded here. `APP_ENV` is only an alias when `ENVIRONMENT`
is absent; this profile explicitly sets production. The copied default revocation
profile ID has no native reader and the audited Python helper has no call site;
its presence is not claimed as an implemented feature or a reason to delete it.

The independent frozen baseline is the original self-host file at `98e78b8d0`,
Git blob `7bff1a842865b9101516d839c10bb645a50089c3`. Its normalized SHA-256 is
`5c643478422ecb9f71bb9bd3133af55805e91b184bd8f3c84852fafd418905f8`.
`scripts/test_selfhost_native_owner_compose.py` compares the entire rendered
model with only the new anchor/service, original three gateway additions and
the separately governed signing-target repair below allowed.
Native expectations derive from the frozen owner's environment and secrets,
not from the new source. Pure mutation tests are explicitly not a Compose emulator.

Currently qualified: no-interpolate and default/empty/custom interpolated
before/after rendering, all ten required inputs missing/empty in both models,
existing complete bundle preservation, exact native dispatcher exception, frozen
identity and model mutation guards. Interpolation uses only synthetic files and
a sanitized subprocess environment, not operator secrets. The new preservation
command is mandatory in image CI.

Still required before claiming this slice qualified: independent
review, actual generated/extracted bundle rendering, packaged secret-loader/main
failure cases and database access, gateway/signing/wallet behavior for selected
routes, and exact-head CI. Config rendering alone proves none of those runtime
claims. Preserve the legacy service and its features until all consumer gates pass.

## Separate-container signing target repair

The self-host gateway now explicitly binds `SIGNING_KEYS_SERVICE_URL` to
`http://signing-keys:8017`. Previously the omitted setting selected the Rust
gateway default `http://localhost:8017`, although signing is a distinct service.
Native issuance already calls the gateway's `/internal/signing-keys` route and
the unchanged gateway readiness roster already requires signing-keys. The
existing shared API-key file identity is unchanged.

The frozen pre-native model remains immutable. Its whole-model comparator allows
exactly this additional gateway field and rejects missing, loopback and wrong
owner targets. Source-derived checks tie the URL to the actual signer port,
native proxy URL, readiness roster and existing key bindings. These checks and
the full synthetic Compose matrix are configuration evidence only: they do not
prove signing/provider capability, non-root secret readability, packaged startup,
workload TLS, release-image provenance or deployment readiness. KMS remains out
of scope.

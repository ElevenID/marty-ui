# General-base native issuance configuration checkpoint

Current status: the opt-in described below was the historical qualification
stage. The default base now selects Rust for 120 HTTP routes and all twelve gRPC
methods while retaining Python for the exact eleven-route remainder. See
[universal ownership](issuance-universal-native-ownership.md). The detailed
configuration inventory below remains authoritative unless superseded there.

Source base: UI `b7c5d7746317cb01df833159fe2836a581ddbc5b`. This is the
configuration portion of consumer-retirement Batch 1, **not runtime acceptance,
a deployment, or permission to remove Python**. At that historical checkpoint,
the embedded contract selected 74 exact HTTP operations; the current contract
selects 120. The full 131-operation source contract remains the accounting
boundary.

## Composition and unchanged consumers

`docker-compose.profile.issuance-native.yml` remains a reusable overlay, and the
default base now imports the same native service definition. It adds a
distinct internal native owner, gateway `ISSUANCE_NATIVE_SERVICE_URL`, native
healthy dependency and readiness membership. The readiness list is the gateway's
actual `DEFAULT_READY_SERVICES` plus `issuance-native`, checked against Rust source,
not a list guessed from Compose service names. The base's existing auth expression
`${GRPC_SERVICE_TOKEN:-dev-grpc-service-token-change-before-production}` is paired
across the native owner and the thirteen existing clients/peers. It is a retained
development default, **not a new production credential**.

Gateway and Flow retain `ISSUANCE_SERVICE_URL` for the eleven Python-only HTTP
routes, while Flow gRPC and canonical Envoy now select native. Legacy loopback
8005/9005 publications are retained; native has no host-port publication.

The environment/network-neutral `docker-compose.service.issuance-native-runtime.yml`
contains only the common native build, four readiness dependencies, HTTP health
probe and restart rule. The existing beta/conformance wrapper retains its exact
environment and network requirements. A closed, single-edge source reconstruction
and complete rendered beta/conformance comparisons preserve their behavior and
required-variable errors (including the separately governed token-capacity repair).

The local-source base selects native without an extra profile. Released-image
compositions add the existing `docker-compose.profile.ghcr.yml` and
`docker-compose.profile.issuance-native-images.yml`. The latter is the renamed
existing conformance immutable-image overlay, not duplicate content or a changed
public conformance CLI. The base and conformance profiles both explicitly bind
`SERVICE_NAME=issuance_native`, entrypoint `/app/services/entrypoint.sh`, and empty
command; the shared image's build-time selector is not relied upon. Immutable
artifact provenance, compatible source coverage and runtime acceptance remain
separate release requirements; a `:?` Compose expression alone does not authenticate
an image or enforce a digest grammar.

All referenced Compose files remain relative to the full source checkout. No new
files are silently added to the separate self-host runtime-asset package. Self-host
network, secret-file and package work is Batch 2.

## Full configuration inventory

The inventory is bound to production `rust/services/issuance/src/config.rs`, with
every literal input before its test module classified by
`scripts/test_base_native_issuance_compose.py`. Changes to that input set or to any
base/profile environment expression fail the source guard. The binary main uses
that config owner and `RUST_LOG`; no second native configuration parser is added.

The following existing base issuance inputs are forwarded **with byte-identical
Compose expressions**, including unset-versus-empty `:-` precedence. Complete
rendered models independently compare every value to the old owner.

| Surface | Forwarded inputs |
| --- | --- |
| Runtime endpoints | `ISSUANCE_SERVICE_PORT`, `ISSUANCE_GRPC_PORT`, `DATABASE_URL`, `ISSUER_BASE_URL`, `UI_BASE_URL` |
| API and persisted-secret identity | `ISSUANCE_API_KEY`, `TOKEN_HMAC_KEY`, `INTEGRATION_SECRET_MASTER_KEY`, `SIGNING_KEYS_INTERNAL_API_KEY` |
| Named control-plane dependencies | `SIGNING_KEYS_INTERNAL_URL`, `ORG_GRPC_TARGET`, `CT_GRPC_TARGET`, `RP_GRPC_TARGET`, `CREDENTIAL_TEMPLATE_SERVICE_URL`, `REVOCATION_PROFILE_SERVICE_URL` |
| Offers/token/resources | `ISSUANCE_OFFER_TTL_MINUTES`, `TOKEN_RATE_LIMIT`, `VCDM_RELATED_RESOURCE_URLS` |
| DID resolution and endpoint policy | `UNIVERSAL_RESOLVER_URL`, `DIDCOMM_DID_WEB_INTERNAL_BASE_URL`, `DIDCOMM_ALLOW_PRIVATE_IPS` |
| LTI/experience | `CANVAS_LTI_EXPERIENCE_BASE_URL`, `CANVAS_OAUTH_COMPLETION_REDIRECT_URL`, `CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID`, `CANVAS_LTI_TOOL_ISSUER_DID`, `CANVAS_LTI_STATE_TTL_MINUTES`, `CANVAS_LTI_JWKS_TTL_MINUTES` |
| Canvas eligibility/evidence | `CANVAS_PORTABLE_INTEGRATION_ENABLED`, `CANVAS_PILOT_ORGANIZATION_IDS`, `CANVAS_LEGACY_EVENT_INGEST_ENABLED`, `CANVAS_BINDING_READINESS_MAX_AGE_SECONDS`, `CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS` |
| Canvas origin policy | `CANVAS_PRIVATE_ORIGIN_ALLOWLIST`, `CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST`, `CANVAS_ALLOW_PRIVATE_BASE_URLS`, `CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS` |
| Canvas webhook authentication | `CANVAS_CREDENTIALS_SHARED_SECRET`, `CANVAS_CREDENTIALS_SIGNATURE_TOLERANCE_SECONDS` |
| Canvas provider/validation/status | `CANVAS_CREDENTIALS_PROVIDER`, `CANVAS_CREDENTIALS_PUBLISH_URL`, `CANVAS_CREDENTIALS_STATUS_SYNC_URL`, `CANVAS_CREDENTIALS_API_BASE_URL`, `CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST`, `CANVAS_CREDENTIALS_API_TOKEN`, `CANVAS_CREDENTIALS_ISSUER_ID`, `CANVAS_CREDENTIALS_BADGECLASS_ID`, `CANVAS_CREDENTIALS_ASSERTION_SCOPE` |
| Canvas publication projection | `CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE`, `CANVAS_CREDENTIALS_ASSERTION_NARRATIVE`, `CANVAS_CREDENTIALS_PROVENANCE_BASE_URL`, `CANVAS_CREDENTIALS_RECIPIENT_HASHED`, `CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS` |

The base's explicit database `/marty` and public issuer URL prevent the native
standalone `/marty_credentials`/beta-issuer defaults from leaking into this profile.
Its existing OAuth redirect expression is also copied exactly; the different
standalone native default is not substituted. No CA is added and the shared
private-IP expression still defaults to `false`.

The only additional native bindings are the paired `GRPC_SERVICE_TOKEN`, fixed
`SERVICE_NAME`, `ISSUANCE_GRPC_ENABLED=true`, `${ENVIRONMENT:-development}`,
`${MARTY_RELEASE_VERSION:-development}`, `${MARTY_UI_SHA:-unknown}`, and native
`RUST_LOG` from `${ISSUANCE_NATIVE_RUST_LOG:-info}`. These are explicit binary,
authentication and build/runtime identities, not inherited beta environment.

### Supported legacy knobs that base does not forward

These inputs are supported by legacy and native owners but are **not exported by
the current base legacy service**. This profile likewise does not silently promote
host environment variables into container configuration. Operators using custom
overlays must pair relevant settings explicitly; this checkpoint does not qualify
arbitrary custom compositions. Defaults/semantics are existing runtime behavior,
not new configuration promises:

| Inputs | Existing default or role / source |
| --- | --- |
| `ISSUER_DISPLAY_NAME`, `CORS_ALLOWED_ORIGINS` | ElevenID LLC; localhost:3000. Python issuance `main.py:176,409`; native `config.rs` discovery/server defaults. Gateway's `CORS_ORIGINS` is a different input. |
| `TOKEN_RATE_WINDOW` | 60 seconds; Python `routes.py:770`, native rate-limit settings. Integer-grammar/window parity is integrated separately in `3552a9f84`; see [qualification and platform limits](token-rate-config-parity.md). Profile rendering does not establish runtime parity. |
| `VCDM_RELATED_RESOURCE_MAX_BYTES`, `VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS` | 2,000,000 bytes / 10 seconds; Python `routes.py` related-resource owner and native initiation settings. |
| `DIDCOMM_UNIVERSAL_RESOLVER_URL` | Preferred nonempty resolver alias, before `UNIVERSAL_RESOLVER_URL`; Python `application/rust_integration.py:840`, native `legacy_environment`. |
| `CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS`, `CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES` | 60 seconds / 30 minutes; Python `canvas_routes.py:159-160`, native experience config. |
| `CANVAS_LTI_DEEP_LINKING_ISSUER` | Optional override, otherwise platform client identity; Python `canvas_routes.py:3078` and native deep-linking owner. |
| `APP_ENV`, `CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK`, `CANVAS_ADMIN_API_TOKEN` | Environment alias and explicitly gated non-production fallback. Native's new explicit `ENVIRONMENT` takes precedence over `APP_ENV`; fallback remains disabled in this profile. Python `canvas_routes.py:1076`. |
| `CANVAS_CREDENTIALS_BASE_URL`, `CANVAS_CREDENTIALS_VALIDATE_URL_TEMPLATE`, `CANVAS_CREDENTIALS_REVOKE_URL_TEMPLATE` | Legacy provider-base alias and optional provider endpoint templates, consumed by Python `canvas_credentials_adapter.py` and native validation/status config. |
| `CANVAS_CREDENTIALS_PUBLISH_TIMEOUT_SECONDS`, `CANVAS_CREDENTIALS_STATUS_SYNC_TIMEOUT_SECONDS` | Existing shared provider timeout derivation (20-second default); native `canvas_credentials_protocol::timeout_values`, not a new HTTP timeout implementation. |
| `INTEGRATION_SECRET_MASTER_KEY_ENV` | Existing alternate secret-variable name, default `INTEGRATION_SECRET_MASTER_KEY`; Python `postgres_repository.py:132`, native config secret resolution. |
| `ISSUANCE_AUTH_SESSION_TTL_MINUTES`, `ALLOWED_REDIRECT_URIS` | Operator-selected OID4VCI persisted-session lifetime and redirect allowlist. Both legacy and native owners receive the same expressions; native still validates redirect scheme safety before applying the allowlist. The historical 600-second Rust engine lifetime remains distinct from the persisted-session default of 60 minutes. |

### File inputs, native-only overrides, and fixed settings

`DIDCOMM_ENCRYPTION_POLICY_FILE` is provided only by the separate explicit policy
overlay below. `DIDCOMM_TLS_CA_FILE` is a supported native trust extension; this
general profile adds no trust mount and does not reuse conformance's synthetic CA.
These are not omitted default secret values.

Explicit literal file aliases in native config are `GRPC_SERVICE_TOKEN_FILE`,
`CANVAS_CREDENTIALS_API_TOKEN_FILE`, and `CANVAS_CREDENTIALS_SHARED_SECRET_FILE`.
The shared native secret helper additionally accepts `<name>_FILE` for
`ISSUANCE_API_KEY`, `TOKEN_HMAC_KEY`, `INTEGRATION_SECRET_MASTER_KEY` (or its configured
alternate name), `SIGNING_KEYS_INTERNAL_API_KEY`, and `CANVAS_ADMIN_API_TOKEN`.
The packaged entrypoint's existing secret loader handles supported file aliases,
conflicts and `DATABASE_URL_TEMPLATE`; none are rewritten here. Base remains a
direct-value development composition. Actual file-only packaged acceptance belongs
to the self-host batch; do not stack file selectors on these nonempty direct
defaults and claim equivalent secret handling.

Native-only `MARTY_ISSUANCE__` layered overrides can customize the existing
`server`, `build`, `discovery`, `dependencies`, `initiation`, `didcomm` and
`rate_limit` settings. They are not forwarded from the host by this profile.
Native server host remains `0.0.0.0`; public exposure is controlled by Compose's
absence of native publications. `CARGO_PKG_VERSION` is build metadata, not an
operator environment variable. Native dependency timeout is fixed at ten seconds
and pool maximum at five in the current main; this slice adds no knobs for them.

### Base-only fields retained on their actual legacy owner

This section records the first native-issuance landing slice, not the later
passport cutover. The native passport candidate can now opt into
`PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED=true`: each job supplies an
organization-scoped public `issuer_did`, resolves its profile-bound DSC, and
asks the existing signing-keys service to sign an opaque CMS input with its
KMS-held key. Before signing, the Rust verifier checks the DSC against an active
organization CSCA from the public-only lifecycle projection; the trusted CSCA,
not a caller-supplied chain entry, is returned with the SOD. The switch defaults
off and cannot be combined with a remote or self-signed signer. It does **not**
authorize beta activation while artifact encryption, callback authentication,
bureau handoff, DSC revocation/country policy, and acceptance remain on their
separate cutover gates.

The excluded set is exact and guarded; exclusion does not mean feature deletion:

- `BAO_ADDR`, `BAO_TOKEN`: legacy custody configuration. Native uses its existing
  remote signing owner; custody changes remain out of scope.
- `ICAO_DOCUMENT_SIGNER_URL/API_KEY`, `PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED`,
  `PHYSICAL_DOCUMENT_ARTIFACT_KEY`, `PERSONALIZATION_BUREAU_URL/API_KEY/WEBHOOK_SECRET`:
  physical-document features and consumers remain legacy.
- `CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS`, `CANVAS_LTI_TOOL_ACTIVE_KID`,
  `CANVAS_LTI_TOOL_PUBLIC_JWKS`: no readers in the audited pinned Credentials Python
  tree or current Rust tree. Both actual tool signers resolve organization-scoped
  issuer DID through the signing service instead (`canvas_routes.py:1881-2025`,
  native `canvas_lti_tool_signing.rs`). The two identity inputs they do consume are
  forwarded above. These old exported settings remain on legacy unchanged; their
  presence is not mistaken for an active static-JWKS/profile-ID feature.

Python source references above are the unchanged retained renewal/DIDComm reference
at `87eae307` (route blob `6b3a7fa0e169862e815bcb6bca64b0b21a5adf6a`). CI source
guards are repo-local and do not require that separate checkout or Python binding.

## Explicit authcrypt compatibility policy

Add `docker-compose.profile.issuance-native-authcrypt.yml` only when both owners
need the existing compatibility policy. One shared mount definition binds the
exact required `DIDCOMM_ENCRYPTION_POLICY_DIR` read-only to both issuance owners,
sets the existing policy-file target, and forbids host directory auto-creation.
No other service receives the mount. The existing policy/model validator is reused;
no new policy schema, parser or encryption implementation is introduced.

The historical `docker-compose.profile.didcomm-authcrypt.yml` is deliberately not
reused: it mounts only legacy using short syntax that permits missing-directory
creation. The new opt-in is **not equivalent to that missing-directory behavior**.
Its directory must already exist and is checked in the actual rendered-model gate;
Compose's `:?` alone only checks nonempty interpolation. Default anoncrypt has no
policy mount. Beta/conformance overlay behavior remains unchanged. This preserves
both modes and leaves `DIDCOMM-KMS-001` explicitly outstanding.

## Qualification and remaining acceptance

Commands:

```text
python -m pytest tests/test_base_native_issuance_compose.py tests/test_conformance_native.py
python scripts/test_base_native_issuance_compose.py
python scripts/test_conformance_native_compose.py
```

The new mandatory CI step reuses the existing pinned read-only Compose renderer.
It checks all default/empty/custom × local/released × anoncrypt/authcrypt models,
complete unchanged siblings and native bindings, and missing/empty/non-directory
policy negatives. Custom synthetic strings test interpolation, **not runtime
validity**. Pure tests corrupt URLs, readiness, credentials, mounts, dependencies,
ports, environment precedence and CI registration; their small modeled controls
are not presented as Compose emulation or an application execution.

Remaining Batch 1 acceptance: run packaged native main plus gateway using a valid
rendered base model, with ordinary/token/discovery/Canvas and both DIDComm modes,
initiation/renewal, actual PG/signing/wallet decryption, and legacy-fallback traps.
Existing main/gateway behavior gates are reusable evidence but do not by themselves
prove the new composition works. Keep Python, all direct consumers, and production
unchanged until that acceptance and subsequent consumer batches pass.

The [runtime acceptance checkpoint](base-native-runtime-acceptance.md) records
the now-passing rendered native-main stage and the separate, still-unqualified
isolated executable gateway composition. Native-only evidence does not close
the remaining Batch 1 gate.

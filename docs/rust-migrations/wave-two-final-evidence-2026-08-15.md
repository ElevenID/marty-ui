# Rust migration wave-two final evidence

## Outcome

Wave two of the [Consolidated Rust Migration Roadmap](../CONSOLIDATED_RUST_MIGRATION_ROADMAP.md) is complete at the approved beta boundary. All nine workstreams were implemented in descending order of removable non-Rust source. Their intended public behavior was captured in implementation-independent fixtures and service, executable, or mobile contracts; the Rust implementations and adapters passed those contracts; and the superseded Python, handwritten JavaScript, or Dart decision implementations were deleted before the workstreams were declared complete.

The accepted aggregate is `marty-ui v1.1.194` at `cf8f67007261960bbf12cb9f2c2b135c26ecf392`, deployed only to beta with coordinated source ID `a8453d786de0bec69b1fed64d463482ddff13ce4`. Production and persistent self-host deployments were not updated.

## Porting and deletion result

The roadmap ordering represented approximately 27,934 lines of removable non-Rust implementation. Counts are physical-source estimates or deletion totals from the individual PRs; they are not a claim that orchestration, UI, provider, persistence, or platform code should be rewritten merely to change language statistics.

| Order | Workstream | Non-Rust implementation removed | Canonical Rust result |
|---|---|---:|---|
| 1 | Signing-key and KMS service | approximately 7,820 Python lines | Complete Rust service plus shared JWK/key/certificate decisions |
| 2 | Marty CLI and API client | 7,218 handwritten JavaScript lines | One native Rust CLI and Rust/WASM browser client |
| 3 | Notification and webhook service | 7,142 Python/service lines | One Rust REST/gRPC service with PostgreSQL, outbox, secret-envelope, and delivery behavior |
| 4 | Credential attestation, evidence, governance, and VCDM decisions | 1,804 Python lines in the completed slices | Canonical `marty-oid4vci` and `marty-verification` decisions with fail-closed Python adapters |
| 5 | Passport-chip protocol and integrity kernels | more than 1,300 Python lines | BAC/PACE compatibility, EAC, active authentication, APDU, ISO 9796, and integrity kernels in Rust |
| 6 | eMRTD EF, DG15, and biometric parsing | approximately 1,300 Python lines | Bounded Rust parsers with stable Python DTO adapters |
| 7 | Subscription API-key lifecycle | approximately 539 Python lines plus duplicated policy/webhook kernels | Canonical format, hash, scope, CIDR, quota, expiry, and webhook decisions in `marty-license` |
| 8 | Trust-registry synchronization | approximately 433 Python lines | Canonical destination, feed, state-machine, token, scheduling, and certificate-profile decisions in Rust |
| 9 | Wallet status-list and liveness | at least 378 Dart lines | Bounded status decoding and liveness challenge decisions in Rust through generated Flutter bindings |

Retained Python and Dart code performs API orchestration, transport, persistence, OCR, external-provider integration, UI, camera, cache, or platform work. It does not maintain a second implementation of the migrated decisions. Required native paths fail closed when unavailable, malformed, unsupported, untrusted, or missing required state.

## Merged implementation chain

The canonical and consuming changes landed through task-scoped branches, worktrees, protected PR checks, and merge queues.

| Repository and PR | Merge commit | Result |
|---|---|---|
| `marty-core` [#229](https://github.com/ElevenID/marty-core/pull/229), [#233](https://github.com/ElevenID/marty-core/pull/233) | `98e07e56d52235c9099eafe40990587cdced6467`, `34cf79d77161feba79934cb78700f885edf07a75` | Shared public-key/JWK conversion prerequisite |
| `marty-ui` [#515](https://github.com/ElevenID/marty-ui/pull/515), [#518](https://github.com/ElevenID/marty-ui/pull/518), [#520](https://github.com/ElevenID/marty-ui/pull/520), [#522](https://github.com/ElevenID/marty-ui/pull/522), [#524](https://github.com/ElevenID/marty-ui/pull/524), [#527](https://github.com/ElevenID/marty-ui/pull/527) | `4dc470150fe5816a74bf9a09c291d725a5316b02`, `ac15bfd9886a56babfa5e847f6481c02ab07718a`, `56bcaaddd0ff12c0b616bacf0891b94d9d18d54e`, `c0c7f53d5f8daa05f58dc4bb5e67829f766b2720`, `91f60663026cb1411fbc5ce362ff5863cc0a9c6c`, `5b62726c380766d324a0a5417875e89b74c3e1e7` | Complete signing/KMS service and Python deletion slices |
| `marty-cli` [#14](https://github.com/ElevenID/marty-cli/pull/14) | `60e438802a83a201ebe8a7db5e31194a116dc161` | Rust CLI and Rust/WASM API client; handwritten JavaScript removed |
| `marty-ui` [#529](https://github.com/ElevenID/marty-ui/pull/529) | `3dc00a96be73c2d122b9a167ead111912944f8bc` | Rust notification/webhook service; superseded Python service removed |
| `marty-core` [#230](https://github.com/ElevenID/marty-core/pull/230), [#231](https://github.com/ElevenID/marty-core/pull/231) | `918ad5e167ba4424a8fa5d8b045bf073bd640cb4`, `2d7419847fc01641bbe726627397280df258b5e6` | Credential policy/evidence and key-attestation decisions |
| `marty-credentials` [#182](https://github.com/ElevenID/marty-credentials/pull/182), [#183](https://github.com/ElevenID/marty-credentials/pull/183) | `b9e305da4c7b84471a5f0de7ee849cb36817248c`, `dc942c8f4a72e640579b75a2ba0c8b2cb7cf3695` | Fail-closed consumers and Python decision deletion |
| `marty-core` [#232](https://github.com/ElevenID/marty-core/pull/232), [#235](https://github.com/ElevenID/marty-core/pull/235) | `eb28f3dbfe48bb5c40d883466e512ea3d8f35a2c`, `359df1d20f152e21783fe43078d753fa1b494ce4` | Passport-chip and bounded eMRTD parser kernels |
| `Marty` [#51](https://github.com/ElevenID/Marty/pull/51), [#54](https://github.com/ElevenID/Marty/pull/54) | `8467c7a4d82ee5f0e1bb39675bccb4dbff414cb6`, `97a0c9cba664639f162ed40a3e4eaf61803bd582` | Stable adapters and Python passport/parser deletion |
| `marty-subscriptions` [#31](https://github.com/ElevenID/marty-subscriptions/pull/31) | `4c8d7f553c5c9cfe8acdbbe5d85b4278829f6cf1` | API-key, quota, plan, and webhook policy in Rust |
| `marty-core` [#236](https://github.com/ElevenID/marty-core/pull/236) and `marty-ui` [#546](https://github.com/ElevenID/marty-ui/pull/546) | `780ea7c45164b6c314ac62e4a7704c030ad7c45b`, `ed43849c4eae11be9e896bbe417b8209ed1afb11` | Trust-registry decisions in Rust and consuming cutover |
| `marty-core` [#238](https://github.com/ElevenID/marty-core/pull/238) and `marty-authenticator` [#35](https://github.com/ElevenID/marty-authenticator/pull/35) | `a7027c6fb4a45a6e7fb1d618ae915cd2bb95578c`, `8bc37873484cacf7a0424214bb01443d4ce97ee7` | Bounded status decoder, liveness bridge, and Dart-kernel deletion |
| `marty-ui` [#547](https://github.com/ElevenID/marty-ui/pull/547) | `8b34bebbcd17b59d8d16bde86ec2c56df310798c` | Managed issuer authcrypt key agreements aligned with the native signing service |
| `marty-integration-tests` [#375](https://github.com/ElevenID/marty-integration-tests/pull/375), [#377](https://github.com/ElevenID/marty-integration-tests/pull/377) | `b3b1cc46b5cfd62af22883d7305e28556f0cea2d`, `8959f09967abebee5a736fdac955d9230b2b3fed` | Canonical Rust signing topology and runtime selection in behavioral tests |
| `ElevenID/.github` [#32](https://github.com/ElevenID/.github/pull/32) | `d8068d1da4dd5b4ca5daacbb76282ffd2a241f87` | Cross-platform Rust bridge coverage-path enforcement |

The roadmap progress update landed in `marty-ui` [#540](https://github.com/ElevenID/marty-ui/pull/540) as `4191d533893a4a5eaa12395bff5167b5f4d901ca`.

## Behavioral and packaging gates

Each workstream used language-neutral JSON/golden vectors, standards fixtures, black-box HTTP or executable contracts, generated bindings, or public service/mobile behavior. Tests that merely imported the implementation being deleted were not accepted as parity evidence. The combined gates covered:

- exact CLI command names, options, environment/config precedence, HTTP requests, output, errors, and exit codes;
- signing provider capabilities, key lifecycle, wrapping, CSR/certificate, JWKS, DID, issuer profile, persistence, rotation, and audit behavior;
- notification REST/gRPC schemas, destination security, HMAC, Transit-bound secret envelopes, durable outbox leasing, retries, idempotency, migrations, and concurrency;
- credential evidence transitions, governance digests, VCDM policy, key attestation, PostgreSQL races, native-wheel packaging, Rust, Python, and WASM consumers;
- valid and malformed APDU, BAC/PACE/EAC, active-authentication, ISO 9796, EF.COM, DG1, DG2, DG15, DER/TLV, biometric, truncation, oversize, and unsupported-algorithm vectors;
- API-key formats, hashes, masks, scopes, CIDRs, expiry, quotas, Redis atomicity, unavailable-enforcement failures, and Square/webhook signatures;
- trust-registry URL/destination policy, bounded fetching, strict feed/state schemas, tokens, pagination, sequence, scheduling, deltas, removals, X.509 profiles, TLS/SSRF transport, and storage behavior; and
- status-list purpose, bounds, freshness and bit decisions plus liveness challenge creation/sign/verify, generated Flutter bindings, maintained Dart coverage, Android build, and iOS configuration checks.

`marty-core v0.1.57` was released from `54ff554906f5fa2791b7fcb6a5965d7e8db8b0e8`. The Linux wheels used by the aggregate are:

| Binding | SHA-256 |
|---|---|
| `_marty_rs` | `c83d047be16f42fb45e5c1ac86da1c90da673500a0599786b190f454e6e2a559` |
| `marty-verification` | `0ecfa44b6e829b0eda4ea6f7cc0c86cc5dedf69c038c37657ed76d650e2759bb` |
| `marty-iso18013` | `03ec21af09d37362e04a5a8ececbcc54907c25b40fa9a1431108c19d9dcdf747` |

Credential release `v0.1.64` landed as `b57f9f43334ba85cbdfd8db660b5899a0cf2e9f3`; release run `31894431860` and publication run `31895286807` passed. The final stack pins `marty-credentials v0.1.65` at `41a26237179d8950216aaeb1e19fdfcf8a2ea100`, with issuance image `sha256:b4ff6a1c407a258876856e77ec6101e42824943846822849377d0365ebf8f179`. The test topology was released as `marty-integration-tests v1.2.67` at `285aa62cccd736edec33eae99a54d0026d5c5e04`, source digest `sha256:979ad07e5f417c1f2c1db2d97c6cdbae66aacd998437abe3d0aa192dcf03a64f`.

## Immutable aggregate release

[`marty-ui v1.1.194`](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.194) was built by successful Stack release run [31915536750](https://github.com/ElevenID/marty-ui/actions/runs/31915536750) from `cf8f67007261960bbf12cb9f2c2b135c26ecf392`.

| Artifact | SHA-256 |
|---|---|
| `stack-manifest.json` | `22f128bc1fae2f732dafe610ee35ad63ddfc9d6244284afa227fe1df2b41aa03` |
| `SHA256SUMS` | `3fae7d97813f466538d3f8e2379ea27b497b5f927d343648904931cb129e390f` |
| Released UI image | `d6efb337ec8099584d3a15889ccfe49ddadf8a0da307a7df2e8cfa88ed8af239` |
| Released services image | `c6b832f36f304446f76ab2781b6ab5c55e3692fc62b7182882a061def82713d3` |
| Released migrations image | `e24fad8dbcde8d89d9d5d680244253384dc3add080982cceecd8092ea863eca7` |

The manifest pins Core `v0.1.57`, Credentials `v0.1.65`, CLI/API Core `v0.2.3`, Marty common `v0.2.15`, and integration tests `v1.2.67` by exact commit and artifact digest. Release validation, service/UI builds, artifact-only public-stack smoke, SBOMs, checksums, signatures/attestations, and publication all passed.

## Fail-closed rollout history

The beta rollout surfaced topology and product-boundary defects without enabling a Python fallback:

1. `v1.1.187` failed release checks because the signing topology was absent. Beta was unchanged.
2. `v1.1.188` failed because the shared image selected the Python gateway rather than the Rust signing executable. Beta was unchanged.
3. `v1.1.189` passed release CI, but the pre-deployment contract found that the beta runner omitted `signing-keys`. It was not deployed.
4. The first `v1.1.190` live attempt passed rehearsal and migrations, then found host port `8017` already owned by the Canvas sandbox. Supervised recovery restored beta to `v1.1.171`. `marty-ui` [#554](https://github.com/ElevenID/marty-ui/pull/554), merge `9bbdbf613e3b3088b1eee447c68d4d70943aabc9`, made signing internal-network-only.
5. The `v1.1.191` attempt passed rehearsal and migrations, then the signing service failed closed because its Redis URL lacked beta authentication. Supervised recovery again restored `v1.1.171`. `marty-ui` [#557](https://github.com/ElevenID/marty-ui/pull/557), merge `74a179bdd4b905132078d2309f03bced06cf48e9`, added the authenticated beta Redis URL.
6. `v1.1.192` deployed successfully. Its protected lifecycle run [31914114392](https://github.com/ElevenID/marty-ui/actions/runs/31914114392) then found a released product regression: the Cedar gateway middleware attempted an authenticated owner lookup for the public wallet request-object route and returned HTTP 502. No fallback was enabled.
7. `marty-ui` [#559](https://github.com/ElevenID/marty-ui/pull/559), merge `cf8f67007261960bbf12cb9f2c2b135c26ecf392`, aligned Cedar's public wallet request/submit boundary while retaining authorization on result access. Focused local tests reported 159 passing, and protected PR, merge-group, release, and stack smoke matrices passed.

The unrelated `v1.1.193` release was not deployed to beta. A transient Sigstore Rekor timeout during the `v1.1.192` release was retried only after the failure was identified as external transparency-log retrieval; the rerun passed without a source change.

## Accepted beta deployment

The v1.1.194 deployment verified the exact eight-repository coordinated snapshot, rehearsed one-way migrations on an isolated beta copy, captured preflight and quiesced backups, applied all live migrations, bootstrapped KMS/DID state, recreated the aggregate atomically, and verified local and tunneled runtime markers. Deployment completed at `2026-08-16T00:15:10.3512940Z`.

| Evidence | Value |
|---|---|
| Release | `1.1.194` |
| Coordinated source ID | `a8453d786de0bec69b1fed64d463482ddff13ce4` |
| Source manifest SHA-256 | `834c521944399cfeb55c22451d19f912449c9621697fa04b79c87f318bcb1102` |
| Local deployment manifest SHA-256 | `c8b7b0ff0e88299f58d924b4278b097c6f7434e0676ca46ee42ff590d3514a3c` |
| Quiesced backup manifest SHA-256 | `db9bfc351cb3cf2e2a3383eea58ce5bd336c823b4812dd88277ad0e7114fea9c` |

The marker-bearing beta image IDs include:

| Service | Runtime image ID |
|---|---|
| signing keys | `sha256:6f0fa6c049844044f7d1f7cd3f91bbc730436adbc07613e732a6861c90ed68f9` |
| notification | `sha256:252d08851d6bbd6b783c926c53b7a83d45b3b71c56c7d380de9fd9e49be73f4f` |
| event stream | `sha256:137b916e7371a8c39070d1afdb1d67731cb71adf1187d2674ac3672b9449eac2` |
| revocation profile | `sha256:9f53e376655715d09f171818f270321cd06cb163879348cde92bb3f3c635db4a` |
| gateway | `sha256:52ff373aa42f5ac8eb5b980262792e9eba3c99ec7392e89e12ac49b361c2fc68` |
| public UI | `sha256:b430bdcbf3af07267c5b00bea5b5ec99965fdaa656eb9643d4e7338937fbb7f9` |
| issuance and Canvas worker | `sha256:b4ff6a1c407a258876856e77ec6101e42824943846822849377d0365ebf8f179` |

Every health-governed application container was healthy after recreation. The Rust signing service was healthy on the internal network with authenticated Redis and no host port exposure. Public service and UI markers both named release `1.1.194` and source ID `a8453d786de0bec69b1fed64d463482ddff13ce4` where applicable.

## Protected lifecycle acceptance

Protected workflow [run 31916804935](https://github.com/ElevenID/marty-ui/actions/runs/31916804935) passed against the exact v1.1.194 release SHA, successful stack-release run, beta source ID, and Marty protocol revision `725e797d873412f68da08e5ce7774bb24cc9ac4c`. It verified:

- released manifest checksum and attestation binding;
- exact deployed release/source markers and MIP 0.4.1 discovery;
- SpruceKit-compatible issuer metadata;
- creation and activation of every organization credential primitive;
- canonical and removed applicant contracts;
- membership-badge issuance, logout, and credential-based login;
- template creation, issuance, and browser-wallet verification; and
- renewal, suspension, reinstatement, revocation, status ownership, and cross-organization enforcement.

The accepted `mip-03-beta-credential-lifecycle` artifact has ID `9255195428`, size 7,533,450 bytes, and digest `sha256:9285f949581a958c934bc04fa6c5ea47e1fd724ddfe6a0f0caed660879c700d2`.

## Deployment boundary and rollback

Only beta received the aggregate improvements. Production and persistent self-host were not promoted. Docker-engine recovery restarted existing persistent self-host containers during the work, but it did not replace their images, configuration, or container identities; the recorded OpenBao invariant remained container `7f79675530af42d3e95bd4ea53cd8c2a768364c3b717b15367779d7bde59e922`, image `sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878`, healthy.

Rollback is selection of a prior immutable beta artifact plus the supervised backup/forward-repair procedure. It never enables the deleted Python, JavaScript, or Dart implementation. Production or persistent self-host promotion requires a separate reviewed decision based on this evidence.

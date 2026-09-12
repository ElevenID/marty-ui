# Base opt-in executable acceptance

This is the runtime follow-up to [the base native profile](base-native-issuance-profile.md), not permission to remove the standalone Python consumer or deploy production. The profile's 74 selected routes and 57 legacy siblings are unchanged.

## Qualified checkpoint

The actual rendered base/native configuration launched the packaged native issuance executable against owned PostgreSQL and HTTPS wallets in both anoncrypt and authcrypt modes. It passed the existing complete fresh-renewal response, remote signature, decrypted credential, durable delivery, source-revocation and event assertions. The original fresh-main test also passed after extracting its unchanged named control-plane/signing peers.

The renderer receives explicit synthetic inputs, first checks the complete real base/native Compose model against the configuration contract, and then accepts only a closed fixture overlay: owned dependency addresses, isolated listener ports, and synthetic CA/policy paths. The native executable receives exactly that rendered environment through `env_clear`; no smoke configuration is injected afterward. Positive loopback wallet cases explicitly opt into the existing private-IP setting. They do not establish that the default permits private endpoints.

Recent exact gates:

| Gate | Evidence |
| --- | --- |
| Rendered native renewal, both modes | Final session 83722: pass, 10.64 seconds |
| Original fresh-main renewal, both modes | Final session 83722: pass, 5.41 seconds |
| Existing configured DIDComm regression | Final session 83722: 19 passed, 0 failed, 127.17 seconds |
| Shared process/Redis/container controls | Final session 83722: eight tests passed; strict target Clippy passed in 4.27 seconds |
| Cleanup | All 29 exact resources from the final sequence independently absent, including the controlled Redis readiness-timeout container; earlier successful seven-resource runs also verified absent |

The process controls exercise stdout closed before process exit, oversized output, timeout and successful capture. Shared regular-file capture avoids inherited-pipe reader hangs; Docker CLI calls and owned-child termination are separately bounded. Redis tests exercise actual namespace PING, loopback PING, and explicit constructor-failure cleanup. These are finite per-operation bounds, not a claim that cleanup is included in the outer container's polling deadline.

Two initial native-stage attempts failed before application startup because the cleared environment hid Docker CLI plugin discovery. Using the explicit installed standalone Compose 5.4.0 path fixed the test launch; no application environment forwarding was broadened. All printed failed-run resources were independently absent. One early forced-timeout Redis ID was not emitted: that run has verified exact UUID-label cleanup, not an independent exact-ID absence claim. Later runs log and independently verify that ID too.

## Final isolated composition — still being qualified

The Linux-only final gate runs the actual test, issuance and gateway ELF executables inside an owned read-only container sharing the already-verified PostgreSQL network namespace. It publishes no gateway/native ports and mounts neither the Docker socket nor a checkout directory. Only the closed source-file allowlist, exact executables and SHA256-pinned standalone Compose renderer are mounted read-only. Temporary policy, CA and render files remain in tmpfs. The outer owner verifies namespace, mounts, artifacts, completion and exact cleanup.

The inner gate uses the same native graph, not a replacement router or signing implementation. Its planned acceptance includes:

- Both-mode renewal with default private-IP refusal and explicit opt-in success, retaining the full fresh-renewal assertions.
- Fresh automatic DIDComm initiation, canonical decrypt/signature checks and durable direct-delivery replay without another wallet POST.
- Actual gateway authentication and required legacy resource-owner GETs backed by the owned database; selected legacy writes are traps. A native outage must fail closed, while an unselected legacy route remains reachable.
- Ordinary keyed fresh native admission, gateway Redis-cache retry/conflict, token exchange/replay, nonce and static discovery through the actual gateway. A cache hit is not a second native admission lookup; the existing dedicated real-PostgreSQL native admission recovery gate remains separate evidence. This helper does not bypass or evict the gateway cache.
- Six representative Canvas reads against the unchanged frozen seed/DTOs, with unchanged operational and protected application/evidence rows. These reads supplement, and do not replace, the existing full Canvas input, atomicity, lifecycle/publication and task-cancellation gates.

The final isolated gateway gate has **not yet passed**. Windows native-only evidence is not equivalent to it. CI requires both exact service artifacts, the same pinned renderer, connected parent/child registrations and successful outer completion; missing artifacts or incompatible host execution must not be accepted as qualification. The same pinned renderer path is exported for the separately integrated self-host bundle acceptance tests. The clean source checkpoint may be submitted for exact-head Linux CI, but is not a completed gateway acceptance or permission to merge or deploy before that gate passes.

Mounted source-built executable acceptance is not proof of authenticated released OCI-image provenance, Compose service-network deployment, self-host secret-loader behavior, or aggregate beta acceptance. Those remain their separately governed release/deployment boundaries. KMS-only DIDComm corrections remain out of scope; neither mode is removed.

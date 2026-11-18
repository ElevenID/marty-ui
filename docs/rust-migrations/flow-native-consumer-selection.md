# Flow native issuance consumer selection

The general-base native opt-in and standalone self-host model now select
`issuance-native:9005` for Flow initiation. Standalone base remains
`issuance:9005`; beta already selected native and is unchanged. Both owners use
port 9005: this is a DNS-owner change, not a port renumbering. Envoy and Kubernetes
remain separate qualification work.

`ISSUANCE_SERVICE_URL` stays `http://issuance:8005`, preserving the physical-document
HTTP provider. No sibling URLs, gRPC token identity, transport/TLS policy,
published ports, readiness dependency, or deployment credential is changed.

The self-host Flow model was missing two required production configuration
values. It now mounts the existing `issuance_api_key` secret and binds both
`ISSUANCE_API_KEY_FILE` and `SIGNING_KEYS_INTERNAL_API_KEY_FILE` to that same file,
matching the existing owner key identity. No secret is generated for deployment.

## Qualification and limits

The configured gate
`flow_rendered_settings_select_native_rpc_and_preserve_legacy_http` renders the
actual three Compose models, then invokes the canonical `load-secrets-env.sh`
with an isolated environment and exact synthetic files. It calls the actual
`FlowServiceConfig::from_env`, `FlowGrpcChannelFactories::from_config`, and
provider factory. The renderer is test support, not a new operational service.
POSIX loader assets receive the same CRLF-to-LF normalization used in packaging.

Only approved owned listener/file paths are substituted. Crucially, the renderer
maps the *observed* legacy/native target to distinct real listeners, rather than
silently replacing every target with native. The standalone-base control reaches
a counted legacy RPC peer; an explicit synthetic-token control proves that peer
is live and authenticated. Selected profiles preserve their own rendered tokens.

Windows execution passed: each selected profile creates a distinct fresh ordinary
offer, replays its stable key, rejects conflicting claims and wrong tokens,
preserves PostgreSQL snapshots on failures, and refuses fallback after native
shutdown. Development missing-token requests are rejected by the actual native
RPC; deployed missing-token/issuance/signing keys fail in the actual config
loader before any RPC. All seven Flow response fields and the decoded offer are
asserted. The separate legacy HTTP peer receives exactly the expected authenticated
physical-provider health calls. The prior full Flow preparation/artifact/retry
and seven-operation physical-document gate remains mandatory and separate.

This does **not** claim packaged/public Flow startup, public Flow authorization,
container DNS, workload TLS handshakes, Linux execution, release deployment, or
permission to delete Python. Policy TLS configuration/material loading is retained;
unrelated lazy provider channels are never called. Linux execution remains an
exact-head hosted requirement. Each subprocess capture is bounded to 120 seconds
with the shared output/termination limits; that is not an aggregate-suite deadline.

Whole-model comparisons retain the immutable pre-native self-host fixture and
permit only the exact reviewed native-owner/Flow deltas. Default, empty and custom
Compose inputs, all ten missing/empty required self-host inputs, and the twelve
base opt-in local/release/anoncrypt/authcrypt models are checked. DIDComm keyed
admission policy is unchanged; keys are never dropped to manufacture success.
`DIDCOMM-KMS-001` and KMS custody/API corrections remain out of scope.

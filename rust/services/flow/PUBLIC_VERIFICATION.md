# Public website verification sessions

This surface runs a server-selected, active OID4VP verification definition. Visitors can select approved scenarios and requirements without organization membership. Flow sessions and narrow gateway forwarding have local contract qualification. The visitor page, demo-holder credentials, retention qualification and real wallet/signing qualification are still required. No sample verification is simulated by these endpoints.

## Configuration and admission

The feature is disabled unless `FLOW_PUBLIC_VERIFICATION_CONFIG_FILE` points to an operator-owned JSON file. Missing configuration returns 404. Malformed or oversized configuration fails service startup. The maximum file size is 64 KiB.

The file has these fields:

| Field | Purpose |
| --- | --- |
| `principal_id` | Existing server-side principal authorized for `flow-instance:start` in the configured organization. |
| `issuer_did` | Configured verifier identity resolved through the existing signing provider. |
| `demo_holder_did` | Optional, separate synthetic-holder DID. Enables only the dedicated holder signing authority; it does not expose an example endpoint or provision a profile/key. |
| `limits.starts_per_minute` | Required tenant-wide limit, 1–240 starts in a rolling minute. |
| `limits.starts_per_day` | Required tenant-wide limit, 1–10,000 starts in a rolling day. |
| `limits.maximum_active` | Required tenant-wide limit, 1–1,000 unexpired active sessions. |
| `catalog.organization_id` | Fixed organization; visitor input cannot override it. |
| `catalog.application_origin` | One canonical HTTPS browser origin, without a trailing slash or path. Development/test may explicitly permit HTTP loopback. |
| `catalog.notice` | Consent notice for this catalog revision. |
| `catalog.scenarios` | At most eight scenarios, each with at most eight finite choices. |

Each scenario has `id`, `label`, and `choices`. Each choice has `id`, `label`, `definition` (`organization_id`, `definition_id`, `version`), `presentation_policy_id`, and `policy_configuration_digest`. The digest is the policy owner's full canonical `sha256:` configuration digest, including rules and referenced authorities. It is not a hash of the wallet query alone. Identifiers and labels are bounded, unknown fields and duplicate public choice IDs within a scenario are rejected, and every definition must belong to the catalog organization.

The public catalog includes only labels, public IDs, the notice and a content-derived revision. Any operator edit changes the revision and invalidates prior consent. The selected flow must be the built-in, automatic OID4VP verification graph. Authorization and active policy/template/trust/deployment/signing references are checked through their existing owners. Custom hooks, issuance and approval work cannot be skipped by the public adapter.

## Visitor contract

| Method and path | Behavior |
| --- | --- |
| `GET /v1/flows/public/verification/catalog` | Read the public catalog; creates no session. |
| `POST /v1/flows/public/verification/preview` | Read the exact bounded claim/rule preview for a catalog choice; creates no session. |
| `POST /v1/flows/public/verification/sessions` | Start or reconcile a launch using the same visitor capability. |
| `GET /v1/flows/public/verification/sessions/{session_id}` | Read only the capability's own session. |
| `POST /v1/flows/public/verification/sessions/{session_id}/example` | Execute or reconcile the session-bound synthetic specimen; accepts only `{}`. |
| `POST /v1/flows/public/verification/sessions/{session_id}/cancel` | Cancel only that session; preserve an already terminal decision. |

Before launching, the browser creates 32 cryptographically random bytes with Web Crypto and encodes them as 43 canonical base64url characters, without padding. Send this capability in `X-Verification-Session` for launch, read and cancel. Retain it across uncertain launch responses and reloads within the intended session lifetime. Keep it out of URLs, analytics, general logs and error reports. Do not use the wallet nonce or public instance ID as the capability. A fresh selection requires a fresh capability; retrying an existing key does not reopen a terminal session or change its request.

Launch accepts only this JSON shape, with values from the current catalog:

```json
{
  "catalog_revision": "sha256:<revision returned by catalog>",
  "scenario_id": "age",
  "choice_id": "over-18",
  "consent": true
}
```

The API rejects management IDs, arbitrary rules, callbacks and principals in visitor input. Launch and cancel require the exact configured browser `Origin`. Reads allow an omitted Origin for normal same-origin GETs; a supplied Origin must match. Origin is an application boundary, while the secret capability establishes session access. Gateway CORS must explicitly allow the application origin and capability header. These calls require no organization session cookie.

The session ID is derived from the capability, organization and origin before protocol construction. Only a separate domain-separated capability hash is stored. Concurrent launches use a unique insertion and return the winning stored session. Capacity checks and insertion share a tenant-wide PostgreSQL transaction lock. Rejected or uncertain launches must not cause the browser to mint a replacement key automatically. Gateway request limits remain necessary for traffic that never becomes an admitted session.

All responses are `Cache-Control: no-store`. Launch returns 201 for an insertion and 200 for a retry. Status is one of `awaiting_wallet`, `verifying`, `completed`, `failed`, `cancelled`, or `expired`. The response contains public selection IDs, catalog revision, session/deadline fields, an optional terminal `verified` boolean, and a wallet URI only while pending. It contains no holder claims, credential bodies, policy IDs, raw provider errors or histories. Terminal success requires the canonical stored passed/allow decision. Configuration drift prevents pending reads and retries from advertising the obsolete wallet request; terminal decisions are not re-evaluated against later policies.

Session expiry follows the governed definition. Result access ends ten minutes after the original verification deadline, including for sessions completed earlier. At the verification deadline, an active session projects as expired without extending its lifetime; canonical wallet retrieval and submission enforce their existing deadline and replay checks. Capability expiry is an access boundary, not a backend data-deletion policy. Retention/deletion qualification remains required before enablement.

| Response | Visitor action |
| --- | --- |
| 400 consent required / 422 invalid selection | Review the request and correct the selection. |
| 403 origin rejected | Correct the application origin configuration. |
| 404 unavailable | The feature is disabled, session is absent, capability is wrong, or access has expired. |
| 409 configuration or selection conflict | Fetch the current catalog, review it, then start with a fresh capability. |
| 429 capacity | Wait before attempting another launch. |
| 503 dependency unavailable or uncertain response | Retain the same capability and reconcile; do not create another operation. |

Cancellation uses the repository's terminal-state predicate. A completion that wins the race remains completed; a cancellation that wins prevents the competing nonterminal update. Cancellation does not require the current policy provider to be available.

## Qualification and enablement

Gateway exposes only the six declared public routes and preserves protected Flow management. It rejects duplicate Origin/capability headers before map conversion, enforces a 4 KiB public request limit, strips browser credentials/authority headers, and supplies only its configured workload credential. Public session operations bypass the gateway's general idempotency cache and ETag/conditional-response handling; Flow owns capability-bound reconciliation. Anonymous gateway request limits remain active, and no-store headers cover failures as well as successful responses.

The browser transport in `ui/src/services/publicVerificationApi.js` uses the same Rust/WASM API client package as the UI, with cookies omitted. It keeps capabilities in request headers, binds responses to the selected request/session, checks pending wallet URI structure and terminal verdict consistency, and projects only public fields. It does not implement local cryptographic verification or synthesize an example result. The approved experience is example-first with optional requirement controls and a secondary wallet path; the example endpoint and application `/verify` page implement that path. Governed runtime fixtures and release qualification remain required before enablement.

## Synthetic holder boundary

`DemoHolder` delegates ES256 signing to the existing opaque signing provider. Core's wallet engine verifies the signed SD-JWT against the selected issuer, holder key and credential type, constructs the proof from the admitted session nonce/audience, and verifies the returned KMS signature before completing it. Disclosure names come from the same immutable policy/template graph used to reconstruct and validate the admitted request fingerprint. This adapter creates protocol material only. It does not produce a verification verdict, persist a completion or bypass the ordinary Flow evaluator and atomic nonce finalizer.

The identity represents Marty's fictional example, not the website visitor. Its KMS key may persist across demonstrations; this is not a promise of a fresh private key per visit. Issuer and holder must have different DIDs, key references and public keys. Runtime code does not generate, import or retain software private keys. Local cryptographic tests use test-only P256 keys behind the opaque signing interface; they do not qualify a live KMS deployment.

The new key purpose is `demo_holder_binding`, restricted to ES256 and the `dc+sd-jwt` credential family (`SD_JWT_VC` in profile management). Its managed-key prefix is `demo-holder-`. Do not use protocol JWT types such as `kb+jwt` as credential families. Create its managed key/profile explicitly through the existing management owner; the default bootstrap purpose list is unchanged.

Signing grants use a separate `FlowDemoHolder` origin with MAC authority `marty-sign-grant-flow-demo-holder-v1`. Other origins cannot authorize this purpose, and this origin cannot authorize credential issuance, verifier requests or certificate signing. OpenBao deployments must provision a distinct MAC key, a Flow mint-only token referenced by `FLOW_DEMO_HOLDER_SIGN_GRANT_MINT_TOKEN_FILE`, and a SigningKeys verify-only role. AWS deployments must add a distinct immutable regional ARN at `keys.flow_demo_holder` in the existing signing-grant authority configuration, with corresponding least-privilege GenerateMac/VerifyMac permissions. Legacy seven-origin AWS configurations remain valid; the optional authority has no fallback to the verifier-request key. Neither backend provisions these authorities automatically.

Before enabling the example lane, add bounded operator-owned signed specimens bound to the dedicated holder/profile, qualify freshness/renewal and canonical completion, and expose only finite sample choices. Expired or malformed credentials may be rejected by Core before holder signing; display an input-rejection stage instead of inventing a verifier verdict. An authentic specimen that fails a business requirement must still pass through the canonical policy evaluator. Changes to the request or specimen require a new consent-bound session.

`verification_start_behavior` covers catalog-to-canonical preparation, authorization, pinned policy admission, capability scope and bounded projection. Its explicitly ignored `public_http_postgres_retry_quota_and_cancel_races` test requires `FLOW_PUBLIC_VERIFICATION_TEST_URL`, restricted to a fresh loopback database named `marty_public_verification_test`. It creates its own schema and refuses shared runtime database names. Local PostgreSQL tests use mock external providers and do not prove a wallet or signing/KMS integration.

Keep the runtime manifest absent until gateway forwarding, browser UX, signed demo specimens/holder presentation, supported wallets, deletion/retention behavior, release compatibility and required review/checks are qualified. An absent manifest is the feature rollback switch; existing sessions retain their records but public access is disabled. Presentation Policy must support the typed configuration precondition before configured Flow sessions can be admitted. Older or incompatible policy services fail closed. Website publication and runtime enablement require the applicable release authorization.


## Example catalog and browser entry

The private catalog accepts at most sixteen `examples`, each with a unique public `id`, existing `scenario_id`, bounded `label`/`description`, `profile` (`credential_template_id`, `issuer_did`, `vct`) and a signed, holder-bound SD-JWT `credential` of at most16KiB. The complete operator manifest remains capped at64KiB. These must be fictional specimens from dedicated demo identities/templates; never repurpose production member/login credentials. The public projection exposes only ID, scenario, label and description. Signed credentials and profile/issuer identifiers are not public catalog fields. Any specimen/profile/description change changes the consent-bound catalog revision. Examples require the explicit dedicated `demo_holder_did` setting.

An example launch adds `example_id` to the ordinary selection. Omit it for the secondary wallet lane. The specimen must belong to the selected scenario and cannot be replaced by reusing the capability. Request controls choose finite governed policy variants; they do not alter the signed specimen. Changing either requires a new session and fresh consent.

`POST .../{session_id}/example` requires the same capability and exact browser Origin, accepts an empty object only, and uses the stored selection. It prepares and persists the ordinary signed OID4VP request, constructs the holder proof using Core, preserves Core's emitted standard DCQL submission shape and calls the existing Flow submission evaluator/atomic nonce finalizer. No browser-provided presentation, trust setting or rule is accepted. Terminal retries return the stored canonical result. Example sessions do not expose a wallet URI and reject external wallet request, direct-post and DC-API calls, preventing another credential from replacing the specimen. Wallet-mode sessions keep those existing protocol routes.

A PostgreSQL compare-and-swap snapshot lease bounds concurrent example work without holding a database transaction during provider calls. The lease lasts90seconds and permits at most three attempts per admitted session. Crashed or uncertain attempts can be recovered after lease expiry without changing the original verification deadline. Cancellation/completion winners are reloaded, and stale lease holders cannot overwrite them. These controls supplement existing gateway/start quotas. Pending projections may include `example_status`: `running`, `retry_available`, `input_rejected` or `retry_exhausted`. Input rejection means Core could not prepare the specimen; it is not a fabricated verifier denial. KMS/signature-provider failure remains a service error. Terminal projections omit attempt status and expose only the canonical verdict.

The anonymous application route `/verify` defaults to the first configured signed example, offers finite optional scenario/requirement/specimen controls and makes wallet QR/mobile presentation secondary. Loading the page/catalog creates no session. Consent precedes launch; sessionStorage holds only capability, selection, session ID and recovery deadlines. Uncertain launch responses retain the same capability; refresh reads a known session, and explicit Resume reconciles or continues it. An edit clears the previous result, cancels a pending session when possible, and requires new consent. Capability expiry remains enforced server-side. All Start Verifying CTAs hand off to this application route through the existing surface boundary; `/verify` is not added to the static website's route set.

Local UI/transport tests and intercepted visual fixtures do not demonstrate live credentials, a supported wallet or a deployed service. The disposable PostgreSQL example test exercises real Core signatures, the actual in-process Presentation Policy verifier/evaluator and the HTTP/CAS/nonce finalizer. Signing, trust-registry and status transports remain fixtures; deployed workload-authenticated service and managed KMS qualification remain required. Complete that qualification, matching profile provisioning, meaningful negative fixtures, claim/retention explanations, backend deletion/retention and compatible release configuration before public enablement.


## Canonical request preview

The browser posts only catalog_revision, scenario_id and choice_id to the no-store preview route, with the exact configured Origin and no session capability. It resolves one immutable policy reference including the configuration digest returned on the same GetPolicy response. The digest must match the operator-pinned full policy digest. Older owners lacking that field fail closed for previews, while ordinary standalone references retain compatibility.

Preview returns those public selection IDs, a request_digest and at most16 bounded claim entries: name/display_name, required flag, purpose/description, explicit intent_to_retain when present, and at most four supported canonical constraints per claim. Rule values are bounded scalars or small scalar arrays. Unknown rules, predicates, duplicate claims, nested values and oversized metadata fail closed rather than being omitted or approximated. Private policy/template/issuer IDs and credential values are excluded. An absent retention field is shown as unspecified; it is not a promise of no backend retention or deletion. Retention qualification remains an enablement gate.

The website page waits for a valid preview before accepting consent or launching. It forwards request_digest with the selection. Launch compares it with the actual admitted canonical query fingerprint before persistence; retries bind that same fingerprint into the capability snapshot. A mismatch requires a fresh preview/consent. The full policy configuration binding independently covers business rules and descriptions. Legacy non-page consumers can omit the additive query fingerprint; the new page always supplies it. Editing the choice invalidates the preview immediately, clears consent/result and loads a new preview. This endpoint is read-only despite using POST and never starts a flow instance.

The local sample qualification now uses the actual RustCredentialKernel, VerifiedFactsOrchestrator, Cedar authorization and policy evaluator rather than a verdict test double. One fixed signed age20 specimen allows18 and denies21 through ordinary Flow finalization. Separate actual-policy tests reject untrusted/revoked credentials and leave tampered/wrong-audience inputs as nonterminal authentication rejections. The explicit PostgreSQL race test also exercises this real policy logic and the public preview. Signing, trust-registry and credential-status transports remain local fixtures; live KMS, managed profile lifecycle and real-wallet/type/format qualification are still required. No runtime profile/issuer key or live website is provisioned by these tests.

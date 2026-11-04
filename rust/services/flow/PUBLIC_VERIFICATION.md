# Public website verification sessions

This surface runs a server-selected, active OID4VP verification definition. Visitors can select approved scenarios and requirements without organization membership. Flow sessions and narrow gateway forwarding have local contract qualification. The visitor page, demo-holder credentials, retention qualification and real wallet/signing qualification are still required. No sample verification is simulated by these endpoints.

## Configuration and admission

The feature is disabled unless `FLOW_PUBLIC_VERIFICATION_CONFIG_FILE` points to an operator-owned JSON file. Missing configuration returns 404. Malformed or oversized configuration fails service startup. The maximum file size is 64 KiB.

The file has these fields:

| Field | Purpose |
| --- | --- |
| `principal_id` | Existing server-side principal authorized for `flow-instance:start` in the configured organization. |
| `issuer_did` | Configured verifier identity resolved through the existing signing provider. |
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
| `POST /v1/flows/public/verification/sessions` | Start or reconcile a launch using the same visitor capability. |
| `GET /v1/flows/public/verification/sessions/{session_id}` | Read only the capability's own session. |
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

Gateway exposes only the four declared public routes and preserves protected Flow management. It rejects duplicate Origin/capability headers before map conversion, enforces a 4 KiB public request limit, strips browser credentials/authority headers, and supplies only its configured workload credential. Public session operations bypass the gateway's general idempotency cache and ETag/conditional-response handling; Flow owns capability-bound reconciliation. Anonymous gateway request limits remain active, and no-store headers cover failures as well as successful responses.

The browser transport in `ui/src/services/publicVerificationApi.js` uses the same Rust/WASM API client package as the UI, with cookies omitted. It keeps capabilities in request headers, binds responses to the selected request/session, checks pending wallet URI structure and terminal verdict consistency, and projects only public fields. It does not implement local cryptographic verification or synthesize an example result. The approved experience is example-first with optional requirement controls and a secondary wallet path; the signed example/temporary-holder producer remains required before that default can be enabled.

`verification_start_behavior` covers catalog-to-canonical preparation, authorization, pinned policy admission, capability scope and bounded projection. Its explicitly ignored `public_http_postgres_retry_quota_and_cancel_races` test requires `FLOW_PUBLIC_VERIFICATION_TEST_URL`, restricted to a fresh loopback database named `marty_public_verification_test`. It creates its own schema and refuses shared runtime database names. Local PostgreSQL tests use mock external providers and do not prove a wallet or signing/KMS integration.

Keep the runtime manifest absent until gateway forwarding, browser UX, signed demo specimens/holder presentation, supported wallets, deletion/retention behavior, release compatibility and required review/checks are qualified. An absent manifest is the feature rollback switch; existing sessions retain their records but public access is disabled. Presentation Policy must support the typed configuration precondition before configured Flow sessions can be admitted. Older or incompatible policy services fail closed. Website publication and runtime enablement require the applicable release authorization.

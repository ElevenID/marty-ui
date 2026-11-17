# Canvas administration API operation migration matrix


> Historical migration inventory. The removal candidate retires these provider-specific Marty routes. This table is not a current supported API list and does not authorize reintroducing the adapter. Missing generic Gateway capabilities remain disabled connector TODOs. See [current boundary](canvas-gateway-api-boundary.md).
Source reviewed: `ui/src/services/canvasIntegrationsApi.js` at Marty-ui main. This file currently calls Marty UI's shared `api.js` helpers (`get/post/put/del`) and idempotency helper. It sends requests from the signed-in Marty console context today; it is not yet a standalone connector API-key client.

## Mandatory migration behavior

The extracted connector must NOT copy this browser-side client and insert a long-lived API key into it. The replacement must be:
- browser UI -> connector-owned backend/BFF using the connector's authenticated admin session;
- connector backend -> public Marty Common Gateway using server-side `X-API-Key` and explicit organization context;
- no browser bundle, local storage, query string, Canvas launch claim or browser network request may contain the Gateway API key.

If a customer configures their own API key, it is submitted over TLS to the connector backend once, validated through the Gateway, then stored only in connector-owned secret custody. Prefer per-organization/per-connector keys and allow rotation/revocation.

## Existing UI operations and target permissions

All paths below are under `/v1/integrations/canvas` unless otherwise stated.

| Existing client operation | Method and route | Expected API key scope | Target |
|---|---|---|---|
| listCanvasPlatforms | GET /platforms | integrations:read | Gateway |
| createCanvasPlatform | POST /platforms | integrations:write | Gateway; idempotent |
| updateCanvasPlatform | PUT /platforms/{platform_id} | integrations:write | Gateway |
| finalizeCanvasLtiInstallation | PUT /platforms/{platform_id}/lti-installation | integrations:write | Gateway |
| deleteCanvasPlatform | DELETE /platforms/{platform_id} | integrations:write | Gateway |
| getCanvasLtiRegistrationConfig | GET /platforms/{platform_id}/registration-config | integrations:read | Gateway |
| getCanvasPlatformReadiness | GET /platforms/{platform_id}/readiness | integrations:read | Gateway |
| startCanvasOAuthConnection | POST /platforms/{platform_id}/oauth/authorizations | integrations:write | Gateway; sensitive OAuth handoff |
| disconnectCanvasOAuthConnection | DELETE /platforms/{platform_id}/oauth | integrations:write | Gateway |
| listCanvasProgramBindings | GET /program-bindings | integrations:read | Gateway |
| createCanvasProgramBinding | POST /platforms/{platform_id}/program-bindings | integrations:write | Gateway; idempotent |
| updateCanvasProgramBinding | PUT /program-bindings/{binding_id} | integrations:write | Gateway |
| deleteCanvasProgramBinding | DELETE /program-bindings/{binding_id} | integrations:write | Gateway |
| validateCanvasProgramBinding | POST /program-bindings/{binding_id}/validate | integrations:write | Gateway |
| activateCanvasProgramBinding | POST /program-bindings/{binding_id}/activate | integrations:write | Gateway |
| deactivateCanvasProgramBinding | POST /program-bindings/{binding_id}/deactivate | integrations:write | Gateway |
| validateCanvasCredentialsProvider | POST /canvas-credentials/validate | integrations:read | Gateway; current route is a validation/read permission despite POST |
| listCanvasIntegrationSecrets | GET /integration-secrets | integrations:read | Gateway; metadata only, never return secret plaintext |
| createCanvasIntegrationSecret | POST /integration-secrets | integrations:write | Gateway; sensitive write, idempotent |
| updateCanvasIntegrationSecret | PUT /integration-secrets/{secret_id} | integrations:write | Gateway; sensitive write |
| deleteCanvasIntegrationSecret | DELETE /integration-secrets/{secret_id} | integrations:write | Gateway |
| discoverCanvasScope | POST /platforms/{platform_id}/scope-discovery | integrations:read | Gateway; provider read operation |
| enqueueCanvasEvidenceSync | POST /applications/{application_id}/canvas-sync | integrations:write | Gateway; idempotent enqueue |
| getCanvasSyncJob | GET /canvas-sync-jobs/{job_id} | integrations:read | Gateway |
| retryCanvasSyncJob | POST /canvas-sync-jobs/{job_id}/retry | integrations:write | Gateway |
| resolveCanvasSyncJob | POST /canvas-sync-jobs/{job_id}/resolve | integrations:write | Gateway |
| listCanvasSyncJobs | GET /canvas-sync-jobs | integrations:read | Gateway |
| listCanvasAwardCandidates | GET /canvas-award-candidates | integrations:read | Gateway; review candidates only |
| listCanvasEvidencePolicyReviews | GET /evidence-policy-reviews | integrations:read | Gateway |
| resolveCanvasEvidencePolicyReview | POST /evidence-policy-reviews/{review_id}/resolve | integrations:write | Gateway; must preserve reviewer authorization and audit |
| getCanvasMirrorProvenance | GET /v1/issuance/delivery-records/canvas-credentials/provenance | integrations:read | Gateway; canonical data remains core-owned |
| getCanvasMirrorHealth | GET /v1/issuance/organizations/{organization_id}/canvas-mirror-health | integrations:read | Gateway; verify tenant binding |
| processPendingCanvasMirrorDeliveries | POST /v1/issuance/delivery-records/canvas-credentials/process-pending | integrations:write | Gateway; verify whether this operator action should be exposed to connector |
| processCanvasMirrorStatusSyncFailures | POST /v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures | integrations:write | Gateway; verify whether this operator action should be exposed to connector |
| runCanvasMirrorAutomationCycle | POST /v1/issuance/delivery-records/canvas-credentials/run-automation-cycle | integrations:write | Gateway; verify whether this operator action should be exposed to connector |

## Permission and privilege review required

The table records the currently inferred API-key scope from the Gateway's integration permission family. It is not a recommendation to give every connector these operations.

In particular:
- `applications/{id}/approve` is a privileged core workflow operation. The normal connector must not receive approval authority by default. Approval remains governed by core application policy and human/operator authorization. The integration's routine key should not be able to approve.
- `integration-secrets` endpoints require special review. Canvas provider OAuth credentials belong to the connector's secret vault after extraction. Do not store Canvas tokens in Marty core integration secrets unless there is a documented cross-platform governance requirement. Do not return secret values through list/read endpoints.
- Canvas Credentials mirror processing endpoints are operator/worker operations. Prefer connector-owned worker scheduling plus narrowly scoped public Gateway operations for individual publish/status actions. Do not expose broad batch/automation controls to a generic integration key without explicit need.
- `scope-discovery` is a provider read but currently POST. It should be mapped to the least-privilege read scope and verified by an API-key integration test.
- Any public Gateway operation that uses `organization_id` in a query/body must still derive and validate tenant ownership from the authenticated API key; a caller-supplied organization identifier is never authority.
- The connector should not call `approve`, select issuer keys, mint signing grants, or request arbitrary credential issuance.

## Required follow-up tests

1. Connector BFF never serializes the Gateway key into browser-visible responses or bundles.
2. Every operation above is tested with valid key, missing key, wrong-org key, read-only key and revoked key.
3. Read-only key can list platforms/bindings/readiness/catalog/jobs/reviews but cannot mutate platform, binding, secret, job or review state.
4. Default connector key cannot approve applications or run unrestricted mirror automation.
5. Query/body organization IDs cannot override API-key organization.
6. OAuth callback secrets, client secrets and refresh tokens are encrypted at rest in connector-owned storage and never included in logs.
7. Gateway responses use stable DTOs; no core database row or private internal model is exposed.
8. All write/retry operations use idempotency keys or stable provider event identifiers.

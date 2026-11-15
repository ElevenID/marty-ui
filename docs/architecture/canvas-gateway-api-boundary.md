# Canvas connector: Common Gateway API boundary audit

Observed baseline: Marty-ui `main` at `8ff6cefaa2856ab8a00be7e449981198943960dd`.

## API-key model already present

The API Keys console exposes `integrations:read` and `integrations:write`. Gateway authorization resolves Canvas administrative read operations to `integration-connector:view` and administrative writes to `integration-connector:edit`. Existing authorization tests verify read scope cannot perform edit and that a key whose organization differs from the target organization is rejected.

The connector must use a server-side HTTP client that sends `X-API-Key` and explicit organization context. Never place the key in the Canvas browser frame, a React bundle, local storage, a URL, or Canvas launch claims.

## Existing Canvas routes requiring classification

The public route contract currently includes Canvas routes in three categories.

### A. Canvas-facing protocol endpoints currently hosted by Marty

These must move to the connector's public edge. Canvas calls the connector; the connector then calls Marty through the Common Gateway using its API key.

- `GET /v1/integrations/canvas/lti/jwks`
- `GET /v1/integrations/canvas/lti/config/{registration_token}`
- `POST /v1/integrations/canvas/lti/platforms/{platform_id}/login`
- `POST /v1/integrations/canvas/lti/platforms/{platform_id}/experience-login`
- `POST /v1/integrations/canvas/lti/platforms/{platform_id}/launch`
- `POST /v1/integrations/canvas/lti/platforms/{platform_id}/experience`
- `GET /v1/integrations/canvas/oauth/callback`
- `POST /v1/integrations/canvas/lti/experience-sessions/exchange`
- `GET /v1/integrations/canvas/lti/experience-sessions/current`
- current-session bootstrap, evidence-sync, evidence-status and deep-linking-response routes
- state-based experience-session routes

The gateway authorization classifier explicitly skips tenant authorization for the Canvas LTI/JWKS/config/login/launch/callback and one-time experience-session protocol paths. These are protocol callback exceptions, not permission for the connector to call core without a key. After connector cutover, the equivalent routes should be removed from Marty Gateway only after compatibility, DNS/redirect, LTI registration and rollback proof. Do not preserve these as a hidden second Canvas implementation.

### B. Organization administration and integration operations

These remain public Common Gateway operations and must be called by the connector with its scoped organization API key. Existing routes cover:
- Canvas platform and program-binding CRUD;
- LTI installation metadata and registration/readiness configuration;
- OAuth authorization and disconnect operations;
- catalog/scope discovery and sandbox probes;
- evidence sync enqueue and job inspection/retry/resolve;
- evidence-policy review and award-candidate operations;
- integration secret management and Canvas Credentials validation.

The existing gateway route inventory contains the current method/path contract. The existing authorization classifier has explicit Canvas rules for readiness/registration, scope discovery, probe/JWKS refresh/OAuth authorization, LTI installation, binding validate/activate/deactivate, application approval/sync, job retry/resolve, review resolution and Canvas Credentials validation. Generic integration routes use the integration-connector permission family.

Before extraction, enumerate every required route and its actual resolved permission using the Gateway's `resolve_action` behavior and `api_key_allowed` mapping. Do not infer a route's permission from its name. Some operations may have no appropriate customer API key mapping or may be too privileged for a connector and must be redesigned.

### C. Core-owned credential and mirror operations

Canvas Credentials provenance, publish/status/revoke and mirror-health operations touch canonical credential delivery state. The provider adapter can move, but the canonical delivery record, credential status, issuer identity and audit remain in core. Connector calls these operations only through public Gateway endpoints and its API key.

## Known gap: worker API contract

The existing Canvas worker is not a customer-style connector. It directly opens PostgreSQL repositories, accesses a PostgreSQL integration-secret vault, and calls internal signing/issuance endpoints using internal service credentials. It must be replaced, not relocated.

A route-by-route worker capability matrix is a blocking deliverable. Each worker operation must map to a documented public Gateway method/path, stable request/response DTO, minimum API-key scope, organization binding, idempotency key behavior and audit event. Any missing operation must be added to the Gateway first. Do not create a second Canvas-private API inside issuance.

## Acceptance requirements for the boundary

- With a valid organization API key and correct scope, the connector can perform its intended public operations.
- Missing, expired, revoked or malformed key is rejected.
- Wrong-organization key is rejected even when its scopes are otherwise sufficient.
- Read scope cannot perform a write or administrative operation.
- The connector cannot call a core service hostname or `/internal/*` path; network policy denies it.
- Canvas protocol callbacks terminate at the connector, validate Canvas protocol proofs, and use the Gateway API key for any subsequent core operation.
- No connector database connection can reach Marty core PostgreSQL/Redis.
- Core evidence, policy, approval, signing and status effects remain visible in canonical core audit records.
- Retried worker requests are idempotent and cannot duplicate evidence facts or credential delivery.

# Revocation Support Plan

## Goal
Implement scalable revocation support without per-tenant subdomains by using organization/profile path routing, while reusing existing status-list logic and matching established Marty service patterns.

## Problem Statement
The previous `status_list_base_url` default implied subdomain-based publication (`status.<env>.<domain>`). This does not scale for many organizations and does not align with service-oriented routing where gateway/API paths are preferred.

## Target URL Strategy
Use a canonical, tenant-safe route shape:

`/v1/organizations/{organization_id}/revocation-profiles/{profile_id}/status-lists/{mechanism}/{purpose}`

Where:
- `mechanism`: `bitstring-status-list` or `token-status-list`
- `purpose`: `revocation` or `suspension`

This route is now served by the revocation-profile service.

## Architecture Direction
1. Keep `revocation_profile` as orchestration boundary.
2. Keep status-list storage/update behavior in existing manager logic.
3. Scope list storage by org + profile to support multiple revocation services per org.
4. Return public verifier documents from service-layer routes.

## Incremental Implementation Plan

### Slice 1 (Implemented)
1. Add org/path public status-list endpoint in revocation-profile service.
2. Introduce canonical URL builder for org/profile/mechanism/purpose paths.
3. Scope status-list storage key to organization + profile.
4. Update internal allocation/revocation endpoints to return canonical path URLs.
5. Update seed migration defaults to path-template URLs (remove hardcoded status subdomain assumption).

### Slice 2 (Next)
1. Add explicit purpose-aware allocation support for suspension lists.
2. Persist canonical URL/publication metadata by profile/mechanism/purpose.
3. Add focused endpoint tests for route rendering and document retrieval.

### Slice 3
1. Introduce adapter to call lower status-list package directly (hex adapter boundary).
2. Replace remaining local-manager-only assumptions with lower-layer ports.
3. Add compatibility alias endpoint for legacy URLs during migration.

### Slice 4
1. Add operational controls: TTL, cache headers, ETag/version semantics.
2. Add migration mode flag (`legacy`, `dual`, `path-only`).
3. Add rollout telemetry for verifier fetch failures and stale URL usage.

## Data/Config Guidance
- Keep `issuer_config.status_list_base_url` as a compatibility field.
- Treat template-like values (with placeholders) as non-authoritative for runtime URL composition.
- Use `STATUS_LIST_PUBLIC_BASE_URL` (fallback to `STATUS_LIST_BASE_URL`) as root for canonical URL composition.

## Security and Auth
- Public status-list retrieval endpoint should remain unauthenticated (verifier consumption).
- Admin and mutation paths remain org/member protected through existing middleware and org client checks.

## Test Plan
1. Unit tests:
   - URL builder composition for org/profile/mechanism/purpose.
   - Mechanism parsing (`bitstring` vs `token`).
2. API tests:
   - `GET /v1/organizations/{org}/revocation-profiles/{profile}/status-lists/...` returns expected shape.
   - Internal allocate/process endpoints return canonical path URLs.
3. Integration tests:
   - Issue credential -> embedded status URL is path-based and resolvable.

## Progress Log
- 2026-04-17: Slice 1 started and implemented in service code and seed migrations.

# API Key Authentication for Marty Microservices

## Overview

This document describes the API key authentication system for Marty microservices. API keys provide an alternative to session-based authentication for programmatic access to production APIs.

## Architecture

The API key authentication system extends the existing organization-scoped authorization framework with support for API key-based authentication.

### Components

1. **marty_common.org_authorization** - Shared authentication library
   - `ApiKeyContext`: Context containing API key metadata (org, scopes, key ID)
   - `require_api_key()`: FastAPI dependency for API key-only authentication
   - `require_api_key_with_scope()`: Factory for scope-checking dependencies
   - `require_api_key_or_session()`: Dual authentication (API key OR session)
   - `OrganizationClient.validate_api_key()`: Validates keys via organization service

2. **Organization Service** - API key management and validation
   - `/v1/organizations/{org_id}/api-keys` - CRUD endpoints (admin only)
   - `/internal/v1/api-keys/validate` - Internal validation endpoint (no auth)
   - `ApiKey` domain entity with key hashing and scoping
   - `ApiKeyUseCase` with create, revoke, validate, list operations

3. **Gateway** - (Future) API key middleware for X-API-Key header support

## API Key Features

### Key Properties

- **Organization-scoped**: Each API key belongs to exactly one organization
- **Hashed storage**: Keys are hashed with SHA256, only prefix stored for identification
- **Scoped permissions**: Keys can have specific scopes (e.g., `read:credentials`, `write:issuance`)
- **Rate limiting**: Keys can have rate limit configuration (not enforced yet)
- **Expiration**: Keys support expiration dates
- **Status tracking**: ACTIVE or REVOKED status

### Scope Format

Scopes follow the pattern `<action>:<resource>`:

Examples:
- `read:credentials` - Read credential templates and issuance
- `write:credentials` - Create/update credentials
- `read:profiles` - Read trust/compliance/presentation profiles
- `write:profiles` - Modify profiles
- `admin:organization` - Full organization admin access

## Using API Keys

### 1. Creating API Keys (Admin Only)

Only organization admins and owners can create API keys:

```bash
POST /v1/organizations/{org_id}/api-keys
X-User-Id: {user_id}  # Set by gateway from session
Content-Type: application/json

{
  "name": "Production Integration",
  "scopes": ["read:credentials", "write:issuance"],
  "expires_at": "2025-12-31T23:59:59Z"  # Optional
}
```

Response (key only shown once):
```json
{
  "api_key": "mk_abc123...",  # Full key - save this!
  "key": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "organization_id": "org_123",
    "name": "Production Integration",
    "key_prefix": "mk_abc1",
    "scopes": ["read:credentials", "write:issuance"],
    "status": "active",
    "expires_at": "2025-12-31T23:59:59Z",
    "created_at": "2024-06-15T10:00:00Z"
  }
}
```

### 2. Authenticating with API Keys

API keys can be provided in two ways:

**Option 1: Authorization Header (Recommended)**
```bash
Authorization: Bearer mk_abc123...
```

**Option 2: X-API-Key Header**
```bash
X-API-Key: mk_abc123...
```

### 3. Using API Keys in Endpoints

Services can accept API keys in three ways:

#### A. API Key Only (Programmatic Access)

For endpoints that should only accept API keys:

```python
from marty_common import require_api_key, ApiKeyContext

@router.post("/api/v1/credentials")
async def create_credential(
    request: CreateCredentialRequest,
    api_ctx: ApiKeyContext = Depends(require_api_key),
):
    # api_ctx.organization_id - Organization the key belongs to
    # api_ctx.scopes - List of granted scopes
    # api_ctx.api_key_id - Unique key identifier
    # api_ctx.key_prefix - First 8 chars for logging
    
    # Access organization resources
    credential = await create_credential_for_org(
        api_ctx.organization_id,
        request
    )
    return credential
```

#### B. API Key with Scope Checking

For endpoints requiring specific permissions:

```python
from marty_common import require_api_key_with_scope, ApiKeyContext

@router.post("/api/v1/credentials")
async def create_credential(
    request: CreateCredentialRequest,
    api_ctx: ApiKeyContext = Depends(
        require_api_key_with_scope("write:credentials")
    ),
):
    # Automatically enforces scope check
    # Returns 403 if API key lacks required scope
    ...
```

#### C. API Key OR Session (Dual Authentication)

For endpoints that should accept both API keys and user sessions:

```python
from marty_common import require_api_key_or_session, OrganizationContext

@router.post("/v1/organizations/{organization_id}/credentials")
async def create_credential(
    organization_id: str,
    request: CreateCredentialRequest,
    org_ctx: OrganizationContext = Depends(require_api_key_or_session),
):
    # org_ctx.source - "api_key" or "session"
    # org_ctx.organization_id - Organization ID
    # org_ctx.user_id - User ID (or "api_key" for API key auth)
    # org_ctx.membership - Membership details (None for API keys)
    
    if org_ctx.source == "api_key":
        # Authenticated via API key
        logger.info(f"API key access to org {organization_id}")
    else:
        # Authenticated via session
        logger.info(f"User {org_ctx.user_id} access to org {organization_id}")
    
    # Both authentication methods provide organization_id
    credential = await create_credential_for_org(
        org_ctx.organization_id,
        request
    )
    return credential
```

### 4. Listing API Keys (Admin Only)

```bash
GET /v1/organizations/{org_id}/api-keys
X-User-Id: {user_id}
```

Response:
```json
{
  "api_keys": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "organization_id": "org_123",
      "name": "Production Integration",
      "key_prefix": "mk_abc1",
      "scopes": ["read:credentials", "write:issuance"],
      "status": "active",
      "last_used_at": "2024-06-15T15:30:00Z",
      "created_at": "2024-06-15T10:00:00Z"
    }
  ]
}
```

Note: Full API keys are never returned after creation.

### 5. Revoking API Keys (Admin Only)

```bash
DELETE /v1/organizations/{org_id}/api-keys/{key_id}
X-User-Id: {user_id}
```

Response:
```json
{
  "revoked": true
}
```

## Implementation Guide

### Adding API Key Support to a Service

1. **Import dependencies from marty_common:**

```python
from marty_common import (
    require_api_key,
    require_api_key_with_scope,
    require_api_key_or_session,
    ApiKeyContext,
    OrganizationContext,
)
```

2. **Choose authentication strategy:**

- Use `require_api_key` for API-only endpoints
- Use `require_api_key_or_session` for endpoints supporting both methods
- Keep `require_org_membership` for session-only endpoints (existing)

3. **Update endpoint signatures:**

```python
# Before (session only):
@router.post("/v1/organizations/{organization_id}/resources")
async def create_resource(
    organization_id: str,
    request: CreateResourceRequest,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    ...

# After (dual authentication):
@router.post("/v1/organizations/{organization_id}/resources")
async def create_resource(
    organization_id: str,
    request: CreateResourceRequest,
    org_ctx: OrganizationContext = Depends(require_api_key_or_session),
):
    ...
```

4. **Handle authentication source:**

```python
if org_ctx.source == "api_key":
    # API key authentication
    # org_ctx.user_id will be "api_key"
    # org_ctx.membership will be None
    logger.info(f"API access to {organization_id}")
else:
    # Session authentication
    # org_ctx.user_id contains actual user ID
    # org_ctx.membership contains role details
    logger.info(f"User {org_ctx.user_id} access to {organization_id}")

# Both provide org_ctx.organization_id
await perform_operation(org_ctx.organization_id, request)
```

### Internal API Validation Endpoint

The organization service provides an internal endpoint for API key validation:

```
POST /internal/v1/api-keys/validate
Content-Type: application/json

{
  "api_key": "mk_abc123..."
}
```

**Success Response (200):**
```json
{
  "api_key_id": "550e8400-e29b-41d4-a716-446655440000",
  "organization_id": "org_123",
  "key_prefix": "mk_abc1",
  "scopes": ["read:credentials", "write:issuance"]
}
```

**Invalid Response (401):**
```json
{
  "detail": "Invalid or expired API key"
}
```

This endpoint is used by:
- `OrganizationClient.validate_api_key()` in marty_common
- Gateway API key middleware (future)
- Other services for direct validation (if needed)

## Security Considerations

### Key Storage

- **Server-side**: Only SHA256 hash stored, plus 8-character prefix for identification
- **Client-side**: Full key must be stored securely by the client (shown only once)
- **Transmission**: Always use HTTPS in production

### Key Rotation

1. Create new API key with same scopes
2. Update client applications with new key
3. Revoke old key after migration complete

### Scope Design

- Follow principle of least privilege
- Grant only required scopes
- Use granular scopes (e.g., `read:templates` vs `admin:organization`)

### Rate Limiting

Rate limiting is configured per key but enforcement is not yet implemented:

```python
api_key.rate_limit = {
    "requests_per_minute": 100,
    "requests_per_hour": 5000,
}
```

Future enhancement: Implement rate limiting in gateway or service middleware.

### Monitoring

Log API key usage for audit:

```python
logger.info(
    f"API key {api_ctx.key_prefix} accessed {endpoint}",
    extra={
        "api_key_id": api_ctx.api_key_id,
        "organization_id": api_ctx.organization_id,
        "endpoint": endpoint,
        "scopes": api_ctx.scopes,
    }
)
```

## Migration Path

### Phase 1: Internal Services (Current)

- ✅ API key entity and repository in organization service
- ✅ CRUD endpoints for key management (admin only)
- ✅ Internal validation endpoint (`/internal/v1/api-keys/validate`)
- ✅ marty_common support (`require_api_key`, `require_api_key_or_session`)
- ✅ Syntax validation complete

### Phase 2: Service Integration (Next)

- [ ] Update credential_template service to use `require_api_key_or_session`
- [ ] Update trust_profile service endpoints
- [ ] Update flow service endpoints
- [ ] Update other services as needed
- [ ] Add API key logging and monitoring

### Phase 3: Gateway Integration (Future)

- [ ] Add API key middleware to gateway
- [ ] Check X-API-Key or Authorization headers before routing
- [ ] Inject `X-Organization-Id` header from validated key
- [ ] Cache validated keys in Redis (short TTL)

### Phase 4: Advanced Features (Future)

- [ ] Implement rate limiting enforcement
- [ ] Add last_used_at tracking and update
- [ ] Add API key usage analytics
- [ ] Support for key rotation notifications
- [ ] Webhook support for key events (created, revoked, expired)

## Testing

### Manual Testing

1. **Create an API key:**
```bash
curl -X POST http://localhost:8002/v1/organizations/org_123/api-keys \
  -H "X-User-Id: user_456" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "scopes": ["read:credentials", "write:credentials"]
  }'
```

2. **Use the API key:**
```bash
# Option 1: Authorization header
curl -X POST http://localhost:8003/api/v1/credentials \
  -H "Authorization: Bearer mk_abc123..." \
  -H "Content-Type: application/json" \
  -d '{...}'

# Option 2: X-API-Key header
curl -X POST http://localhost:8003/api/v1/credentials \
  -H "X-API-Key: mk_abc123..." \
  -H "Content-Type: application/json" \
  -d '{...}'
```

3. **Verify validation endpoint:**
```bash
curl -X POST http://localhost:8002/internal/v1/api-keys/validate \
  -H "Content-Type: application/json" \
  -d '{"api_key": "mk_abc123..."}'
```

### Automated Testing

```python
import pytest
from marty_common import OrganizationClient, require_api_key_or_session

@pytest.mark.asyncio
async def test_api_key_authentication():
    # Create test API key
    org_client = OrganizationClient(base_url="http://localhost:8002")
    
    # Validate API key
    api_ctx = await org_client.validate_api_key("mk_test...")
    assert api_ctx is not None
    assert api_ctx.organization_id == "org_123"
    assert "read:credentials" in api_ctx.scopes
    
    # Test invalid key
    invalid_ctx = await org_client.validate_api_key("mk_invalid")
    assert invalid_ctx is None
```

## Troubleshooting

### Common Issues

1. **"API key required" error**
   - Ensure Authorization or X-API-Key header is present
   - Check key format: should start with `mk_`

2. **"Invalid or expired API key" error**
   - Key may be revoked - check status in organization service
   - Key may be expired - check expires_at timestamp
   - Key hash mismatch - ensure full key is provided

3. **"API key missing required scopes" error**
   - Check endpoint required scopes vs key scopes
   - Create new key with additional scopes if needed

4. **"API key does not have access to this organization" error**
   - Key organization_id doesn't match requested organization
   - Verify the organization ID in the request path

### Debug Logging

Enable debug logging to see API key validation:

```python
import logging
logging.getLogger("marty_common.org_authorization").setLevel(logging.DEBUG)
```

Output:
```
DEBUG:marty_common.org_authorization:Validating API key via http://organization:8002/internal/v1/api-keys/validate
DEBUG:marty_common.org_authorization:API key validated: mk_abc1
```

## Related Documentation

- [ORG_AUTHORIZATION_IMPLEMENTATION.md](./ORG_AUTHORIZATION_IMPLEMENTATION.md) - Session-based organization authorization
- [ORG_AUTHORIZATION_PHASE2_MIGRATION.md](./ORG_AUTHORIZATION_PHASE2_MIGRATION.md) - Service migration guide
- Organization service API documentation: http://localhost:8002/docs

## Changelog

- **2024-06-15**: Initial implementation
  - Added ApiKeyContext and API key dependencies to marty_common
  - Added internal validation endpoint to organization service
  - Created comprehensive documentation
- **2026-02-14**: Consolidated implementations
  - Removed duplicate API key implementation from `src/api_keys/`
  - Removed unused import from `oid4vc_api.py`
  - All API key management now handled by organization service
  - UI already using correct endpoints: `/v1/organizations/{org_id}/api-keys`

## Notes

### Deployment Profile API Keys

Note: The `deployment_profile` service has its own `ApiKeyResponse` model (lines 376-379 in `main.py`). This is **NOT** a duplicate - it's for deployment-specific API keys used in runtime configuration, separate from the organization-wide authentication API keys described in this document.


# Console Context Switching - Implementation Summary

## Implementation Date
February 3, 2026

## Feature Overview
Implemented a comprehensive organization switching and view mode toggle system that allows users to seamlessly switch between applicant mode and organization administrator modes, discover new organizations, and join organizations via codes.

## Files Created

### Backend
1. **services/organization/infrastructure/migrations/versions/20260203_0001_add_join_fields_and_preferences.py**
   - Database migration for new tables and columns
   - Adds `console_context_preferences` table
   - Adds `join_codes` table
   - Adds join-related columns to `organizations` table

### Frontend
1. **ui/src/contexts/ViewModeContext.jsx**
   - React context for managing view mode state
   - Handles applicant vs org_admin mode switching
   - Manages active organization ID
   - Syncs preferences with backend
   - Implements optimistic UI updates with error rollback

2. **ui/src/services/preferencesApi.js**
   - API client for console preferences endpoints
   - GET /v1/me/preferences
   - PUT /v1/me/preferences

3. **ui/src/components/navigation/ContextPill.jsx**
   - Dropdown pill component in header bar
   - Shows current mode and organization
   - Provides mode switching UI
   - Lists user's organizations
   - Quick navigation to My Organizations / Discover pages

4. **ui/src/components/pages/MyOrganizationsPage.jsx**
   - Grid view of user's organizations
   - Displays membership details (role, status)
   - Membership badges (Owner, Admin, Member)
   - Status indicators (Active, Pending, Invited, Deactivated)
   - Switch to organization action buttons
   - Empty state with CTAs

5. **ui/src/components/pages/DiscoverOrganizationsPage.jsx**
   - Browse discoverable organizations
   - Search by name
   - Filter by organization type and join mechanism
   - Join method badges (Open, Join Code, Invite Only, Domain)
   - Join with code dialog
   - Auto-switch to organization after successful join

### Documentation
1. **docs/CONSOLE_CONTEXT_SWITCHING.md**
   - Comprehensive feature documentation
   - Architecture overview
   - User workflows
   - Deployment checklist
   - Testing guide
   - Troubleshooting section

2. **docs/CONSOLE_CONTEXT_SWITCHING_CHANGES.md** (this file)
   - Summary of all changes
   - File modification list

## Files Modified

### Backend

#### Gateway Service
1. **services/gateway/main.py**
   - Added SessionCache class for Keycloak session caching (60s TTL)
   - Implemented AuthMiddleware for session validation
   - Injects X-User-Id, X-User-Email, X-User-Domain headers
   - Added routes for:
     - POST /v1/organizations/join/code
     - GET /v1/organizations/discover
     - GET /v1/organizations/mine

#### Organization Service

1. **services/organization/domain/entities.py**
   - Added ConsoleContextPreference entity
   - Added JoinCode entity with:
     - generate_code() method (8-char alphanumeric)
     - is_valid() validation
     - increment_usage() tracking
   - Added JoinMechanism enum: open, code, invite, domain
   - Enhanced Organization entity with join fields:
     - join_mechanism
     - requires_approval
     - is_discoverable

2. **services/organization/infrastructure/models.py**
   - Added console_context_preferences_table
     - user_id (unique)
     - view_mode (applicant/org_admin)
     - active_org_id
     - updated_at
   - Added join_codes_table
     - organization_id
     - code (unique, 8 chars)
     - expires_at
     - max_uses
     - use_count
     - created_by
   - Enhanced organizations_table with:
     - join_mechanism column
     - requires_approval column
     - is_discoverable column

3. **services/organization/infrastructure/adapters/postgres_adapter.py**
   - Added PostgresJoinCodeRepository with:
     - create()
     - find_by_code()
     - update()
     - find_by_organization()
   - Enhanced PostgresOrganizationRepository with:
     - list_discoverable() method
     - Filters: search, org_type, join_mechanism
     - Returns only is_discoverable='true' and status='active'

4. **services/organization/application/use_cases.py**
   - Added JoinUseCase with join_by_code() method:
     - Validates join code
     - Checks existing membership
     - Creates membership (PENDING if requires_approval else ACTIVE)
     - Increments code usage
     - Publishes events
   - Enhanced OrganizationUseCase with:
     - discover_organizations() method
     - Takes search and filter parameters

5. **services/organization/infrastructure/adapters/http_adapter.py**
   - Added ConsoleContextPreferenceResponse schema
   - Added OrganizationWithMembership response schema
   - Added endpoints:
     - GET /me/preferences
     - PUT /me/preferences
     - POST /join/code (with JoinByCodeRequest schema)
     - GET /discover (with query parameters)
   - Enhanced GET /mine endpoint:
     - Returns OrganizationWithMembership objects
     - Includes role, status, is_admin_capable

6. **services/organization/main.py**
   - Wired PostgresJoinCodeRepository into lifespan
   - Wired JoinUseCase into application dependencies
   - Connected join code repository to use case

### Frontend

1. **ui/src/App.jsx**
   - Imported ViewModeProvider
   - Imported MyOrganizationsPage, DiscoverOrganizationsPage
   - Wrapped AppContent in ViewModeProvider (after AuthProvider)
   - Added routes:
     - /organizations/mine → MyOrganizationsPage
     - /organizations/discover → DiscoverOrganizationsPage

2. **ui/src/services/organizationsApi.jsx**
   - Added getMyOrganizations() function
     - GET /v1/organizations/mine
   - Added discoverOrganizations({search, orgType, joinMechanism}) function
     - GET /v1/organizations/discover with query params
   - Added joinByCode(code) function
     - POST /v1/organizations/join/code

3. **ui/src/components/navigation/ConsoleHeaderBar.jsx**
   - Replaced OrgSwitcher with ContextPill
   - Updated import statement
   - Positioned ContextPill in center Box

4. **ui/src/components/navigation/index.js**
   - Added export for ContextPill

5. **ui/src/components/pages/index.js**
   - Added export for MyOrganizationsPage
   - Added export for DiscoverOrganizationsPage

## Database Schema Changes

### New Tables

#### console_context_preferences
- Primary key: id (UUID)
- user_id (UUID, unique, indexed)
- view_mode (VARCHAR, default: 'applicant')
- active_org_id (UUID, nullable)
- updated_at (TIMESTAMP)

#### join_codes
- Primary key: id (UUID)
- organization_id (UUID, foreign key)
- code (VARCHAR(8), unique)
- expires_at (TIMESTAMP)
- max_uses (INTEGER, nullable)
- use_count (INTEGER, default: 0)
- created_by (UUID)
- created_at (TIMESTAMP)

### Modified Tables

#### organizations
Added columns:
- join_mechanism (VARCHAR, default: 'invite', check constraint)
- requires_approval (BOOLEAN, default: false)
- is_discoverable (BOOLEAN, default: false)

## API Endpoints Added

### Gateway (Proxied)
- `GET /v1/me/preferences` - Get user's console context preferences
- `PUT /v1/me/preferences` - Update console context preferences
- `GET /v1/organizations/mine` - List user's organizations with membership details
- `GET /v1/organizations/discover` - Search discoverable organizations
- `POST /v1/organizations/join/code` - Join organization with code

### Organization Service (Direct)
- `GET /me/preferences` - Fetch preferences for user from X-User-Id header
- `PUT /me/preferences` - Update preferences for user
- `POST /join/code` - Validate and process join code
- `GET /discover` - Query discoverable organizations with filters
- Enhanced `GET /mine` - Now returns OrganizationWithMembership objects

## Frontend Routes Added

- `/organizations/mine` - My Organizations page
- `/organizations/discover` - Discover Organizations page

## React Context Changes

### New Context: ViewModeContext
- **State**:
  - viewMode: 'applicant' | 'org_admin'
  - activeOrgId: string | null
  - loading: boolean
- **Methods**:
  - setViewMode(mode): Persist and update view mode
  - setActiveOrgId(orgId): Persist and update active organization
  - loadPreferences(): Load from backend on mount

## Component Hierarchy Changes

```
App
├── AuthProvider
│   └── ViewModeProvider ← NEW
│       └── AppContent
│           └── Routes
│               ├── /console (org_admin mode)
│               │   └── AuthenticatedLayout
│               │       └── ConsoleHeaderBar
│               │           └── ContextPill ← NEW (replaces OrgSwitcher)
│               ├── /applicant (applicant mode)
│               │   └── AuthenticatedLayout
│               │       └── ConsoleHeaderBar
│               │           └── ContextPill ← NEW
│               ├── /organizations/mine ← NEW
│               │   └── MyOrganizationsPage ← NEW
│               └── /organizations/discover ← NEW
│                   └── DiscoverOrganizationsPage ← NEW
```

## Key Implementation Patterns

### 1. Optimistic UI Updates
ViewModeContext implements optimistic updates:
- Update state immediately for responsive UI
- Sync with backend asynchronously
- Rollback to previous state on error
- Show error notification on failure

### 2. Gateway Middleware Pattern
SessionCache + AuthMiddleware:
- Cache Keycloak session validation results (60s TTL)
- Inject user context headers for downstream services
- Reduce load on Keycloak
- Enable stateless backend services

### 3. Hexagonal Architecture
Organization service follows ports & adapters:
- Domain entities in `domain/entities.py`
- Use cases in `application/use_cases.py`
- Repository ports defined in use cases
- Postgres adapters implement ports
- HTTP adapters expose REST endpoints

### 4. Repository Pattern
JoinCodeRepository and OrganizationRepository:
- Abstract database operations
- Allow for testing with mock implementations
- Separate domain logic from persistence

## Testing Considerations

### Backend Testing
- **Unit Tests**: Test entities, use cases in isolation
- **Integration Tests**: Test repositories against test database
- **API Tests**: Test HTTP endpoints with test client
- Key scenarios:
  - Join code validation and expiration
  - Membership approval workflows
  - Discovery filtering and search
  - Preferences persistence

### Frontend Testing
- **Component Tests**: Test ViewModeContext, ContextPill, page components
- **Integration Tests**: Test context + API interactions
- **E2E Tests**: Test full user workflows (discover → join → switch)
- Key scenarios:
  - Context switching persists after refresh
  - Organization discovery and filtering works
  - Join code submission creates membership
  - Optimistic updates rollback on error

## Migration Deployment

### Prerequisites
- Database backup completed
- Services stopped or in maintenance mode
- MMF framework dependencies installed
- DATABASE_URL configured correctly

### Execution
```bash
cd services/organization
python3 manage_migrations.py upgrade head
```

### Verification
```bash
# Check current revision
python3 manage_migrations.py current
# Should show: 20260203_0001

# Verify tables created
psql -c "\d console_context_preferences"
psql -c "\d join_codes"
psql -c "\d organizations"
```

### Rollback (if needed)
```bash
python3 manage_migrations.py downgrade -1
```

## Performance Considerations

### Backend
- SessionCache reduces Keycloak load (60s TTL)
- Database indexes on:
  - console_context_preferences.user_id (unique)
  - join_codes.code (unique)
  - organizations.is_discoverable (for discovery queries)
- Membership queries optimized with JOINs

### Frontend
- Optimistic UI updates feel instant
- Organization list loaded once and cached in context
- Lazy loading of organization details
- Minimal re-renders with React.memo on list items

## Security Measures

1. **Authentication**: All endpoints require valid Keycloak session
2. **Authorization**: Membership status checked before org access
3. **Join Code Validation**: Expiration, usage limits, org status checked
4. **Input Validation**: Join codes sanitized (uppercase, alphanumeric only)
5. **CORS**: Configured for allowed origins only
6. **SQL Injection**: Protected by SQLAlchemy parameterized queries
7. **XSS**: React escapes all user input by default

## Known Limitations

1. **No Bulk Operations**: Cannot switch multiple orgs simultaneously
2. **No Offline Support**: Requires active connection for preference sync
3. **Cache Invalidation**: Organization list not auto-refreshed (requires page reload)
4. **Join Code Length**: Fixed at 8 characters (not configurable)
5. **Discovery Limit**: Returns max 100 orgs (pagination not implemented)

## Next Steps / Future Work

See "Future Enhancements" in CONSOLE_CONTEXT_SWITCHING.md for Phase 2 features:
- Domain-based auto-join
- Email invitation system
- Organization directory
- Role escalation requests
- Multi-org operations
- Real-time notifications
- Mobile optimization

## Contributors

Implementation completed by: GitHub Copilot (Claude Sonnet 4.5)

## Change Log

| Date | Version | Changes |
|------|---------|---------|
| 2026-02-03 | 1.0.0 | Initial implementation - all 17 tasks complete |

---

**Status**: ✅ Implementation Complete  
**Code Review Status**: Pending  
**QA Status**: Ready for Testing  
**Deployment Status**: Ready for Staging

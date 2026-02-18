# Console Context Switching Feature

## Overview

The Console Context Switching feature enables users to seamlessly switch between applicant mode and organization administrator modes within the Marty UI console. Users can also discover, join, and switch between multiple organizations they have access to.

## Features

### 1. View Mode Toggle
- **Applicant Mode**: Personal credential and application management
- **Organization Admin Mode**: Organization management console with full administrative capabilities

### 2. Organization Management
- **My Organizations**: View and manage all organizations where you have membership
- **Discover Organizations**: Browse and join publicly discoverable organizations
- **Join by Code**: Join organizations using an 8-character join code

### 3. Persistent Context
- User's selected view mode and active organization are persisted across sessions
- Context automatically loads on login
- Optimistic UI updates with error rollback

## Architecture

### Backend Components

#### Gateway Service (`services/gateway/`)
- **SessionCache**: In-memory cache for Keycloak session validation (60s TTL)
- **AuthMiddleware**: Validates sessions and injects user context headers
  - `X-User-Id`: User's unique identifier
  - `X-User-Email`: User's email address
  - `X-User-Domain`: Email domain for domain-based joins

#### Organization Service (`services/organization/`)

**Domain Entities** ([domain/entities.py](../services/organization/domain/entities.py)):
- `ConsoleContextPreference`: User's view mode and active organization
- `JoinCode`: Shareable codes for organization access
- `JoinMechanism` enum: `open`, `code`, `invite`, `domain`

**API Endpoints** ([infrastructure/adapters/http_adapter.py](../services/organization/infrastructure/adapters/http_adapter.py)):
- `GET /v1/me/preferences`: Fetch user's console preferences
- `PUT /v1/me/preferences`: Update console preferences
- `GET /v1/organizations/mine`: List user's organizations with membership details
- `GET /v1/organizations/discover`: Search discoverable organizations
- `POST /v1/organizations/join/code`: Join organization with code

**Database Schema**:
- `console_context_preferences`: Stores user preferences (view_mode, active_org_id)
- `join_codes`: Manages organization join codes with expiration and usage limits
- `organizations`: Enhanced with join_mechanism, requires_approval, is_discoverable

### Frontend Components

#### Context Management ([ui/src/contexts/](../ui/src/contexts/))
- **ViewModeContext**: Global state for view mode and active organization
  - Loads preferences on mount
  - Optimistic UI updates
  - Backend synchronization via preferences API
  - Error rollback on failures

#### Navigation Components ([ui/src/components/navigation/](../ui/src/components/navigation/))
- **ContextPill**: Dropdown component in header bar
  - Displays current mode icon and organization name
  - Mode switcher (Applicant vs Org Admin)
  - Organization selector with checkmarks for active org
  - Quick actions: "My Organizations", "Discover Organizations"

#### Pages ([ui/src/components/pages/](../ui/src/components/pages/))

**MyOrganizationsPage**:
- Grid layout of organization cards
- Membership badges: Owner, Admin, Member
- Status indicators: Active, Pending, Invited, Deactivated
- "Switch to Organization" action buttons
- Empty state with CTAs to discover or join organizations

**DiscoverOrganizationsPage**:
- Search by organization name
- Filter by organization type and join mechanism
- Organization cards with join method badges
- "Join with Code" dialog for code-based entry
- Success handling: auto-switch to joined organization

#### API Services ([ui/src/services/](../ui/src/services/))
- **preferencesApi.js**: GET/PUT for console preferences
- **organizationsApi.jsx**: Mine, discover, and join operations

## User Workflows

### Switching Context Mode
1. User clicks ContextPill in header
2. Selects "Applicant" or an organization from the menu
3. ViewModeContext updates state optimistically
4. Backend syncs preferences via PUT /v1/me/preferences
5. On success: Navigate to appropriate console
6. On error: Rollback state and show error notification

### Discovering Organizations
1. Navigate to "Discover Organizations" from ContextPill menu
2. Use search/filters to find organizations
3. Click organization card to view details
4. Click "Request to Join" or "Join with Code" based on join_mechanism
5. For code joins: Enter 8-character code in dialog
6. On success: Automatically switch to new organization

### Managing Memberships
1. Navigate to "My Organizations" from ContextPill menu
2. View all organizations with membership details
3. See role (Owner, Admin, Member) and status badges
4. Click "Switch to Organization" to activate that org context
5. Access org admin console with appropriate permissions

## Database Migration

### Running the Migration

The migration adds three critical components:
1. `console_context_preferences` table for persistent user context
2. `join_codes` table for code-based organization access
3. Organization join fields (join_mechanism, requires_approval, is_discoverable)

**Prerequisites**:
- PostgreSQL database running
- DATABASE_URL environment variable configured
- MMF framework dependencies installed

**Commands**:
```bash
# Navigate to organization service
cd services/organization

# Check current migration status
python3 manage_migrations.py current

# Apply the migration
python3 manage_migrations.py upgrade head

# Verify migration succeeded
python3 manage_migrations.py current
```

**Expected Output**:
```
✓ Upgraded to: head
Current revision: 20260203_0001
```

### Migration File
Location: [services/organization/infrastructure/migrations/versions/20260203_0001_add_join_fields_and_preferences.py](../services/organization/infrastructure/migrations/versions/20260203_0001_add_join_fields_and_preferences.py)

## Testing

### Backend API Testing

#### 1. Preferences Endpoints
```bash
# Get preferences (should return null or default for new users)
curl -X GET http://localhost:8000/v1/me/preferences \
  -H "Cookie: session=<keycloak-session>"

# Update preferences
curl -X PUT http://localhost:8000/v1/me/preferences \
  -H "Cookie: session=<keycloak-session>" \
  -H "Content-Type: application/json" \
  -d '{"view_mode": "org_admin", "active_org_id": "<org-uuid>"}'
```

#### 2. Organization Endpoints
```bash
# List my organizations
curl -X GET http://localhost:8000/v1/organizations/mine \
  -H "Cookie: session=<keycloak-session>"

# Discover organizations
curl -X GET 'http://localhost:8000/v1/organizations/discover?search=test' \
  -H "Cookie: session=<keycloak-session>"

# Join by code
curl -X POST http://localhost:8000/v1/organizations/join/code \
  -H "Cookie: session=<keycloak-session>" \
  -H "Content-Type: application/json" \
  -d '{"code": "ABC12345"}'
```

### Frontend Component Testing

#### 1. ViewModeContext
- Verify preferences load on mount
- Test state updates trigger re-renders
- Confirm backend sync on setViewMode()
- Validate error rollback behavior

#### 2. ContextPill
- Check icon changes between modes (PersonIcon vs BusinessIcon)
- Verify dropdown menu renders correctly
- Test organization selection updates context
- Confirm navigation to My Organizations / Discover pages

#### 3. Organization Pages
- **MyOrganizationsPage**: Load orgs, display badges, switch actions
- **DiscoverOrganizationsPage**: Search, filters, join code dialog

### Integration Testing

#### E2E Scenario: Join and Switch to Organization
1. Login as test user
2. Click ContextPill → "Discover Organizations"
3. Search for organization by name
4. Click "Join with Code" button
5. Enter valid join code: `ABC12345`
6. Verify success: Redirected to /console in org_admin mode
7. Check ContextPill shows organization name
8. Verify preferences persisted (refresh page, context remains)

## Deployment Checklist

### Pre-Deployment
- [ ] Review migration file for correctness
- [ ] Backup production database
- [ ] Test migration on staging environment
- [ ] Verify all backend services deployed with latest code
- [ ] Confirm DATABASE_URL points to correct database

### Deployment Steps
1. **Backend Services**
   ```bash
   # Deploy gateway with SessionCache + AuthMiddleware
   docker-compose -f docker-compose.services.yml up -d gateway
   
   # Deploy organization service with new endpoints
   docker-compose -f docker-compose.services.yml up -d organization
   ```

2. **Database Migration**
   ```bash
   # Run migration via Docker or local environment
   cd services/organization
   python3 manage_migrations.py upgrade head
   ```

3. **Frontend**
   ```bash
   # Build and deploy UI with context switching components
   cd ui
   npm run build
   # Deploy dist/ to web server
   ```

### Post-Deployment Verification
- [ ] Check migration applied: `python3 manage_migrations.py current`
- [ ] Verify preferences API: GET /v1/me/preferences returns 200
- [ ] Test mine endpoint includes membership details
- [ ] Confirm discover endpoint returns discoverable orgs
- [ ] Validate join-by-code creates memberships
- [ ] Frontend: ContextPill visible and functional
- [ ] Test context persistence across login sessions

### Rollback Plan
If issues arise:
1. Downgrade migration:
   ```bash
   cd services/organization
   python3 manage_migrations.py downgrade -1
   ```
2. Revert backend services to previous version
3. Redeploy frontend with previous build
4. Clear Redis cache if gateway middleware causes issues

## Configuration

### Environment Variables

#### Gateway Service
```
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/marty
KEYCLOAK_URL=http://localhost:8080
SESSION_CACHE_TTL=60  # seconds
```

#### Organization Service
```
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/marty
REDIS_URL=redis://localhost:6379
```

#### Frontend
```
VITE_API_BASE_URL=http://localhost:8000
```

### Feature Flags (Optional)
```javascript
// ui/.env or ui/.env.production
VITE_ENABLE_ORG_DISCOVERY=true
VITE_ENABLE_JOIN_BY_CODE=true
```

## Security Considerations

### Session Validation
- Gateway middleware validates Keycloak sessions before proxying
- SessionCache reduces Keycloak load with 60s TTL
- Invalid sessions return 401 Unauthorized

### Authorization
- Membership status checked before allowing org access
- Pending members cannot access admin features
- Owner-only operations require role verification

### Join Code Security
- Codes expire after configured duration
- Usage limits prevent abuse
- Codes are case-insensitive and alpha-numeric
- Requires approval flow for sensitive organizations

## Troubleshooting

### Issue: Preferences Not Persisting
**Symptoms**: Context resets on page refresh

**Solutions**:
1. Check browser cookies - session must be present
2. Verify preferences API returns 200 on GET
3. Confirm PUT request succeeds (check network tab)
4. Validate database has console_context_preferences table

### Issue: Organizations Not Loading
**Symptoms**: Empty organization list or errors

**Solutions**:
1. Verify membership records exist in database
2. Check gateway AuthMiddleware injects X-User-Id header
3. Confirm organization service logs for errors
4. Test mine endpoint directly with curl

### Issue: Join Code Invalid
**Symptoms**: "Invalid join code" error on valid code

**Solutions**:
1. Check code expiration date in database
2. Verify max_uses not exceeded
3. Confirm organization status is 'active'
4. Look for case sensitivity issues (codes are uppercase)

### Issue: ContextPill Not Showing
**Symptoms**: Header bar missing context pill

**Solutions**:
1. Verify ViewModeProvider wraps AppContent in App.jsx
2. Check ContextPill export in navigation/index.js
3. Confirm ConsoleHeaderBar imports ContextPill (not OrgSwitcher)
4. Look for JavaScript errors in browser console

## Future Enhancements

### Phase 2 Considerations
- **Domain-based Auto-Join**: Automatically join organizations matching email domain
- **Invitation System**: Email invitations with acceptance workflow
- **Organization Directory**: Public directory of all discoverable organizations
- **Role Escalation**: Request admin privileges from organization owners
- **Multi-Org Actions**: Perform actions across multiple organizations simultaneously
- **Audit Trail**: Track organization switches and context changes
- **Mobile Optimization**: Responsive design for mobile devices
- **Notifications**: Real-time alerts for membership approvals

### Performance Optimizations
- Cache organization list in Redux/Zustand for faster loading
- Implement pagination for large organization lists
- Add debouncing to discover page search
- Optimize membership queries with database indexes

## Support

### Documentation Links
- [Backend Implementation Summary](../BACKEND_IMPLEMENTATION_SUMMARY.md)
- [Microservices Architecture](../MICROSERVICES.md)
- [Development Setup](../DEVELOPMENT_SETUP.md)

### Contact
For questions or issues:
- File GitHub issue with `[context-switching]` prefix
- Contact: [your-team-email@example.com]
- Slack: #marty-ui channel

---

**Last Updated**: February 3, 2026  
**Version**: 1.0.0  
**Status**: ✅ Implementation Complete

# Dashboard Intelligence Implementation

## Summary

Implemented a **state-aware, intelligent dashboard** that replaces hardcoded placeholders with real API data and blocker detection logic.

## What Was Implemented

### Phase 1: Setup Readiness & Blocking Logic ✅

#### 1. Dashboard Data Hook (`useDashboardData.js`)
- Fetches all setup resources in parallel (Trust Profiles, Templates, Policies, Deployments, Flows, API Keys)
- Polls system health every 60 seconds
- Handles loading, error states, and organization scoping
- Uses `Promise.allSettled` to handle partial failures gracefully

#### 2. Dashboard Rules Engine (`dashboardRules.js`)
- **Setup Order**: Encodes canonical dependency chain (Trust → Template → Policy → Deployment → Flow)
- **Readiness States**: `READY` ✔, `BLOCKED` ⚠, `MISSING` ○
- **Blocker Detection**: Identifies specific issues preventing progress:
  - Missing signing artifacts
  - Inactive status
  - Missing references
  - No API keys
- **Quick Action Visibility**: Context-aware rules that show/hide/disable actions based on prerequisite completion

#### 3. SetupReadinessPanel Component
- Visual checklist showing canonical setup progression
- State indicators: ✔ (ready), ⚠ (blocked), ○ (missing)
- Actionable buttons: "Create", "Fix", "Activate"
- Dependency blocking: Grays out steps that require previous completion
- Vertical connector lines showing progression flow

#### 4. BlockingIssuesPanel Component
- Only appears when blockers exist
- Lists actionable issues with specific fix CTAs
- Each blocker links directly to resolution page
- Warning-styled alert to grab attention

### Phase 2: System Status Bar ✅

#### 5. Health API Service (`healthApi.js`)
- Fetches `/health` endpoint
- Maps backend health statuses to UI states
- Handles API Gateway, Issuer Metadata, Verifier Service
- Graceful degradation on failure

#### 6. SystemStatusBar Component
- Real-time health indicators for all services
- Color-coded status: green (healthy), yellow (warning), red (error)
- Prominent error/warning banners when issues detected
- Clickable services navigate to filtered audit logs

### Phase 3: Context-Aware Quick Actions ✅

#### 7. Enhanced QuickActionCard
- Shows/hides actions based on prerequisite completion
- Disables actions with tooltip explaining requirements
- Examples:
  - "Create Template" hidden until Trust Profile exists
  - "Start Verification" disabled until Policy + Deployment ready
  - Tooltips: "Requires an active Trust Profile"

### Phase 4: Organization Switcher ✅

#### 8. OrgSwitcher Component
- Dropdown for multi-org users (especially Admins)
- Shows current org name for single-org Vendors
- Persists selection to localStorage
- Compact mode when sidebar collapsed
- "Admin view" label for Administrators

#### 9. Sidebar Integration
- OrgSwitcher positioned below header, above navigation
- Respects collapsed state
- Divider for visual separation

## Architecture Decisions

### No New Backend APIs Required
All data comes from existing endpoints:
- `GET /v1/trust-profiles`
- `GET /v1/credential-templates`
- `GET /v1/presentation-policies`
- `GET /v1/identity/deployment-profiles`
- `GET /v1/identity/flows`
- `GET /v1/organizations/{id}/api-keys`
- `GET /health`

### Client-Side Composition
- Dashboard rules engine runs entirely in browser
- Reduces backend complexity
- Instant updates when data changes
- Easy to extend with new rules

### Polling vs Real-Time
- System health: 60-second polling (simple, reliable)
- Resource data: Fetch on mount (can add refresh button later)
- SSE infrastructure exists but not needed yet

## File Structure

```
ui/src/
├── hooks/
│   └── useDashboardData.js          # Data fetching hook
├── services/
│   └── healthApi.js                 # Health check service
├── config/
│   └── dashboardRules.js            # Readiness logic & blocker detection
├── components/
│   ├── console/
│   │   ├── ConsoleDashboard.jsx     # Updated main dashboard
│   │   └── dashboard/
│   │       ├── index.js
│   │       ├── SystemStatusBar.jsx
│   │       ├── SetupReadinessPanel.jsx
│   │       └── BlockingIssuesPanel.jsx
│   └── navigation/
│       ├── OrgSwitcher.jsx          # Organization switcher
│       └── SidebarNavigation.jsx    # Updated with OrgSwitcher
```

## Dashboard Layout Order

Following the specification:

1. **System Status Bar** — Health indicators at top
2. **Blocking Issues** — Warning alerts (only if blockers exist)
3. **Setup Readiness** — Canonical progression checklist
4. **Quick Actions** — Context-filtered action grid
5. **Developer Resources** — API docs link

## Readiness Logic Examples

### Trust Profile
- ✔ Ready: ≥1 exists with `status: 'active'`
- ⚠ Blocked: Exists but `status ≠ 'active'`
- ○ Missing: None exist

### Credential Template
- ✔ Ready: ≥1 active with valid artifacts + trust_profile_id
- ⚠ Blocked: Exists but `artifacts_status: 'missing'` or `'invalid'`
- ○ Missing: None exist (requires Trust Profile first)

### Deployment Profile
- ✔ Ready: ≥1 active + ≥1 API key exists
- ⚠ Blocked: Active deployment but no API keys
- ○ Missing: None exist (requires Policy first)

## Next Steps (Not Yet Implemented)

### Phase 5: Runtime Activity (Optional)
- **Audit API Service**: `listAuditEvents()` integration
- **RecentActivityPanel**: Last 5 events with links
- **VerificationHealthPanel**: Success rate, failure stats

### Phase 6: Polish (Optional)
- ESLint warning cleanup
- Unit tests for `dashboardRules.js`
- Loading skeleton states
- Refresh button for dashboard data

## Testing the Implementation

### Manual Verification Steps

1. **Empty State**: 
   - New org with no resources
   - All readiness should show ○ Missing
   - Only "Create Trust Profile" visible in Quick Actions

2. **Progression**:
   - Create Trust Profile → ✔ Trust, Template action unlocks
   - Create Template without artifacts → ⚠ Blocked + blocker alert
   - Fix artifacts → ✔ Template
   - Complete all 5 steps → All ✔, all Quick Actions enabled

3. **Health Check**:
   - All services healthy → Green indicators
   - Stop backend service → Red indicator + error banner
   - Click service → Navigate to audit logs

4. **Org Switching** (Admin):
   - See org dropdown in sidebar
   - Switch org → Dashboard reloads with new org's data
   - Persists on page refresh

## Dependencies

No new npm packages required. Uses existing:
- Material-UI components
- React Router
- Existing API service layer

## Performance Considerations

- **Parallel fetching**: All resources fetched simultaneously
- **Memoization**: `useMemo` prevents unnecessary rule recalculations
- **Lazy rendering**: Blockers panel only mounts when blockers exist
- **Health polling**: 60s interval, canceled on unmount

## Accessibility

- Semantic HTML with ARIA-compliant MUI components
- Color + icon redundancy (not color-only indicators)
- Keyboard navigation supported
- Tooltips for disabled actions explain requirements

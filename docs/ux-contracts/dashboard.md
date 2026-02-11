# Dashboard UX Contract

## Overview
The Console Dashboard provides organization readiness status and guides users through initial setup phases.

## States

### 1. Empty State (No Configuration)
**Trigger**: Organization has no Trust Profiles, Templates, Policies, or Deployments  
**Visual**:
- Warning icon with "Setup Required" message
- Card grid showing 4 blocked components
- Each card displays: icon, title, status badge ("Missing"), description
- "Get Started" CTA button prominently displayed

**Message**: 
```
"Your organization needs initial configuration before you can issue or verify credentials."
```

**Card Structure**:
- Trust Profile: "Create a trust profile to define which issuers you trust"
- Credential Templates: "Define credential schemas for issuance"
- Presentation Policies: "Configure verification requirements"
- Deployment Profiles: "Set up runtime environments"

---

### 2. Partial Configuration (Some Missing)
**Trigger**: 1-3 of 4 required components are configured  
**Visual**:
- Info icon with "Configuration In Progress"
- Mixed card states: configured (success icon) vs missing (warning icon)
- Progress indicator showing X/4 complete
- "Continue Setup" button

**Behavior**:
- Configured cards show success checkmark and "Active" badge
- Missing cards show warning triangle and "Required" badge
- Clicking any card navigates to creation wizard or list view

---

### 3. Fully Ready
**Trigger**: At least one of each: Trust Profile, Template, Policy, Deployment exists  
**Visual**:
- Success icon with "Ready to Operate"
- All cards show success state
- "Go to Operate" button as primary CTA
- Quick stats displayed (# of each resource type)

**Message**:
```
"Your organization is configured. You can now issue credentials and verify presentations."
```

---

### 4. Loading State
**Trigger**: Initial data fetch in progress  
**Visual**:
- Circular progress spinner centered
- No cards visible
- "Loading dashboard..." text

**Duration**: Typically <500ms with API mocking

---

### 5. Error State
**Trigger**: API error fetching dashboard status  
**Visual**:
- Error Alert component at top
- Red error icon
- Error message from API
- "Retry" button

**Message Example**:
```
"Failed to load dashboard status: [error.message]"
```

---

## Component Hierarchy
```
Dashboard (Container)
├── Alert (Conditional: error state)
├── LoadingSpinner (Conditional: loading state)
└── ReadinessCards (Main content)
    ├── StatusHeader (icon + message)
    ├── Grid Container
    │   ├── TrustProfileCard
    │   ├── CredentialTemplateCard
    │   ├── PresentationPolicyCard
    │   └── DeploymentProfileCard
    └── ActionButton ("Get Started" or "Go to Operate")
```

---

## Accessibility

### ARIA Labels
- Cards: `role="article"` with `aria-label="[Resource Type] Status"`
- Status badges: `aria-label="Status: [Active/Missing/Required]"`
- Action buttons: Descriptive text, no icon-only buttons

### Keyboard Navigation
- All cards are focusable and clickable
- Tab order: Status message → Card 1-4 → Action button
- Enter/Space activates card navigation

### Screen Reader Announcements
- On load: Announce readiness status summary
- On state change: Announce updated status

---

## User Flows

### First-Time User (Empty State)
1. User navigates to `/console`
2. Dashboard loads → Empty state displayed
3. User reads "Setup Required" message
4. User clicks "Get Started" → Navigates to setup wizard or first creation page
5. Alternatively, user clicks specific card → Navigates to that resource's creation wizard

### Returning User (Fully Ready)
1. Dashboard loads → Fully Ready state
2. User sees success confirmation
3. User clicks "Go to Operate" → Navigates to `/console/operate`
4. User can click any card to manage that resource type

---

## API Integration

### Endpoint
`GET /v1/dashboard`

### Response Shape
```json
{
  "status": "ready" | "partially_configured" | "requires_setup",
  "readiness": {
    "trust_profiles": { "count": 2, "configured": true },
    "credential_templates": { "count": 3, "configured": true },
    "presentation_policies": { "count": 1, "configured": true },
    "deployment_profiles": { "count": 1, "configured": true }
  },
  "message": "Your organization is ready to operate"
}
```

### Error Handling
- Network errors: Display retry button
- 401/403: Redirect to login
- 500: Display error message with support contact info

---

## Testing Scenarios

### Visual Regression Tests
- [ ] Empty state renders correctly
- [ ] Partially configured shows mixed card states
- [ ] Fully ready shows all success states
- [ ] Loading spinner displays during fetch
- [ ] Error alert displays on API failure

### Interaction Tests
- [ ] "Get Started" navigates to first setup page
- [ ] "Go to Operate" navigates to operate page
- [ ] Clicking Trust Profile card navigates to trust profiles
- [ ] Clicking Template card navigates to templates
- [ ] Clicking Policy card navigates to policies
- [ ] Clicking Deployment card navigates to deployments
- [ ] Retry button refetches dashboard data

### Accessibility Tests
- [ ] All interactive elements keyboard accessible
- [ ] ARIA labels present and descriptive
- [ ] Focus indicators visible
- [ ] Screen reader announces status changes

---

## Design Tokens

### Colors
- Success: `theme.palette.success.main` (green)
- Warning: `theme.palette.warning.main` (amber)
- Error: `theme.palette.error.main` (red)
- Info: `theme.palette.info.main` (blue)

### Spacing
- Card spacing: `theme.spacing(3)` (24px)
- Section spacing: `theme.spacing(4)` (32px)

### Typography
- Header: `variant="h4"`
- Card titles: `variant="h6"`
- Descriptions: `variant="body2"` with `color="text.secondary"`

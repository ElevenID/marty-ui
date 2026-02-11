# Trust Profiles UX Contract

## Overview
Trust Profiles define which credential issuers an organization trusts for verification. They specify trust lists (collections of trusted issuer certificates/DIDs) and validation rules.

## Component Views

### 1. Trust Profile List
**Path**: `/console/trust`  
**Purpose**: Display all trust profiles with status, actions

### 2. Trust Profile Creation Wizard
**Path**: `/console/trust/create`  
**Purpose**: Guided creation of new trust profile

### 3. Trust Profile Detail View
**Path**: `/console/trust/:id`  
**Purpose**: View and edit existing trust profile

---

## States

### List View States

#### Empty State
**Trigger**: Organization has zero trust profiles  
**Visual**:
- Empty state illustration (shield icon)
- Heading: "No Trust Profiles"
- Subtext: "Create your first trust profile to start verifying credentials"
- Primary button: "Create Trust Profile"

**Accessibility**:
- Empty state container: `role="region"` with `aria-label="Empty trust profiles list"`

---

#### Loading State
**Trigger**: Initial fetch or refresh in progress  
**Visual**:
- Skeleton loaders (3-5 card placeholders)
- Pulsing animation on skeletons
- No interaction possible

**Duration**: Typically <500ms

---

#### Success State (Grid View)
**Trigger**: API returns 1+ trust profiles  
**Visual**:
- Grid layout (3 columns desktop, 2 tablet, 1 mobile)
- Each card shows:
  - Trust profile name (h6 typography)
  - Description (truncated to 2 lines)
  - Status badge (Active/Inactive)
  - Trust list type (URL or Inline)
  - Issuer count badge
  - Last updated timestamp
  - Action menu (⋮ icon)

**Card Hover State**:
- Elevation increases (shadow deepens)
- Border color changes to primary
- Action menu button becomes visible

**Card Interactive Elements**:
- Click card body → Navigate to detail view
- Click action menu → Show dropdown (View, Edit, Deactivate, Delete)

---

#### Error State
**Trigger**: API error fetching trust profiles  
**Visual**:
- Error Alert at top of page
- Red error icon
- Message: "Failed to load trust profiles: [error message]"
- "Retry" button in alert

**Behavior**:
- Retry button refetches data
- Previous data (if any) remains visible below error

---

### Creation Wizard States

See [wizards.md](./wizards.md) for general wizard patterns.

#### Step 1: Profile Info
**Fields**:
- Name (required, text, max 100 chars)
- Description (optional, textarea, max 500 chars)
- Status (dropdown: Active/Inactive, default Active)

**Validation**:
- Name: Non-empty, no special chars except spaces/hyphens
- Valid when: `name.trim() !== ''`

---

#### Step 2: Trust List Configuration
**Options**:
- **URL-based**: Fetch trust list from external URL
  - Field: Trust List URL (required, validated URL)
  - Example: `https://example.com/trust-list.json`
  - Auto-fetch preview on blur
  
- **Inline**: Manually specify trusted issuers
  - Add issuer button
  - Issuer entries: DID or Certificate thumbprint
  - Supports drag-drop reordering
  - Remove button per entry

**Validation**:
- URL mode: `trustListUrl !== '' && isValidUrl(trustListUrl)`
- Inline mode: `issuers.length > 0 && allIssuersValid`

---

#### Step 3: Validation Rules (Optional)
**Purpose**: Define additional validation constraints  
**Fields**:
- Require unexpired certificates (toggle, default: true)
- Require certificate revocation check (toggle, default: true)
- Custom validation script (textarea, JavaScript, optional)

**Validation**: Always valid (optional step)

---

#### Step 4: Review
**Display**:
- Summary table of all configured values
- Edit button per section → Jump back to that step
- Warning if status is Inactive

**Actions**:
- Back: Return to Step 3
- Submit: Create trust profile

---

### Detail View States

#### View Mode (Default)
**Trigger**: Navigate to `/console/trust/:id`  
**Visual**:
- Header: Profile name, status badge, action buttons (Edit, Deactivate, Delete)
- Tabs: Overview, Trust List, Validation Rules, History (future)

**Overview Tab**:
- Description
- Created/Updated timestamps
- Created by (user)
- Trust list type and source
- Issuer count

**Trust List Tab**:
- If URL: Display URL, last fetch timestamp, refresh button
- If Inline: Paginated table of issuers with DID/thumbprint
- Search/filter controls

**Validation Rules Tab**:
- Display configured rules
- Toggle preview (read-only)

---

#### Edit Mode
**Trigger**: Click "Edit" button  
**Visual**:
- Form fields become editable
- Save/Cancel buttons appear
- Changes highlighted (yellow background fade)

**Behavior**:
- Inline editing (no wizard)
- Auto-save option (future)
- Validation on save

**API**: `PATCH /v1/trust-profiles/:id`

---

#### Activated State
**Trigger**: Trust profile status changed to "Active"  
**Visual**:
- Status badge: Green "Active"
- Used in active verifications metric updated

---

#### Deactivated State
**Trigger**: User deactivates trust profile  
**Visual**:
- Status badge: Gray "Inactive"
- Warning banner: "This trust profile is inactive and won't be used for verification"
- "Reactivate" button available

---

#### Delete Confirmation
**Trigger**: User clicks Delete  
**Visual**:
- Modal dialog appears
- Title: "Delete Trust Profile?"
- Warning: "This action cannot be undone. Active verifications using this profile will fail."
- Checkbox: "I understand the consequences"
- Buttons: "Cancel" (default), "Delete" (danger, enabled only if checkbox checked)

**API**: `DELETE /v1/trust-profiles/:id`

**Success Behavior**:
- Show toast: "Trust profile deleted"
- Redirect to list view

---

## Accessibility

### List View
- Cards: `role="article"` with `aria-label="[Profile Name] trust profile"`
- Action menu: `aria-label="Actions for [Profile Name]"`
- Status badge: `aria-label="Status: [Active/Inactive]"`

### Detail View
- Tabs: `role="tablist"` with proper `aria-selected` states
- Edit button: `aria-label="Edit [Profile Name]"`
- Delete button: `aria-label="Delete [Profile Name]"` with `aria-describedby` pointing to warning text

### Keyboard Navigation
- Tab through cards in list
- Enter/Space to open card or activate buttons
- Arrow keys to navigate tabs in detail view
- Escape to close modals

---

## User Flows

### Create Trust Profile (URL-based)
1. User clicks "Create Trust Profile" from list or dashboard
2. Wizard opens → Step 1
3. User enters name "Production Trust" and description
4. User clicks Next → Step 2
5. User selects "URL-based" option
6. User enters trust list URL
7. System fetches and previews trust list → Shows issuer count
8. User clicks Next → Step 3
9. User keeps default validation rules
10. User clicks Next → Step 4 (Review)
11. User reviews configuration
12. User clicks "Create Trust Profile"
13. Success message appears
14. Auto-redirect to trust profile detail view

### Edit Trust Profile (Add Issuer)
1. User navigates to trust profile detail
2. User clicks "Trust List" tab
3. User clicks "Add Issuer" button (inline trust list only)
4. Modal appears with issuer form
5. User enters DID: `did:example:123456`
6. User clicks "Add"
7. Issuer appears in list immediately (optimistic update)
8. API call confirms addition
9 Success toast: "Issuer added"

### Deactivate Trust Profile
1. User opens trust profile detail
2. User clicks "Deactivate" button
3. Confirmation modal appears: "Deactivate this trust profile?"
4. User confirms
5. Status changes to "Inactive"
6. Warning banner appears
7. Success toast: "Trust profile deactivated"

---

## API Integration

### List Trust Profiles
```
GET /v1/trust-profiles
Query params:
  - status: active|inactive
  - limit: number (default 50)
  - offset: number (default 0)

Response:
[
  {
    "id": 1,
    "name": "Production Trust",
    "description": "Production issuer trust list",
    "status": "active",
    "trust_list_type": "url",
    "trust_list_url": "https://example.com/trust-list.json",
    "issuer_count": 5,
    "created_at": "2024-01-15T10:00:00Z",
    "updated_at": "2024-02-01T14:30:00Z"
  }
]
```

### Get Trust Profile
```
GET /v1/trust-profiles/:id

Response:
{
  "id": 1,
  "name": "Production Trust",
  "description": "...",
  "status": "active",
  "trust_list_type": "url",
  "trust_list_url": "https://example.com/trust-list.json",
  "issuers": [...],  // Only for inline type
  "validation_rules": {
    "require_unexpired": true,
    "require_revocation_check": true,
    "custom_script": null
  },
  "created_by": "user@example.com",
  "created_at": "2024-01-15T10:00:00Z",
  "updated_at": "2024-02-01T14:30:00Z"
}
```

### Create Trust Profile
```
POST /v1/trust-profiles
Request:
{
  "name": "Production Trust",
  "description": "...",
  "status": "active",
  "trust_list_type": "url",
  "trust_list_url": "https://example.com/trust-list.json",
  "validation_rules": {...}
}

Response: 201 Created
{ ...trust profile object }
```

### Update Trust Profile
```
PATCH /v1/trust-profiles/:id
Request:
{
  "description": "Updated description",
  "status": "inactive"
}

Response: 200 OK
{ ...updated trust profile }
```

### Delete Trust Profile
```
DELETE /v1/trust-profiles/:id

Response: 200 OK
{ "message": "Trust profile deleted" }

Errors:
- 409 Conflict: "Trust profile is in use by active flows"
```

---

## Testing Scenarios

### List View Tests
- [ ] Empty state renders when no profiles exist
- [ ] Loading state shows skeletons during fetch
- [ ] Grid displays all profiles with correct data
- [ ] Cards navigate to detail on click
- [ ] Action menu opens and shows correct options
- [ ] Error state displays on API failure
- [ ] Retry button refetches data

### Creation Wizard Tests  
- [ ] Step 1: Name required, Next disabled when empty
- [ ] Step 2: URL validation works
- [ ] Step 2: Inline mode allows adding/removing issuers
- [ ] Step 3: Optional step can be skipped
- [ ] Review displays all configured values
- [ ] Submit creates profile and redirects
- [ ] API errors display correctly

### Detail View Tests
- [ ] Profile data loads and displays
- [ ] Tabs switch correctly
- [ ] Edit mode activates and saves changes
- [ ] Deactivate shows confirmation and updates status
- [ ] Delete shows confirmation requiring checkbox
- [ ] Trust list pagination works (inline mode)

### Accessibility Tests
- [ ] All interactive elements keyboard accessible
- [ ] Screen reader announces status changes
- [ ] ARIA labels present and descriptive
- [ ] Focus management correct in modals

---

## Design Tokens

### Status Colors
- Active: `success.main` (green)
- Inactive: `grey.500` (gray)

### Card Sizing
- Min height: 200px
- Padding: 24px
- Border radius: 8px

### Action Button Styles
- Edit: Primary contained
- Deactivate: Warning outlined
- Delete: Error outlined

---

## Error Messages

### Validation Errors
- `"Trust profile name is required"`
- `"Trust list URL must be a valid HTTPS URL"`
- `"At least one trusted issuer is required"`
- `"Invalid issuer DID format"`

### API Errors
- `"Failed to create trust profile: [API message]"`
- `"Trust profile not found"`
- `"Cannot delete trust profile: in use by [N] active flows"`
- `"Network error: Please check your connection"`

---

## Future Enhancements
- [ ] Trust list auto-refresh on schedule
- [ ] Issuer certificate validation preview
- [ ] Trust profile templates
- [ ] Audit log tab showing usage history
- [ ] Bulk issuer import via CSV
- [ ] Trust profile duplication

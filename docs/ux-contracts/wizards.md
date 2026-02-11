# Wizard UX Contract

## Overview
Multi-step wizards provide guided creation flows for complex resources (Flows, Templates, Trust Profiles, Deployment Profiles, Policies). All wizards follow consistent patterns for navigation, validation, and submission.

## Common Wizard Structure

### Components
```
Wizard (Container)
├── Stepper (Progress indicator)
│   └── Steps (labeled, clickable if visited)
├── Step Content (Dynamic based on activeStep)
├── Navigation Controls
│   ├── Back Button (disabled on first step)
│   ├── Skip Button (optional, for optional steps)
│   └── Next/Submit Button (disabled if step invalid)
└── Status Messages (Success/Error alerts)
```

---

## States

### 1. Step Validation States

#### Valid Step
- **Trigger**: All required fields have valid values
- **Visual**: Next button enabled (primary blue)
- **Behavior**: Clicking Next advances to next step

#### Invalid Step
- **Trigger**: Required fields empty  or have invalid values
- **Visual**: 
  - Next button disabled (gray)
  - Button shows tooltip on hover: "Complete required fields"
- **Behavior**: Next button unresponsive to clicks

#### Loading State (During Submission)
- **Trigger**: Final step submission in progress
- **Visual**:
  - Submit button shows spinner
  - Button text changes to "Creating..." or "Submitting..."
  - All form controls disabled
- **Behavior**: No user interaction possible

### 2. Navigation States

#### First Step
- **Visual**: Back button hidden or disabled
- **Behavior**: Only Next button active

#### Middle Steps
- **Visual**: Both Back and Next buttons visible
- **Behavior**: 
  - Back always enabled (no validation)
  - Next enabled only if step valid

#### Last Step (Review)
- **Visual**: "Submit" or "Create" button instead of "Next"
- **Behavior**: 
  - Button disabled if any previous step invalid
  - Clicking submits form via API

#### Optional Steps
- **Visual**: "Skip" button visible
- **Behavior**: Clicking Skip advances without validation

---

## Wizard Types

### Flow Definition Wizard
**Path**: `/console/flows/create`  
**Steps**: 
1. Flow Type (Verification/Issuance/Combined)
2. Configure Steps (Name, description, flow steps)
3. Bind Deployment (Optional - select deployment profile)
4. Review

**Validation Rules**:
- Step 1: `flowType !== null`
- Step 2: `name.trim() !== '' && flowSteps.length > 0`
- Step 3: Always valid (optional)
- Step 4: Always valid (review only)

**Test IDs**:
- Flow type cards: `flow-type-verification`, `flow-type-issuance`, `flow-type-combined`
- Next button: `wizard.flow.next`
- Back button: `wizard.flow.back`
- Submit button: `wizard.flow.submit`

---

### Credential Template Wizard
**Path**: `/console/templates/create`  
**Steps**:
1. Template Info (Name, doc type, namespace)
2. Claims Configuration (Define claims structure)
3. Trust Profile Selection
4. Artifacts (Optional - iOS/Android configs)
5. Review

**Validation Rules**:
- Step 1: `name !== '' && doctype !== '' && namespace !== ''`
- Step 2: `claims.length > 0 && allClaimsValid`
- Step 3: `trustProfileId !== null`
- Step 4: Always valid (optional)
- Step 5: Always valid

**Special Behaviors**:
- Claims can be added/removed dynamically
- Drag-and-drop reordering supported
- Auto-save draft functionality (future)

---

### Trust Profile Wizard
**Path**: `/console/trust/create`  
**Steps**:
1. Profile Info (Name, description)
2. Trust List Configuration (URL or inline)
3. Validation Rules (Optional)
4. Review

**Validation Rules**:
- Step 1: `name.trim() !== ''`
- Step 2: `trustListUrl !== '' || inlineTrustList.length > 0`
- Step 3: Always valid (optional)
- Step 4: Always valid

---

### Deployment Profile Wizard
**Path**: `/console/deploy/create`  
**Steps**:
1. Environment Selection (Dev/Staging/Production)
2. Runtime Configuration (URLs, keys)
3. Integration Settings (Webhooks, logging)
4. Review

**Validation Rules**:
- Step 1: `environment !== null`
- Step 2: `baseUrl !== '' && apiKey !== ''`
- Step 3: Always valid (optional integrations)
- Step 4: Always valid

---

## Keyboard Navigation

### Tab Order
1. Step content form fields (top to bottom, left to right)
2. Back button
3. Skip button (if present)
4. Next/Submit button

### Keyboard Shortcuts
- `Enter`: Advance to next step (if valid)
- `Esc`: Cancel wizard (show confirmation dialog)
- `Tab`: Navigate through focusable elements
- `Shift+Tab`: Navigate backwards

---

## Validation Patterns

### Real-Time Validation
- Field-level validation on blur
- Form-level validation on data change
- Next button reactivity: instantly enables/disables as data changes

### Error Display
- Inline field errors: Red text below invalid fields
- Field highlighting: Red border on invalid fields with focus
- Error summary: Alert at top of step showing all errors

### Success Indicators
- Valid fields: Green checkmark icon (optional, not always shown)
- Completed steps: Green checkmark in stepper
- Submit success: Green success alert with confirmation message

---

## API Integration

### Submission Endpoint Pattern
```
POST /v1/{resource-type}
```

Examples:
- `POST /v1/flows`
- `POST /v1/credential-templates`
- `POST /v1/trust-profiles`
- `POST /v1/deployment-profiles`

### Success Response
```json
{
  "id": "resource_123",
  "status": "active",
  ...resource fields
}
```

### Error Response
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid configuration",
    "details": {
      "field": "name",
      "issue": "Name already exists"
    }
  }
}
```

### Error Handling
- 400 Validation: Display field-level errors
- 401/403: Redirect to login
- 409 Conflict: Show "Resource exists" error
- 500 Server: Show generic error with retry option

---

##Accessibility

### ARIA Attributes
- Stepper: `role="navigation"` with `aria-label="Wizard progress"`
- Active step: `aria-current="step"`
- Completed steps: `aria-disabled="false"` (clickable)
- Incomplete steps: `aria-disabled="true"`
- Form fields: `aria-required="true"` for required fields
- Error messages: `aria-live="polite"` for validation errors

### Screen Reader Announcements
- Step navigation: "Step 2 of 4: Configure Steps"
- Validation changes: "Next button enabled" / "Next button disabled"
- Submission: "Creating resource..." → "Success: Resource created"

### Focus Management
- On step change: Focus moves to step heading
- On error: Focus moves to first invalid field
- On success: Focus moves to success message

---

## User Flows

### Happy Path (Create Flow)
1. User clicks "Create Flow"
2. Wizard opens at Step 1
3. User selects "Verification" flow type → Next enabled
4. User clicks Next → Advances to Step 2
5. User enters name "Age Verification" → partial validation
6. User clicks "Add Step" → adds verification step → Next enabled
7. User clicks Next → Advances to Step 3
8. User selects deployment profile → Next enabled
9. User clicks Next → Advances to Review
10. User reviews configuration → Submit enabled
11. User clicks Submit → Loading state → Success
12. Success message displays → Auto-redirect to Operate page after 2s

### Error Path (Validation Failure)
1. User completes steps 1-3
2. User reaches Review step
3. User clicks Submit
4. API returns 400 validation error
5. Error alert displays at top: "Validation failed: [message]"
6. User clicks "Edit" on invalid step
7. Wizard jumps back to that step
8. User corrects the issue
9. User navigates forward again to Review
10. User resubmits → Success

### Cancel Flow
1. User starts wizard
2. User clicks browser back or "Cancel" button
3. Confirmation dialog appears: "Abandon changes?"
4. User confirms → Wizard closes, data discarded
5. User redirected to list view

---

## Testing Scenarios

### Validation Tests
- [ ] Next button disabled on initial load
- [ ] Next button enables when required fields filled
- [ ] Next button disables when fields cleared
- [ ] Submit button disabled if any step invalid
- [ ] Skip button  bypasses validation for optional steps

### Navigation Tests
- [ ] Back button navigates to previous step
- [ ] Next button advances to next step when valid
- [ ] Stepper labels display correct step names
- [ ] Clicking completed step in stepper navigates there
- [ ] Clicking incomplete step in stepper does nothing

### Submission Tests
- [ ] Submit shows loading state immediately
- [ ] Success displays alert with confirmation
- [ ] Success auto-redirects after delay
- [ ] Error displays alert with message
- [ ] Error keeps user on wizard for correction

### Accessibility Tests
- [ ] All steps keyboard navigable
- [ ] Tab order follows logical flow
- [ ] Enter key advances when valid
- [ ] Screen reader announces step changes
- [ ] Focus management correct on navigation

---

## Design Patterns

### Step Indicators
- Material-UI Stepper component
- Horizontal layout on desktop
- Vertical or collapsed on mobile
- Alternating labels showing step names

### Button Styling
- Primary (contained): Next, Submit
- Secondary (outlined): Back
- Text: Skip, Cancel
- Disabled state: Reduced opacity, no hover effect

### Form Layout
- Single column on mobile
- Two columns on desktop for dense forms
- Consistent 24px spacing between fields
- Field groups use Cards for visual separation

### Responsive Behavior
- Desktop: Side-by-side fields where appropriate
- Tablet: Single column, wider fields
- Mobile: Stack all elements, full-width fields

---

## Future Enhancements
- [ ] Draft auto-save (persist incomplete wizards)
- [ ] Wizard resume from URL (deep linking)
- [ ] Multi-tenant organization selection
- [ ] Bulk import via file upload
- [ ] Wizard templates/presets

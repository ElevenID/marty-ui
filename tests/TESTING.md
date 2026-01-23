# Marty UI E2E Testing Guide

Comprehensive testing infrastructure for Marty's web application and wallet integration using Playwright, with event-driven testing patterns and DRY helper utilities.

## Table of Contents

- [Quick Start](#quick-start)
- [Test Infrastructure](#test-infrastructure)
- [Event-Driven Testing](#event-driven-testing)
- [Split-Screen Test Harness](#split-screen-test-harness)
- [Helper Classes & Utilities](#helper-classes--utilities)
- [Custom Matchers](#custom-matchers)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Quick Start

```bash
# Run all E2E tests
cd marty-ui/tests
npm test

# Run specific test project
npm run test:unit-api      # API-only tests (parallel)
npm run test:integration   # UI component tests (sequential)
npm run test:e2e           # Full user journeys (sequential)

# Run with headed browser
npx playwright test --headed

# Run specific test file
npx playwright test e2e/e2e-flows/credential-issuance.spec.js
```

## Test Infrastructure

### Project Structure

```
marty-ui/tests/
├── e2e/
│   ├── unit-api/          # API-only tests (parallel, fast)
│   ├── integration-ui/    # UI component tests (sequential)
│   └── e2e-flows/         # Complete user journeys (sequential)
├── fixtures/
│   ├── auth.fixture.js    # Authentication & split-screen fixtures
│   ├── split-screen-harness.html  # Test harness HTML
│   └── users.js           # Seeded test users
└── utils/
    ├── test-helpers.js    # Main helper classes
    ├── api-client.js      # API wrapper
    ├── test-data-builders.js  # Mock data builders
    └── custom-matchers.js # Playwright matchers

```

### Test Execution Order

1. **unit-api**: Fast API-only tests (parallel)
2. **integration-ui**: UI component tests (workers=1)
3. **e2e-flows**: Full wallet integration tests (workers=1)

## Event-Driven Testing

### EventWaiter - Replace Polling with SSE

The `EventWaiter` class subscribes to server-sent events for real-time test synchronization, eliminating arbitrary delays and polling loops.

#### Backend SSE Events

| Event Type | When Emitted | Data Fields |
|-----------|-------------|-------------|
| `application.approved` | Application approved | `application_id`, `application_number`, `status` |
| `credential.issued` | Credential issued to wallet | `session_id`, `transaction_id`, `application_id` |
| `check.completed` | Vetting check completed | `check_id`, `check_type`, `passed`, `result` |
| `device.registered` | Device registered | `device_id`, `platform`, `registration_id` |

#### Usage

```javascript
const { EventWaiter } = require('../utils/test-helpers');

test('wait for credential issuance', async ({ page }) => {
  const waiter = new EventWaiter(page);
  
  // Start listening before triggering action
  const eventPromise = waiter.waitForEvent('credential.issued', {
    application_id: applicationId
  }, 30000);
  
  // Trigger action that emits event
  await page.click('[data-testid="issue-credential-btn"]');
  
  // Wait for event
  const event = await eventPromise;
  expect(event.data.application_id).toBe(applicationId);
  
  // Cleanup
  waiter.closeAll();
});
```

#### Wait for Multiple Events

```javascript
const events = await waiter.waitForEvents([
  { eventType: 'application.approved', filter: { application_id: appId } },
  { eventType: 'credential.issued', filter: { application_id: appId }, timeout: 60000 }
]);
```

## Split-Screen Test Harness

The split-screen harness displays Marty UI (60%) and Wallet UI (40%) side-by-side for visual testing and debugging.

### Using splitScreenPage Fixture

```javascript
const { test, expect } = require('@playwright/test');

test('credential issuance with split screen', async ({ splitScreenPage }) => {
  const { page, martyFrame, walletFrame, walletBridge } = splitScreenPage;
  
  // Interact with Marty UI
  await martyFrame.click('[data-testid="issue-credential-btn"]');
  
  // Interact with Wallet
  await walletBridge.acceptCredentialOffer(walletFrame);
  
  // Verify both sides
  await expect(martyFrame).toShowCredential('Jane Doe');
  await expect(walletFrame).toHaveCredentialCount(1);
});
```

### authenticatedVendorSplitScreen Fixture

Pre-authenticated vendor with split-screen setup and organization credentials configured.

```javascript
test('test with authenticated vendor', async ({ authenticatedVendorSplitScreen }) => {
  const { martyFrame, walletFrame, organizationId, credentialConfigId } = authenticatedVendorSplitScreen;
  
  // Organization setup already complete!
  // Trust config, signing keys, and credential config exist
  
  await martyFrame.goto(`/admin/credentials`);
  // ... test logic
});
```

## Helper Classes & Utilities

### setupOrganizationWithCredentials()

Consolidates organization ID retrieval, credential config setup, and trust configuration.

```javascript
const { setupOrganizationWithCredentials } = require('../utils/test-helpers');

test.beforeAll(async ({ page }) => {
  const auth = new AuthHelpers(page);
  await page.goto('/');
  await auth.loginAsSeededUser('vendor');
  
  const { organizationId, credentialConfigId } = await setupOrganizationWithCredentials(page, {
    credentialType: 'employee_badge',
    signingAlgorithm: 'ES256',
  });
  
  // Ready to test!
});
```

### AuthenticatedApiClient

DRY wrapper for common API operations.

```javascript
const { AuthenticatedApiClient } = require('../utils/test-helpers');

test('create application via API', async ({ page }) => {
  const api = new AuthenticatedApiClient(page);
  
  // Ensure setup
  await api.ensureCredentialConfig(organizationId, 'employee_badge');
  await api.ensureTrustConfig(organizationId);
  
  // Create application
  const application = await api.createApplication(organizationId, {
    given_name: 'John',
    family_name: 'Doe',
    email: 'john@example.com',
  });
  
  // Approve application
  await api.approveApplication(application.id);
});
```

### Test Data Builders

Generate consistent mock data with builder pattern.

```javascript
const { CredentialDataBuilder, UserDataBuilder } = require('../utils/test-helpers');

// Build mDL credential data
const mdlData = CredentialDataBuilder.mdl()
  .withName('Jane', 'Doe')
  .withBirthDate('1990-01-15')
  .withAddress('123 Main St', 'Anytown', 'CA', '12345')
  .build();

// Build user data
const applicant = UserDataBuilder.applicant()
  .withName('John', 'Smith')
  .withEmail('john.smith@example.com')
  .build();
```

## Custom Matchers

Domain-specific assertions for improved test readability.

```javascript
// Check credentials
await expect(walletFrame).toShowCredential('Jane Doe');
await expect(walletFrame).toHaveCredentialCount(2);

// Check page state
await expect(page).toBeOnDashboard();
await expect(page).toShowNotification('Success', 'success');

// Check application status
await expect(page).toHaveApplicationStatus('approved');

// Check loading state
await expect(page.locator('.content')).toBeLoaded();

// Check validation errors
await expect(form).toHaveValidationError('Email is required');

// Check SSE events
await expect(waiter).toReceiveSSEEvent('credential.issued', { application_id: '123' });
```

## Best Practices

### 1. Use Event-Driven Waits

❌ **DON'T:**
```javascript
await page.click('[data-testid="approve-btn"]');
await page.waitForTimeout(2000); // Arbitrary delay
```

✅ **DO:**
```javascript
const responsePromise = page.waitForResponse(r => 
  r.url().includes('/api/approve') && r.ok()
);
await page.click('[data-testid="approve-btn"]');
await responsePromise;
```

✅ **BETTER:**
```javascript
const waiter = new EventWaiter(page);
const eventPromise = waiter.waitForEvent('application.approved');
await page.click('[data-testid="approve-btn"]');
await eventPromise;
```

### 2. Use Fixtures for Common Setup

❌ **DON'T:**
```javascript
test.beforeEach(async ({ page }) => {
  await page.goto('/');
  const auth = new AuthHelpers(page);
  await auth.loginAsSeededUser('vendor');
  
  const meResponse = await page.request.get('/auth/me');
  const organizationId = (await meResponse.json()).user.organization_id;
  
  // ... 20 more lines of setup
});
```

✅ **DO:**
```javascript
test('my test', async ({ authenticatedVendorPage }) => {
  const { page, organizationId, credentialConfigId } = authenticatedVendorPage;
  // Setup complete!
});
```

### 3. Use AuthenticatedApiClient for API Calls

❌ **DON'T:**
```javascript
const response = await page.request.post(
  `${apiUrl}/api/organizations/${orgId}/credential-types`,
  { data: { credential_type: 'employee_badge', ... } }
);
```

✅ **DO:**
```javascript
const api = new AuthenticatedApiClient(page);
await api.ensureCredentialConfig(orgId, 'employee_badge');
```

### 4. Use Data Builders for Mock Data

❌ **DON'T:**
```javascript
const credentialData = {
  given_name: 'John',
  family_name: 'Doe',
  birth_date: '1990-01-01',
  document_number: 'DL123456',
  // ... repeated across files
};
```

✅ **DO:**
```javascript
const mdlData = CredentialDataBuilder.mdl()
  .withName('John', 'Doe')
  .withBirthDate('1990-01-01')
  .build();
```

### 5. Replace networkidle with Specific Waits

❌ **DON'T:**
```javascript
await page.goto('/dashboard');
await page.waitForLoadState('networkidle'); // Slow, unreliable
```

✅ **DO:**
```javascript
const [response] = await Promise.all([
  page.waitForResponse(r => r.url().includes('/api/dashboard') && r.ok()),
  page.goto('/dashboard')
]);
```

### 6. When to Keep vs Replace waitForTimeout

#### ✅ Keep waitForTimeout for:
- **UI Animations** (300ms or less)
  ```javascript
  await dropdown.click();
  await page.waitForTimeout(300); // Let animation complete
  await option.click();
  ```
- **Debouncing** user input
  ```javascript
  await input.fill('search term');
  await page.waitForTimeout(500); // Match frontend debounce
  await expect(results).toBeVisible();
  ```
- **Known async processing** with no observable event
  ```javascript
  await button.click();
  await page.waitForTimeout(1000); // Known backend delay
  ```

#### ❌ Replace waitForTimeout with:
- **API responses** → Use `waitForResponse()`
  ```javascript
  // OLD: await page.click(); await page.waitForTimeout(2000);
  const respPromise = page.waitForResponse(r => r.url().includes('/api/approve'));
  await page.click('[data-testid="approve-btn"]');
  await respPromise;
  ```
- **SSE events** → Use `EventWaiter`
  ```javascript
  // OLD: await approve(); await page.waitForTimeout(5000);
  const waiter = new EventWaiter(page);
  const promise = waiter.waitForEvent('application.approved');
  await approve();
  await promise;
  ```
- **Element visibility** → Use `expect(locator).toBeVisible()`
  ```javascript
  // OLD: await page.waitForTimeout(1000);
  await expect(page.locator('[data-testid="success"]')).toBeVisible();
  ```
- **Email arrival** → Use `expect.poll()` with EmailHelpers
  ```javascript
  // OLD: await page.waitForTimeout(3000);
  const mailhog = new MailHogHelpers(page);
  await expect.poll(() => mailhog.getEmailsTo('user@example.com'))
    .toHaveLength(1);
  ```

### 7. Use expect.poll() for Email/External Services

```javascript
const { MailHogHelpers } = require('../utils/test-helpers');

const mailhog = new MailHogHelpers(page);

await expect.poll(async () => {
  const emails = await mailhog.getEmailsTo('user@example.com');
  return emails.find(e => e.Content?.Headers?.Subject?.[0]?.includes('Verify'));
}, {
  timeout: 30000,
  intervals: [1000, 2000, 5000], // Exponential backoff
  message: 'Email not received'
}).toBeTruthy();
```

### 7. Clean Up Resources

```javascript
test('credential issuance', async ({ page }) => {
  const waiter = new EventWaiter(page);
  
  try {
    // Test logic
    await waiter.waitForEvent('credential.issued');
  } finally {
    waiter.closeAll(); // Always cleanup
  }
});
```

## Examples

### Complete E2E Flow with Event-Driven Testing

```javascript
const { test, expect } = require('@playwright/test');
const { 
  EventWaiter, 
  AuthenticatedApiClient, 
  CredentialDataBuilder 
} = require('../utils/test-helpers');

test('complete application approval and credential issuance', async ({ authenticatedVendorPage }) => {
  const { page, organizationId } = authenticatedVendorPage;
  const api = new AuthenticatedApiClient(page);
  const waiter = new EventWaiter(page);
  
  try {
    // Create application
    const application = await api.createApplication(organizationId, 
      CredentialDataBuilder.mdl().withName('Jane', 'Doe').build()
    );
    
    // Wait for approval event
    const approvalPromise = waiter.waitForEvent('application.approved', {
      application_id: application.id
    });
    
    // Approve application
    await api.approveApplication(application.id);
    await approvalPromise;
    
    // Wait for credential issuance
    const issuanceEvent = await waiter.waitForEvent('credential.issued', {
      application_id: application.id
    }, 60000);
    
    expect(issuanceEvent.data.session_id).toBeTruthy();
    await expect(page).toShowNotification('Credential issued successfully');
    
  } finally {
    waiter.closeAll();
  }
});
```

### Split-Screen Wallet Integration Test

```javascript
test('credential pickup in wallet', async ({ authenticatedVendorSplitScreen }) => {
  const { martyFrame, walletFrame, walletBridge, organizationId } = authenticatedVendorSplitScreen;
  const api = new AuthenticatedApiClient(martyFrame);
  
  // Create and issue credential
  const offer = await api.createCredentialOffer({
    organizationId,
    credentialData: CredentialDataBuilder.employeeBadge()
      .withName('John', 'Smith')
      .build()
  });
  
  // Accept in wallet
  await walletBridge.acceptCredentialOffer(walletFrame, offer.credential_offer_uri);
  
  // Verify in both UIs
  await expect(martyFrame).toHaveApplicationStatus('issued');
  await expect(walletFrame).toHaveCredentialCount(1);
  await expect(walletFrame).toShowCredential('John Smith');
});
```

## Debugging

### View Split-Screen Recordings

All E2E flow tests record video with both Marty UI and Wallet UI visible:

```bash
# Videos saved to
marty-ui/tests/test-results/

# Open most recent
open test-results/*/video.webm
```

### Run Tests in Headed Mode

```bash
npx playwright test --headed --workers=1
```

### Debug Specific Test

```bash
npx playwright test --debug e2e/e2e-flows/my-test.spec.js
```

### Check SSE Events in Browser Console

```javascript
// In test
await page.evaluate(() => {
  const es = new EventSource('/api/events/push?device_id=test');
  es.onmessage = (e) => console.log('SSE:', e.data);
});
```

## Migration from Old Patterns

If you encounter old test patterns, migrate them using this guide:

| Old Pattern | New Pattern |
|------------|------------|
| `await page.waitForTimeout(1000)` | `await page.waitForResponse(...)` or `EventWaiter` |
| `await page.waitForLoadState('networkidle')` | `await page.waitForResponse(...)` |
| Manual org setup in beforeAll | `setupOrganizationWithCredentials()` |
| Inline page.request calls | `AuthenticatedApiClient` |
| Repeated mock data | `CredentialDataBuilder`, `UserDataBuilder` |
| Custom polling loops | `EventWaiter.waitForEvent()` |
| `await expect(locator).toContainText()` | `await expect(page).toShowCredential()` |

---

**For more examples, see existing tests in `marty-ui/tests/e2e/e2e-flows/`.**

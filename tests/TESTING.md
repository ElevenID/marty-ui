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

### Beta Lifecycle Gate

The beta release gate uses the local Marty browser wallet for deterministic final-spec OID4VCI and signed DCQL OID4VP execution. Start `marty-test-wallet` on `127.0.0.1:8787`, then run:

```bash
node tests/scripts/probe-beta-membership-badge.js
node tests/scripts/verify-beta-credential-login.js
node tests/scripts/audit-beta-org-credential-paths.js
node tests/scripts/audit-beta-credential-lifecycle.js
```

The full audit requires fresh holder-bound credential receipt, explicit logout and badge login, Application Template activation, linked renewal, suspend/deny, reinstate/allow, revoke/deny, cross-organization denial, and a valid verification result with `evaluation=passed` and `decision=allow`. SpruceKit acceptance remains a separate protected conformance/device lane. Walt.id is diagnostic-only and must not be treated as a passing presentation wallet while its registry entry is inactive.

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
  const mailpit = new MailpitHelpers(page);
  await expect.poll(() => mailpit.getEmailsTo('user@example.com'))
    .toHaveLength(1);
  ```

### 7. Use expect.poll() for Email/External Services

```javascript
const { MailpitHelpers } = require('../utils/test-helpers');

const mailpit = new MailpitHelpers(page);

await expect.poll(async () => {
  const emails = await mailpit.getEmailsTo('user@example.com');
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

## MIP 0.3 Release Gates

The PR browser gate is deterministic and mocked. The real deployed lifecycle is
`.github/workflows/e2e-tests.yml`, triggered manually or by the deployment
orchestrator with the `beta-deployed` repository-dispatch event.

Every dispatch must identify `release_version` and `cd_run_id` in addition to
the beta origin and audit organization. The workflow downloads that CD run's
build-ready manifest, requires the run to be a successful `CD` execution at the
workflow checkout SHA, and rejects a manifest for another release or revision.
The deployed services and UI images independently expose their embedded release
identity at `/.well-known/marty-release` and `/marty-ui-release.json`; both must
match before any browser journey starts.

Configure the protected `beta-lifecycle` environment with:

```text
vars.BETA_ORIGIN
vars.BETA_AUDIT_ORG_ID
secrets.TEST_APPLICANT_EMAIL
secrets.TEST_APPLICANT_PASSWORD
secrets.TEST_VENDOR_EMAIL
secrets.TEST_VENDOR_PASSWORD
```

Every release environment must have at least one required reviewer, self-review
and administrator bypass disabled, and a protected-branch or custom deployment-branch policy. CD
checks the live GitHub configuration before running repository tests or building
an image:

```bash
GH_TOKEN=... python scripts/check_github_release_environments.py
```

The required environment inputs and repository revision variables are declared
in `deploy-config/github-release-environments.json`. The checker reports names
only and never reads secret values.

The job starts the deterministic Marty browser wallet and fails unless:

- the well-known configuration and response header advertise MIP `0.3.1`, and
  the body uses the canonical strict discovery schema with an
  `active_compliance_profiles` array and without removed `api_base_url`, endpoint
  maps, or authorization extensions;
- canonical and appended SpruceKit issuer metadata match, identify `ElevenID LLC`,
  include `MemberCredential#spruce-sd-jwt`, and point to the canonical public VCT;
- that VCT document identifies `Marty Verified Member Badge`, uses only supported
  SpruceKit formats, and no active configuration uses `marty.example`;
- canonical applicant, application, and holder-inventory routes succeed;
- removed applicant routes return `404`;
- a membership badge is accepted from the canonical UI flow;
- an Application Template is created as draft and activated;
- organization verification completes through the browser wallet;
- an eligible credential renews through the operator UI, the replacement is linked, and the superseded source is revoked;
- suspension, reinstatement, and revocation produce deny, allow, and deny verification decisions;
- lifecycle status is organization-owned and wrong-organization actions return `403`;
- no required fixture is missing.

CD also requires exact 40-character `MARTY_PROTOCOL_REF`,
`MARTY_CREDENTIALS_REF`, `MARTY_CORE_REF`, `MARTY_CLI_REF`, `MARTY_BLOG_REF`,
and `MARTY_SUBSCRIPTIONS_REF` repository variables. Configure the protected `beta-migration-rehearsal`
environment with:

```text
secrets.MIGRATION_REHEARSAL_DATABASE_URL
secrets.MIGRATION_REHEARSAL_DATABASE_MARKER
vars.MIGRATION_REHEARSAL_SNAPSHOT_ID
vars.MIGRATION_REHEARSAL_PUBLIC_API_URL
```

The marker must begin with `beta-copy-`, be at least six characters, and appear
in the rehearsal database URL. The snapshot ID identifies the beta snapshot
restored into that isolated database. There is no empty-schema fallback. CD
requires the public URL to be the exact absolute HTTPS beta origin, applies the
one-way migration with that origin, verifies it, captures built image digests, and
emits `build-ready-manifest-<version>` only after the beta-copy rehearsal
succeeds.
The deployed beta environment must also set `MARTY_MIGRATION_PROFILE=beta`;
do not let a tunnel deployment inherit the compose `dev` profile.
Before building, CD also requires successful exact-SHA source workflows: `CI`
for Marty Protocol and Marty Credentials, and `MIP Release Wallet` for Marty
Core. The Core release lane verifies the tracked lockfile and vendored patch,
tests the final-spec OID4VCI engine and browser wallet, and compiles the Python
bindings against that same locked engine.
This manifest is not a promotion attestation: `release_ready` remains false until
the deployed beta lifecycle and protected wallet-login lanes pass against the
same repository revisions and image digests.

SpruceKit Open Badge login remains a protected device-lab gate because SpruceKit
Mobile is a native SDK/showcase rather than a hosted browser wallet. Its evidence
must record the wallet build revision, signed request resolution, badge and issuer
display, requested email disclosure, callback completion, existing-user lookup,
and authenticated Marty session without changing the standards-compliant request.

### Protected Wallet Conformance Promotion

CD intentionally emits only `build-ready-manifest-<version>` with
`release_ready: false`. The beta lifecycle workflow adds `release-context.json`
to its evidence artifact so the CD run, release version, tested UI SHA, Marty
Core SHA, beta origin, MIP version, and workflow run cannot be substituted later.
It also preserves the independently fetched services/UI runtime markers.
The artifact also contains `spruce-metadata.json`; promotion rejects missing,
empty, wrong-origin, or non-displayable issuer metadata and rechecks the live
endpoints before validating protected device evidence.
It also contains the fail-closed fresh-organization report. Promotion requires
that report to pass with no page/request failures and to prove the complete,
dependency-linked signing, issuer, trust, revocation, template, policy,
deployment, issuance-flow, verification-flow, and API-key inventory.

After the SpruceKit and native-wallet device runs, start
`.github/workflows/wallet-conformance.yml` in the protected
`wallet-conformance` environment with:

```text
secrets.WALLET_EVIDENCE_BEARER_TOKEN (optional only when every attachment URL is public)
```

The environment itself is mandatory even when the bearer token is not used; it
must satisfy the same reviewer, administrator-bypass, and deployment-branch
protections as the other release environments. Dispatch the workflow with:

```text
release_version
cd_run_id
beta_lifecycle_run_id
marty_ui_sha
beta_origin
wallet_evidence_url
wallet_evidence_sha256
```

The evidence JSON follows schema v2 in
`docs/wallet-conformance-evidence-template.json`; authoritative required checks
and wallet IDs are in
`deploy-config/catalog/wallet-conformance-requirements.json`. The protected job
downloads the build-ready and beta artifacts by run ID, requires both source
workflow runs to have completed successfully at the exact Marty UI SHA, verifies
the Marty Core wallet revision and all seven coordinated repository revisions,
downloads the device evidence over HTTPS, checks its SHA-256, and validates:

- SpruceKit badge receipt, badge and issuer display, signed request resolution,
  requested email disclosure, callback, existing-user lookup, and session creation;
- byte-identity of the signed Marty request and the request resolved by SpruceKit;
- app handoff, target opening, payload resolution, and recoverable return for
  SpruceKit, Marty Authenticator, LISSI, Sphereon, DC4EU, Google, and Apple;
- exact wallet build, platform, device model, and OS version for every native
  handoff;
- protected recordings/request capture and a native handoff matrix by actually
  downloading each HTTPS attachment and verifying its bytes against the recorded
  SHA-256. Signed URLs may be used; otherwise the same protected environment can
  provide `WALLET_EVIDENCE_BEARER_TOKEN`. Authorization is removed on cross-host
  redirects;
- the deterministic beta reports for membership, login, organization
  verification, renewal, status transitions, cross-organization denial, and
  fresh-organization primitive creation.

The historical nine wallet-selection targets are fully accounted for: the
generic `wr-default` handoff passes in the deterministic browser lane, seven
active app-specific targets require device evidence, and `wr-waltid-001` is an
explicit inactive external blocker. `wr-didcomm-001` is a push integration and
is tested as a service flow, not misclassified as a wallet handoff.

Only that workflow can publish `release-ready-manifest-<version>`. The promoted
manifest contains hashes and non-sensitive summaries, not holder email or raw
device evidence. It records the successful CD, beta lifecycle, and promotion run
IDs plus verified attachment kind, hash, and byte count; protected attachment
URLs are not copied into the release-ready manifest.

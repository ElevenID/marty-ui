/**
 * mDL Issuance Flow - End-to-End Tests
 * 
 * Comprehensive tests covering the full mDL (mobile Driver's License) issuance workflow:
 * 1. Org admin onboarding
 * 2. Admin enables and configures mDL application
 * 3. Applicant fills out application
 * 4. User onboards Marty Authenticator app (wallet pairing)
 * 5. Org admin issues mDL to user's auth app
 */
const { test, expect } = require('@playwright/test');
const path = require('path');
const { 
  AuthHelpers, 
  WalletBridge,
  DeviceRegistrationHelpers,
  PushNotificationHelpers,
  generateTestKeypair,
  signChallenge,
  getVendorOrganizationId,
  SEEDED_USERS 
} = require('../../utils/test-helpers');
const { SEEDED_ORGS, SEEDED_PASSWORDS } = require('../../fixtures/users');

const API_BASE = process.env.API_URL || 'http://localhost:8000';
const PORTRAIT_PATH = path.resolve(__dirname, '../../fixtures/test-portrait.jpg');

// Test data for mDL application
const MDL_APPLICATION_DATA = {
  firstName: 'Michael',
  lastName: 'Johnson',
  email: 'michael.johnson@test.marty.demo',
  dateOfBirth: '1988-05-15',
  address: {
    street: '456 Oak Avenue',
    city: 'Austin',
    state: 'TX',
    zip: '78701'
  },
  licenseClass: 'C',
  restrictions: 'none',
  documentNumber: 'DL' + Date.now().toString().slice(-8),
  expiryDate: '2030-12-31'
};

// mDL credential configuration
const MDL_CREDENTIAL_CONFIG = {
  type: 'org.iso.18013.5.1.mDL',
  namespace: 'org.iso.18013.5.1',
  validityDays: 365 * 4, // 4 years
  attributes: [
    'family_name',
    'given_name',
    'birth_date',
    'issue_date',
    'expiry_date',
    'issuing_country',
    'issuing_authority',
    'document_number',
    'portrait',
    'driving_privileges',
    'resident_address',
    'age_over_18',
    'age_over_21'
  ]
};

test.describe.serial('mDL Issuance Flow - Complete Workflow', () => {
  let auth;
  let walletBridge;
  let pushHelpers;
  let deviceHelpers;
  let vendorContext;
  let applicantContext;
  let applicationId;
  let applicationReference;
  let issuedDocumentNumber;
  let credentialConfigId;
  let organizationId;
  let applicantUserId;
  
  test.beforeAll(async ({ browser }) => {
    // Create separate browser contexts for vendor and applicant
    vendorContext = await browser.newContext();
    applicantContext = await browser.newContext();

    const page = await vendorContext.newPage();
    const adminAuth = new AuthHelpers(page);
    const vendorOrg = await getVendorOrganizationId(browser);
    organizationId = vendorOrg.organizationId;
    await page.goto('/');
    await adminAuth.loginAsSeededUser('admin');

    const listResponse = await page.request.get(
      `/api/organizations/${organizationId}/credential-types`
    );
    // Gracefully handle if endpoint fails - credential config may not exist yet
    if (listResponse.ok()) {
      const listData = await listResponse.json();
      const configs = listData.credential_types || [];
      const existing = configs.find((config) => config.credential_type === 'drivers_license');

      if (existing) {
        credentialConfigId = existing.id;
      } else {
        const createResponse = await page.request.post(
          `/api/organizations/${organizationId}/credential-types`,
          {
            data: {
              credential_type: 'drivers_license',
              display_name: 'Mobile Driver\'s License',
              validity_days: 365,
            },
          }
        );
        if (createResponse.ok()) {
          const created = await createResponse.json();
          credentialConfigId = created.credential_type?.id;
        }
      }
    }

    await page.close();
  });

  test.afterAll(async () => {
    await vendorContext?.close();
    await applicantContext?.close();
  });

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
    walletBridge = new WalletBridge(page);
    deviceHelpers = new DeviceRegistrationHelpers(page);
    pushHelpers = new PushNotificationHelpers(page, deviceHelpers);
  });

  test.describe('Step 1: Organization Admin Onboarding', () => {
    test('new org admin can complete onboarding wizard', async ({ page }) => {
      // Onboarding wizard with role selection and org details form
      const timestamp = Date.now();
      const newOrg = {
        name: `Test DMV ${timestamp}`,
        type: 'government',
        jurisdiction: 'US-TX',
        adminEmail: `admin-${timestamp}@test.marty.demo`
      };
      const testPassword = 'TestPassword123!';

      await page.goto('/');
      
      // Start onboarding - this redirects to Keycloak registration
      await page.click('[data-testid="get-started-btn"], button:has-text("Get Started")');
      
      // Complete Keycloak registration form
      await page.waitForSelector('#firstName, input[name="firstName"]', { timeout: 15000 });
      await page.fill('#firstName, input[name="firstName"]', 'Test');
      await page.fill('#lastName, input[name="lastName"]', 'Admin');
      await page.fill('#email, input[name="email"]', newOrg.adminEmail);
      await page.fill('#password, input[name="password"]', testPassword);
      await page.fill('#password-confirm, input[name="password-confirm"]', testPassword);
      await page.click('input[type="submit"], button[type="submit"]');
      
      // Wait for redirect back to app's onboarding page
      await page.waitForURL(url => !url.toString().includes('realms'), { timeout: 15000 });
      
      // Step 1: Select organization type (now on onboarding page)
      await expect(page.locator('[data-testid="role-selection"]')).toBeVisible({ timeout: 10000 });
      await page.click('[data-testid="role-issuer"], [data-testid="role-vendor"]');
      await page.click('[data-testid="continue-btn"], button:has-text("Continue")');
      
      // Step 2: Organization details - fill form and create org
      await expect(page.locator('text=Create Your Organization')).toBeVisible({ timeout: 10000 });
      
      // Fill organization name
      const orgNameInput = page.locator('input[placeholder*="Acme"]');
      await orgNameInput.fill(newOrg.name);
      
      // Select organization type - click dropdown then option
      await page.click('[role="combobox"]');
      await page.click('[role="option"]:has-text("Government")');
      await page.waitForTimeout(500); // Wait for dropdown to close
      
      // Fill jurisdiction
      const jurisdictionInput = page.locator('input[placeholder*="US-TX"]');
      await jurisdictionInput.fill(newOrg.jurisdiction);
      
      // Click create organization button
      await page.click('button:has-text("Create Organization")');
      
      // Step 3: Verify we reached dashboard or next step
      await page.waitForURL(/dashboard|vendor|admin|complete/i, { timeout: 30000 });
    });

    test('seeded vendor admin can login and access dashboard', async ({ page, baseURL }) => {
      // Navigate to app first
      await page.goto(baseURL || 'http://host.docker.internal:9080/');
      
      // Vendor admin login and dashboard access
      await auth.loginAsSeededUser('vendor');
      
      // Verify dashboard access
      await expect(page.getByRole('tab', { name: 'Dashboard' })).toBeVisible({ timeout: 10000 });
      await expect(page.getByRole('tab', { name: 'Applicants' })).toBeVisible();
      await expect(page.getByRole('tab', { name: 'Settings' })).toBeVisible();
      
      // Verify org info is displayed
      await expect(page.locator('body')).toContainText(SEEDED_USERS.vendor.email);
    });
  });

  // Step 2-5 tests require mDL configuration UI pages that are not yet implemented.
  // These tests are skipped pending completion of:
  // - /vendor/mdoc-config page for mDL credential configuration
  // - Multi-step application wizard with photo upload
  // - Wallet pairing flow with QR code generation
  // - Admin issuance workflow with applicant selection
  //
  // TODO: Remove .skip() when UI pages are implemented
  test.describe.skip('Step 2: Admin Enables and Configures mDL Application', () => {
    test('admin can enable mDL credential type', async ({ page }) => {
      // Enable mDL credential type in Settings
      await auth.loginAsSeededUser('vendor');
      
      // Navigate to mDoc configuration page
      await page.goto('/vendor/mdoc-config');
      
      // Find mDL and enable it
      await expect(page.locator('[data-testid="credential-type-mDL"]')).toBeVisible({ timeout: 10000 });
      
      const mdlToggle = page.locator('[data-testid="enable-mDL-toggle"]');
      const isEnabled = await mdlToggle.isChecked();
      
      if (!isEnabled) {
        await mdlToggle.click();
        await expect(page.locator('[data-testid="mDL-enabled-badge"]')).toBeVisible();
      }
      
      // Verify mDL is in the active credential types list
      await expect(page.locator('[data-testid="active-credential-types"]')).toContainText('mDL');
    });

    test('admin can configure mDL application form', async ({ page }) => {
      // Configure mDL application form in Form Builder
      await auth.loginAsSeededUser('vendor');
      
      // Navigate to mDoc configuration page
      await page.goto('/vendor/mdoc-config');
      await page.click('[data-testid="form-builder-tab"]');
      
      // Select mDL template
      await page.selectOption('[data-testid="credential-type-select"]', 'org.iso.18013.5.1.mDL');
      
      // Verify required fields are present
      const requiredFields = ['family_name', 'given_name', 'birth_date', 'portrait', 'document_number'];
      for (const field of requiredFields) {
        await expect(page.locator(`[data-testid="field-${field}"]`)).toBeVisible();
      }
      
      // Enable driving privileges section
      await page.click('[data-testid="toggle-driving-privileges"]');
      await expect(page.locator('[data-testid="field-driving_privileges"]')).toBeVisible();
      
      // Save configuration
      await page.click('[data-testid="save-form-config-btn"]');
      await expect(page.locator('[data-testid="config-saved-toast"]')).toBeVisible();
    });

    test('admin can configure mDL issuance policy', async ({ page }) => {
      // Configure mDL issuance policy
      await auth.loginAsSeededUser('vendor');
      
      // Navigate to mDoc configuration page
      await page.goto('/vendor/mdoc-config');
      await page.click('[data-testid="issuance-policy-tab"]');
      
      // Configure mDL validity period
      await page.fill('[data-testid="validity-years-input"]', '4');
      
      // Configure required verifications
      await page.check('[data-testid="require-identity-verification"]');
      await page.check('[data-testid="require-document-verification"]');
      
      // Configure auto-renewal settings
      await page.check('[data-testid="allow-renewal"]');
      await page.fill('[data-testid="renewal-window-days"]', '90');
      
      // Save policy
      await page.click('[data-testid="save-policy-btn"]');
      await expect(page.locator('[data-testid="policy-saved-toast"]')).toBeVisible();
    });
  });

  test.describe.skip('Step 3: Applicant Fills Out Application', () => {
    test('applicant can start mDL application', async ({ page }) => {
      // Start mDL application from /apply page
      await auth.loginAsSeededUser('applicant1');
      if (!applicantUserId) {
        const meResponse = await page.request.get('/auth/me');
        if (meResponse.ok()) {
          const meData = await meResponse.json();
          applicantUserId = meData?.user?.user_id || null;
          pushHelpers.setUserId(applicantUserId);
        }
      }
      
      // Navigate to apply page
      await page.goto(`/apply/${credentialConfigId}`);
      
      // Verify application form is displayed
      await expect(page.locator('[data-testid="credential-application-form"]')).toBeVisible();
      await expect(page.locator('h1, h2')).toContainText(/Mobile Driver.*License|mDL/i);
    });

    test('applicant can fill and submit mDL application', async ({ page, request }) => {
      // Fill and submit mDL application with multi-step wizard
      await auth.loginAsSeededUser('applicant1');
      await page.goto(`/apply/${credentialConfigId}`);
      
      // Wait for form to load
      await expect(page.locator('[data-testid="credential-application-form"]')).toBeVisible({ timeout: 10000 });
      
      // Step 1: Personal Information
      await page.fill('[data-testid="first-name-input"]', MDL_APPLICATION_DATA.firstName);
      await page.fill('[data-testid="last-name-input"]', MDL_APPLICATION_DATA.lastName);
      await page.fill('[data-testid="dob-input"]', MDL_APPLICATION_DATA.dateOfBirth);
      const emailInput = page.locator('[data-testid="email-input"]');
      if ((await emailInput.inputValue()) === '') {
        await emailInput.fill(MDL_APPLICATION_DATA.email);
      }
      await page.click('[data-testid="next-step-btn"]');
      
      // Step 2: Address Information
      await expect(page.locator('[data-testid="address-step"]')).toBeVisible();
      await page.fill('[data-testid="street-input"]', MDL_APPLICATION_DATA.address.street);
      await page.fill('[data-testid="city-input"]', MDL_APPLICATION_DATA.address.city);
      await page.selectOption('[data-testid="state-select"]', MDL_APPLICATION_DATA.address.state);
      await page.fill('[data-testid="zip-input"]', MDL_APPLICATION_DATA.address.zip);
      await page.click('[data-testid="next-step-btn"]');
      
      // Step 3: License Details
      await expect(page.locator('[data-testid="license-step"]')).toBeVisible();
      await page.selectOption('[data-testid="license-class-select"]', MDL_APPLICATION_DATA.licenseClass);
      await page.fill('[data-testid="document-number-input"]', MDL_APPLICATION_DATA.documentNumber);
      await page.click('[data-testid="next-step-btn"]');
      
      // Step 4: Photo Upload
      await expect(page.locator('[data-testid="photo-step"]')).toBeVisible();
      // Use test photo file
      const photoInput = page.locator('[data-testid="portrait-upload-input"]');
      await photoInput.setInputFiles(PORTRAIT_PATH);
      await expect(page.locator('[data-testid="photo-preview"]')).toBeVisible();
      await page.click('[data-testid="next-step-btn"]');
      
      // Step 5: Review and Submit
      await expect(page.locator('[data-testid="review-step"]')).toBeVisible();
      await expect(page.locator('[data-testid="review-first-name"]')).toContainText(MDL_APPLICATION_DATA.firstName);
      await expect(page.locator('[data-testid="review-last-name"]')).toContainText(MDL_APPLICATION_DATA.lastName);
      
      // Accept terms
      await page.check('[data-testid="accept-terms-checkbox"]');
      
      // Submit application
      await page.click('[data-testid="submit-application-btn"]');
      
      // Verify submission success
      await expect(page.locator('[data-testid="application-submitted"]')).toBeVisible({ timeout: 15000 });
      applicationId = await page.getAttribute('[data-testid="application-id"]', 'data-value');
      expect(applicationId).toBeTruthy();

      const detailResponse = await request.get(
        `${API_BASE}/api/applicants/applications/${applicationId}`
      );
      if (detailResponse.ok()) {
        const detailData = await detailResponse.json();
        applicationReference =
          detailData.application?.reference_number || detailData.reference_number || null;
      }
      
      // Store for later steps
      test.info().annotations.push({ type: 'applicationId', description: applicationId });
    });

    test('applicant can view application status', async ({ page }) => {
      // View application status in /my-applications
      await auth.loginAsSeededUser('applicant1');
      
      // Navigate to applications list
      await page.goto('/my-applications');
      
      // Verify application is listed
      await expect(page.locator('[data-testid="applications-table"]')).toBeVisible({ timeout: 10000 });
      if (applicationId) {
        const row = page.locator(`[data-testid="application-row-${applicationId}"]`);
        await expect(row).toBeVisible();
      }
    });
  });

  test.describe.skip('Step 4: User Onboards Marty Authenticator App', () => {
    test('user can start wallet pairing from web', async ({ page }) => {
      // SKIPPED: Requires /wallet/setup page with container and QR generation
      // TODO: Wire up WalletSetup component to this route
      await auth.loginAsSeededUser('applicant1');
      
      // Navigate to wallet setup
      await page.goto('/wallet/setup');
      
      // Verify wallet setup page
      await expect(page.locator('[data-testid="wallet-setup-page"]')).toBeVisible({ timeout: 10000 });
      await expect(page.locator('h1, h2')).toContainText(/Connect.*Wallet|Set Up.*Authenticator/i);
    });

    test('user can generate pairing QR code', async ({ page }) => {
      // SKIPPED: Requires QR code generation with data-testid attributes
      // TODO: Add data-testid to WalletSetup QR code element
      await auth.loginAsSeededUser('applicant1');
      await page.goto('/wallet/setup');
      
      // Refresh QR to ensure a pairing payload exists
      await page.click('[data-testid="refresh-qr-button"]');
      
      // Wait for QR code to be generated
      await expect(page.locator('[data-testid="pairing-qr-code"]')).toBeVisible({ timeout: 10000 });
      
      // Verify QR contains pairing data
      const qrData = await page.getAttribute('[data-testid="pairing-qr-code"]', 'data-value');
      expect(qrData).toBeTruthy();
      expect(qrData).toMatch(/marty:\/\/pair|openid-credential-offer/);
    });

    test('wallet can complete device registration', async ({ page }) => {
      // Generate a test user ID (in real flow, comes from auth)
      const testUserId = SEEDED_USERS.applicant1.email;
      pushHelpers.setUserId(testUserId);
      
      // Register device with backend (auto-generates keypair)
      const registrationResult = await deviceHelpers.registerDevice(testUserId, {
        platform: 'ios',
        deviceModel: 'iPhone 15 Pro',
        osVersion: '17.0'
      });
      
      expect(registrationResult.device_id).toBeTruthy();
      expect(registrationResult.keypair).toBeTruthy();
      
      const deviceId = registrationResult.deviceId;
      
      // Create a push challenge to verify device
      const challengeResult = await pushHelpers.createPushChallenge(deviceId, {
        title: 'Verify device',
        question: 'Approve this device registration',
        ttl_seconds: 300,
        data: { action: 'verify_device' }
      });
      expect(challengeResult.challenge_id).toBeTruthy();
      expect(challengeResult.nonce).toBeTruthy();
      
      // Sign and respond to challenge
      const signature = deviceHelpers.signChallengeForDevice(deviceId, challengeResult.nonce);
      expect(signature).toBeTruthy();
      
      const responseResult = await pushHelpers.respondToChallenge(
        deviceId,
        challengeResult.challenge_id,
        'accept',
        challengeResult.nonce,
        signature
      );
      
      expect(responseResult.success).toBe(true);
    });

    test('wallet can pair with user account', async ({ page }) => {
      await auth.loginAsSeededUser('applicant1');
      await page.goto('/wallet/setup');

      await expect(page.locator('[data-testid="pairing-qr-code"]')).toBeVisible({ timeout: 10000 });
      await page.click('[data-testid="simulate-pairing-button"]');
      await expect(page.locator('[data-testid="wallet-connected-alert"]')).toBeVisible({ timeout: 10000 });
    });

    test('user can enable push notifications', async ({ page }) => {
      await auth.loginAsSeededUser('applicant1');
      await page.context().grantPermissions(['notifications']);
      
      // Navigate to notification settings
      await page.goto('/settings/notifications');
      
      await expect(page.locator('[data-testid="notification-preferences-page"]')).toBeVisible({ timeout: 10000 });
      
      const pushToggle = page.locator('[data-testid="push-master-toggle"] input');
      if (!(await pushToggle.isChecked())) {
        const registerResponse = page.waitForResponse(
          (response) =>
            response.url().includes('/api/devices/register') && response.ok()
        );
        await page.click('[data-testid="push-master-toggle"]');
        await registerResponse;
      }
      
      await expect(page.locator('[data-testid="notification-snackbar"]')).toBeVisible({ timeout: 10000 });
    });
  });

  test.describe.skip('Step 5: Org Admin Issues mDL to User', () => {
    test('admin can view pending applications', async ({ page }) => {
      await auth.loginAsSeededUser('admin');
      await page.goto('/applicants');
      
      await expect(page.locator('[data-testid="applications-table"]')).toBeVisible({ timeout: 10000 });
      expect(applicationId).toBeTruthy();
      const row = page.locator(`[data-testid="application-row-${applicationId}"]`);
      await expect(row).toBeVisible({ timeout: 10000 });
    });

    test('admin can review and approve mDL application', async ({ page }) => {
      await auth.loginAsSeededUser('admin');
      await page.goto('/applicants');
      
      expect(applicationId).toBeTruthy();
      const row = page.locator(`[data-testid="application-row-${applicationId}"]`);
      await expect(row).toBeVisible({ timeout: 10000 });
      await row.locator('[data-testid="view-application-btn"]').click();
      
      await expect(page.locator('[data-testid="application-detail-view"]')).toBeVisible({ timeout: 10000 });
      
      let pendingChecks = page.locator('[data-testid^="check-pass-btn-"]');
      while (await pendingChecks.count()) {
        await pendingChecks.first().click();
        await page.waitForTimeout(300);
        pendingChecks = page.locator('[data-testid^="check-pass-btn-"]');
      }
      
      await page.locator('[data-testid="application-detail-view"] button:has-text("Close")').click();
      
      await expect(row.locator('[data-testid="approve-application-btn"]')).toBeVisible({ timeout: 10000 });
      await row.locator('[data-testid="approve-application-btn"]').click();
      
      await expect(page.locator('[data-testid="approval-dialog"]')).toBeVisible({ timeout: 10000 });
      await page.fill('[data-testid="approval-notes"]', 'Documents verified. All requirements met.');
      await page.click('[data-testid="confirm-approval-btn"]');
      
      await expect(page.locator('[data-testid="approval-dialog"]')).toBeHidden({ timeout: 10000 });
    });

    test('admin can issue mDL credential', async ({ page }) => {
      await auth.loginAsSeededUser('admin');
      if (applicantUserId) {
        pushHelpers.setUserId(applicantUserId);
        await pushHelpers.clearAllNotifications();
      }
      
      expect(applicationId).toBeTruthy();
      await page.goto('/documents');
      await page.click('[data-testid="issue-document-button"]');
      
      await expect(page.locator('[data-testid="issue-document-dialog"]')).toBeVisible({ timeout: 10000 });
      await page.click('[data-testid="issue-tab-applicant"]');
      
      await page.click(
        '[data-testid="approved-applicant-select"] [role="combobox"], ' +
          '[data-testid="approved-applicant-select"] [role="button"]'
      );
      await page.click(`li[data-value="${applicationId}"]`);
      
      issuedDocumentNumber = `DL${Date.now().toString().slice(-8)}`;
      await page.fill('[data-testid="issue-document-number"]', issuedDocumentNumber);
      
      await page.click('[data-testid="confirm-issue-document"]');
      
      await expect(page.locator('[data-testid="documents-success-snackbar"]')).toBeVisible({ timeout: 30000 });
      await expect(page.locator('[data-testid="issue-document-dialog"]')).toBeHidden({ timeout: 10000 });
    });

    test('user receives credential in wallet via push notification', async ({ page }) => {
      expect(applicationId).toBeTruthy();
      if (applicantUserId) {
        pushHelpers.setUserId(applicantUserId);
      }
      await expect.poll(async () => {
        const notifications = await pushHelpers.getNotificationsByEventType('credential_offer');
        return notifications.find(
          (n) => n.data?.application_id === applicationId || n.data?.document_id
        );
      }, { timeout: 15000 }).toBeTruthy();
    });

    test('user can view issued credential in wallet', async ({ page }) => {
      await auth.loginAsSeededUser('applicant1');
      expect(issuedDocumentNumber).toBeTruthy();
      await page.goto('/my-documents');
      
      await expect(page.locator('[data-testid="my-documents-page"]')).toBeVisible({ timeout: 10000 });
      await expect(page.locator('[data-testid="document-number"]')).toContainText(issuedDocumentNumber, { timeout: 15000 });
    });
  });

  test.describe.skip('Full Flow Integration', () => {
    test.skip('complete mDL issuance flow from application to wallet', async ({ browser }) => {
      // SKIPPED: Requires all individual components to be implemented first
      // This test will be enabled when all Step 1-5 tests pass
      // Create separate contexts for vendor and applicant
      const vendorPage = await vendorContext.newPage();
      const applicantPage = await applicantContext.newPage();
      const vendorAuth = new AuthHelpers(vendorPage);
      const applicantAuth = new AuthHelpers(applicantPage);
      
      try {
        const testData = {
          firstName: 'IntegrationTest',
          lastName: 'User' + Date.now(),
          email: `integration-${Date.now()}@test.marty.demo`,
          dob: '1990-01-15'
        };
        
        // === STEP 1: Applicant submits application ===
        await applicantAuth.loginAsSeededUser('applicant1');
        await applicantPage.goto(`/apply/${credentialConfigId}`);
        
        await applicantPage.fill('[data-testid="first-name-input"]', testData.firstName);
        await applicantPage.fill('[data-testid="last-name-input"]', testData.lastName);
        await applicantPage.fill('[data-testid="dob-input"]', testData.dob);
        
        // Complete minimal required fields
        await applicantPage.click('[data-testid="next-step-btn"]');
        await applicantPage.fill('[data-testid="street-input"]', '123 Test St');
        await applicantPage.fill('[data-testid="city-input"]', 'Austin');
        await applicantPage.selectOption('[data-testid="state-select"]', 'TX');
        await applicantPage.fill('[data-testid="zip-input"]', '78701');
        await applicantPage.click('[data-testid="next-step-btn"]');
        
        await applicantPage.selectOption('[data-testid="license-class-select"]', 'C');
        await applicantPage.fill('[data-testid="document-number-input"]', 'DL' + Date.now());
        await applicantPage.click('[data-testid="next-step-btn"]');
        
        // Skip photo for integration test (use default)
        await applicantPage.click('[data-testid="skip-photo-btn"], [data-testid="next-step-btn"]');
        
        await applicantPage.check('[data-testid="accept-terms-checkbox"]');
        await applicantPage.click('[data-testid="submit-application-btn"]');
        
        await expect(applicantPage.locator('[data-testid="application-submitted"]')).toBeVisible({ timeout: 15000 });
        const applicationId = await applicantPage.getAttribute('[data-testid="application-id"]', 'data-value');
        expect(applicationId).toBeTruthy();
        
        // === STEP 2: Applicant sets up wallet ===
        await applicantPage.goto('/wallet/setup');
        await applicantPage.click('[data-testid="generate-pairing-qr-btn"]');
        const pairingData = await applicantPage.getAttribute('[data-testid="pairing-qr-code"]', 'data-value');
        
        // Simulate wallet pairing (in real flow, mobile app would scan)
        const keypair = generateTestKeypair();
        const deviceId = `device-${Date.now()}`;
        
        const meResponse = await applicantPage.request.get('/auth/me');
        const meData = meResponse.ok() ? await meResponse.json() : null;
        const applicantUserId = meData?.user?.user_id;

        // Register device via API
        const apiResponse = await applicantPage.evaluate(async ({ deviceId, publicKey, apiUrl, userId }) => {
          const response = await fetch(`${apiUrl}/api/devices/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-User-ID': userId },
            body: JSON.stringify({
              device_id: deviceId,
              public_key: publicKey,
              platform: 'ios',
              fcm_token: `push-${deviceId}`,
              app_version: '1.0.0-test'
            })
          });
          return response.json();
        }, { 
          deviceId, 
          publicKey: keypair.publicKeyDerBase64,
          apiUrl: process.env.API_URL || 'http://localhost:8000',
          userId: applicantUserId,
        });
        
        expect(apiResponse.success).toBe(true);
        
        // === STEP 3: Vendor approves and issues credential ===
        await vendorAuth.loginAsSeededUser('vendor');
        await vendorPage.goto(`/admin/applications/${applicationId}`);
        
        // Approve application
        await vendorPage.click('[data-testid="approve-application-btn"]');
        await vendorPage.fill('[data-testid="approval-notes"]', 'Integration test approval');
        await vendorPage.click('[data-testid="confirm-approval-btn"]');
        await expect(vendorPage.locator('[data-testid="approval-success"]')).toBeVisible({ timeout: 10000 });
        
        // Issue credential
        await vendorPage.click('[data-testid="issue-credential-btn"]');
        await vendorPage.selectOption('[data-testid="credential-type-select"]', MDL_CREDENTIAL_CONFIG.type);
        await vendorPage.click('[data-testid="confirm-issue-btn"]');
        
        await expect(vendorPage.locator('[data-testid="credential-issued-success"]')).toBeVisible({ timeout: 30000 });
        const credentialId = await vendorPage.getAttribute('[data-testid="credential-id"]', 'data-value');
        expect(credentialId).toBeTruthy();
        
        // === STEP 4: Verify credential was sent to wallet ===
        // Check push notification was queued
        const pushResult = await vendorPage.evaluate(async ({ deviceId, apiUrl, userId }) => {
          const response = await fetch(`${apiUrl}/api/notifications?user_id=${encodeURIComponent(userId)}`);
          return response.json();
        }, { deviceId, userId: applicantUserId, apiUrl: process.env.API_URL || 'http://localhost:8000' });
        
        const credentialNotification = pushResult.notifications?.find(
          n => n.type === 'CREDENTIAL_OFFER'
        );
        expect(credentialNotification).toBeTruthy();
        
        // === STEP 5: Applicant sees issued credential ===
        await applicantPage.goto('/my-credentials');
        await expect(applicantPage.locator('[data-testid="credential-card-mdl"]')).toBeVisible({ timeout: 15000 });
        await expect(applicantPage.locator('[data-testid="credential-status-active"]')).toBeVisible();
        
        console.log('✅ Complete mDL issuance flow succeeded');
        console.log(`   Application ID: ${applicationId}`);
        console.log(`   Credential ID: ${credentialId}`);
        console.log(`   Device ID: ${deviceId}`);
        
      } finally {
        await vendorPage.close();
        await applicantPage.close();
      }
    });
  });
});

// =============================================================================
// Additional Helper Functions
// =============================================================================

/**
 * Wait for element with better error messages
 */
async function waitForElement(page, selector, options = {}) {
  const { timeout = 10000, state = 'visible' } = options;
  try {
    await page.waitForSelector(selector, { timeout, state });
  } catch (error) {
    throw new Error(`Element not found: ${selector} (waited ${timeout}ms for state: ${state})`);
  }
}

/**
 * Login helper with error handling
 */
async function loginAs(page, email, password) {
  const auth = new AuthHelpers(page);
  await auth.login(email, password);
}

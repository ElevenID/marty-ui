// Test utilities and helpers
const { expect } = require('@playwright/test');
const crypto = require('crypto');
const { SEEDED_USERS, SEEDED_PASSWORDS, SEEDED_ORGS, getUserByRole, generateTestUser } = require('../fixtures/users');
const { AuthenticatedApiClient } = require('./api-client');
const { CredentialDataBuilder, UserDataBuilder, MockResponses } = require('./test-data-builders');

// =============================================================================
// EventWaiter - SSE Event Listener for Test Observability
// =============================================================================

/**
 * EventWaiter subscribes to SSE events for event-driven testing.
 * Replaces polling patterns with real-time event listening.
 * 
 * Usage:
 *   const waiter = new EventWaiter(page);
 *   await waiter.waitForEvent('credential.issued', { application_id: '123' });
 * 
 * Events emitted by backend:
 *   - application.approved
 *   - credential.issued
 *   - check.completed
 *   - device.registered
 */
class EventWaiter {
  constructor(page, apiUrl = process.env.API_BASE_URL || 'http://localhost:8000') {
    this.page = page;
    this.apiUrl = apiUrl;
    this.activeConnections = new Map();
  }

  /**
   * Wait for a specific SSE event.
   * 
   * @param {string} eventType - Event type to wait for (e.g., 'credential.issued')
   * @param {object} filter - Optional filter for event data fields
   * @param {number} timeout - Timeout in milliseconds (default: 30000)
   * @param {string} deviceId - Optional device ID for SSE connection
   * @returns {Promise<object>} Event data when received
   */
  async waitForEvent(eventType, filter = {}, timeout = 30000, deviceId = null) {
    const EventSource = require('eventsource');
    const effectiveDeviceId = deviceId || `test-waiter-${Date.now()}`;
    
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        if (es) es.close();
        reject(new Error(`Timeout waiting for event: ${eventType} after ${timeout}ms`));
      }, timeout);

      const es = new EventSource(`${this.apiUrl}/api/events/push?device_id=${effectiveDeviceId}`);
      this.activeConnections.set(effectiveDeviceId, es);
      
      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          // Check if event type matches
          if (data.type === eventType || data.event_type === eventType) {
            // Check filter conditions
            if (this._matchesFilter(data.data, filter)) {
              clearTimeout(timeoutId);
              es.close();
              this.activeConnections.delete(effectiveDeviceId);
              resolve(data);
            }
          }
        } catch (e) {
          console.log('SSE parse error:', e);
        }
      };
      
      es.onerror = (err) => {
        clearTimeout(timeoutId);
        es.close();
        this.activeConnections.delete(effectiveDeviceId);
        reject(new Error(`SSE connection failed: ${err.message || 'Unknown error'}`));
      };
    });
  }

  /**
   * Wait for multiple events in sequence.
   * 
   * @param {Array<{eventType: string, filter?: object, timeout?: number}>} events
   * @returns {Promise<Array<object>>} Array of event data
   */
  async waitForEvents(events) {
    const results = [];
    for (const event of events) {
      const data = await this.waitForEvent(
        event.eventType,
        event.filter || {},
        event.timeout || 30000
      );
      results.push(data);
    }
    return results;
  }

  /**
   * Close all active SSE connections (cleanup).
   */
  closeAll() {
    for (const [deviceId, es] of this.activeConnections.entries()) {
      try {
        es.close();
      } catch (e) {
        console.log(`Error closing SSE connection ${deviceId}:`, e);
      }
    }
    this.activeConnections.clear();
  }

  /**
   * Check if event data matches filter conditions.
   * @private
   */
  _matchesFilter(data, filter) {
    if (!filter || Object.keys(filter).length === 0) {
      return true;
    }
    
    for (const [key, value] of Object.entries(filter)) {
      if (data[key] !== value) {
        return false;
      }
    }
    return true;
  }
}

// =============================================================================
// RSA Key Utilities for Push Challenge Signing
// =============================================================================

/**
 * Generate an RSA keypair for testing push challenges.
 * Returns keypair with PEM-encoded keys and DER-encoded public key for API.
 */
function generateTestKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  
  // Export public key as DER for API registration
  const publicKeyDer = crypto.createPublicKey(publicKey).export({
    type: 'pkcs1',
    format: 'der',
  });
  
  // Compute key ID as first 16 chars of SHA-256 hex digest (per RFC 7638)
  const keyId = crypto.createHash('sha256').update(publicKeyDer).digest('hex').substring(0, 16);
  
  return {
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    publicKeyDerBase64: publicKeyDer.toString('base64'),
    keyId,
  };
}

/**
 * Sign a challenge nonce using RSA PKCS#1 SHA-256.
 * @param {string} privateKeyPem - PEM-encoded private key
 * @param {string} nonce - Challenge nonce to sign
 * @returns {string} Base64-encoded signature
 */
function signChallenge(privateKeyPem, nonce) {
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(nonce);
  sign.end();
  return sign.sign(privateKeyPem, 'base64');
}

class DemoTestHelpers {
  constructor(page) {
    this.page = page;
  }

  // Navigation helpers
  async navigateToTab(tabName) {
    await this.page.click(`text=${tabName}`);
    await this.page.waitForLoadState('networkidle');
  }

  async waitForPageLoad() {
    await this.page.waitForLoadState('domcontentloaded');
    await this.page.waitForLoadState('networkidle');
  }

  // Common UI interaction helpers
  async fillFormField(label, value) {
    await this.page.fill(`[aria-label="${label}"], [placeholder*="${label}"], input[name*="${label.toLowerCase()}"]`, value);
  }

  async clickButton(buttonText) {
    await this.page.click(`button:has-text("${buttonText}")`);
  }

  async waitForAlert(type = 'success') {
    await this.page.waitForSelector(`[role="alert"]:has-text("${type}"), .MuiAlert-${type}`);
  }

  async waitForApiCall(urlPattern) {
    return this.page.waitForResponse(response =>
      response.url().includes(urlPattern) &&
      response.status() === 200
    );
  }

  // Enhanced features helpers
  async selectAgeVerificationUseCase(useCase) {
    await this.page.click('[role="button"]:has-text("Use Case")');
    await this.page.click(`[role="option"]:has-text("${useCase}")`);
  }

  async verifyQRCodeGenerated() {
    await this.page.waitForSelector('img[alt*="QR"], canvas');
    const qrElement = await this.page.locator('img[alt*="QR"], canvas').first();
    await expect(qrElement).toBeVisible();
  }

  async expandAccordion(title) {
    await this.page.click(`[aria-expanded="false"]:has-text("${title}")`);
  }

  async verifyCardContent(cardTitle, expectedContent) {
    const card = this.page.locator('.MuiCard-root').filter({ hasText: cardTitle });
    await expect(card).toContainText(expectedContent);
  }

  // API response validation helpers
  async mockApiResponse(url, response) {
    await this.page.route(url, route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response)
      });
    });
  }

  async verifyApiCall(urlPattern, expectedPayload = null) {
    const [request] = await Promise.all([
      this.page.waitForRequest(request => request.url().includes(urlPattern)),
      // Trigger action that makes the API call
    ]);

    if (expectedPayload) {
      const payload = request.postDataJSON();
      expect(payload).toMatchObject(expectedPayload);
    }

    return request;
  }

  // Assertion helpers
  async verifySuccessMessage(message) {
    await expect(this.page.locator('.MuiAlert-success')).toContainText(message);
  }

  async verifyErrorMessage(message) {
    await expect(this.page.locator('.MuiAlert-error')).toContainText(message);
  }

  async verifyChipStatus(status, color) {
    const chip = this.page.locator(`.MuiChip-${color}:has-text("${status}")`);
    await expect(chip).toBeVisible();
  }

  async verifyTableRow(rowText) {
    await expect(this.page.locator('tr').filter({ hasText: rowText })).toBeVisible();
  }

  // Screenshot helpers for visual testing
  async takeScreenshot(name) {
    await this.page.screenshot({
      path: `test-results/screenshots/${name}.png`,
      fullPage: true
    });
  }

  async compareScreenshot(name) {
    await expect(this.page).toHaveScreenshot(`${name}.png`);
  }
}

// Mock data for testing
const mockCredentialData = {
  given_name: 'Jane',
  family_name: 'Doe',
  birth_date: '1990-01-01',
  document_number: 'DL123456789',
  issuing_country: 'XX',
  issuing_authority: 'Demo DMV',
  expiry_date: '2030-01-01'
};

const mockVerifiablePresentation = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiablePresentation"],
  "verifiableCredential": [{
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "mDL"],
    "issuer": "did:example:issuer",
    "issuanceDate": new Date().toISOString(),
    "credentialSubject": mockCredentialData
  }]
};

const mockApiResponses = {
  issuerSuccess: {
    success: true,
    credential: {
      id: 'cred_123456',
      type: 'mDL',
      format: 'mso_mdoc',
      created_at: new Date().toISOString()
    }
  },

  verifierSuccess: {
    success: true,
    verified: true,
    checks: [
      { check_name: 'Signature Verification', passed: true, details: 'Valid signature' },
      { check_name: 'Certificate Chain', passed: true, details: 'Valid certificate chain' },
      { check_name: 'Expiry Check', passed: true, details: 'Credential not expired' }
    ],
    presentation_summary: {
      holder: 'Jane Doe',
      credential_type: 'mDL',
      attributes_shared: ['given_name', 'family_name', 'age_over_21']
    }
  },

  ageVerificationSuccess: {
    verification_result: {
      verified: true,
      age_requirement_met: true,
      use_case: 'alcohol_purchase'
    },
    privacy_report: {
      privacy_level: 'high',
      attributes_disclosed: ['age_over_21'],
      attributes_protected: ['birth_date', 'exact_age'],
      zero_knowledge_proof_used: true
    }
  },

  offlineQRSuccess: {
    success: true,
    offline_qr: {
      qr_code_data: 'mock_cbor_data',
      qr_code_image: 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAU...', // Mock base64
      size_bytes: 1024,
      expires_at: new Date(Date.now() + 3600000).toISOString()
    }
  },

  certificateDashboard: {
    overview: {
      total_certificates: 5,
      critical_alerts: 1,
      certificates_needing_renewal: 2,
      expired_certificates: 0
    },
    certificates: [
      {
        certificate_id: 'dsc_001',
        common_name: 'Demo DMV DSC',
        status: 'critical',
        days_until_expiry: 7,
        issuer: 'Demo Root CA'
      },
      {
        certificate_id: 'dsc_002',
        common_name: 'Test Authority DSC',
        status: 'expiring_soon',
        days_until_expiry: 25,
        issuer: 'Test Root CA'
      }
    ]
  },

  policyEvaluation: {
    recommended_action: 'approve',
    disclosed_attributes: ['given_name', 'age_over_21'],
    protected_attributes: ['birth_date', 'address', 'document_number'],
    privacy_score: 0.85,
    rationale: 'Commercial context with verified business, minimal data disclosure approved'
  }
};

module.exports = {
  DemoTestHelpers,
  mockCredentialData,
  mockVerifiablePresentation,
  mockApiResponses,
};

// =============================================================================
// Authentication Helpers
// =============================================================================

class AuthHelpers {
  constructor(page) {
    this.page = page;
    this.frame = null; // Can be bound to a specific frame
    this.keycloakUrl = process.env.KEYCLOAK_URL || 'http://localhost:8180';
  }

  /**
   * Create a new AuthHelpers instance bound to a frame
   * @param {import('@playwright/test').FrameLocator} frameLocator 
   */
  withFrame(frameLocator) {
    const instance = new AuthHelpers(this.page);
    instance.frame = frameLocator;
    return instance;
  }

  // Helper to get page or frame
  get _target() {
    return this.frame || this.page;
  }

  /**
   * Login with a seeded user
   * @param {string} userType - 'admin', 'vendor', 'applicant1', 'applicant2', 'applicant3'
   * @param {object} options - Login options
   * @param {boolean} options.uiOnboarding - Use UI-based onboarding instead of API
   */
  async loginAsSeededUser(userType, options = {}) {
    const user = SEEDED_USERS[userType];
    if (!user) {
      throw new Error(`Unknown seeded user type: ${userType}`);
    }
    await this.login(user.email, user.password);
    
    // Vendor specific onboarding
    if (userType === 'vendor') {
      if (options.uiOnboarding) {
        // Just verify we're not stuck on Keycloak, let fixture handle UI detection
        await this.page.waitForTimeout(1000);
      } else {
        // API-based quick onboarding (legacy mode)
        const { updated } = await this.ensureVendorOrganization({
          organizationName: user.organization,
        });
        if (updated) {
          const target = this._target;
          target.goto ? await target.goto('/') : await this.page.goto('/');
          await this.page.waitForLoadState('networkidle');
        }
      }
    }
  }

  /**
   * Login with email and password via Keycloak
   */
  async login(email, password) {
    const target = this._target;
    
    // Wait for app to hydrate/load at least the root or something
    try {
        await target.locator('#root, [data-testid="onboarding-page"], #kc-form-login').first().waitFor({ state: 'attached', timeout: 15000 });
    } catch {
        console.log('Timeout waiting for any app content to attach.');
    }

    // Smart Wait: Wait for EITHER "Logged In" state OR "Login Form" state
    const loggedInMarker = target.locator('[data-testid="logout-button"], [data-testid="onboarding-page"], [data-testid="nav-tab-dashboard"], button:has-text("Logout")');
    const loginFormMarker = target.locator('#username, #kc-form-login, button:has-text("Sign In to Continue"), button:has-text("Login")');

    try {
        console.log('Login: Waiting for recognizable state...');
        await loggedInMarker.or(loginFormMarker).first().waitFor({ state: 'visible', timeout: 30000 });
        console.log('Login: Recognizable state found.');
    } catch (e) {
        console.log('Timeout waiting for any recognizable state (Login or Dashboard)');
    }

    // 1. Check if already logged in (Optimized with shorter waits)
    // Reduced iterations with faster checks for better performance
    for (let i = 0; i < 10; i++) {
        const isOnboarding = (await target.locator('[data-testid="onboarding-page"]').count()) > 0;
        const isLogoutVisible = (await target.locator('[data-testid="logout-button"]').count()) > 0;
        const isLogoutText = (await target.locator('button:has-text("Logout")').count()) > 0;
        const isDashboard = (await target.locator('[data-testid="nav-tab-dashboard"]').count()) > 0;
        
        if (i === 0 || i === 4 || i === 9) {
            console.log(`Login Status Check (Attempt ${i+1}/10): Onboarding=${isOnboarding}, LogoutBtn=${isLogoutVisible}, LogoutText=${isLogoutText}, Dashboard=${isDashboard}`);
        }

        if (isOnboarding || isLogoutVisible || isLogoutText || isDashboard) {
            console.log('Already logged in (state detected), skipping login.');
            return;
        }

        // If we found the ACTUAL Keycloak login form, we can break early.
        if (await target.locator('#username, #kc-form-login').count() > 0) {
            console.log('Keycloak Login form detected (stable), proceeding to login...');
            break;
        }
        await this.page.waitForTimeout(200);  // Reduced from 500ms to 200ms
    }
      
    // 2. Navigate/Login Logic
    // Navigate to login if not already there - handle both Page and Frame context
    try {
      // Click login button in app - support multiple button text variations
      const loginBtn = target.locator('button:has-text("Sign In to Continue"), button:has-text("Login"), button:has-text("Sign In"), a:has-text("Login")').first();
      // Wait briefly for login button - we might already be on the login page
      // Use count instead of isVisible to avoid waiting if it's not there
      if ((await loginBtn.count()) > 0 && (await loginBtn.isVisible({ timeout: 2000 }))) {
        console.log('Clicking Landing Page Login Button...');
        await loginBtn.click();
      }
    } catch (e) {
      // Ignore navigation errors
    }

    // Wait for EITHER Keycloak login form OR App Logged In state
    // This handles scenarios where "Sign In" click triggers an auto-login/redirect (SSO)
    // skipping the Keycloak input screens.
    console.log('Waiting for Keycloak Form OR Authenticated State...');
    const keycloakSelector = '#username, [data-testid="username"], input[name="username"], input[type="email"]';
    const appSelector = '[data-testid="onboarding-page"], [data-testid="logout-button"]';
    
    try {
        await target.locator(`${keycloakSelector}, ${appSelector}`).first().waitFor({ state: 'visible', timeout: 15000 });
        
        // Check what we found
        if ((await target.locator(appSelector).count()) > 0) {
             console.log('Detected Authenticated State (Auto-Login/SSO). Skipping credentials.');
             return; // Success!
        }
        console.log('Detected Keycloak Form. Proceeding with credentials...');

    } catch (e) {
        // Debugging: Log the page content if waiting fails
        console.log('Timeout waiting for login form OR app state. Current frame content:');
        console.log(await target.locator('body').innerHTML().catch(() => 'Could not get body content'));
        throw e;
    }

    // Check if we have a two-step flow (only email field visible)
    try {
        // Need to wait for username to be strictly visible before typing
        await target.locator('#username, [data-testid="username"], input[name="username"], input[type="email"]').first().waitFor({ state:'visible', timeout: 5000 });
    } catch(e) {
        // If we are here, something is wrong, but we let the loop below crash naturally or try to recover
    }

    const passwordFieldVisible = await target.locator('#password').isVisible().catch(() => false);
    
    if (passwordFieldVisible) {
      // Classic login form - username and password together
      await target.locator('#username').fill(email);
      await target.locator('#password').fill(password);
      await target.locator('#kc-login, button[type="submit"]').click();
    } else {
      // Two-step login flow - email first, then password
      const emailInput = target.locator('#username, input[type="email"], input[name="username"]').first();
      await emailInput.fill(email);
      
      // Click Sign In / Next to proceed to password step
      await target.locator('button:has-text("Sign In"), button:has-text("Next"), button[type="submit"], #kc-login').click();
      
      // Wait for password field to appear
      await target.locator('#password, input[type="password"]').first().waitFor({ timeout: 15000 });
      await target.locator('#password, input[type="password"]').fill(password);
      await target.locator('button:has-text("Sign In"), button[type="submit"], #kc-login').click();
    }

    // Wait for redirect back to app
    // Note: Frame URL checks are tricky, relying on element visibility instead
    try {
      await expect(target.locator('#username')).not.toBeVisible({ timeout: 15000 });
      await this.page.waitForLoadState('networkidle');
    } catch (e) {
      // Best effort wait
    }
  }

  /**
   * Detect current onboarding step from UI
   * @returns {Promise<string>} 'user-type' | 'org-name' | 'complete' | 'none'
   */
  async detectOnboardingStep() {
    const target = this._target;
    try {
      console.log('Checking for onboarding state...');
      // Priority 1: Check for Onboarding Page explicitly. Use first() to match login logic.
      const onboardingPage = target.locator('[data-testid="onboarding-page"]').first();
      // Increase timeout slightly more
      if (await onboardingPage.isVisible({ timeout: 5000 }).catch(() => false)) {
          console.log('Onboarding page detected.');
          // ...
          // Check for specific steps
          if (await target.getByText('Choose Your Role').isVisible().catch(() => false) ||
              await target.getByText('Select User Type').isVisible().catch(() => false)) {
              return 'user-type';
          }
          
          if (await target.getByText('Organization Settings').isVisible().catch(() => false) ||
              await target.locator('[data-testid="vendor-create-org-step"]').isVisible().catch(() => false) ||
              await target.getByLabel(/organization name/i).isVisible().catch(() => false)) {
              return 'org-name';
          }
          
          return 'user-type';
      }

      // Check for User Type selection (Legacy check)
      if (await target.getByText('Select User Type').isVisible().catch(() => false)) {
        return 'user-type';
      }
      
      // Check for Dashboard (complete) - Strong Signal
      if (await target.getByRole('tab', { name: 'Dashboard' }).isVisible().catch(() => false)) {
        console.log('Dashboard detected (Complete).');
        return 'complete';
      }
      
      // Check for Organization Name entry (Legacy check)
      if (await target.getByLabel(/organization name/i).isVisible().catch(() => false)) {
        return 'org-name';
      }
      
      console.log('No onboarding or dashboard detected. Dumping frame content (2000 chars):');
      const body = await target.locator('body').innerHTML().catch(e => `Failed to get body: ${e.message}`);
      console.log(body.substring(0, 2000)); 
      
      return 'none';
    } catch (e) {
      console.log('Error in detectOnboardingStep:', e);
      return 'none';
    }
  }

  /**
   * Complete onboarding via UI interactions
   * @param {string} userType - 'vendor' or 'applicant'
   * @returns {Promise<object>} Result with organization name/id
   */
  async completeOnboardingViaUI(userType) {
    const target = this._target;
    let step = await this.detectOnboardingStep();
    let orgName = `Auto Org ${Date.now()}`;
    
    // Step 1: User Type
    if (step === 'user-type') {
      console.log(`Onboarding: Selecting ${userType} role`);
      // Relaxed selector: Check for button role OR just text (Material UI cards often use divs)
      if (userType === 'vendor') {
        const vendorBtn = target.getByRole('button', { name: /vendor|issuer|organization/i })
            .or(target.getByText(/vendor|issuer/i))
            .first();
        await vendorBtn.click();
      } else {
        const applicantBtn = target.getByRole('button', { name: /applicant|user|holder/i })
            .or(target.getByText(/applicant|user|holder/i))
            .first();
        await applicantBtn.click();
      }
      
      // Click continue/next if present
      const nextBtn = target.getByRole('button', { name: /continue|next/i });
      try {
        if (await nextBtn.isVisible({ timeout: 2000 })) {
            await nextBtn.click();
        }
      } catch (e) {
        // Ignore if no next button needed (direct selection)
      }
      
      await this.page.waitForTimeout(1000); // Wait for transition
      step = await this.detectOnboardingStep();
    }
    
    // Step 2: Org Name (Vendor only)
    if (step === 'org-name' && userType === 'vendor') {
      console.log(`Onboarding: Entering org name ${orgName}`);
      const orgInput = target.getByLabel(/organization name/i);
      if (await orgInput.isEditable()) {
        await orgInput.fill(orgName);
      } else {
        console.log('Onboarding: Org name input is disabled, skipping fill.');
      }
      
      const submitBtn = target.getByRole('button', { name: /complete|finish|create|save/i });
      await submitBtn.click();
      
      await this.page.waitForTimeout(2000); // Wait for API
    }
    
    // Verify completion
    await target.getByRole('tab', { name: 'Dashboard' }).waitFor({ timeout: 15000 }).catch(() => {});
    
    return {
      organizationName: orgName,
      // Cannot easily get ID from UI only without API interception, 
      // but fixture can fetch it from /auth/me later
      organizationId: null 
    };
  }

  /**
   * Detect and complete onboarding if detected
   */
  async detectAndCompleteOnboarding(userType) {
    const step = await this.detectOnboardingStep();
    if (step !== 'complete' && step !== 'none') {
      console.log(`Onboarding required (step: ${step}), completing via UI...`);
      await this.completeOnboardingViaUI(userType);
      
      // Refresh auth info to get IDs
      const meResponse = await this.page.request.get('/auth/me');
      if (meResponse.ok()) {
        const me = await meResponse.json();
        return {
          organizationId: me.user?.organization_id,
          organizationName: me.user?.organization_name
        };
      }
    }
    
    // Already complete
    const meResponse = await this.page.request.get('/auth/me');
    if (meResponse.ok()) {
      const me = await meResponse.json();
      return {
        organizationId: me.user?.organization_id,
        organizationName: me.user?.organization_name
      };
    }
    return {};
  }

  async ensureVendorOrganization(options = {}) {
    const organizationName = options.organizationName
      || SEEDED_USERS.vendor.organization
      || 'Demo Vendor Org';
    const isDiscoverable = options.isDiscoverable ?? true;
    const membershipMode = options.membershipMode || 'open';

    let organizationId = null;
    let organizationDisplayName = null;
    let updated = false;

    // Get cookies from browser context and build Cookie header for API requests
    const cookies = await this.page.context().cookies();
    const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ');
    const headers = cookieHeader ? { 'Cookie': cookieHeader } : {};

    const meResponse = await this.page.request.get('/auth/me', { headers });
    if (meResponse.ok()) {
      const meData = await meResponse.json();
      organizationId = meData?.user?.organization_id || null;
      organizationDisplayName = meData?.user?.organization_name || null;
    }

    if (organizationId) {
      return {
        organizationId,
        organizationName: organizationDisplayName || organizationName,
        updated,
      };
    }

    let existingOrgId = null;
    const listResponse = await this.page.request.get('/api/onboarding/organizations', { headers });
    if (listResponse.ok()) {
      const listData = await listResponse.json();
      const orgs = listData?.organizations || [];
      const match = orgs.find((org) => org.name === organizationName);
      if (match) {
        existingOrgId = match.id;
      }
    }

    const onboardingPayload = existingOrgId ? {
      user_type: 'vendor',
      organization_id: existingOrgId,
      is_discoverable: isDiscoverable,
      membership_mode: membershipMode,
    } : {
      user_type: 'vendor',
      organization_name: organizationName,
      is_discoverable: isDiscoverable,
      membership_mode: membershipMode,
    };

    let completeResponse = await this.page.request.post('/api/onboarding/complete', {
      headers,
      data: onboardingPayload,
    });
    if (!completeResponse.ok() && !existingOrgId) {
      const fallbackName = `${organizationName} ${Date.now()}`;
      completeResponse = await this.page.request.post('/api/onboarding/complete', {
        headers,
        data: {
          user_type: 'vendor',
          organization_name: fallbackName,
          is_discoverable: isDiscoverable,
          membership_mode: membershipMode,
        },
      });
      if (!completeResponse.ok()) {
        const errorText = await completeResponse.text().catch(() => '');
        throw new Error(`Failed to complete vendor onboarding for organization: ${completeResponse.status()} ${errorText}`);
      }
      const fallbackData = await completeResponse.json();
      return {
        organizationId: fallbackData.organization_id,
        organizationName: fallbackData.organization_name || fallbackName,
        updated: true,
      };
    }
    if (!completeResponse.ok()) {
      const errorText = await completeResponse.text().catch(() => '');
      throw new Error(`Failed to complete vendor onboarding for organization: ${completeResponse.status()} ${errorText}`);
    }

    const completeData = await completeResponse.json();
    organizationId = completeData.organization_id || existingOrgId;
    organizationDisplayName = completeData.organization_name || organizationName;
    updated = true;

    if (!organizationId) {
      const refreshed = await this.page.request.get('/auth/me', { headers });
      if (refreshed.ok()) {
        const refreshedData = await refreshed.json();
        organizationId = refreshedData?.user?.organization_id || null;
        organizationDisplayName = refreshedData?.user?.organization_name || organizationDisplayName;
      }
    }

    if (!organizationId) {
      throw new Error('Vendor organization ID not found after onboarding');
    }

    return {
      organizationId,
      organizationName: organizationDisplayName || organizationName,
      updated,
    };
  }

  /**
   * Logout from the application
   */
  async logout() {
    await this.page.click('button:has-text("Logout"), button:has-text("Sign Out")');
    await this.page.waitForURL(url => !url.toString().includes('/dashboard'), { timeout: 10000 });
  }

  /**
   * Check if currently authenticated
   */
  async isAuthenticated() {
    const target = this._target;
    try {
      // Use distinct timeout to avoid hanging
      const logoutButton = target.locator('button:has-text("Logout"), button:has-text("Sign Out")').first();
      if (await logoutButton.isVisible({ timeout: 2000 }).catch(() => false)) {
          // Check if stuck on onboarding
          const onboardingPage = target.locator('[data-testid="onboarding-page"]');
          if (await onboardingPage.isVisible({ timeout: 1000 }).catch(() => false)) {
              console.log('[Auth] User is logged in but stuck on Onboarding Page -> Treating as Unauthenticated');
              return false;
          }
          return true;
      }
      return false;
    } catch {
      return false;
    }
  }
}

// =============================================================================
// Mobile Wallet Helpers
// =============================================================================

class MobileWalletHelpers {
  constructor(page) {
    this.page = page;
    this.walletFrame = null;
    this.walletUrl = process.env.WALLET_URL || 'http://localhost:9081';
  }

  /**
   * Open the mobile wallet iframe
   * @param {string} deviceId - Optional device ID to inject
   * @param {string} orgId - Optional organization ID
   */
  async openWallet(deviceId = null, orgId = null) {
    // Construct URL with test parameters
    let url = `${this.walletUrl}?test_mode=true`;
    if (deviceId) {
      url += `&device_id=${encodeURIComponent(deviceId)}`;
    }
    if (orgId) {
      url += `&org_id=${encodeURIComponent(orgId)}`;
    }

    // Find or create wallet iframe
    const existingFrame = this.page.frameLocator('#wallet-frame');
    if (await existingFrame.locator('body').count() > 0) {
      this.walletFrame = existingFrame;
      return;
    }

    // Navigate to wallet in new tab for standalone testing
    await this.page.goto(url);
    await this.page.waitForLoadState('networkidle');
  }

  /**
   * Send a message to the wallet via postMessage
   * @param {string} type - Message type
   * @param {object} payload - Message payload
   */
  async sendMessage(type, payload) {
    await this.page.evaluate(({ type, payload, walletUrl }) => {
      const walletFrame = document.getElementById('wallet-frame');
      if (walletFrame && walletFrame.contentWindow) {
        walletFrame.contentWindow.postMessage({ type, payload }, walletUrl);
      }
    }, { type, payload, walletUrl: this.walletUrl });
  }

  /**
   * Inject a QR code payload for the wallet to scan
   * @param {string} qrData - QR code data (credential offer or presentation request)
   */
  async injectQRCode(qrData) {
    await this.sendMessage('SCAN_QR_CODE', { data: qrData });
    await this.page.waitForTimeout(500); // Give Flutter time to process
  }

  /**
   * Wait for wallet to show credential offer
   */
  async waitForCredentialOffer() {
    if (this.walletFrame) {
      await this.walletFrame.locator('text=Credential Offer').waitFor({ timeout: 10000 });
    } else {
      await this.page.waitForSelector('text=Credential Offer', { timeout: 10000 });
    }
  }

  /**
   * Accept a credential offer in the wallet
   */
  async acceptCredentialOffer() {
    const acceptButton = this.walletFrame 
      ? this.walletFrame.locator('button:has-text("Accept"), button:has-text("Add Credential")')
      : this.page.locator('button:has-text("Accept"), button:has-text("Add Credential")');
    await acceptButton.click();
    await this.page.waitForTimeout(1000);
  }

  /**
   * Get the current device ID from the wallet
   */
  async getDeviceId() {
    return await this.page.evaluate(() => {
      // Flutter web stores device ID in localStorage
      return localStorage.getItem('marty_device_id');
    });
  }

  /**
   * Set a test device ID in the wallet
   * @param {string} deviceId - Device ID to set
   */
  async setDeviceId(deviceId) {
    await this.page.evaluate((id) => {
      localStorage.setItem('marty_device_id', id);
    }, deviceId);
  }

  /**
   * Get stored credentials from the wallet
   */
  async getStoredCredentials() {
    return await this.page.evaluate(() => {
      const stored = localStorage.getItem('marty_credentials');
      return stored ? JSON.parse(stored) : [];
    });
  }

  /**
   * Clear all wallet data (for test cleanup)
   */
  async clearWalletData() {
    await this.page.evaluate(() => {
      localStorage.removeItem('marty_device_id');
      localStorage.removeItem('marty_credentials');
      localStorage.removeItem('marty_push_token');
    });
  }
}

// =============================================================================
// WalletBridge - Full postMessage-based wallet control for E2E testing
// =============================================================================

/**
 * WalletBridge - Bidirectional postMessage communication with Flutter web wallet.
 *
 * This class navigates to the marty-authenticator Flutter web app in the SAME PAGE
 * context and communicates via postMessage. Because the wallet renders in the
 * Playwright-controlled browser, all wallet UI is captured in:
 * - Video recordings
 * - Screenshots
 * - Trace files
 *
 * ## Usage Pattern
 * ```javascript
 * const wallet = new WalletBridge(page);
 * await wallet.init({ deviceId: 'my-device', orgId: 'my-org' });
 * await wallet.scanQrCode(credentialOfferUrl);
 * const response = await wallet.waitForMessage('CREDENTIAL_STORED');
 * ```
 *
 * ## Message Protocol
 * All messages include `{ source: 'marty-wallet', type: string, payload: object }`.
 *
 * | Message Type           | Direction       | Description                              |
 * |------------------------|-----------------|------------------------------------------|
 * | WALLET_READY           | Wallet → Test   | Flutter app has finished initialization  |
 * | SCAN_QR_CODE           | Test → Wallet   | Inject QR data for processing            |
 * | QR_CODE_INJECTED       | Wallet → Test   | QR injection acknowledged                |
 * | INJECT_CHALLENGE       | Test → Wallet   | Inject push challenge                    |
 * | CHALLENGE_INJECTED     | Wallet → Test   | Challenge received                       |
 * | SET_DEVICE_ID          | Test → Wallet   | Set device ID and org                    |
 * | GET_DEVICE_ID          | Test → Wallet   | Request current device ID                |
 * | DEVICE_ID              | Wallet → Test   | Current device ID response               |
 * | REGISTER_PUSH_VIA_QR   | Test → Wallet   | Register device via QR data              |
 * | PUSH_REGISTERED        | Wallet → Test   | Registration result                      |
 * | STORE_CREDENTIAL       | Test → Wallet   | Store a credential                       |
 * | CREDENTIAL_STORED      | Wallet → Test   | Credential storage confirmed             |
 * | GET_CREDENTIALS        | Test → Wallet   | Request stored credentials               |
 * | CREDENTIALS            | Wallet → Test   | Stored credentials response              |
 * | CLEAR_DATA             | Test → Wallet   | Clear all wallet data                    |
 * | DATA_CLEARED           | Wallet → Test   | Data cleared confirmation                |
 * | PROCESS_OID4VP_REQUEST | Test → Wallet   | Process presentation request             |
 * | APPROVE_PRESENTATION   | Test → Wallet   | Approve and submit presentation          |
 * | PRESENTATION_SUBMITTED | Wallet → Test   | Presentation submitted to verifier       |
 *
 * ## WalletBridge Usage
 * WalletBridge is the ONLY supported way to test wallet flows in E2E tests.
 * It provides UI capture in recordings and tests the actual Flutter web wallet.
 * 
 * For API-only tests without wallet UI (SSE, token exchange), use unit-api tests
 * with direct HTTP/fetch calls instead.
 *
 * ## Prerequisites
 * The Flutter web wallet must be running at WALLET_URL (default: http://localhost:9081).
 * Start it with: `cd marty-authenticator && ./scripts/run-web-test.sh`
 *
 * @see main_web_test.dart - Flutter entry point that handles these messages
 */
class WalletBridge {
  constructor(page) {
    this.page = page;
    this.walletUrl = process.env.WALLET_URL || 'http://localhost:9081';
    this.apiUrl = process.env.API_URL || 'http://localhost:8000';
    this._isReady = false;
    this._messageQueue = [];
    this._responseHandlers = new Map();
    this._needsFreshContext = false; // First init uses provided page
    this._ownedContext = null;
    this._listenerInstalled = false;
    this.frame = null; // Can be bound to specific frame
  }

  /**
   * Initialize in a specific frame (for split-screen testing)
   * @param {import('@playwright/test').FrameLocator} frameLocator
   * @param {object} options
   */
  async initInFrame(frameLocator, options = {}) {
    this.frame = frameLocator;
    const { deviceId, orgId, timeout = 30000 } = options;

    // Construct URL with test parameters
    let url = `${this.walletUrl}?test_mode=true&api_url=${encodeURIComponent(this.apiUrl)}`;
    if (deviceId) url += `&device_id=${encodeURIComponent(deviceId)}`;
    if (orgId) url += `&org_id=${encodeURIComponent(orgId)}`;

    // Set up message listener BEFORE navigation so we catch WALLET_READY
    await this._setupMessageListenerInFrame();
    
    // Start waiting for WALLET_READY before we navigate
    const walletReadyPromise = this._waitForMessage('WALLET_READY', timeout);

    // Set frame source via evaluate (assumes harness has setFrameSource)
    console.log(`[initInFrame] Setting wallet frame to: ${url}`);
    try {
      // For cross-origin iframe handling in harness
      const frameId = 'wallet-frame'; // Default ID in harness
      await this.page.evaluate(({ id, url }) => {
        console.log('[Harness] Setting frame source:', id, url);
        if (window.setFrameSource) {
          window.setFrameSource(id, url);
        } else {
          // Fallback if not using harness helper
          const f = document.getElementById(id);
          if (f) f.src = url;
        }
      }, { id: frameId, url });
    } catch (e) {
      console.log(`[initInFrame] Error setting frame source: ${e.message}`);
    }
    
    // Now wait for WALLET_READY
    await walletReadyPromise;
    this._isReady = true;

    await this.enableAccessibility();

    console.log('WalletBridge: Wallet ready in frame');
    return true;
  }

  async _waitForWalletLoad(timeout = 30000) {
    // Wait for frame to have content
    // This is tricky with cross-origin, but we can look for locator
    if (this.frame) {
      await this.frame.locator('body').waitFor({ timeout });
    }
  }

  async _setupMessageListenerInFrame() {
    if (!this.frame) return this._setupMessageListener();

    // For split-screen mode: the harness page relays messages from wallet iframe
    // We just need to listen for console logs on the harness page
    console.log('[Setup] Setting up message listener for split-screen harness...');

    // Listen for console logs on the harness page (which relays wallet messages)
    this.page.on('console', msg => {
      const text = msg.text();
      // Debug all logs
      console.log(`[BrowserLog] ${text}`);
      
      if (text.startsWith('__WALLET_BRIDGE_MSG__:')) {
        try {
          const data = JSON.parse(text.substring(22));
          console.log(`[Bridge] Received ${data.type}`);
          this._handleMessage(data);
        } catch (e) {
          console.log(`[Bridge] Parse error: ${e.message}`);
        }
      }
    });
  }

  _handleMessage(data) {
    const { type, payload } = data;
    if (this._responseHandlers.has(type)) {
      const handlers = this._responseHandlers.get(type);
      handlers.forEach(resolve => resolve(payload));
      this._responseHandlers.delete(type);
    }
    this._messageQueue.push({ type, payload, timestamp: Date.now() });
  }

  /**
   * Initialize the wallet bridge and wait for wallet to be ready.
   * @param {object} options - Initialization options
   * @param {string} options.deviceId - Optional device ID to inject
   * @param {string} options.orgId - Optional organization ID
   * @param {number} options.timeout - Timeout for wallet ready (ms)
   */
  async init(options = {}) {
    const { deviceId, orgId, timeout = 30000 } = options;

    // Create a fresh browser context to avoid exposeFunction conflicts between tests
    if (!this.frame) { // Only change context if NOT in split-screen mode
      const browser = this.page.context().browser();
      if (browser && this._needsFreshContext) {
        const newContext = await browser.newContext();
        this.page = await newContext.newPage();
        this._ownedContext = newContext;
      }
      this._needsFreshContext = true;
    }

    // Construct URL with test parameters
    let url = `${this.walletUrl}?test_mode=true&api_url=${encodeURIComponent(this.apiUrl)}`;
    if (deviceId) url += `&device_id=${encodeURIComponent(deviceId)}`;
    if (orgId) url += `&org_id=${encodeURIComponent(orgId)}`;

    // Set up message listener before navigating
    await this._setupMessageListener();

    // Start waiting for WALLET_READY before we navigate to avoid race conditions
    const readyPromise = this._waitForMessage('WALLET_READY', timeout);

    // Navigate to wallet
    await this.page.goto(url);

    // Wait for WALLET_READY message
    await readyPromise;
    this._isReady = true;

    await this.enableAccessibility();

    console.log('WalletBridge: Wallet ready');
    return true;
  }

  /**
   * Clean up resources when done with this bridge
   */
  async cleanup() {
    if (this._ownedContext) {
      await this._ownedContext.close();
      this._ownedContext = null;
    }
    this._isReady = false;
    this._messageQueue = [];
    this._responseHandlers.clear();
  }

  /**
   * Set up postMessage listener in the page context
   */
  async _setupMessageListener() {
    // Add console listener for debugging
    this.page.on('console', msg => {
      const text = msg.text();
      // Include more filter terms to capture registerDevice and registerFromQRCode logs
      if (text.includes('TestMessageHandler') || text.includes('Push') || text.includes('REGISTER') || 
          text.includes('register') || text.includes('device') || text.includes('RSA') ||
          text.includes('HTTP') || text.includes('Starting') || text.includes('Exception')) {
        console.log(`[Wallet Console] ${msg.type()}: ${text}`);
      }
    });

    // Only expose function if not already installed on this page
    if (!this._listenerInstalled) {
      try {
        await this.page.exposeFunction('_walletBridgeReceive', (data) => {
          this._handleMessage(data);
        });
        this._listenerInstalled = true;
      } catch (err) {
        // Function already registered from a previous test - this is OK if using same context
        if (err.message.includes('has been already registered')) {
          console.log('WalletBridge: Reusing existing listener');
          this._listenerInstalled = true;
        } else {
          throw err;
        }
      }
    }

    await this.page.addInitScript(() => {
      if (window.__walletBridgeListenerInstalled) {
        return;
      }
      window.__walletBridgeListenerInstalled = true;
      window.addEventListener('message', (event) => {
        if (event.data?.source === 'marty-wallet') {
          window._walletBridgeReceive(event.data);
        }
      });
    });
  }

  /**
   * Enable Flutter web accessibility if the prompt is present.
   */
  async enableAccessibility(timeout = 2000) {
    try {
      const button = this.page.getByRole('button', {
        name: 'Enable accessibility',
      });
      if (await button.isVisible({ timeout })) {
        await button.click();
        await this.page.waitForTimeout(500);
      }
    } catch (error) {
      // Ignore if the accessibility prompt is not present.
    }
  }

  /**
   * Wait for a specific message type from the wallet
   */
  async _waitForMessage(type, timeout = 10000) {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Timeout waiting for message: ${type}`));
      }, timeout);

      if (!this._responseHandlers.has(type)) {
        this._responseHandlers.set(type, []);
      }
      this._responseHandlers.get(type).push((payload) => {
        clearTimeout(timeoutId);
        resolve(payload);
      });
    });
  }

  /**
   * Send a message to the wallet and optionally wait for response
   */
  async sendMessage(type, payload = {}, waitForResponse = null, timeout = 30000) {
    console.log(`Sending message: ${type}`, JSON.stringify(payload));
    const responsePromise = waitForResponse ? this._waitForMessage(waitForResponse, timeout) : null;

    if (this.frame) {
      // Execute within the frame context
      await this.frame.locator('body').evaluate((body, { type, payload }) => {
        const msg = { type, payload, source: 'marty-harness' };
        console.log('PostMessage Sending:', JSON.stringify(msg));
        window.postMessage(msg, '*');
      }, { type, payload });
    } else {
      await this.page.evaluate(({ type, payload }) => {
        const msg = { type, payload, source: 'marty-harness' };
        console.log('PostMessage Sending:', JSON.stringify(msg));
        window.postMessage(msg, '*');
      }, { type, payload });
    }

    if (responsePromise) {
      return responsePromise;
    }
  }

  /**
   * Inject a QR code (credential offer or presentation request) into the wallet
   * @param {string} qrData - QR code data (URL or encoded data)
   */
  async scanQrCode(qrData) {
    return this.sendMessage('SCAN_QR_CODE', { data: qrData }, 'QR_CODE_INJECTED');
  }

  /**
   * Inject a push challenge into the wallet for testing
   * @param {object} challenge - Challenge data
   */
  async injectChallenge(challenge) {
    return this.sendMessage('INJECT_CHALLENGE', challenge, 'CHALLENGE_INJECTED');
  }

  /**
   * Register for push notifications via QR code data
   * Simulates scanning a QR code from the web UI and registering the device
   * @param {object} qrData - QR code data with organization_id, api_url, temp_token, user_id
   * @returns {Promise<object>} - Registration result with device_id, registration_id, organization_id
   */
  async registerPushViaQR(qrData) {
    const result = await this.sendMessage(
      'REGISTER_PUSH_VIA_QR',
      { qr_data: qrData },
      'PUSH_REGISTERED'
    );
    
    if (!result.success) {
      throw new Error(`Push registration via QR failed: ${result.error}`);
    }
    
    return result;
  }

  /**
   * Set the device ID in the wallet
   * @param {string} deviceId - Device ID
   * @param {string} orgId - Optional organization ID
   */
  async setDeviceId(deviceId, orgId = null) {
    return this.sendMessage('SET_DEVICE_ID', { device_id: deviceId, org_id: orgId }, 'DEVICE_ID_SET');
  }

  /**
   * Get the current device ID from the wallet
   */
  async getDeviceId() {
    const response = await this.sendMessage('GET_DEVICE_ID', {}, 'DEVICE_ID');
    return response?.device_id;
  }

  /**
   * Get stored credentials from the wallet
   */
  async getCredentials() {
    const response = await this.sendMessage('GET_CREDENTIALS', {}, 'CREDENTIALS');
    return response?.credentials || [];
  }

  /**
   * Get display credentials from the wallet UI state
   */
  async getDisplayCredentials() {
    const response = await this.sendMessage(
      'GET_DISPLAY_CREDENTIALS',
      {},
      'DISPLAY_CREDENTIALS'
    );
    return response?.credentials || [];
  }

  /**
   * Clear all wallet data (for test cleanup)
   */
  async clearData() {
    return this.sendMessage('CLEAR_DATA', {}, 'DATA_CLEARED');
  }

  /**
   * Wait for the wallet to have at least N credentials
   * @param {number} count - Expected credential count
   * @param {number} timeout - Timeout in ms
   */
  async waitForCredentials(count = 1, timeout = 30000) {
    return await expect.poll(async () => {
      const credentials = await this.getCredentials();
      return credentials.length >= count ? credentials : null;
    }, {
      timeout,
      intervals: [500, 1000, 2000],
      message: `Wallet did not receive ${count} credential(s)`
    }).toBeTruthy();
  }

  /**
   * Wait for a display credential matching a predicate
   * @param {function} matchFn - Predicate to match a display credential
   * @param {number} timeout - Timeout in ms
   */
  async waitForDisplayCredential(matchFn, timeout = 10000) {
    return await expect.poll(async () => {
      const credentials = await this.getDisplayCredentials();
      return credentials.find(matchFn);
    }, {
      timeout,
      intervals: [500, 1000, 2000],
      message: 'Display credential matching predicate not found'
    }).toBeTruthy();
  }

  /**
   * Get all received messages
   */
  getMessageHistory() {
    return [...this._messageQueue];
  }

  /**
   * Clear message history
   */
  clearMessageHistory() {
    this._messageQueue = [];
  }

  /**
   * Check if wallet is ready
   */
  get isReady() {
    return this._isReady;
  }

  // ===========================================================================
  // OID4VP Presentation Request Methods
  // ===========================================================================

  /**
   * Store a credential in the wallet's localStorage
   * @param {object} credential - Credential object with jwt, type, claims, etc.
   */
  async storeCredential(credential) {
    return this.sendMessage('STORE_CREDENTIAL', { credential }, 'CREDENTIAL_STORED');
  }

  /**
   * Process an OID4VP presentation request
   * Sends the request to the wallet which finds matching credentials
   * @param {string} requestUri - The OID4VP request URI
   * @param {string} credentialType - The type of credential being requested
   * @returns {Promise<object>} - Object with matching_credentials array
   */
  async processOid4vpRequest(requestUri, credentialType = null) {
    return this.sendMessage(
      'PROCESS_OID4VP_REQUEST',
      { request_uri: requestUri, credential_type: credentialType },
      'OID4VP_PROCESSED'
    );
  }

  /**
   * Approve a presentation request and create a Verifiable Presentation
   * Uses WASM for real crypto if available, otherwise creates mock VP
   * @param {object} options - Approval options
   * @param {number} options.credentialIndex - Index of credential to use (default: 0)
   * @param {string} options.audience - Verifier audience (default: 'demo_verifier')
   * @param {string} options.nonce - Challenge nonce for replay protection
   * @param {string} options.callbackUrl - URL to submit the presentation to
   * @returns {Promise<object>} - Object with vp_jwt
   */
  async approvePresentation(options = {}) {
    const { credentialIndex = 0, audience = 'demo_verifier', nonce = null, callbackUrl = null } = options;
    return this.sendMessage(
      'APPROVE_PRESENTATION',
      { credential_index: credentialIndex, audience, nonce, callback_url: callbackUrl },
      'PRESENTATION_APPROVED'
    );
  }

  /**
   * Wait for a presentation to be submitted to the verifier
   * Polls the verifier API for the presentation submission
   * @param {string} requestId - The presentation request ID
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<object>} - The submitted presentation data
   */
  async waitForPresentationSubmission(requestId, timeout = 30000) {
    return await expect.poll(async () => {
      try {
        const response = await this.page.request.get(
          `${this.apiUrl}/api/verifier/requests/${requestId}/status`
        );
        if (response.ok()) {
          const data = await response.json();
          if (data.status === 'submitted') {
            return data;
          }
        }
      } catch (err) {
        // Continue polling
      }
      return null;
    }, {
      timeout,
      intervals: [500, 1000, 2000],
      message: `Presentation not submitted for request ${requestId}`
    }).toBeTruthy();
  }

  /**
   * Complete OID4VP flow: process request, approve with first matching credential
   * This is a convenience method for E2E tests
   * @param {string} requestUri - The OID4VP request URI
   * @param {string} credentialType - The type of credential being requested
   * @param {object} options - Additional options for approval
   * @returns {Promise<object>} - Object with vp_jwt and matching credential info
   */
  async completeOid4vpFlow(requestUri, credentialType = null, options = {}) {
    // Process the request to find matching credentials
    const processResult = await this.processOid4vpRequest(requestUri, credentialType);
    
    if (!processResult.success) {
      throw new Error(`Failed to process OID4VP request: ${processResult.error}`);
    }

    if (processResult.matching_count === 0) {
      throw new Error('No matching credentials found for presentation request');
    }

    // Approve with the first matching credential (or specified index)
    const approvalResult = await this.approvePresentation({
      credentialIndex: options.credentialIndex || 0,
      audience: options.audience,
      nonce: options.nonce,
      callbackUrl: options.callbackUrl,
    });

    if (!approvalResult.success) {
      throw new Error(`Failed to approve presentation: ${approvalResult.error}`);
    }

    return {
      ...approvalResult,
      matching_credentials: processResult.matching_credentials,
    };
  }
}

// =============================================================================
// Push Notification Helpers
// =============================================================================

class PushNotificationHelpers {
  constructor(page, deviceRegHelpers = null, userId = null) {
    this.page = page;
    this.apiUrl = process.env.API_URL || 'http://localhost:8000';
    // Optional reference to DeviceRegistrationHelpers for auto-signing
    this.deviceRegHelpers = deviceRegHelpers;
    // User ID for API calls
    this.userId = userId;
  }

  /**
   * Set the user ID for API calls
   * @param {string} userId
   */
  setUserId(userId) {
    this.userId = userId;
  }

  /**
   * Set the DeviceRegistrationHelpers for auto-signing challenges.
   * @param {DeviceRegistrationHelpers} helpers
   */
  setDeviceRegHelpers(helpers) {
    this.deviceRegHelpers = helpers;
  }

  /**
   * Get all mock notifications sent during test
   * @param {number} limit - Max notifications to retrieve
   */
  async getAllNotifications(limit = 50) {
    const headers = {};
    const params = new URLSearchParams();
    if (this.userId) {
      headers['X-User-ID'] = this.userId;
      params.append('user_id', this.userId);
    }
    const response = await this.page.request.get(
      `${this.apiUrl}/api/notifications?${params.toString()}`,
      { headers }
    );
    const data = await response.json();
    return data.notifications || [];
  }

  /**
   * Get notifications by event type
   * @param {string} eventType - Event type to filter by
   */
  async getNotificationsByEventType(eventType) {
    const headers = {};
    const params = new URLSearchParams();
    if (this.userId) {
      headers['X-User-ID'] = this.userId;
      params.append('user_id', this.userId);
    }
    const response = await this.page.request.get(
      `${this.apiUrl}/api/notifications?${params.toString()}`,
      { headers }
    );
    const data = await response.json();
    const notifications = data.notifications || [];
    return notifications.filter(
      (notification) => notification.event_type === eventType || notification.type === eventType
    );
  }

  /**
   * Create a push challenge for testing
   * @param {string} deviceId - Target device ID
   * @param {object} challenge - Challenge data
   */
  async createPushChallenge(deviceId, challenge) {
    const headers = {};
    if (this.userId) {
      headers['X-User-ID'] = this.userId;
    }
    const response = await this.page.request.post(
      `${this.apiUrl}/api/push/challenges`,
      { 
        data: { device_id: deviceId, ...challenge },
        headers,
      }
    );
    return response.json();
  }

  /**
   * Get pending challenges for a device
   * @param {string} deviceId - Device ID
   */
  async getPendingChallenges(deviceId) {
    const headers = {};
    if (this.userId) {
      headers['X-User-ID'] = this.userId;
    }
    const response = await this.page.request.get(
      `${this.apiUrl}/api/push/challenges/pending?device_id=${encodeURIComponent(deviceId)}`,
      { headers }
    );
    const data = await response.json();
    return data.challenges || [];
  }

  /**
   * Respond to a push challenge with automatic signature generation.
   * If deviceRegHelpers is set and no signature provided, will auto-sign.
   * @param {string} deviceId - Device ID
   * @param {string} challengeId - Challenge ID
   * @param {string} responseValue - 'accept' or 'reject'
   * @param {string} nonce - Challenge nonce (required for auto-signing)
   * @param {string} signature - Optional signature (if not provided, will auto-sign)
   */
  async respondToChallenge(deviceId, challengeId, responseValue, nonce = null, signature = null) {
    // Auto-sign if possible and no signature provided
    if (!signature && nonce && this.deviceRegHelpers) {
      signature = this.deviceRegHelpers.signChallengeForDevice(deviceId, nonce);
    }
    
    const headers = {};
    if (this.userId) {
      headers['X-User-ID'] = this.userId;
    }
    
    const response = await this.page.request.post(
      `${this.apiUrl}/api/push/challenges/${challengeId}/respond?device_id=${encodeURIComponent(deviceId)}`,
      { data: { response: responseValue, signature }, headers }
    );
    return response.json();
  }

  /**
   * Clear all mock notifications (test cleanup)
   */
  async clearAllNotifications() {
    const headers = {};
    const params = new URLSearchParams();
    if (this.userId) {
      headers['X-User-ID'] = this.userId;
      params.append('user_id', this.userId);
    }
    await this.page.request.delete(
      `${this.apiUrl}/api/notifications?${params.toString()}`,
      { headers }
    );
  }

  /**
   * Clear all push challenges (test cleanup)
   * @param {string} deviceId - Optional device ID, clears all if not specified
   */
  async clearAllChallenges(deviceId = null) {
    const url = deviceId 
      ? `${this.apiUrl}/api/push/challenges?device_id=${encodeURIComponent(deviceId)}`
      : `${this.apiUrl}/api/push/challenges`;
    const headers = {};
    if (this.userId) {
      headers['X-User-ID'] = this.userId;
    }
    await this.page.request.delete(url, { headers });
  }

  /**
   * Wait for a notification with specific event type
   * @param {string} eventType - Event type to wait for
   * @param {number} timeout - Timeout in ms
   */
  async waitForNotification(eventType, timeout = 10000) {
    return await expect.poll(async () => {
      const notifications = await this.getNotificationsByEventType(eventType);
      return notifications.length > 0 ? notifications[0] : null;
    }, {
      timeout,
      intervals: [500, 1000, 2000],
      message: `Notification with event type "${eventType}" not received`
    }).toBeTruthy();
  }

  // ===========================================================================
  // QR-Based Push Registration (Mobile wallet scans web UI QR code)
  // ===========================================================================

  /**
   * Generate a QR code for device registration
   * Returns QR data that a mobile wallet can scan to register for push notifications
   * @param {string} orgId - Optional organization ID
   * @returns {Promise<object>} - QR data with organization_id, api_url, temp_token, user_id, qr_url
   */
  async generateQRRegistration(orgId = 'test_org') {
    const headers = {
      'Content-Type': 'application/json',
      'X-Organization-ID': orgId,
    };
    if (this.userId) {
      headers['X-User-ID'] = this.userId;
    }

    const response = await this.page.request.post(
      `${this.apiUrl}/api/devices/register-qr`,
      {
        data: { user_id: this.userId || 'test_user' },
        headers,
      }
    );

    if (!response.ok()) {
      const errorText = await response.text();
      throw new Error(`Failed to generate QR registration: ${errorText}`);
    }

    const data = await response.json();
    if (!data.success) {
      throw new Error(`QR generation failed: ${data.message}`);
    }

    return data.qr_data;
  }

  /**
   * Check the status of a QR registration
   * @param {string} tokenPrefix - First 32 characters of the temp_token
   * @returns {Promise<object>} - Status with completed, device_id, etc.
   */
  async checkQRRegistrationStatus(tokenPrefix) {
    const response = await this.page.request.get(
      `${this.apiUrl}/api/devices/qr-status/${tokenPrefix}`
    );
    
    if (!response.ok()) {
      const status = response.status();
      if (status === 404) {
        throw new Error('QR registration not found');
      } else if (status === 410) {
        throw new Error('QR registration expired');
      }
      throw new Error(`Failed to check QR status: ${response.statusText()}`);
    }

    return response.json();
  }

  /**
   * Wait for a QR registration to complete
   * Polls the status endpoint until the device registers via QR
   * @param {string} tempToken - The temp_token from QR data
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<object>} - Completed registration status with device_id
   */
  async waitForQRRegistration(tempToken, timeout = 60000) {
    const tokenPrefix = tempToken.substring(0, 32);

    return await expect.poll(async () => {
      try {
        const status = await this.checkQRRegistrationStatus(tokenPrefix);
        if (status.completed) {
          return status;
        }
      } catch (err) {
        // If expired or not found, rethrow
        if (err.message.includes('expired') || err.message.includes('not found')) {
          throw err;
        }
      }
      return null;
    }, {
      timeout,
      intervals: [1000, 2000, 5000],
      message: 'QR registration did not complete'
    }).toBeTruthy();
  }
}

// =============================================================================
// Device Registration Helpers
// =============================================================================

class DeviceRegistrationHelpers {
  constructor(page) {
    this.page = page;
    this.apiUrl = process.env.API_URL || 'http://localhost:8000';
    // Store keypairs by device ID for signing challenges
    this.deviceKeypairs = new Map();
  }

  /**
   * Generate a test device ID
   * @param {string} orgId - Organization ID
   * @param {string} platform - 'ios', 'android', or 'web'
   */
  generateDeviceId(orgId = null, platform = 'web') {
    const platformId = `test-${platform}-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    return orgId ? `${orgId}:${platformId}` : platformId;
  }

  /**
   * Generate a mock FCM token
   */
  generateMockFcmToken() {
    return `mock-fcm-token-${Date.now()}-${Math.random().toString(36).substring(2, 16)}`;
  }

  /**
   * Register a test device with RSA keypair for push challenge signing.
   * @param {string} userId - User ID (for header)
   * @param {object} deviceInfo - Device information
   * @param {boolean} generateKeys - Whether to generate RSA keypair (default true)
   * @returns {object} Response with keypair info if generated
   */
  async registerDevice(userId, deviceInfo, generateKeys = true) {
    const deviceId = deviceInfo.deviceId || this.generateDeviceId();
    let keypair = null;
    let publicKeyDerBase64 = null;
    
    if (generateKeys) {
      keypair = generateTestKeypair();
      publicKeyDerBase64 = keypair.publicKeyDerBase64;
      this.deviceKeypairs.set(deviceId, keypair);
    }
    
    const response = await this.page.request.post(
      `${this.apiUrl}/api/devices/register`,
      {
        headers: { 'X-User-ID': userId },
        data: {
          device_id: deviceId,
          fcm_token: deviceInfo.fcmToken || this.generateMockFcmToken(),
          platform: deviceInfo.platform || 'web',
          app_version: deviceInfo.appVersion || '1.0.0-test',
          os_version: deviceInfo.osVersion,
          device_model: deviceInfo.deviceModel,
          public_key: publicKeyDerBase64,
        },
      }
    );
    
    const result = await response.json();
    
    // Include keypair info in response for tests that need it
    if (keypair) {
      result.keypair = keypair;
    }
    result.deviceId = deviceId;
    
    return result;
  }

  /**
   * Get the keypair for a registered device.
   * @param {string} deviceId - Device ID
   * @returns {object|null} Keypair or null if not found
   */
  getDeviceKeypair(deviceId) {
    return this.deviceKeypairs.get(deviceId) || null;
  }

  /**
   * Sign a challenge nonce for a device.
   * @param {string} deviceId - Device ID
   * @param {string} nonce - Challenge nonce to sign
   * @returns {string|null} Base64-encoded signature or null if no keypair
   */
  signChallengeForDevice(deviceId, nonce) {
    const keypair = this.deviceKeypairs.get(deviceId);
    if (!keypair) {
      return null;
    }
    return signChallenge(keypair.privateKeyPem, nonce);
  }

  /**
   * Unregister a device
   * @param {string} userId - User ID
   * @param {string} deviceId - Device ID to unregister
   */
  async unregisterDevice(userId, deviceId) {
    // Clean up keypair
    this.deviceKeypairs.delete(deviceId);
    
    const response = await this.page.request.delete(
      `${this.apiUrl}/api/devices/${encodeURIComponent(deviceId)}`,
      { headers: { 'X-User-ID': userId } }
    );
    return response.ok();
  }

  /**
   * Get all devices for a user
   * @param {string} userId - User ID
   * @param {string} orgId - Optional organization filter
   */
  async getUserDevices(userId, orgId = null) {
    let url = `${this.apiUrl}/api/devices`;
    if (orgId) {
      url += `?organization_id=${encodeURIComponent(orgId)}`;
    }
    const response = await this.page.request.get(url, {
      headers: { 'X-User-ID': userId },
    });
    const data = await response.json();
    return data.devices || [];
  }
}

// =============================================================================
// MailHog Helpers (for email verification in tests)
// =============================================================================

class MailHogHelpers {
  constructor(page) {
    this.page = page;
    this.mailhogUrl = process.env.MAILHOG_URL || 'http://localhost:8025';
  }

  /**
   * Get all emails from MailHog
   */
  async getAllEmails() {
    const response = await this.page.request.get(`${this.mailhogUrl}/api/v2/messages`);
    const data = await response.json();
    return data.items || [];
  }

  /**
   * Get emails sent to a specific address
   * @param {string} email - Recipient email address
   */
  async getEmailsTo(email) {
    const allEmails = await this.getAllEmails();
    return allEmails.filter(msg => 
      msg.Raw.To?.some(to => to.includes(email)) ||
      msg.Content?.Headers?.To?.some(to => to.includes(email))
    );
  }

  /**
   * Wait for an email to arrive
   * @param {string} email - Recipient email
   * @param {string} subjectContains - Subject must contain this text
   * @param {number} timeout - Timeout in ms
   */
  async waitForEmail(email, subjectContains = null, timeout = 30000) {
    const result = await expect.poll(async () => {
      const emails = await this.getEmailsTo(email);
      for (const msg of emails) {
        const subject = msg.Content?.Headers?.Subject?.[0] || '';
        if (!subjectContains || subject.includes(subjectContains)) {
          return msg;
        }
      }
      return null;
    }, {
      timeout,
      intervals: [1000, 2000, 5000],
      message: `Email to ${email}${subjectContains ? ` with subject "${subjectContains}"` : ''} not received`
    }).toBeTruthy();
    
    return result;
  }

  /**
   * Extract link from email body
   * @param {object} email - Email message from MailHog
   * @param {RegExp} pattern - Regex pattern to match link
   */
  extractLink(email, pattern = /https?:\/\/[^\s"<>]+/g) {
    const body = email.Content?.Body || '';
    const matches = body.match(pattern);
    return matches ? matches[0] : null;
  }

  /**
   * Clear all emails
   */
  async clearAllEmails() {
    await this.page.request.delete(`${this.mailhogUrl}/api/v1/messages`);
  }
}

// =============================================================================
// Mock Email Helpers (for CI/CD environments without MailHog)
// =============================================================================

class MockEmailHelpers {
  constructor(page) {
    this.page = page;
    // In-memory email storage keyed by recipient email
    this.emails = new Map();
  }

  /**
   * Get all emails from mock storage
   */
  async getAllEmails() {
    const allEmails = [];
    for (const emails of this.emails.values()) {
      allEmails.push(...emails);
    }
    return allEmails.sort((a, b) => 
      new Date(b.Created) - new Date(a.Created)
    );
  }

  /**
   * Get emails sent to a specific address
   * @param {string} email - Recipient email address
   */
  async getEmailsTo(email) {
    return this.emails.get(email) || [];
  }

  /**
   * Wait for an email to arrive
   * @param {string} email - Recipient email
   * @param {string} subjectContains - Subject must contain this text
   * @param {number} timeout - Timeout in ms
   */
  async waitForEmail(email, subjectContains = null, timeout = 30000) {
    const result = await expect.poll(async () => {
      const emails = await this.getEmailsTo(email);
      return emails.find(msg => {
        const subject = msg.Content?.Headers?.Subject?.[0] || '';
        return !subjectContains || subject.includes(subjectContains);
      });
    }, {
      timeout,
      intervals: [1000, 2000, 5000],
      message: `Email to ${email}${subjectContains ? ` with subject "${subjectContains}"` : ''} not received`
    }).toBeTruthy();
    
    return result;
  }

  /**
   * Extract link from email body
   * @param {object} email - Email message
   * @param {RegExp} pattern - Regex pattern to match link
   */
  extractLink(email, pattern = /https?:\/\/[^\s"<>]+/g) {
    const body = email.Content?.Body || '';
    const matches = body.match(pattern);
    return matches ? matches[0] : null;
  }

  /**
   * Clear all emails from mock storage
   */
  async clearAllEmails() {
    this.emails.clear();
  }

  /**
   * Mock sending an email (for testing email sending functionality)
   * @param {string} to - Recipient email
   * @param {string} subject - Email subject
   * @param {string} body - Email body (HTML or plain text)
   * @param {string} from - Sender email
   */
  async mockSendEmail(to, subject, body, from = 'noreply@marty.demo') {
    const email = {
      ID: `mock-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      Created: new Date().toISOString(),
      Raw: {
        From: from,
        To: [to],
        Data: `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\n\r\n${body}`
      },
      Content: {
        Headers: {
          Subject: [subject],
          From: [from],
          To: [to],
          Date: [new Date().toUTCString()],
          'Content-Type': ['text/html; charset=UTF-8']
        },
        Body: body,
        Size: body.length,
        MIME: null
      }
    };

    if (!this.emails.has(to)) {
      this.emails.set(to, []);
    }
    this.emails.get(to).push(email);
    return email;
  }
}

// =============================================================================
// Email Test Helpers (Production-Ready Facade)
// =============================================================================

/**
 * EmailTestHelpers - High-level email testing facade with provider abstraction
 * 
 * This class provides a production-ready email testing interface that automatically
 * selects the appropriate email provider based on the TEST_PROVIDER environment variable:
 * - 'mailhog' (default): Uses MailHog for local development and full E2E testing
 * - 'mock': Uses in-memory mock for CI/CD environments without external dependencies
 * 
 * Usage Examples:
 * 
 * // Basic usage (auto-detects provider)
 * const emailHelper = new EmailTestHelpers(page);
 * await emailHelper.clearAllEmails();
 * const email = await emailHelper.waitForEmail('user@example.com', 'Welcome');
 * 
 * // Content extraction
 * const subject = emailHelper.getEmailSubject(email);
 * const body = emailHelper.getEmailBody(email);
 * const htmlBody = emailHelper.getHtmlBody(email);
 * const links = emailHelper.getAllLinks(email);
 * 
 * // Verification
 * emailHelper.verifyEmailSubject(email, 'Welcome to Marty');
 * emailHelper.verifyEmailContains(email, 'Click here to verify');
 * const hasLink = emailHelper.verifyLinkExists(email, /verify-email/);
 * 
 * // Advanced search
 * const invites = await emailHelper.getEmailsBySubject('Invitation');
 * const latest = await emailHelper.getLatestEmailTo('user@example.com');
 * const adminEmails = await emailHelper.getEmailsFrom('admin@marty.demo');
 */
class EmailTestHelpers {
  constructor(page) {
    this.page = page;
    this.provider = process.env.TEST_PROVIDER || 'mailhog';
    
    // Initialize appropriate low-level helper based on provider
    if (this.provider === 'mock') {
      this.impl = new MockEmailHelpers(page);
    } else {
      this.impl = new MailHogHelpers(page);
    }
  }

  // =============================================================================
  // Delegated Methods (pass-through to underlying provider)
  // =============================================================================

  /**
   * Get all emails
   * @returns {Promise<Array>} Array of email objects
   */
  async getAllEmails() {
    return this.impl.getAllEmails();
  }

  /**
   * Get emails sent to a specific address
   * @param {string} email - Recipient email address
   * @returns {Promise<Array>} Array of email objects
   */
  async getEmailsTo(email) {
    return this.impl.getEmailsTo(email);
  }

  /**
   * Wait for an email to arrive
   * @param {string} email - Recipient email
   * @param {string} subjectContains - Subject must contain this text
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<object>} Email object
   */
  async waitForEmail(email, subjectContains = null, timeout = 30000) {
    return this.impl.waitForEmail(email, subjectContains, timeout);
  }

  /**
   * Extract link from email body
   * @param {object} email - Email message
   * @param {RegExp} pattern - Regex pattern to match link
   * @returns {string|null} Extracted link or null
   */
  extractLink(email, pattern = /https?:\/\/[^\s"<>]+/g) {
    return this.impl.extractLink(email, pattern);
  }

  /**
   * Clear all emails
   */
  async clearAllEmails() {
    return this.impl.clearAllEmails();
  }

  // =============================================================================
  // Content Extraction Methods
  // =============================================================================

  /**
   * Get email subject
   * @param {object} email - Email message
   * @returns {string} Email subject
   */
  getEmailSubject(email) {
    return email.Content?.Headers?.Subject?.[0] || '';
  }

  /**
   * Get email body (HTML or plain text)
   * @param {object} email - Email message
   * @returns {object} Object with html and text properties
   */
  getEmailBody(email) {
    const body = email.Content?.Body || '';
    const contentType = email.Content?.Headers?.['Content-Type']?.[0] || '';
    
    if (contentType.includes('text/html')) {
      return { html: body, text: this._stripHtml(body) };
    } else {
      return { html: null, text: body };
    }
  }

  /**
   * Get HTML body part
   * @param {object} email - Email message
   * @returns {string|null} HTML body or null
   */
  getHtmlBody(email) {
    return this.getEmailBody(email).html;
  }

  /**
   * Get plain text body part
   * @param {object} email - Email message
   * @returns {string} Plain text body
   */
  getTextBody(email) {
    return this.getEmailBody(email).text;
  }

  /**
   * Get all links from email body
   * @param {object} email - Email message
   * @returns {Array<string>} Array of URLs
   */
  getAllLinks(email) {
    const body = email.Content?.Body || '';
    const matches = body.match(/https?:\/\/[^\s"<>]+/g);
    return matches || [];
  }

  /**
   * Extract links by anchor text (works with HTML emails)
   * @param {object} email - Email message
   * @param {string} linkText - Text to search for in anchor tags
   * @returns {string|null} First matching link or null
   */
  extractLinksByText(email, linkText) {
    const htmlBody = this.getHtmlBody(email);
    if (!htmlBody) return null;

    // Match <a> tags with the specified text
    const regex = new RegExp(`<a[^>]+href=["']([^"']+)["'][^>]*>${linkText}</a>`, 'i');
    const match = htmlBody.match(regex);
    return match ? match[1] : null;
  }

  /**
   * Extract action button link (common pattern in email templates)
   * @param {object} email - Email message
   * @returns {string|null} Button link or null
   */
  extractActionButtonLink(email) {
    const htmlBody = this.getHtmlBody(email);
    if (!htmlBody) return null;

    // Match common button patterns
    const patterns = [
      /<a[^>]+class=["'][^"']*button[^"']*["'][^>]+href=["']([^"']+)["']/i,
      /<a[^>]+href=["']([^"']+)["'][^>]+class=["'][^"']*button[^"']*["']/i,
      /<button[^>]+onclick=["'](?:window\.)?location\.href=["']([^"']+)["']/i
    ];

    for (const pattern of patterns) {
      const match = htmlBody.match(pattern);
      if (match) return match[1];
    }

    return null;
  }

  /**
   * Get sender information
   * @param {object} email - Email message
   * @returns {object} Object with email and name properties
   */
  getSenderInfo(email) {
    const from = email.Content?.Headers?.From?.[0] || email.Raw?.From || '';
    const match = from.match(/([^<]+)<([^>]+)>/);
    
    if (match) {
      return { name: match[1].trim(), email: match[2].trim() };
    }
    return { name: '', email: from.trim() };
  }

  /**
   * Get all recipient addresses
   * @param {object} email - Email message
   * @returns {Array<string>} Array of recipient email addresses
   */
  getRecipients(email) {
    const to = email.Content?.Headers?.To || email.Raw?.To || [];
    return Array.isArray(to) ? to : [to];
  }

  // =============================================================================
  // Advanced Search Methods
  // =============================================================================

  /**
   * Get emails by subject (partial match)
   * @param {string} subject - Subject text to search for
   * @returns {Promise<Array>} Array of matching email objects
   */
  async getEmailsBySubject(subject) {
    const allEmails = await this.getAllEmails();
    return allEmails.filter(email => 
      this.getEmailSubject(email).toLowerCase().includes(subject.toLowerCase())
    );
  }

  /**
   * Get emails from a specific sender
   * @param {string} from - Sender email address
   * @returns {Promise<Array>} Array of matching email objects
   */
  async getEmailsFrom(from) {
    const allEmails = await this.getAllEmails();
    return allEmails.filter(email => {
      const sender = this.getSenderInfo(email).email;
      return sender.toLowerCase().includes(from.toLowerCase());
    });
  }

  /**
   * Get latest email to a recipient
   * @param {string} email - Recipient email address
   * @returns {Promise<object|null>} Latest email or null
   */
  async getLatestEmailTo(email) {
    const emails = await this.getEmailsTo(email);
    return emails.length > 0 ? emails[0] : null;
  }

  /**
   * Get email by ID
   * @param {string} id - Email ID
   * @returns {Promise<object|null>} Email object or null
   */
  async getEmailById(id) {
    const allEmails = await this.getAllEmails();
    return allEmails.find(email => email.ID === id) || null;
  }

  /**
   * Count emails to a recipient
   * @param {string} email - Recipient email address
   * @returns {Promise<number>} Count of emails
   */
  async countEmailsTo(email) {
    const emails = await this.getEmailsTo(email);
    return emails.length;
  }

  // =============================================================================
  // Verification Methods (throw on failure)
  // =============================================================================

  /**
   * Verify email subject matches expected value
   * @param {object} email - Email message
   * @param {string} expected - Expected subject (partial match)
   * @throws {Error} If subject doesn't match
   */
  verifyEmailSubject(email, expected) {
    const subject = this.getEmailSubject(email);
    if (!subject.includes(expected)) {
      throw new Error(`Email subject "${subject}" does not contain "${expected}"`);
    }
  }

  /**
   * Verify email body contains text
   * @param {object} email - Email message
   * @param {string} text - Text to search for
   * @throws {Error} If text not found
   */
  verifyEmailContains(email, text) {
    const body = this.getTextBody(email);
    if (!body.includes(text)) {
      throw new Error(`Email body does not contain "${text}"`);
    }
  }

  /**
   * Verify email sender
   * @param {object} email - Email message
   * @param {string} expectedFrom - Expected sender email
   * @throws {Error} If sender doesn't match
   */
  verifyEmailFrom(email, expectedFrom) {
    const sender = this.getSenderInfo(email).email;
    if (!sender.toLowerCase().includes(expectedFrom.toLowerCase())) {
      throw new Error(`Email from "${sender}" does not match expected "${expectedFrom}"`);
    }
  }

  /**
   * Verify email recipient
   * @param {object} email - Email message
   * @param {string} expectedTo - Expected recipient email
   * @throws {Error} If recipient doesn't match
   */
  verifyEmailTo(email, expectedTo) {
    const recipients = this.getRecipients(email);
    const found = recipients.some(to => 
      to.toLowerCase().includes(expectedTo.toLowerCase())
    );
    if (!found) {
      throw new Error(`Email recipients ${recipients.join(', ')} do not include "${expectedTo}"`);
    }
  }

  /**
   * Verify email contains a link matching pattern
   * @param {object} email - Email message
   * @param {RegExp|string} pattern - Pattern to match
   * @returns {boolean} True if link found
   */
  verifyLinkExists(email, pattern) {
    const links = this.getAllLinks(email);
    const regex = pattern instanceof RegExp ? pattern : new RegExp(pattern);
    return links.some(link => regex.test(link));
  }

  /**
   * Verify custom header value
   * @param {object} email - Email message
   * @param {string} headerName - Header name
   * @param {string} expectedValue - Expected header value
   * @throws {Error} If header doesn't match
   */
  verifyHeader(email, headerName, expectedValue) {
    const headerValue = email.Content?.Headers?.[headerName]?.[0] || '';
    if (headerValue !== expectedValue) {
      throw new Error(`Header "${headerName}" value "${headerValue}" does not match "${expectedValue}"`);
    }
  }

  // =============================================================================
  // Waiting Utilities
  // =============================================================================

  /**
   * Wait for specific number of emails to arrive
   * @param {string} email - Recipient email address
   * @param {number} count - Expected number of emails
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<Array>} Array of email objects
   */
  async waitForEmails(email, count, timeout = 30000) {
    const result = await expect.poll(async () => {
      const emails = await this.getEmailsTo(email);
      return emails.length >= count ? emails.slice(0, count) : null;
    }, {
      timeout,
      intervals: [1000, 2000, 5000],
      message: `Did not receive ${count} email(s) to ${email}`
    }).toBeTruthy();
    
    return result;
  }

  /**
   * Wait for email from specific sender
   * @param {string} recipient - Recipient email address
   * @param {string} from - Sender email address
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<object>} Email object
   */
  async waitForEmailFrom(recipient, from, timeout = 30000) {
    const result = await expect.poll(async () => {
      const emails = await this.getEmailsTo(recipient);
      for (const email of emails) {
        const sender = this.getSenderInfo(email).email;
        if (sender.toLowerCase().includes(from.toLowerCase())) {
          return email;
        }
      }
      return null;
    }, {
      timeout,
      intervals: [1000, 2000, 5000],
      message: `Email from ${from} to ${recipient} not received`
    }).toBeTruthy();
    
    return result;
  }

  /**
   * Wait for email containing specific link
   * @param {string} email - Recipient email address
   * @param {RegExp|string} linkPattern - Link pattern to match
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<object>} Email object
   */
  async waitForEmailWithLink(email, linkPattern, timeout = 30000) {
    const regex = linkPattern instanceof RegExp ? linkPattern : new RegExp(linkPattern);
    
    const result = await expect.poll(async () => {
      const emails = await this.getEmailsTo(email);
      for (const msg of emails) {
        if (this.verifyLinkExists(msg, regex)) {
          return msg;
        }
      }
      return null;
    }, {
      timeout,
      intervals: [1000, 2000, 5000],
      message: `Email with link matching ${linkPattern} to ${email} not received`
    }).toBeTruthy();
    
    return result;
  }

  // =============================================================================
  // Private Helper Methods
  // =============================================================================

  /**
   * Strip HTML tags from text
   * @private
   * @param {string} html - HTML string
   * @returns {string} Plain text
   */
  _stripHtml(html) {
    return html
      .replace(/<style[^>]*>.*?<\/style>/gi, '')
      .replace(/<script[^>]*>.*?<\/script>/gi, '')
      .replace(/<[^>]+>/g, '')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .trim();
  }
}

// =============================================================================
// API Test Helpers
// =============================================================================

class ApiTestHelpers {
  constructor(page) {
    this.page = page;
    this.apiUrl = process.env.API_URL || 'http://localhost:8000';
  }

  /**
   * Make authenticated API request
   * @param {string} method - HTTP method
   * @param {string} path - API path
   * @param {object} options - Request options
   */
  async request(method, path, options = {}) {
    const url = `${this.apiUrl}${path}`;
    return this.page.request[method.toLowerCase()](url, options);
  }

  /**
   * Get API health status
   */
  async getHealthStatus() {
    const response = await this.request('GET', '/health');
    return response.json();
  }

  /**
   * Wait for API to be ready
   * @param {number} timeout - Timeout in ms
   */
  async waitForApiReady(timeout = 30000) {
    return await expect.poll(async () => {
      try {
        const response = await this.request('GET', '/health');
        if (response.ok) {
          return true;
        }
      } catch {
        // API not ready yet
      }
      return null;
    }, {
      timeout,
      intervals: [1000, 2000, 5000],
      message: 'API did not become ready'
    }).toBeTruthy();
  }
}

/**
 * Standalone login helper function for backward compatibility
 * @param {Page} page - Playwright page object
 * @param {string} email - User email
 * @param {string} password - User password
 */
async function loginAs(page, email, password) {
  const auth = new AuthHelpers(page);
  await auth.login(email, password);
}

/**
 * Wait for an element to appear on the page
 * @param {Page} page - Playwright page object
 * @param {string} selector - CSS selector
 * @param {number} timeout - Timeout in ms
 */
async function waitForElement(page, selector, timeout = 10000) {
  await page.waitForSelector(selector, { timeout });
}

/**
 * Generate a unique test email address
 * @param {string} prefix - Prefix for the email address
 * @returns {string} Unique email address
 */
function generateTestEmail(prefix = 'test') {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 8);
  return `${prefix}-${timestamp}-${random}@test.marty.demo`;
}

/**
 * Setup organization with credentials and trust configuration.
 * Consolidates getVendorOrganizationId + credential config + trust config patterns.
 * Used in 15+ test files' beforeAll/beforeEach hooks.
 * 
 * @param {Page} page - Authenticated page (vendor user)
 * @param {object} options - Setup options
 * @param {string} options.credentialType - Credential type to ensure (default: 'employee_badge')
 * @param {string} options.signingAlgorithm - Signing algorithm (default: 'ES256')
 * @param {boolean} options.ensureCredentialConfig - Whether to ensure credential config exists
 * @returns {Promise<object>} - { organizationId, organizationName, credentialConfigId }
 */
async function setupOrganizationWithCredentials(page, options = {}) {
  const {
    credentialType = 'employee_badge',
    signingAlgorithm = 'ES256',
    ensureCredentialConfig = true,
  } = options;

  // Get organization ID from current session
  const meResponse = await page.request.get('/auth/me');
  if (!meResponse.ok()) {
    throw new Error('Failed to read user session');
  }
  const meData = await meResponse.json();
  const organizationId = meData?.user?.organization_id || null;
  const organizationName = meData?.user?.organization_name || null;

  if (!organizationId) {
    throw new Error('Organization ID not found in user session');
  }

  // Setup trust configuration with signing key
  await ensureTrustConfig(page, {
    organizationId,
    trustFramework: 'marty_hosted',
    keySource: 'marty_generated',
    signingAlgorithm,
  });

  let credentialConfigId = null;

  // Optionally ensure credential config exists
  if (ensureCredentialConfig) {
    const apiUrl = process.env.API_URL || 'http://localhost:8000';
    const listResponse = await page.request.get(
      `${apiUrl}/api/organizations/${organizationId}/credential-types`
    );

    if (listResponse.ok()) {
      const listData = await listResponse.json();
      const configs = listData.credential_types || [];
      const existing = configs.find((c) => c.credential_type === credentialType);

      if (existing) {
        credentialConfigId = existing.id;
      } else {
        // Create new credential config
        const createResponse = await page.request.post(
          `${apiUrl}/api/organizations/${organizationId}/credential-types`,
          {
            data: {
              credential_type: credentialType,
              name: `${credentialType} Credential`,
              description: `Auto-generated ${credentialType} credential for testing`,
              schema: { type: 'object', properties: {} },
            },
          }
        );

        if (createResponse.ok()) {
          const created = await createResponse.json();
          credentialConfigId = created.id || created.credential_type_id;
        }
      }
    }
  }

  return {
    organizationId,
    organizationName,
    credentialConfigId,
  };
}

async function getVendorOrganizationId(browser) {
  const baseURL = process.env.BASE_URL || 'http://localhost:9080';
  const context = await browser.newContext({ baseURL });
  const page = await context.newPage();
  const auth = new AuthHelpers(page);

  try {
    await page.goto('/');
    await auth.loginAsSeededUser('vendor');

    const meResponse = await page.request.get('/auth/me');
    if (!meResponse.ok()) {
      throw new Error('Failed to read vendor session');
    }
    const meData = await meResponse.json();
    const organizationId = meData?.user?.organization_id || null;
    const organizationName = meData?.user?.organization_name || null;

    if (!organizationId) {
      throw new Error('Vendor organization ID not found');
    }

    return { organizationId, organizationName };
  } finally {
    await context.close();
  }
}

// =============================================================================
// Shared Test Helper Functions (DRY helpers for common test operations)
// =============================================================================

/**
 * Create a credential offer for testing.
 * This helper consolidates the common pattern of creating offers across 8+ test files.
 * 
 * @param {Page} page - Playwright page object (authenticated)
 * @param {object} options - Offer configuration
 * @param {string} options.organizationId - Organization ID
 * @param {string} options.credentialConfigId - Credential type config ID (default: 'employee_badge')
 * @param {string} options.applicantId - Applicant identifier
 * @param {string} options.deviceId - Target device ID for push delivery
 * @param {object} options.credentialData - Credential claims data
 * @param {string} options.credentialFormat - Format: 'vc+sd-jwt', 'jwt_vc_json', 'mso_mdoc'
 * @returns {Promise<object>} - Created offer with credential_offer_uri
 */
async function createCredentialOffer(page, options) {
  const {
    organizationId,
    credentialConfigId = 'employee_badge',
    applicantId = `test-applicant-${Date.now()}`,
    deviceId = null,
    credentialData = {
      given_name: 'Test',
      family_name: 'User',
      employee_id: `EMP-${Date.now()}`,
    },
    credentialFormat = 'vc+sd-jwt',
  } = options;

  const apiUrl = process.env.API_URL || 'http://localhost:8000';
  const response = await page.request.post(`${apiUrl}/api/issuance/offers`, {
    data: {
      organization_id: organizationId,
      credential_config_id: credentialConfigId,
      applicant_id: applicantId,
      device_id: deviceId,
      credential_data: credentialData,
      credential_format: credentialFormat,
    },
  });

  if (!response.ok()) {
    const error = await response.text();
    throw new Error(`Failed to create credential offer: ${response.status()} - ${error}`);
  }

  return response.json();
}

/**
 * Ensure trust configuration exists for an organization.
 * This helper consolidates the common pattern of setting up trust config in beforeAll hooks.
 * 
 * @param {Page} page - Playwright page object (authenticated as admin)
 * @param {object} options - Trust config options
 * @param {string} options.organizationId - Organization ID
 * @param {string} options.trustFramework - Trust framework: 'marty_hosted', 'did_web', etc.
 * @param {string} options.keySource - Key source: 'marty_generated', 'uploaded', etc.
 * @param {string} options.signingAlgorithm - Signing algorithm: 'ES256', 'RS256', 'P-256'
 * @returns {Promise<object>} - Trust config result
 */
async function ensureTrustConfig(page, options) {
  const {
    organizationId,
    trustFramework = 'marty_hosted',
    keySource = 'marty_generated',
    signingAlgorithm = 'ES256',
  } = options;

  const apiUrl = process.env.API_URL || 'http://localhost:8000';

  // Create or update trust config
  const configResponse = await page.request.put(
    `${apiUrl}/api/organizations/${organizationId}/trust-config`,
    {
      data: {
        trust_framework: trustFramework,
        key_source: keySource,
      },
    }
  );

  if (!configResponse.ok()) {
    console.warn(`Trust config update returned ${configResponse.status()}`);
  }

  // Generate signing key
  const keyResponse = await page.request.post(
    `${apiUrl}/api/organizations/${organizationId}/trust-config/keys`,
    {
      data: {
        algorithm: signingAlgorithm,
        key_purpose: 'signing',
      },
    }
  );

  // Key might already exist, which is OK
  if (!keyResponse.ok() && keyResponse.status() !== 409) {
    console.warn(`Signing key generation returned ${keyResponse.status()}`);
  }

  return { configResponse, keyResponse };
}

/**
 * Validate that Flutter wallet is running at the expected URL.
 * Checks for Flutter-specific elements to ensure it's the real wallet, not a test stub.
 * 
 * @param {Page} page - Playwright page object
 * @param {string} walletUrl - Wallet URL to validate (default: http://localhost:9081)
 * @returns {Promise<boolean>} - True if Flutter wallet is running
 * @throws {Error} - If wallet is not running or is not Flutter web app
 */
async function validateFlutterWallet(page, walletUrl = null) {
  const url = walletUrl || process.env.WALLET_URL || 'http://localhost:9081';
  
  try {
    const response = await page.request.get(url, { timeout: 5000 });
    if (!response.ok()) {
      throw new Error(`Wallet not responding at ${url}: ${response.status()}`);
    }

    // Navigate and check for Flutter-specific elements
    await page.goto(url, { timeout: 10000 });
    
    // Wait for Flutter to initialize - look for flt-glass-pane or flt-semantics
    try {
      await page.waitForSelector('flt-glass-pane, flt-semantics-host, [flt-renderer]', { timeout: 5000 });
      return true;
    } catch {
      // Check if it's an HTML test stub (should not be used)
      const isHtmlStub = await page.locator('#test-wallet, .test-wallet-container').count();
      if (isHtmlStub > 0) {
        throw new Error(
          `Found HTML test wallet stub at ${url}. ` +
          'Flutter web wallet is required. Run: make build-wallet && docker compose restart wallet'
        );
      }
      throw new Error(
        `Flutter wallet not detected at ${url}. ` +
        'Ensure Flutter web build is running: make build-wallet && make dev'
      );
    }
  } catch (err) {
    if (err.message.includes('Flutter wallet') || err.message.includes('HTML test wallet')) {
      throw err;
    }
    throw new Error(`Cannot connect to wallet at ${url}: ${err.message}`);
  }
}

module.exports = {
  EventWaiter,
  AuthenticatedApiClient,
  CredentialDataBuilder,
  UserDataBuilder,
  MockResponses,
  DemoTestHelpers,
  AuthHelpers,
  MobileWalletHelpers,
  WalletBridge,
  PushNotificationHelpers,
  DeviceRegistrationHelpers,
  MailHogHelpers,
  MockEmailHelpers,
  EmailTestHelpers,
  ApiTestHelpers,
  mockCredentialData,
  mockVerifiablePresentation,
  mockApiResponses,
  // Standalone helper functions
  loginAs,
  waitForElement,
  generateTestEmail,
  generateTestUser,
  getVendorOrganizationId,
  // Shared test helpers (DRY)
  setupOrganizationWithCredentials,
  createCredentialOffer,
  ensureTrustConfig,
  validateFlutterWallet,
  // RSA signing utilities
  generateTestKeypair,
  signChallenge,
  // Re-export user fixtures
  SEEDED_USERS,
  SEEDED_PASSWORDS,
  SEEDED_ORGS,
  getUserByRole,
};

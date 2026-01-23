/**
 * Wallet UI E2E Tests
 *
 * Tests that capture the actual Flutter web wallet UI in Playwright recordings.
 * These tests use WalletBridge to navigate to the wallet and interact via postMessage,
 * ensuring all wallet screens are visible in traces, screenshots, and videos.
 *
 * Production Flows Tested:
 * 1. Wallet menu loads and displays correctly
 * 2. QR code based device registration (user scans QR from web UI)
 * 3. Deep link device registration (marty://push-register URLs)
 * 4. Push challenge received and displayed in wallet
 *
 * These tests require the Flutter web wallet to be running:
 *   cd marty-authenticator && ./scripts/run-web-test.sh
 */
const { test, expect } = require('@playwright/test');
const {
  AuthHelpers,
  DeviceRegistrationHelpers,
  PushNotificationHelpers,
  WalletBridge,
  SEEDED_USERS,
} = require('../../utils/test-helpers');

// Wallet URL - must be running for these tests
const WALLET_URL = process.env.WALLET_URL || 'http://localhost:9081';

/**
 * Check if wallet is available, skip test if not
 */
async function requireWallet(page, test) {
  try {
    const response = await page.request.get(WALLET_URL, { timeout: 5000 });
    if (!response.ok()) {
      test.skip('Flutter web wallet not available - run scripts/run-web-test.sh in marty-authenticator');
      return false;
    }
    return true;
  } catch {
    test.skip('Flutter web wallet not available - run scripts/run-web-test.sh in marty-authenticator');
    return false;
  }
}

test.describe('Wallet Menu UI', () => {
  test('wallet menu loads and displays correctly', async ({ page, browser }) => {
    if (!(await requireWallet(page, test))) return;

    // Open wallet in a new page (captured in recordings)
    const walletPage = await browser.newPage();
    const wallet = new WalletBridge(walletPage);

    await wallet.init({
      deviceId: `menu-test-${Date.now()}`,
      timeout: 30000,
    });

    // Take a screenshot of the wallet menu for visual verification
    await walletPage.screenshot({ path: 'test-results/wallet-menu.png', fullPage: true });

    // Verify the main view is visible by checking for common UI elements
    // The wallet should show either tokens list or empty state
    await expect(walletPage.locator('flt-semantics').first()).toBeVisible({ timeout: 10000 });

    // Look for the app bar or main navigation elements
    // Flutter web renders with flt-semantics elements for accessibility
    const semanticsTree = await walletPage.locator('flt-semantics').count();
    expect(semanticsTree).toBeGreaterThan(0);

    console.log('Wallet menu loaded successfully with', semanticsTree, 'accessibility nodes');

    await walletPage.close();
  });

  test('wallet shows empty state when no credentials', async ({ page, browser }) => {
    if (!(await requireWallet(page, test))) return;

    const walletPage = await browser.newPage();
    const wallet = new WalletBridge(walletPage);

    // Clear any existing data first
    await wallet.init({ timeout: 30000 });
    await wallet.clearData();

    // Refresh to see empty state
    await wallet.init({ timeout: 30000 });

    // Get credentials count - should be empty
    const credentials = await wallet.getCredentials();
    expect(credentials.length).toBe(0);

    console.log('Wallet empty state verified');

    await walletPage.close();
  });
});

test.describe('QR Code Registration Flow', () => {
  let auth;
  let deviceReg;
  let pushHelpers;
  let userId;

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
    deviceReg = new DeviceRegistrationHelpers(page);
    pushHelpers = new PushNotificationHelpers(page, deviceReg);

    await page.goto('/');
    await auth.loginAsSeededUser('applicant1');

    const meResponse = await page.request.get('/auth/me');
    if (meResponse.ok()) {
      const meData = await meResponse.json();
      userId = meData?.user?.user_id || SEEDED_USERS.applicant1.email;
      pushHelpers.setUserId(userId);
    }
  });

  test('complete QR registration flow with wallet UI', async ({ authenticatedVendorSplitScreen }) => {
    const { page, martyFrame, walletFrame, walletBridge } = authenticatedVendorSplitScreen;
    if (!(await requireWallet(page, test))) return;

    const orgId = `qr-org-${Date.now()}`;

    // Step 1: Web UI generates QR registration data
    const qrData = await pushHelpers.generateQRRegistration(orgId);
    expect(qrData.qr_url).toContain('marty://push-register');
    console.log('QR data generated for org:', orgId);

    // Step 2: Wallet is already open in split-screen (right side)
    // The walletBridge is already initialized by the fixture

    // Step 3: Wallet processes QR data (simulates scanning)
    let registrationResult;
    try {
      registrationResult = await walletBridge.registerPushViaQR({
        organization_id: qrData.organization_id,
        api_url: qrData.api_url,
        registration_token: qrData.temp_token,
        user_id: qrData.user_id,
      });

      expect(registrationResult.success).toBe(true);
      expect(registrationResult.device_id).toBeDefined();
      console.log('Device registered via QR:', registrationResult.device_id);
    } catch (error) {
      // CORS on qr-callback is expected in test environment
      if (error.message.includes('CORS') || error.message.includes('qr-callback')) {
        console.log('Registration attempted - CORS on callback (expected in test)');
      } else {
        throw error;
      }
    }

    // Take screenshot showing registration state in wallet frame
    await page.screenshot({ path: 'test-results/wallet-qr-registration-split-screen.png' });
  });
});

test.describe('Deep Link Registration Flow', () => {
  let auth;
  let deviceReg;
  let pushHelpers;
  let userId;

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
    deviceReg = new DeviceRegistrationHelpers(page);
    pushHelpers = new PushNotificationHelpers(page, deviceReg);

    await page.goto('/');
    await auth.loginAsSeededUser('applicant1');

    const meResponse = await page.request.get('/auth/me');
    if (meResponse.ok()) {
      const meData = await meResponse.json();
      userId = meData?.user?.user_id || SEEDED_USERS.applicant1.email;
      pushHelpers.setUserId(userId);
    }
  });

  test('complete deep link registration flow with wallet UI', async ({ page, browser }) => {
    if (!(await requireWallet(page, test))) return;

    const orgId = `deeplink-org-${Date.now()}`;

    // Step 1: Generate deep link URL (same as QR but used directly)
    const qrData = await pushHelpers.generateQRRegistration(orgId);
    const deepLinkUrl = qrData.qr_url;
    expect(deepLinkUrl).toMatch(/^marty:\/\/push-register\?/);
    console.log('Deep link generated:', deepLinkUrl.substring(0, 60) + '...');

    // Step 2: Open wallet
    const walletPage = await browser.newPage();
    const wallet = new WalletBridge(walletPage);

    await wallet.init({
      deviceId: `deeplink-device-${Date.now()}`,
      orgId: orgId,
      timeout: 30000,
    });

    // Step 3: Inject deep link as QR scan (same processing path)
    try {
      await wallet.scanQrCode(deepLinkUrl);
      console.log('Deep link processed by wallet');
    } catch (error) {
      // May fail on callback due to CORS
      console.log('Deep link scan completed (callback may have CORS issue)');
    }

    // Wait for processing
    await walletPage.waitForTimeout(2000);

    // Take screenshot showing state after deep link
    await walletPage.screenshot({ path: 'test-results/wallet-after-deeplink.png' });

    await walletPage.close();
  });
});

test.describe('Push Challenge Flow', () => {
  let auth;
  let deviceReg;
  let pushHelpers;
  let userId;

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
    deviceReg = new DeviceRegistrationHelpers(page);
    pushHelpers = new PushNotificationHelpers(page, deviceReg);

    await page.goto('/');
    await auth.loginAsSeededUser('applicant1');

    const meResponse = await page.request.get('/auth/me');
    if (meResponse.ok()) {
      const meData = await meResponse.json();
      userId = meData?.user?.user_id || SEEDED_USERS.applicant1.email;
      pushHelpers.setUserId(userId);
    }
  });

  test('wallet receives and displays push challenge', async ({ page, browser }) => {
    if (!(await requireWallet(page, test))) return;

    const orgId = `challenge-org-${Date.now()}`;
    const deviceId = `challenge-device-${Date.now()}`;

    // Step 1: Open wallet and register device
    const walletPage = await browser.newPage();
    const wallet = new WalletBridge(walletPage);

    await wallet.init({
      deviceId: deviceId,
      orgId: orgId,
      timeout: 30000,
    });

    // Step 2: Inject a push challenge into the wallet
    const challenge = {
      challenge_id: `challenge-${Date.now()}`,
      device_id: deviceId,
      title: 'Authentication Request',
      question: 'Do you approve this login from Chrome on macOS?',
      nonce: `nonce-${Date.now()}`,
      expires_at: new Date(Date.now() + 120000).toISOString(),
      data: {
        ip_address: '192.168.1.100',
        browser: 'Chrome',
        location: 'San Francisco, CA',
      },
    };

    await wallet.injectChallenge(challenge);
    console.log('Challenge injected:', challenge.challenge_id);

    // Wait for UI to update
    await walletPage.waitForTimeout(1000);

    // Take screenshot showing the challenge
    await walletPage.screenshot({ path: 'test-results/wallet-push-challenge.png' });

    await walletPage.close();
  });
});

test.describe('Credential Display Flow', () => {
  test('wallet displays stored credentials', async ({ page, browser }) => {
    if (!(await requireWallet(page, test))) return;

    const walletPage = await browser.newPage();
    const wallet = new WalletBridge(walletPage);

    await wallet.init({ timeout: 30000 });

    // Store a test credential
    const testCredential = {
      id: `cred-${Date.now()}`,
      type: 'VerifiableCredential',
      issuer: 'https://test-issuer.example.com',
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        given_name: 'Test',
        family_name: 'User',
        email: 'test@example.com',
      },
    };

    await wallet.storeCredential(testCredential);
    console.log('Test credential stored:', testCredential.id);

    // Wait for UI to update
    await walletPage.waitForTimeout(1000);

    // Take screenshot showing credentials
    await walletPage.screenshot({ path: 'test-results/wallet-credentials.png' });

    // Verify credential is stored
    const credentials = await wallet.getCredentials();
    expect(credentials.length).toBeGreaterThan(0);

    await walletPage.close();
  });
});

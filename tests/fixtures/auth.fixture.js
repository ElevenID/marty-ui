/**
 * Authentication & Onboarding Fixtures
 * 
 * Reusable Playwright fixtures for authenticated user sessions using
 * split-screen recording layout to capture both Marty UI and Wallet UI.
 */
const { test: base, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');
const { AuthHelpers, WalletBridge, SEEDED_USERS } = require('../utils/test-helpers');

const STORAGE_DIR = path.join(__dirname, '..', '.auth-state');

// Ensure worker-specific storage directory
function getStoragePath(workerIndex, name) {
  const dir = path.join(STORAGE_DIR, `worker-${workerIndex}`);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, `${name}.json`);
}

function isStorageStateValid(statePath) {
  try {
    if (!fs.existsSync(statePath)) return false;
    const stats = fs.statSync(statePath);
    return (Date.now() - stats.mtimeMs) < (30 * 60 * 1000);
  } catch {
    return false;
  }
}

const test = base.extend({
  authHelpers: async ({ page }, use) => {
    await use(new AuthHelpers(page));
  },

  /**
   * Split-screen page with Marty UI (left) and Wallet UI (right)
   * Returns { page, martyFrame, walletFrame, walletBridge }
   */
  splitScreenPage: async ({ page, context }, use) => {
    // Intercept a specific URL and serve our harness HTML
    const harnessHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Marty Test Harness</title>
  <style>
    body, html { margin: 0; padding: 0; height: 100%; font-family: -apple-system, sans-serif; }
    .container { display: grid; grid-template-rows: 40px 1fr; height: 100vh; background: #1e1e1e; }
    .header { background: #2d2d2d; color: #fff; display: flex; align-items: center; padding: 0 16px; font-size: 14px; }
    .split-view { display: grid; grid-template-columns: 1fr 425px; height: 100%; }
    .frame-container { position: relative; height: 100%; }
    .frame-overlay { position: absolute; top: 4px; right: 8px; background: rgba(0,0,0,0.6); color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 10px; z-index: 100; }
    iframe { width: 100%; height: 100%; border: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span id="testName">Initializing...</span>
      <span id="sessionInfo" style="margin-left: auto;"></span>
    </div>
    <div class="split-view">
      <div class="frame-container">
        <div class="frame-overlay">Marty UI</div>
        <iframe id="marty-frame" name="marty-frame" src="about:blank"></iframe>
      </div>
      <div class="frame-container">
        <div class="frame-overlay">Wallet</div>
        <iframe id="wallet-frame" name="wallet-frame" src="about:blank"></iframe>
      </div>
    </div>
  </div>
  <script>
    console.log('[Harness] Script loaded, adding message listener...');
    window.addEventListener('message', (event) => {
      console.log('[Harness] Message received:', event.data);
      if (event.data?.source === 'marty-wallet') {
        console.log('__WALLET_BRIDGE_MSG__:' + JSON.stringify(event.data));
      }
    });
    window.setFrameSource = (id, url) => { 
      console.log('[Harness] Setting frame source:', id, url);
      document.getElementById(id).src = url; 
    };
    window.setTestInfo = (name, info) => {
      document.getElementById('testName').textContent = name;
      document.getElementById('sessionInfo').textContent = info || '';
    };
    window.__harnessReady = true;
    console.log('[Harness] Ready!');
  </script>
</body>
</html>`;

    // Route a special URL to serve our harness
    await page.route('**/test-harness', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: harnessHTML
      });
    });

    // Navigate to our custom harness URL (under localhost:9080 domain)
    await page.goto('http://localhost:9080/test-harness');
    
    // Wait for harness script to be ready
    await page.waitForFunction(() => window.__harnessReady === true, { timeout: 5000 });
    
    // Get frame handles
    const martyFrame = page.frameLocator('#marty-frame');
    const walletFrame = page.frameLocator('#wallet-frame');
    
    // Initialize WalletBridge in the wallet frame
    const walletBridge = new WalletBridge(page);
    
    // Helper to update harness status
    const updateStatus = async (name, info) => {
      await page.evaluate(({ name, info }) => {
        if (window.setTestInfo) window.setTestInfo(name, info);
      }, { name, info });
    };

    await use({ page, martyFrame, walletFrame, walletBridge, updateStatus });
    
    await walletBridge.cleanup();
  },

  /**
   * Authenticated vendor in split-screen setup
   * Returns { page, martyFrame, walletFrame, walletBridge, auth, organizationId }
   */
  walletOnboardedPage: async ({ splitScreenPage, browser }, use, testInfo) => {
    const { page, martyFrame, walletFrame, walletBridge, updateStatus } = splitScreenPage;
    const workerIndex = testInfo.workerIndex;
    const statePath = getStoragePath(workerIndex, 'vendor');
    
    await updateStatus(testInfo.title, 'Initializing vendor & wallet...');

    // 1. Initialize Wallet (Right Frame)
    const deviceId = `device-${Date.now()}`;
    await walletBridge.initInFrame(walletFrame, {
      deviceId,
      timeout: 60000 // Increased timeout for Flutter web (WASM/Canvas init)
    });

    // 2. Authenticate Vendor (Left Frame)
    // We can't set cookies on the frame directly easily from Playwright if cross-origin
    // But since harness is file:// and frames are localhost, we might access them.
    // Better strategy: reuse storage state if valid, inject into context
    
    // The main page is file://, the frames are http://localhost
    // We need to perform login IN the frame
    
    // Navigate left frame to app
    await page.evaluate((url) => { window.setFrameSource('marty-frame', url); }, process.env.BASE_URL || 'http://localhost:9080');
    
    // Wait for frame load
    await martyFrame.locator('body').waitFor();
    const auth = new AuthHelpers(page).withFrame(martyFrame);

    let organizationId = null;
    let organizationName = null;

    // Perform login (always fresh in this frame context unless we share context cookies?)
    // Note: Frames share the BrowserContext of the page!
    // So if we set storageState on the context, the frame should pick it up.
    
    if (isStorageStateValid(statePath)) {
      // Load cookies/storage into current context
      // Playwright doesn't support hot-loading storage state easily into existing context?
      // Actually context.addCookies() works.
      const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
      if (state.cookies) await page.context().addCookies(state.cookies);
      if (state.origins) {
        // LocalStorage injection is harder for existing page, but frames reload might catch it
        // Or we inject via script
      }
      
      console.log('Using cached session, refreshing frame...');
      await martyFrame.locator('body').evaluate(() => window.location.reload());
      await martyFrame.locator('body').waitFor(); // wait for reload
    }
    
    // Check auth
    if (!await auth.isAuthenticated()) {
      await auth.loginAsSeededUser('vendor', { uiOnboarding: true });
      const result = await auth.detectAndCompleteOnboarding('vendor');
      organizationId = result.organizationId;
      organizationName = result.organizationName;
      
      // Save state
      await page.context().storageState({ path: statePath });
    } else {
       // Fetch org info
       // We can use request context with cookies
       // But frame requests need cookies
    }

    if (!organizationId) {
       // fallback fetch
       // Need to make request from frame context or share cookies
    }

    await updateStatus(testInfo.title, `Vendor: ${organizationName || 'Ready'} | Wallet: Ready`);

    await use({ 
      page, 
      martyFrame, 
      walletFrame, 
      walletBridge, 
      auth, 
      organizationId,
      organizationName,
      deviceId
    });
  },

  /**
   * Authenticated vendor page with organization setup complete.
   * Provides: page, auth, organizationId, organizationName, credentialConfigId
   * Replaces repetitive beforeEach patterns across test files.
   */
  authenticatedVendorPage: async ({ browser }, use, testInfo) => {
    const workerIndex = testInfo.workerIndex;
    const statePath = getStoragePath(workerIndex, 'vendor');
    
    let context = await browser.newContext(
      isStorageStateValid(statePath) ? { storageState: statePath } : {}
    );
    let page = await context.newPage();
    const auth = new AuthHelpers(page);
    const { setupOrganizationWithCredentials } = require('../utils/test-helpers');
    
    await page.goto('/');
    if (!await auth.isAuthenticated()) {
      await auth.loginAsSeededUser('vendor', { uiOnboarding: true });
      await auth.detectAndCompleteOnboarding('vendor');
      await page.context().storageState({ path: statePath });
    }
    
    // Setup organization with credentials and trust config
    const orgSetup = await setupOrganizationWithCredentials(page, {
      credentialType: 'employee_badge',
      signingAlgorithm: 'ES256',
    });
    
    await use({ 
      page, 
      auth, 
      organizationId: orgSetup.organizationId, 
      organizationName: orgSetup.organizationName,
      credentialConfigId: orgSetup.credentialConfigId,
    });
    
    await context.close();
  },

  /**
   * Authenticated vendor context for split-screen tests.
   * Combines authenticatedVendorPage + splitScreenPage features.
   * Provides: page, martyFrame, walletFrame, walletBridge, auth, organizationId, credentialConfigId
   */
  authenticatedVendorSplitScreen: async ({ browser }, use, testInfo) => {
    const workerIndex = testInfo.workerIndex;
    const statePath = getStoragePath(workerIndex, 'vendor-split');
    const { setupOrganizationWithCredentials } = require('../utils/test-helpers');
    
    const context = await browser.newContext(
      isStorageStateValid(statePath) ? { storageState: statePath } : {}
    );
    const page = await context.newPage();
    
    // Setup split-screen harness (inline version of splitScreenPage fixture)
    const harnessHTML = fs.readFileSync(path.join(__dirname, 'split-screen-harness.html'), 'utf8');
    
    await page.route('**/test-harness', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: harnessHTML,
      });
    });

    await page.goto('http://localhost:9080/test-harness');
    await page.waitForFunction(() => window.__harnessReady === true, { timeout: 10000 });

    const martyFrame = page.frameLocator('#marty-frame');
    const walletFrame = page.frameLocator('#wallet-frame');
    const walletBridge = new WalletBridge(page, martyFrame);

    // Initialize frames
    await page.evaluate((url) => { window.setFrameSource('marty-frame', url); }, process.env.BASE_URL || 'http://localhost:9080');
    await page.evaluate((url) => { window.setFrameSource('wallet-frame', url); }, process.env.WALLET_URL || 'http://localhost:9081');

    await martyFrame.locator('body').waitFor();
    await walletFrame.locator('body').waitFor();

    // Authenticate in Marty frame
    const auth = new AuthHelpers(page).withFrame(martyFrame);
    if (!await auth.isAuthenticated()) {
      await auth.loginAsSeededUser('vendor', { uiOnboarding: true });
      await auth.detectAndCompleteOnboarding('vendor');
      await context.storageState({ path: statePath });
    }

    // Setup organization
    const orgSetup = await setupOrganizationWithCredentials(page, {
      credentialType: 'employee_badge',
      signingAlgorithm: 'ES256',
    });

    await use({
      page,
      martyFrame,
      walletFrame,
      walletBridge,
      auth,
      organizationId: orgSetup.organizationId,
      organizationName: orgSetup.organizationName,
      credentialConfigId: orgSetup.credentialConfigId,
    });

    await context.close();
  }
});

module.exports = { test, expect };

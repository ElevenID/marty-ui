// @ts-check
const { defineConfig, devices } = require('@playwright/test');

const isCI = !!process.env.CI;
const timeouts = {
  test: isCI ? 120_000 : 60_000,      // Reduced from 90s to 30s for faster failures
  expect: isCI ? 10_000 : 5_000,      // Reduced from 8s to 5s
  action: isCI ? 30_000 : 10_000,     // Reduced from 20s to 10s
  navigation: isCI ? 30_000 : 10_000, // Reduced from 20s to 10s
  webServerBackend: 120_000,
  webServerWallet: 180_000,           // Flutter web takes longer to start
  webServerFrontend: 120_000,
};

// Service URLs
const BACKEND_URL = process.env.API_URL || 'http://localhost:8000';
const WALLET_URL = process.env.WALLET_URL || 'http://localhost:9081';
const FRONTEND_URL = process.env.BASE_URL || 'http://localhost:9080';

// Path to marty-authenticator (adjust if workspace structure differs)
const AUTHENTICATOR_PATH = process.env.AUTHENTICATOR_PATH || '../../../marty-authenticator';

/**
 * Project-based test configuration for organized execution:
 * - unit-api: API-only tests without UI (parallel, fast)
 * - integration-ui: UI component tests (sequential, workers=1)
 * - e2e-flows: Complete user journeys with wallet UI (sequential, workers=1)
 * 
 * Execution order: unit-api → integration-ui → e2e-flows
 */

const fs = require('fs');
const path = require('path');

// Load custom matchers
require('./utils/custom-matchers');

/**
 * Global teardown to clean up auth state
 */
async function globalTeardown() {
  const storageDir = path.join(__dirname, '.auth-state');
  if (fs.existsSync(storageDir)) {
    // Optional: Clean up old state files or leave them for next run (faster)
    // fs.rmSync(storageDir, { recursive: true, force: true });
  }
}

/**
 * @see https://playwright.dev/docs/test-configuration
 */
module.exports = defineConfig({
  globalTeardown,
  testDir: './e2e',
  timeout: timeouts.test,
  expect: {
    timeout: timeouts.expect,
  },
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: isCI,
  /* Retry on CI only */
  retries: isCI ? 2 : 0,
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: [
    ['html'],
    ['json', { outputFile: 'test-results.json' }],
    ['junit', { outputFile: 'test-results.xml' }]
  ],
  /* Shared settings for all the projects below. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: process.env.BASE_URL || 'http://localhost:9080',
    /* Collect trace when retrying the failed test. */
    trace: 'on-first-retry',
    /* Take screenshot on failure */
    screenshot: 'only-on-failure',
    /* Record video - 'on' for all tests, 'retain-on-failure' for failures only
     * This ensures wallet UI is captured in recordings for debugging */
    video: process.env.PLAYWRIGHT_VIDEO === 'on' ? 'on' : 'retain-on-failure',
    /* Global timeout for each action */
    actionTimeout: timeouts.action,
    /* Global timeout for navigation */
    navigationTimeout: timeouts.navigation
  },

  /* Configure projects for organized test execution */
  projects: [
    // Unit API tests - API-only tests, no UI interaction, parallel-safe
    {
      name: 'unit-api',
      testMatch: '**/unit-api/**/*.spec.js',
      fullyParallel: true,
      workers: isCI ? 4 : undefined,
      use: { ...devices['Desktop Chrome'] },
    },
    // Integration UI tests - UI component tests, sequential
    {
      name: 'integration-ui',
      testMatch: '**/integration-ui/**/*.spec.js',
      fullyParallel: false,
      workers: 1,
      use: { ...devices['Desktop Chrome'] },
    },
    // E2E flows - complete user journeys with wallet UI, sequential
    {
      name: 'e2e-flows',
      testMatch: '**/e2e-flows/**/*.spec.js',
      fullyParallel: false,
      workers: 1,
      use: { 
        ...devices['Desktop Chrome'],
        launchOptions: {
           args: [
             '--disable-web-security', 
             '--disable-features=IsolateOrigins,site-per-process',
             '--unsafely-treat-insecure-origin-as-secure=http://wallet,http://wallet:80'
           ]
        }
      },
    },
  ],

  /* Global setup and teardown */
  globalSetup: require.resolve('./utils/global-setup.js'),
  globalTeardown: require.resolve('./utils/global-teardown.js'),

  /* Run your local dev server before starting the tests */
  // Services must be running before tests start:
  // - Backend: http://localhost:8000 (run Marty demo)
  // - Wallet: http://localhost:9081 (cd marty-authenticator && ./scripts/run-web-test.sh)
  // - Frontend: http://localhost:9080 (run Marty demo)
});

// @ts-check
/**
 * Playwright Demo Recording Configuration
 *
 * Runs only demo.spec.js with video always on, slow motion enabled, and a
 * larger viewport so the recording looks good at full screen.
 *
 * Usage:
 *   cd marty-ui/tests
 *   npx playwright test --config playwright.demo.config.js
 *
 * Or with a local stack already running on the default ports:
 *   BASE_URL=http://localhost:9080 npx playwright test --config playwright.demo.config.js
 *
 * The videos land in demo-recordings/<test-name>/video.webm.
 * Convert to MP4:
 *   ffmpeg -i video.webm -c:v libx264 demo.mp4
 */

const { defineConfig, devices } = require('@playwright/test');

const BASE_URL   = process.env.BASE_URL   || 'http://localhost:9080';
const SLOW_MO    = parseInt(process.env.DEMO_SLOW_MO  || '400', 10);
const DEMO_OUT   = process.env.DEMO_OUT   || 'demo-recordings';

module.exports = defineConfig({
  testDir: './e2e',
  testMatch: '**/demo.spec.js',
  timeout: 180_000,
  retries: 0,
  workers: 1,
  fullyParallel: false,
  outputDir: DEMO_OUT,

  reporter: [
    ['html', { outputFolder: `${DEMO_OUT}-report`, open: 'never' }],
    ['list'],
  ],

  use: {
    baseURL: BASE_URL,

    // ── Video settings ──────────────────────────────────────────────────────
    video: {
      mode: 'on',
      size: { width: 1440, height: 900 },
    },
    screenshot: 'on',
    trace: 'on',

    // ── Viewport ────────────────────────────────────────────────────────────
    viewport: { width: 1440, height: 900 },

    // ── Timing ──────────────────────────────────────────────────────────────
    actionTimeout:     20_000,
    navigationTimeout: 30_000,
  },

  projects: [
    {
      name: 'demo-chrome',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
        launchOptions: {
          slowMo: SLOW_MO,
          args: [
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process',
          ],
        },
      },
    },
  ],
});

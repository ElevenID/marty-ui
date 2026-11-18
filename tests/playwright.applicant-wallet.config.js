// Focused Playwright config for applicant wallet UX regressions.
// It starts the real Vite console app but skips the full-stack global setup so
// specs can mock backend calls at the browser network boundary.
const path = require('path');
const { defineConfig, devices } = require('@playwright/test');

const UI_BASE_URL = process.env.UI_BASE_URL || 'http://127.0.0.1:4174';

module.exports = defineConfig({
  testDir: './e2e/integration-ui/applicant',
  testMatch: ['**/*wallet-selection.spec.js', '**/*mip03.spec.js'],
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report-applicant-wallet', open: 'never' }],
  ],
  use: {
    baseURL: UI_BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1 --port 4174 --strictPort --mode test',
    cwd: path.join(__dirname, '..', 'ui'),
    url: `${UI_BASE_URL}/console/`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      ...process.env,
      DISABLE_PRERENDER: '1',
      PUBLIC_DOMAIN: '',
      UI_BASE_URL,
      VITE_API_URL: 'http://localhost:8000',
      VITE_ENVIRONMENT: 'test',
      VITE_PUBLIC_URL: UI_BASE_URL,
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});

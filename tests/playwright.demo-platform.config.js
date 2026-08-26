// @ts-check
const path = require('path');
const { defineConfig } = require('@playwright/test');

const externalBaseUrl = process.env.BASE_URL;
const baseURL = externalBaseUrl || 'http://127.0.0.1:4173';

module.exports = defineConfig({
  testDir: './e2e/public',
  testMatch: '**/demo-platform.spec.js',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  retries: 0,
  workers: 1,
  fullyParallel: false,
  outputDir: './artifacts/demo-platform-playwright',
  reporter: [
    ['list'],
    ['html', { outputFolder: './artifacts/demo-platform-playwright-report', open: 'never' }],
  ],
  use: {
    baseURL,
    browserName: 'chromium',
    trace: 'on',
    screenshot: 'on',
    video: 'off',
  },
  webServer: externalBaseUrl ? undefined : {
    command: 'npm run build && npm run preview -- --host 127.0.0.1 --port 4173 --strictPort',
    cwd: path.join(__dirname, '..', 'ui'),
    url: `${baseURL}/demos`,
    reuseExistingServer: false,
    timeout: 240_000,
  },
});

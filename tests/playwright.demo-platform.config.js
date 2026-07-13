// @ts-check
const { defineConfig } = require('@playwright/test');

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
    baseURL: process.env.BASE_URL || 'http://127.0.0.1:4173',
    browserName: 'chromium',
    trace: 'on',
    screenshot: 'on',
    video: 'off',
  },
});

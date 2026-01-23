// Simple config for running tests against already-running API
const { defineConfig, devices } = require('@playwright/test');

// Use UI for navigation, but API for fetch requests
const UI_BASE_URL = process.env.UI_BASE_URL || 'http://localhost:3000';
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:8000';

// Set BASE_URL for test-helpers.js to use the UI 
process.env.BASE_URL = UI_BASE_URL;

module.exports = defineConfig({
  testDir: './e2e',
  timeout: 60000,
  use: {
    baseURL: UI_BASE_URL,
    extraHTTPHeaders: {
      'Accept': 'application/json',
    },
    trace: 'off',
  },
  projects: [{
    name: 'test',
    use: { ...devices['Desktop Chrome'] },
  }],
});

/**
 * Custom Playwright matchers for Marty E2E tests
 * 
 * Extends expect with domain-specific assertions to improve test readability.
 * 
 * Usage in tests:
 *   await expect(frame).toShowCredential('Jane Doe');
 *   await expect(frame).toHaveCredentialCount(2);
 *   await expect(page).toBeOnDashboard();
 */
const { expect } = require('@playwright/test');

expect.extend({
  /**
   * Check if a frame/page displays a credential with specific name
   */
  async toShowCredential(locatorOrPage, expectedName) {
    const credentialSelector = '[data-testid*="credential"]';
    const credentials = await locatorOrPage.locator(credentialSelector).allTextContents();
    
    const pass = credentials.some(text => text.includes(expectedName));
    
    return {
      message: () => pass
        ? `Expected not to find credential "${expectedName}" but found it`
        : `Expected to find credential "${expectedName}" but found: ${credentials.join(', ')}`,
      pass,
    };
  },

  /**
   * Check if frame/page has a specific number of credentials
   */
  async toHaveCredentialCount(locatorOrPage, expectedCount) {
    const credentialSelector = '[data-testid*="credential-card"], [data-testid^="credential-"]';
    const count = await locatorOrPage.locator(credentialSelector).count();
    
    const pass = count === expectedCount;
    
    return {
      message: () => pass
        ? `Expected not to have ${expectedCount} credentials but found ${count}`
        : `Expected ${expectedCount} credentials but found ${count}`,
      pass,
    };
  },

  /**
   * Check if page is on the dashboard
   */
  async toBeOnDashboard(page) {
    const url = page.url();
    const isDashboard = url.includes('/dashboard') || url.endsWith('/');
    
    const dashboardElements = await page.locator('[data-testid="dashboard"], h1:has-text("Dashboard")').count();
    const pass = isDashboard || dashboardElements > 0;
    
    return {
      message: () => pass
        ? `Expected not to be on dashboard but was at: ${url}`
        : `Expected to be on dashboard but was at: ${url}`,
      pass,
    };
  },

  /**
   * Check if application is in a specific status
   */
  async toHaveApplicationStatus(locatorOrPage, expectedStatus) {
    const statusSelector = '[data-testid*="status"], [data-testid*="application-status"]';
    const statusElements = await locatorOrPage.locator(statusSelector).allTextContents();
    
    const pass = statusElements.some(text => 
      text.toLowerCase().includes(expectedStatus.toLowerCase())
    );
    
    return {
      message: () => pass
        ? `Expected application not to have status "${expectedStatus}" but found it`
        : `Expected application status "${expectedStatus}" but found: ${statusElements.join(', ')}`,
      pass,
    };
  },

  /**
   * Check if SSE event was received (used with EventWaiter)
   */
  async toReceiveSSEEvent(eventWaiter, eventType, filter = {}, timeout = 10000) {
    try {
      const event = await eventWaiter.waitForEvent(eventType, filter, timeout);
      return {
        message: () => `Expected not to receive SSE event "${eventType}" but received it`,
        pass: true,
        actual: event,
      };
    } catch (error) {
      return {
        message: () => `Expected to receive SSE event "${eventType}" but timed out after ${timeout}ms`,
        pass: false,
      };
    }
  },

  /**
   * Check if element has loading state finished
   */
  async toBeLoaded(locator) {
    const loadingIndicator = locator.locator('[data-testid*="loading"], .loading, .spinner');
    const count = await loadingIndicator.count();
    const pass = count === 0;
    
    return {
      message: () => pass
        ? `Expected element to be loading but it was loaded`
        : `Expected element to be loaded but found ${count} loading indicators`,
      pass,
    };
  },

  /**
   * Check if form has validation errors
   */
  async toHaveValidationError(locator, expectedError) {
    const errorSelector = '[data-testid*="error"], .error-message, .MuiFormHelperText-root.Mui-error';
    const errors = await locator.locator(errorSelector).allTextContents();
    
    const pass = expectedError
      ? errors.some(text => text.includes(expectedError))
      : errors.length > 0;
    
    return {
      message: () => pass
        ? `Expected not to find validation error "${expectedError || 'any'}" but found: ${errors.join(', ')}`
        : `Expected to find validation error "${expectedError || 'any'}" but found none`,
      pass,
    };
  },

  /**
   * Check if notification/toast is visible with specific message
   */
  async toShowNotification(page, expectedMessage, type = 'success') {
    const notificationSelector = `[data-testid*="${type}"], .MuiAlert-${type}, [role="alert"]`;
    const notifications = await page.locator(notificationSelector).allTextContents();
    
    const pass = notifications.some(text => text.includes(expectedMessage));
    
    return {
      message: () => pass
        ? `Expected not to show ${type} notification "${expectedMessage}" but found it`
        : `Expected ${type} notification "${expectedMessage}" but found: ${notifications.join(', ')}`,
      pass,
    };
  },
});

module.exports = { expect };

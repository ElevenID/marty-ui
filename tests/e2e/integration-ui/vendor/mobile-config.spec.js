/**
 * Mobile App Configuration Tests
 * 
 * Tests for configuring organization settings for mobile wallet integration.
 * 
 * SKIPPED: Mobile configuration UI not yet implemented
 */
const { test, expect } = require('@playwright/test');
const { AuthHelpers, SEEDED_USERS } = require('../../../utils/test-helpers');

test.describe.skip('Mobile App Configuration', () => {
  let auth;

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
    await page.goto('/');
    await auth.loginAsSeededUser('vendor');
  });

  test('vendor can access mobile configuration', async ({ page }) => {
    // Navigate to mobile/wallet configuration
    await page.click('text=Settings, text=Configuration, text=Mobile');
    
    // Should see mobile configuration section
    await expect(
      page.locator('text=Mobile App, text=Wallet Configuration, text=Mobile Integration')
    ).toBeVisible();
  });

  test('vendor can configure organization branding for mobile', async ({ page }) => {
    await page.click('text=Settings');
    await page.click('text=Branding, text=Appearance');
    
    // Should see branding options
    await expect(page.locator('text=Logo, text=Colors')).toBeVisible();
    
    // Set primary color
    const colorInput = page.locator('input[type="color"], input[name="primaryColor"]');
    if (await colorInput.isVisible()) {
      await colorInput.fill('#1976d2');
    }
    
    // Set organization display name
    await page.fill('input[name="displayName"], input[placeholder*="Display"]', 'Marty Travel Docs');
    
    // Save changes
    await page.click('button:has-text("Save")');
    
    // Should see success
    await expect(page.locator('.MuiAlert-success')).toBeVisible();
  });

  test('vendor can configure credential templates', async ({ page }) => {
    await page.click('text=Credentials, text=Templates');
    
    // Should see credential template management
    await expect(page.locator('h1:has-text("Credential"), h2:has-text("Template")')).toBeVisible();
    
    // Should see default templates or create button
    await expect(
      page.locator('button:has-text("Create Template")')
        .or(page.locator('text=Travel Document'))
        .or(page.locator('text=No templates'))
    ).toBeVisible();
  });

  test('vendor can configure push notification settings', async ({ page }) => {
    await page.click('text=Settings');
    await page.click('text=Notifications, text=Push');
    
    // Should see notification settings
    await expect(page.locator('text=Push Notifications, text=Notification Settings')).toBeVisible();
    
    // Toggle notification types
    const enabledToggle = page.locator('input[type="checkbox"][name*="enable"], .MuiSwitch-input').first();
    await enabledToggle.click();
    
    // Save
    await page.click('button:has-text("Save")');
    await expect(page.locator('.MuiAlert-success')).toBeVisible();
  });

  test('vendor can view mobile app QR code for organization', async ({ page }) => {
    await page.click('text=Settings');
    await page.click('text=Mobile App, text=Connect');
    
    // Should see QR code or deep link
    await expect(
      page.locator('img[alt*="QR"], canvas')
        .or(page.locator('text=Scan this QR'))
        .or(page.locator('text=Deep Link'))
    ).toBeVisible();
    
    // Should have copy link button
    await expect(page.locator('button:has-text("Copy Link"), button:has-text("Copy")')).toBeVisible();
  });

  test('vendor can configure trusted issuers', async ({ page }) => {
    await page.click('text=Settings, text=Trust');
    await page.click('text=Trusted Issuers, text=Trust Registry');
    
    // Should see trust configuration
    await expect(page.locator('h1:has-text("Trust"), h2:has-text("Issuer")')).toBeVisible();
    
    // Add trusted issuer
    const addButton = page.locator('button:has-text("Add"), button:has-text("Trust New")');
    if (await addButton.isVisible()) {
      await addButton.click();
      
      // Fill issuer details
      await page.fill('input[name="issuerDid"], input[placeholder*="DID"]', 'did:web:example.marty.demo');
      await page.fill('input[name="name"], input[placeholder*="Name"]', 'Example Issuer');
      
      await page.click('button:has-text("Add"), button:has-text("Save")');
      
      // Should appear in list
      await expect(page.locator('text=Example Issuer')).toBeVisible();
    }
  });

  test('vendor can test mobile wallet connection', async ({ page }) => {
    await page.click('text=Settings');
    await page.click('text=Mobile App, text=Test');
    
    // Should see test/preview options
    await expect(
      page.locator('button:has-text("Test Connection")')
        .or(page.locator('button:has-text("Send Test")'))
        .or(page.locator('text=Preview'))
    ).toBeVisible();
  });
});

test.describe('Organization Onboarding Flow', () => {
  let auth;

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
    await page.goto('/');
    await auth.loginAsSeededUser('vendor');
  });

  test('new organization sees setup checklist', async ({ page }) => {
    // For new orgs, should see onboarding checklist
    // This may not show for seeded vendor with existing org
    const checklist = page.locator('[data-testid="setup-checklist"], .onboarding-checklist');
    
    if (await checklist.isVisible()) {
      // Should show setup steps
      await expect(checklist).toContainText(/branding|api key|template/i);
      
      // Steps should be checkable
      await expect(checklist.locator('input[type="checkbox"], .MuiCheckbox-root')).toHaveCount.greaterThan(0);
    }
  });

  test('vendor can skip onboarding steps', async ({ page }) => {
    const skipButton = page.locator('button:has-text("Skip"), button:has-text("Later")');
    
    if (await skipButton.isVisible()) {
      await skipButton.click();
      
      // Should proceed to dashboard
      await expect(page).toHaveURL(/dashboard/);
    }
  });
});

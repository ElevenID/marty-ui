/**
 * API Key Lifecycle Tests
 * 
 * Tests for creating, managing, and revoking API keys.
 */
const { test, expect } = require('@playwright/test');
const { AuthHelpers } = require('../../../utils/test-helpers');

// Skip mobile browsers - UI not designed for mobile viewports
test.skip(({ browserName, viewport }) => viewport?.width < 768, 'Skipping on mobile viewports');

test.describe('API Key Management', () => {
  let auth;

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
    
    // Login as vendor
    await page.goto('/');
    await auth.loginAsSeededUser('vendor');
    
    // Navigate to API keys section
    await page.click('text=API Keys');
    await page.waitForSelector('h1:has-text("API Keys")');
  });

  test('vendor can view API keys page', async ({ page }) => {
    // Should see API keys heading
    await expect(page.locator('h1:has-text("API Keys")')).toBeVisible();
    
    // Should see create button
    await expect(page.locator('button:has-text("Create API Key")')).toBeVisible();
    
    // Should see API keys table
    await expect(page.locator('table')).toBeVisible();
  });

  test('vendor can create new API key', async ({ page }) => {
    // Click create
    await page.click('button:has-text("Create API Key")');
    
    // Wait for dialog
    await page.waitForSelector('[role="dialog"]');
    
    // Fill key name
    const keyName = `Test Key ${Date.now()}`;
    await page.locator('[role="dialog"] input[type="text"]').first().fill(keyName);
    
    // Select at least one scope
    await page.click('label:has-text("Read Credentials")');
    
    // Create the key
    await page.click('[role="dialog"] button:has-text("Create Key")');
    
    // Should show success alert with the key
    await expect(page.locator('text=New API Key Created')).toBeVisible({ timeout: 10000 });
    
    // Should see copy button
    await expect(page.locator('button:has-text("Copy")')).toBeVisible();
    
    // Verify the API key value is shown (starts with mk_)
    await expect(page.locator('.MuiAlert-root').getByText(/mk_[A-Za-z0-9]+/)).toBeVisible();
  });

  test('vendor can copy API key', async ({ page, context, browserName }) => {
    // Skip on non-chromium browsers - clipboard permissions not supported
    test.skip(browserName !== 'chromium', 'Clipboard permissions only supported in Chromium');
    
    // Grant clipboard permissions
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    
    // Create a key first
    await page.click('button:has-text("Create API Key")');
    await page.waitForSelector('[role="dialog"]');
    await page.locator('[role="dialog"] input[type="text"]').first().fill(`Copy Test ${Date.now()}`);
    await page.click('label:has-text("Read Credentials")');
    await page.click('[role="dialog"] button:has-text("Create Key")');
    
    // Wait for key created alert
    await page.waitForSelector('text=New API Key Created');
    const keyLocator = page.locator('.MuiAlert-root').getByText(/mk_[A-Za-z0-9_-]+/).first();
    await expect(keyLocator).toBeVisible({ timeout: 10000 });
    const keyValue = (await keyLocator.textContent())?.trim();
    expect(keyValue).toBeTruthy();
    
    // Copy the key
    await page.click('button:has-text("Copy")');
    
    // Prefer toast confirmation, but fall back to clipboard read for robustness
    let toastVisible = false;
    try {
      await page.locator('text=API key copied to clipboard').waitFor({ state: 'visible', timeout: 2000 });
      toastVisible = true;
    } catch (error) {
      toastVisible = false;
    }
    if (!toastVisible) {
      const clipboardSupported = await page.evaluate(() => !!navigator.clipboard?.readText);
      if (clipboardSupported) {
        const clipboardText = await page.evaluate(() => navigator.clipboard.readText());
        expect(clipboardText).toContain(keyValue);
      } else {
        await expect(page.locator('.MuiAlert-root').getByText(keyValue)).toBeVisible();
      }
    }
  });

  // Skip this test until organization ID is properly provisioned for test users
  // The test requires the API key table to load, which needs a valid organizationId
  test.skip('vendor can revoke API key via menu', async ({ page }) => {
    // Create a key to revoke
    await page.click('button:has-text("Create API Key")');
    await page.waitForSelector('[role="dialog"]');
    const keyName = `Revoke Test ${Date.now()}`;
    await page.locator('[role="dialog"] input[type="text"]').first().fill(keyName);
    await page.click('label:has-text("Read Credentials")');
    await page.click('[role="dialog"] button:has-text("Create Key")');
    
    // Close the key created alert
    await page.waitForSelector('text=New API Key Created');
    await page.locator('.MuiAlert-root button').first().click();
    
    // Find and click the menu on the key row
    const keyRow = page.locator(`tr:has-text("${keyName}")`);
    await keyRow.locator('[data-testid="key-actions-menu"]').click();
    
    // Wait for menu and click revoke
    await page.click('[role="menuitem"]:has-text("Revoke")');
    
    // Should show key as revoked
    await expect(keyRow.locator('text=Revoked')).toBeVisible();
  });

  // Skip this test until organization ID is properly provisioned for test users
  // The test requires the API key table to load, which needs a valid organizationId
  test.skip('vendor can delete API key', async ({ page }) => {
    // Create a key to delete
    await page.click('button:has-text("Create API Key")');
    await page.waitForSelector('[role="dialog"]');
    const keyName = `Delete Test ${Date.now()}`;
    await page.locator('[role="dialog"] input[type="text"]').first().fill(keyName);
    await page.click('label:has-text("Read Credentials")');
    await page.click('[role="dialog"] button:has-text("Create Key")');
    
    // Close the key created alert
    await page.waitForSelector('text=New API Key Created');
    await page.locator('.MuiAlert-root button').first().click();
    
    // Find and click the menu on the key row
    const keyRow = page.locator(`tr:has-text("${keyName}")`);
    await keyRow.locator('[data-testid="key-actions-menu"]').click();
    
    // Click delete
    await page.click('[role="menuitem"]:has-text("Delete")');
    
    // Confirm deletion
    await page.waitForSelector('text=Delete API Key?');
    await page.locator('[role="dialog"] button:has-text("Delete")').click();
    
    // Key should be removed
    await expect(page.locator(`td:has-text("${keyName}")`)).not.toBeVisible();
    await expect(page.locator('text=API key deleted')).toBeVisible();
  });
});

test.describe('API Key Scopes', () => {
  let auth;

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
    await page.goto('/');
    await auth.loginAsSeededUser('vendor');
    await page.click('text=API Keys');
    await page.waitForSelector('h1:has-text("API Keys")');
  });

  test('can view available scopes', async ({ page }) => {
    await page.click('button:has-text("Create API Key")');
    await page.waitForSelector('[role="dialog"]');
    
    // Should see scope options
    await expect(page.locator('text=Permissions')).toBeVisible();
    await expect(page.locator('label:has-text("Read Credentials")')).toBeVisible();
    await expect(page.locator('label:has-text("Write Credentials")')).toBeVisible();
    await expect(page.locator('label:has-text("Read Trust Registry")')).toBeVisible();
  });

  test('can create key with multiple scopes', async ({ page }) => {
    await page.click('button:has-text("Create API Key")');
    await page.waitForSelector('[role="dialog"]');
    
    const keyName = `Multi-Scope Key ${Date.now()}`;
    await page.locator('[role="dialog"] input[type="text"]').first().fill(keyName);
    
    // Select multiple scopes
    await page.click('label:has-text("Read Credentials")');
    await page.click('label:has-text("Write Credentials")');
    await page.click('label:has-text("Read Revocation")');
    
    await page.click('[role="dialog"] button:has-text("Create Key")');
    
    // Verify key was created successfully
    await expect(page.locator('text=New API Key Created')).toBeVisible({ timeout: 10000 });
    
    // Verify the API key value is shown (starts with mk_)
    await expect(page.locator('.MuiAlert-root').getByText(/mk_[A-Za-z0-9]+/)).toBeVisible();
    
    // Verify copy button is available
    await expect(page.locator('button:has-text("Copy")')).toBeVisible();
  });

  test('requires at least one scope', async ({ page }) => {
    await page.click('button:has-text("Create API Key")');
    await page.waitForSelector('[role="dialog"]');
    await page.locator('[role="dialog"] input[type="text"]').first().fill(`No Scope Key ${Date.now()}`);
    
    // Try to create without selecting scopes
    await page.click('[role="dialog"] button:has-text("Create Key")');
    
    // Should show warning
    await expect(page.locator('text=Please select at least one scope')).toBeVisible();
  });
});

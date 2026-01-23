const { test, expect } = require('@playwright/test');

test('debug cookie issue', async ({ page }) => {
  // Navigate to app
  await page.goto('/');
  await page.waitForLoadState('networkidle');
  
  // Click login
  await page.click('button:has-text("Sign In to Continue"), button:has-text("Login"), button:has-text("Sign In"), a:has-text("Login")');
  
  // Wait for Keycloak
  await page.waitForSelector('#username, input[name="username"], input[type="email"]', { timeout: 15000 });
  
  // Fill login - using admin user
  const passwordFieldVisible = await page.locator('#password').isVisible().catch(() => false);
  if (passwordFieldVisible) {
    await page.fill('#username', 'admin@marty.local');
    await page.fill('#password', 'admin123');
    await page.click('#kc-login, button[type="submit"]');
  } else {
    await page.locator('#username, input[type="email"]').first().fill('admin@marty.local');
    await page.click('button:has-text("Sign In"), button:has-text("Next"), button[type="submit"]');
    await page.waitForSelector('#password, input[type="password"]', { timeout: 15000 });
    await page.fill('#password, input[type="password"]', 'admin123');
    await page.click('button:has-text("Sign In"), button[type="submit"]');
  }
  
  // Wait for redirect
  await page.waitForURL(url => !url.toString().includes('realms'), { timeout: 15000 });
  await page.waitForLoadState('networkidle');
  
  // Check cookies for specific URLs
  console.log('=== COOKIES FOR http://localhost:9080 ===');
  const appCookies = await page.context().cookies('http://localhost:9080');
  for (const c of appCookies) {
    console.log(`${c.name} = ${c.value.substring(0, 50)}... (domain: ${c.domain}, path: ${c.path})`);
  }
  
  console.log('=== COOKIES FOR http://localhost:8180 ===');
  const kcCookies = await page.context().cookies('http://localhost:8180');
  for (const c of kcCookies) {
    console.log(`${c.name} = ${c.value.substring(0, 50)}... (domain: ${c.domain}, path: ${c.path})`);
  }
  
  // Check current URL
  console.log('=== CURRENT URL ===');
  console.log(page.url());
  
  // Try fetch from page context - this should work
  console.log('=== TRYING page.evaluate fetch ===');
  const meResult = await page.evaluate(async () => {
    const resp = await fetch('/auth/me', { credentials: 'include' });
    return { status: resp.status, body: await resp.text() };
  });
  console.log('Status:', meResult.status);
  console.log('Body:', meResult.body);
  
  expect(meResult.status).toBe(200);
  expect(JSON.parse(meResult.body).authenticated).toBe(true);
});

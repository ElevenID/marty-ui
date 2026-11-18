const { test, expect } = require('@playwright/test');

test('debug wallet direct', async ({ page }) => {
  page.on('console', msg => console.log(`[BrowserLog] ${msg.text()}`));
  page.on('requestfailed', request => {
    console.log(`[Network] Failed: ${request.url()} - ${request.failure().errorText}`);
  });
  
  console.log('Navigating directly to wallet...');
  const response = await page.goto('http://localhost:9081?test_mode=true');
  console.log('Status:', response.status());
  console.log('Headers:', response.headers());
  
  await page.waitForTimeout(5000);
  await page.screenshot({ path: 'test-results/wallet-direct.png' });
});
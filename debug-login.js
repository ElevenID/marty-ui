/**
 * Playwright Login Debug Script
 * 
 * Troubleshoots login issues on beta.elevenidllc.com
 * Run with: node debug-login.js
 */

const { chromium } = require('playwright');

async function debugLogin() {
  console.log('🔍 Starting login debug session...\n');
  
  const browser = await chromium.launch({
    headless: false, // Show browser for debugging
    slowMo: 1000, // Slow down by 1 second for visibility
  });
  
  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
  });
  
  const page = await context.newPage();
  
  // Capture console messages
  const consoleMessages = [];
  page.on('console', msg => {
    const text = msg.text();
    consoleMessages.push({ type: msg.type(), text });
    console.log(`📝 [Console ${msg.type()}]:`, text);
  });
  
  // Capture network errors
  page.on('requestfailed', request => {
    console.log(`❌ [Network Failed]:`, request.url(), request.failure().errorText);
  });
  
  // Capture response errors
  page.on('response', response => {
    if (response.status() >= 400) {
      console.log(`⚠️  [HTTP ${response.status()}]:`, response.url());
    }
  });
  
  try {
    console.log('1️⃣  Navigating to https://beta.elevenidllc.com...');
    const response = await page.goto('https://beta.elevenidllc.com', {
      waitUntil: 'domcontentloaded',
      timeout: 30000,
    });
    
    console.log(`   Status: ${response.status()}`);
    console.log(`   URL: ${page.url()}\n`);
    
    await page.screenshot({ path: 'debug-1-homepage.png', fullPage: true });
    console.log('   📸 Screenshot saved: debug-1-homepage.png\n');
    
    // Wait a bit for any initial loading
    await page.waitForTimeout(2000);
    
    console.log('2️⃣  Looking for login button...');
    
    // Try multiple selectors for login button
    const loginSelectors = [
      'button:has-text("Login")',
      'button:has-text("Sign In")',
      'button:has-text("Log In")',
      'a:has-text("Login")',
      'a:has-text("Sign In")',
      '[data-testid="login-button"]',
      '.login-button',
      '#login-button',
    ];
    
    let loginButton = null;
    for (const selector of loginSelectors) {
      try {
        loginButton = await page.locator(selector).first();
        if (await loginButton.isVisible({ timeout: 1000 })) {
          console.log(`   ✅ Found login button with selector: ${selector}\n`);
          break;
        }
      } catch (e) {
        // Continue to next selector
      }
    }
    
    if (!loginButton || !(await loginButton.isVisible().catch(() => false))) {
      console.log('   ⚠️  No login button found. Checking page content...\n');
      const bodyText = await page.locator('body').textContent();
      console.log('   Page text (first 500 chars):', bodyText.substring(0, 500));
      
      await page.screenshot({ path: 'debug-2-no-login-button.png', fullPage: true });
      console.log('   📸 Screenshot saved: debug-2-no-login-button.png\n');
    } else {
      console.log('3️⃣  Clicking login button...');
      await loginButton.click();
      
      // Wait for navigation or popup
      await Promise.race([
        page.waitForURL(/keycloak|auth|login/, { timeout: 10000 }),
        page.waitForTimeout(5000),
      ]);
      
      console.log(`   Current URL: ${page.url()}\n`);
      await page.screenshot({ path: 'debug-3-after-login-click.png', fullPage: true });
      console.log('   📸 Screenshot saved: debug-3-after-login-click.png\n');
      
      // Check if we're on Keycloak login page
      if (page.url().includes('keycloak') || page.url().includes('auth/realms')) {
        console.log('4️⃣  On Keycloak login page. Checking form...');
        
        const usernameInput = page.locator('input[name="username"], input#username');
        const passwordInput = page.locator('input[name="password"], input#password, input[type="password"]');
        
        const hasUsername = await usernameInput.isVisible().catch(() => false);
        const hasPassword = await passwordInput.isVisible().catch(() => false);
        
        console.log(`   Username field visible: ${hasUsername}`);
        console.log(`   Password field visible: ${hasPassword}\n`);
        
        await page.screenshot({ path: 'debug-4-keycloak-login.png', fullPage: true });
        console.log('   📸 Screenshot saved: debug-4-keycloak-login.png\n');
        
        // Try to get test credentials from env
        const username = process.env.TEST_USERNAME || 'test@example.com';
        const password = process.env.TEST_PASSWORD || 'test123';
        
        console.log(`5️⃣  Attempting login with username: ${username}`);
        
        if (hasUsername && hasPassword) {
          await usernameInput.fill(username);
          await passwordInput.fill(password);
          
          const loginSubmit = page.locator('button[type="submit"], input[type="submit"]').first();
          await loginSubmit.click();
          
          // Wait for redirect back
          await Promise.race([
            page.waitForURL(/beta\.elevenidllc\.com/, { timeout: 10000 }),
            page.waitForTimeout(5000),
          ]);
          
          console.log(`   After login URL: ${page.url()}\n`);
          await page.screenshot({ path: 'debug-5-after-keycloak.png', fullPage: true });
          console.log('   📸 Screenshot saved: debug-5-after-keycloak.png\n');
        }
      } else {
        console.log('4️⃣  Not redirected to Keycloak. Checking current page...\n');
      }
      
      // Check for cookies
      console.log('6️⃣  Checking cookies...');
      const cookies = await context.cookies();
      const sessionCookie = cookies.find(c => c.name === 'sessionId' || c.name.toLowerCase().includes('session'));
      
      if (sessionCookie) {
        console.log(`   ✅ Found session cookie: ${sessionCookie.name}`);
        console.log(`      Domain: ${sessionCookie.domain}`);
        console.log(`      Path: ${sessionCookie.path}`);
        console.log(`      Secure: ${sessionCookie.secure}`);
        console.log(`      HttpOnly: ${sessionCookie.httpOnly}`);
        console.log(`      SameSite: ${sessionCookie.sameSite}\n`);
      } else {
        console.log('   ❌ No session cookie found');
        console.log('   All cookies:', cookies.map(c => c.name).join(', '), '\n');
      }
      
      // Check localStorage
      console.log('7️⃣  Checking localStorage...');
      const localStorage = await page.evaluate(() => {
        const items = {};
        for (let i = 0; i < window.localStorage.length; i++) {
          const key = window.localStorage.key(i);
          items[key] = window.localStorage.getItem(key);
        }
        return items;
      });
      console.log('   LocalStorage keys:', Object.keys(localStorage).join(', '), '\n');
      
      // Try to call /v1/auth/me
      console.log('8️⃣  Testing auth endpoint...');
      try {
        const authResponse = await page.request.get('https://beta.elevenidllc.com/v1/auth/me');
        console.log(`   /v1/auth/me status: ${authResponse.status()}`);
        if (authResponse.ok()) {
          const data = await authResponse.json();
          console.log('   User data:', JSON.stringify(data, null, 2));
        } else {
          const text = await authResponse.text();
          console.log('   Error:', text);
        }
      } catch (e) {
        console.log('   ❌ Failed to call auth endpoint:', e.message);
      }
      console.log('');
    }
    
    // Summary
    console.log('📊 Summary:');
    console.log(`   - Total console messages: ${consoleMessages.length}`);
    console.log(`   - Errors: ${consoleMessages.filter(m => m.type === 'error').length}`);
    console.log(`   - Warnings: ${consoleMessages.filter(m => m.type === 'warning').length}`);
    console.log(`   - Final URL: ${page.url()}`);
    
    // Keep browser open for inspection
    console.log('\n✋ Browser will stay open for 30 seconds for manual inspection...');
    await page.waitForTimeout(30000);
    
  } catch (error) {
    console.error('\n💥 Error during debug:', error.message);
    await page.screenshot({ path: 'debug-error.png', fullPage: true });
    console.log('📸 Error screenshot saved: debug-error.png\n');
  } finally {
    await browser.close();
    console.log('\n✅ Debug session complete. Check the screenshots for visual inspection.');
  }
}

// Run the debug
debugLogin().catch(console.error);

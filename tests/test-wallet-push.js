const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  
  // Collect console messages
  const consoleLogs = [];
  page.on('console', msg => {
    consoleLogs.push(`[Console] ${msg.type()} ${msg.text()}`);
    console.log(`[Console] ${msg.type()} ${msg.text()}`);
  });
  
  console.log('Navigating to wallet simulator...');
  await page.goto('http://localhost:9081/?test_mode=true');
  
  console.log('Waiting for WALLET_READY...');
  const readyPromise = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timeout waiting for WALLET_READY')), 30000);
    
    page.on('console', (msg) => {
      if (msg.text().includes('WALLET_READY')) {
        clearTimeout(timeout);
        resolve();
      }
    });
  });
  
  try {
    await readyPromise;
    console.log('Wallet is ready!');
  } catch (e) {
    console.log('Timeout waiting for WALLET_READY - checking logs...');
  }
  
  await page.waitForTimeout(3000);
  
  // Send QR registration message
  console.log('Sending REGISTER_PUSH_VIA_QR message...');
  // Payload must have qr_data field containing the QR data
  const qrData = {
    serial: 'TEST123',
    url: 'http://oid4vc-api:8080/push/register',
    ttl: 3600,
    projectid: 'test-project',
    enrollment_credential: 'test-cred',
    sslverify: true
  };
  
  // Wrap in qr_data as expected by _handleRegisterPushViaQR
  const payload = { qr_data: qrData };
  
  const registerPromise = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      console.log('Timeout waiting for PUSH_REGISTERED after 60 seconds');
      reject(new Error('Timeout waiting for PUSH_REGISTERED'));
    }, 60000);
    
    page.on('console', (msg) => {
      const text = msg.text();
      if (text.includes('PUSH_REGISTERED')) {
        console.log('Got PUSH_REGISTERED response!');
        clearTimeout(timeout);
        resolve(text);
      }
      if (text.includes('Error') || text.includes('error')) {
        console.log('Error detected:', text);
      }
    });
  });
  
  // Post message via frame - use { type, payload } format, not JSON.stringify
  const walletFrame = page.frames().find(f => f.url().includes('test_mode=true')) || page.mainFrame();
  await walletFrame.evaluate((payload) => {
    window.postMessage({ 
      type: 'REGISTER_PUSH_VIA_QR', 
      payload: payload 
    }, '*');
  }, payload);
  
  try {
    const result = await registerPromise;
    console.log('SUCCESS! Push registration completed:', result);
  } catch (e) {
    console.log('\n=== Console logs collected ===');
    consoleLogs.forEach(log => console.log(log));
    console.log('\nFailed:', e.message);
  }
  
  await browser.close();
})();

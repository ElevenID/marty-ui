// Global setup for Playwright tests
const axios = require('axios');

async function globalSetup() {
  console.log('🚀 Starting E2E test setup...');

  const base = process.env.BASE_URL || 'http://localhost:9080';
  const walletUrl = process.env.WALLET_URL || 'http://localhost:9081';

  // Step 1: Validate Flutter wallet is running for e2e-flows tests
  await validateFlutterWallet(walletUrl);

  // Step 2: Wait for demo application to be ready
  const maxRetries = 30;
  const retryDelay = 2000; // 2 seconds

  for (let i = 0; i < maxRetries; i++) {
    try {
      console.log(`⏳ Checking if demo is ready (attempt ${i + 1}/${maxRetries})...`);

      // Check main UI
      await axios.get(base, { timeout: 5000 });

      // Check backend services
      const services = [
        { name: 'Issuer', url: `${base.replace(/\/$/, '')}/api/issuer/health` },
        { name: 'Verifier', url: `${base.replace(/\/$/, '')}/api/verifier/health` },
        { name: 'Wallet', url: `${base.replace(/\/$/, '')}/api/wallet/health` }
      ];

      for (const service of services) {
        try {
          await axios.get(service.url, { timeout: 3000 });
          console.log(`✅ ${service.name} service is ready`);
        } catch (error) {
          console.log(`⚠️  ${service.name} service not ready yet`);
        }
      }

      console.log('✅ Demo application is ready!');
      
      // Generate test signing keys
      await generateTestKeys(base);
      
      return;
    } catch (error) {
      if (i === maxRetries - 1) {
        throw new Error(
          `❌ Demo application failed to start after ${maxRetries} attempts. ` +
          'Please ensure the demo is running with ./deploy-k8s.sh'
        );
      }
      console.log(`⏳ Demo not ready yet, retrying in ${retryDelay}ms...`);
      await new Promise(resolve => setTimeout(resolve, retryDelay));
    }
  }
}

/**
 * Generate fresh signing keys for credential issuance tests.
 * 
 * This ensures keys are available in Redis for all credential formats:
 * - ES256: SD-JWT-VC
 * - RS256: JWT VC JSON
 * - P-256: mDL/mso_mdoc
 */
async function generateTestKeys(baseUrl) {
  console.log('🔑 Generating test signing keys...');
  
  try {
    const response = await axios.post(
      `${baseUrl.replace(/\/$/, '')}/api/issuance/test-keys`,
      {
        organization_id: 'test-org',
        algorithms: ['ES256', 'RS256', 'P-256'],
        force_regenerate: false,  // Only generate if not already present
      },
      { timeout: 10000 }
    );
    
    const { generated_keys, message } = response.data;
    console.log(`✅ Test keys ready: ${message}`);
    
    for (const key of generated_keys) {
      console.log(`   ${key.algorithm}:${key.key_id} - ${key.status}`);
    }
  } catch (error) {
    // Log but don't fail - keys might already exist or endpoint not available
    if (error.response?.status === 403) {
      console.log('⚠️  Test key generation not available (non-test environment)');
    } else if (error.response?.status === 404) {
      console.log('⚠️  Test key endpoint not available yet');
    } else {
      console.log(`⚠️  Could not generate test keys: ${error.message}`);
    }
  }
}

module.exports = globalSetup;

/**
 * Validate that Flutter wallet is running at the expected URL.
 * This ensures e2e-flows tests have the real wallet for UI capture.
 * 
 * @param {string} walletUrl - Wallet URL to validate
 */
async function validateFlutterWallet(walletUrl) {
  console.log(`📱 Validating Flutter wallet at ${walletUrl}...`);
  
  try {
    // First, check if wallet is responding
    const response = await axios.get(walletUrl, { timeout: 5000 });
    
    // Check for Flutter-specific content in the response
    const html = response.data;
    const isFlutter = 
      html.includes('flutter.js') || 
      html.includes('flutter_service_worker.js') ||
      html.includes('main.dart.js') ||
      html.includes('canvaskit');
    
    // Check for HTML test stub (should not be present)
    const isHtmlStub = 
      html.includes('class="test-wallet-container"') ||
      html.includes('id="test-wallet"') ||
      html.includes('TestWallet');
    
    if (isHtmlStub) {
      throw new Error(
        `❌ HTML test wallet stub detected at ${walletUrl}.\n` +
        '   Flutter web wallet is required for E2E tests.\n' +
        '   Run: make build-wallet && docker compose restart wallet'
      );
    }
    
    if (!isFlutter) {
      console.log('⚠️  Could not confirm Flutter wallet (may still work)');
    } else {
      console.log('✅ Flutter wallet detected and responding');
    }
  } catch (error) {
    if (error.message.includes('HTML test wallet')) {
      throw error;
    }
    
    // Wallet might not be needed for all test projects
    console.log(`⚠️  Wallet not available at ${walletUrl}: ${error.message}`);
    console.log('   Some e2e-flows tests may fail. Run: make dev');
  }
}

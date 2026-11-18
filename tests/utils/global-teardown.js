// Global teardown for Playwright tests
async function globalTeardown() {
  console.log('🧹 Running E2E test teardown...');

  // Clean up Mailpit emails if TEST_PROVIDER is mailpit
  const testProvider = process.env.TEST_PROVIDER || 'mailpit';
  if (testProvider === 'mailpit') {
    try {
      const mailpitUrl = process.env.MAILPIT_URL || 'http://localhost:8025';
      const response = await fetch(`${mailpitUrl}/api/v1/messages`, {
        method: 'DELETE',
      });
      if (response.ok) {
        console.log('✅ Cleaned up Mailpit emails');
      }
    } catch (error) {
      console.log('⚠️  Failed to clean Mailpit (may not be running):', error.message);
    }
  }

  console.log('✅ E2E test teardown completed');
}

module.exports = globalTeardown;

// Global teardown for Playwright tests
async function globalTeardown() {
  console.log('🧹 Running E2E test teardown...');

  // Clean up MailHog emails if TEST_PROVIDER is mailhog
  const testProvider = process.env.TEST_PROVIDER || 'mailhog';
  if (testProvider === 'mailhog') {
    try {
      const mailhogUrl = process.env.MAILHOG_URL || 'http://localhost:8025';
      const response = await fetch(`${mailhogUrl}/api/v1/messages`, {
        method: 'DELETE',
      });
      if (response.ok) {
        console.log('✅ Cleaned up MailHog emails');
      }
    } catch (error) {
      console.log('⚠️  Failed to clean MailHog (may not be running):', error.message);
    }
  }

  console.log('✅ E2E test teardown completed');
}

module.exports = globalTeardown;

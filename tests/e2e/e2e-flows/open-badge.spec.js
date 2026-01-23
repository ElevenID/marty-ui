/**
 * Open Badge E2E Tests
 *
 * Exercises OB2/OB3 issuance + verification via test endpoints and ensures
 * the wallet can store and render badges like other credentials.
 */

const { test, expect } = require('@playwright/test');
const { WalletBridge, AuthHelpers, getVendorOrganizationId } = require('../../utils/test-helpers');

const API_BASE = process.env.API_URL || 'http://localhost:8000';

// Set longer timeout for wallet communication tests
test.setTimeout(90000);

test.describe('Open Badge E2E', () => {
  let openBadgeConfigId;
  let organizationId;

  test.beforeAll(async ({ browser }) => {
    try {
      const vendorOrg = await getVendorOrganizationId(browser);
      organizationId = vendorOrg.organizationId;

      const page = await browser.newPage();
      const auth = new AuthHelpers(page);
      await page.goto('/');
      await auth.loginAsSeededUser('admin');

      const listResponse = await page.request.get(
        `/api/organizations/${organizationId}/credential-types`
      );
      if (!listResponse.ok()) {
        throw new Error('Failed to list credential configurations');
      }
      const listData = await listResponse.json();
      const configs = listData.credential_types || [];
      const existing = configs.find((config) => config.credential_type === 'open_badge');

      if (existing) {
        openBadgeConfigId = existing.id;
      } else {
        const createResponse = await page.request.post(
          `/api/organizations/${organizationId}/credential-types`,
          {
            data: {
              credential_type: 'open_badge',
              display_name: 'Open Badge',
              validity_days: 365,
            },
          }
        );
        if (!createResponse.ok()) {
          throw new Error('Failed to create Open Badge credential configuration');
        }
        const created = await createResponse.json();
        openBadgeConfigId = created.credential_type?.id;
      }

      await page.close();
    } catch (e) {
      console.log('⚠️ Backend not available:', e.message);
      test.skip();
    }
  });

  test('issues, verifies, and stores Open Badge v2', async ({ page, request }) => {
    const recipientName = 'Open Badge Recipient V2';
    const badgeName = 'Marty OB2 Badge';

    const issueResponse = await request.post(`${API_BASE}/api/open-badges/issue`, {
      data: {
        credential_configuration_id: openBadgeConfigId,
        version: 'v2',
        recipient_identity: 'ob2.recipient@example.org',
        recipient_name: recipientName,
        badge_name: badgeName,
        badge_description: 'OB2 badge for E2E testing',
      },
    });

    expect(issueResponse.ok()).toBeTruthy();
    const issued = await issueResponse.json();
    expect(issued.success).toBe(true);
    expect(issued.issued).toBe(true);
    expect(issued.version).toBe('2.0');
    expect(issued.credential?.id).toBeTruthy();

    const verifyResponse = await request.post(`${API_BASE}/api/open-badges/verify`, {
      data: {
        version: 'v2',
        credential: issued.credential,
        document_store: issued.document_store,
        recipient_identity: 'ob2.recipient@example.org',
      },
    });

    expect(verifyResponse.ok()).toBeTruthy();
    const verified = await verifyResponse.json();
    expect(verified.valid).toBe(true);

    const walletBridge = new WalletBridge(page);
    await walletBridge.init();
    await walletBridge.enableAccessibility();
    await walletBridge.clearData();
    await walletBridge.storeCredential(issued.credential);

    const credentials = await walletBridge.waitForCredentials(1);
    expect(credentials.find((cred) => cred.id === issued.credential.id)).toBeTruthy();
    const displayCredential = await walletBridge.waitForDisplayCredential(
      (cred) => cred.id === issued.credential.id,
      10000
    );
    expect(displayCredential?.subjectName).toBe(recipientName);
    expect(displayCredential?.credentialType).toBe('Open Badge');
  });

  test('issues, verifies, and stores Open Badge v3', async ({ page, request }) => {
    const recipientName = 'Open Badge Recipient V3';
    const badgeName = 'Marty OB3 Badge';

    const issueResponse = await request.post(`${API_BASE}/api/open-badges/issue`, {
      data: {
        credential_configuration_id: openBadgeConfigId,
        version: 'v3',
        recipient_identity: 'did:example:ob3-recipient',
        recipient_name: recipientName,
        badge_name: badgeName,
        badge_description: 'OB3 badge for E2E testing',
      },
    });

    expect(issueResponse.ok()).toBeTruthy();
    const issued = await issueResponse.json();
    expect(issued.success).toBe(true);
    expect(issued.issued).toBe(true);
    expect(issued.version).toBe('3.0');
    expect(issued.credential?.id).toBeTruthy();

    const verifyResponse = await request.post(`${API_BASE}/api/open-badges/verify`, {
      data: {
        version: 'v3',
        credential: issued.credential,
        document_store: issued.document_store,
      },
    });

    expect(verifyResponse.ok()).toBeTruthy();
    const verified = await verifyResponse.json();
    expect(verified.valid).toBe(true);

    const walletBridge = new WalletBridge(page);
    await walletBridge.init();
    await walletBridge.enableAccessibility();
    await walletBridge.clearData();
    await walletBridge.storeCredential(issued.credential);

    const credentials = await walletBridge.waitForCredentials(1);
    expect(credentials.find((cred) => cred.id === issued.credential.id)).toBeTruthy();
    const displayCredential = await walletBridge.waitForDisplayCredential(
      (cred) => cred.id === issued.credential.id,
      10000
    );
    expect(displayCredential?.subjectName).toBe(recipientName);
    expect(displayCredential?.credentialType).toBe('Open Badge');
  });
});

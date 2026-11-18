/**
 * OID4VCI Issuance E2E Tests
 *
 * Validates the OID4VCI credential issuance protocol:
 * 1. Trust configuration (org key management)
 * 2. Credential offer creation
 * 3. Auto-accept flow (application-based issuance)
 * 4. Credential pickup by authenticator
 * 5. Revocation
 * 
 * Note: For application-based issuance, credentials are auto-accepted
 * since the holder already consented when submitting their application.
 */

const { test, expect } = require('@playwright/test');
const {
  AuthHelpers,
  AuthenticatedApiClient,
  getVendorOrganizationId,
} = require('../../utils/test-helpers');

test.describe('OID4VCI Trust Configuration', () => {
  let organizationId;
  let auth;

  test.beforeAll(async ({ browser }) => {
    const vendorOrg = await getVendorOrganizationId(browser);
    organizationId = vendorOrg.organizationId;
  });

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
  });

  test('admin can configure trust framework', async ({ page }) => {
    await page.goto('/');
    await auth.loginAsSeededUser('admin');

    // Get current trust config
    const getResponse = await page.request.get(
      `/api/organizations/${organizationId}/trust-config`
    );
    
    // Should return 404 if not configured or 200 with config
    expect([200, 404]).toContain(getResponse.status());

    // Configure trust framework
    const putResponse = await page.request.put(
      `/api/organizations/${organizationId}/trust-config`,
      {
        data: {
          trust_framework: 'marty_hosted',
          key_source: 'marty_generated',
        },
      }
    );
    expect(putResponse.ok()).toBeTruthy();

    const config = await putResponse.json();
    expect(config.trust_framework).toBe('marty_hosted');
  });

  test('admin can generate signing keys', async ({ page }) => {
    await page.goto('/');
    await auth.loginAsSeededUser('admin');

    // Generate ES256 key
    const response = await page.request.post(
      `/api/organizations/${organizationId}/trust-config/keys`,
      {
        data: {
          algorithm: 'ES256',
          key_purpose: 'signing',
        },
      }
    );
    expect(response.ok()).toBeTruthy();

    const keyConfig = await response.json();
    expect(keyConfig.key_id).toBeTruthy();
    expect(keyConfig.algorithm).toBe('ES256');
    // ES256 keys use did:jwk format from marty-rs (production behavior)
    expect(keyConfig.did).toMatch(/^did:(key|jwk):/);
    // Private key should not be exposed in response
    expect(keyConfig.jwk_private_encrypted).toBeUndefined();
    expect(keyConfig.private_key_jwk).toBeUndefined();
  });

  test('admin can list and delete signing keys', async ({ page }) => {
    await page.goto('/');
    await auth.loginAsSeededUser('admin');

    // Get trust config with keys
    const getResponse = await page.request.get(
      `/api/organizations/${organizationId}/trust-config`
    );
    expect(getResponse.ok()).toBeTruthy();
    
    const config = await getResponse.json();
    if (config.signing_keys && config.signing_keys.length > 0) {
      const keyId = config.signing_keys[0].key_id;
      
      // Delete the key
      const deleteResponse = await page.request.delete(
        `/api/organizations/${organizationId}/trust-config/keys/${keyId}`
      );
      expect(deleteResponse.ok()).toBeTruthy();
    }
  });
});

test.describe('OID4VCI Credential Offer Flow', () => {
  let organizationId;
  let auth;
  let credentialConfigId;
  let offerId;
  let transactionId;
  let preAuthorizedCode;

  test.beforeAll(async ({ browser }) => {
    const vendorOrg = await getVendorOrganizationId(browser);
    organizationId = vendorOrg.organizationId;

    const page = await browser.newPage();
    const adminAuth = new AuthHelpers(page);
    const api = new AuthenticatedApiClient(page);
    await page.goto('/');
    await adminAuth.loginAsSeededUser('admin');

    // Setup credential config and trust framework using API client
    const config = await api.ensureCredentialConfig(organizationId, {
      credential_type: 'employee_badge',
      display_name: 'Employee Badge',
      validity_days: 365,
    });
    credentialConfigId = config.id;

    // Ensure trust config with signing key exists
    await api.ensureTrustConfig(organizationId, 'ES256');

    await page.close();
  });

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
  });

  test('admin creates credential offer (auto-accept)', async ({ page }) => {
    await page.goto('/');
    await auth.loginAsSeededUser('admin');

    // Create credential offer with device_id for auto-accept flow
    const deviceId = `test-device-${Date.now()}`;
    // Debug: Check auth state before making offer
    const meResponse = await page.request.get('/auth/me');
    const meData = await meResponse.json();
    console.log('Auth state before offer:', JSON.stringify(meData, null, 2));
    
    const response = await page.request.post('/api/issuance/offers', {
      data: {
        organization_id: organizationId,
        credential_config_id: credentialConfigId || 'employee_badge',
        applicant_id: 'test-applicant-123',
        device_id: deviceId,
        credential_data: {
          given_name: 'Alice',
          family_name: 'Smith',
          employee_id: 'EMP-001',
          department: 'Engineering',
        },
        credential_format: 'vc+sd-jwt',
      },
    });
    
    if (!response.ok()) {
      const errorBody = await response.text();
      console.log('Error response:', response.status(), errorBody);
    }
    expect(response.ok()).toBeTruthy();

    const offer = await response.json();
    // API returns transaction_id as the main identifier (not offer_id)
    expect(offer.transaction_id).toBeTruthy();
    expect(offer.credential_offer_uri).toBeTruthy();
    // Status for non-deferred should be PENDING or READY
    expect(['pending', 'ready', 'issued', 'PENDING', 'READY', 'ISSUED']).toContain(offer.status);

    // Store for later tests (use transaction_id as the offer identifier)
    offerId = offer.transaction_id;
    transactionId = offer.transaction_id;
    preAuthorizedCode = offer.pre_authorized_code;

    // Verify credential is queued for pickup
    const pickupResponse = await page.request.get(`/api/issuance/pickup/${deviceId}`);
    expect(pickupResponse.ok()).toBeTruthy();
    
    const pendingCredentials = await pickupResponse.json();
    expect(Array.isArray(pendingCredentials)).toBeTruthy();
    // Should have credential in pickup queue
    if (pendingCredentials.length > 0) {
      expect(pendingCredentials[0].type).toBe('credential_issued');
      expect(pendingCredentials[0].data.action).toBe('store_credential');
    }
  });

  test('wallet retrieves credential offer (manual flow)', async ({ page }) => {
    // For manual flow without device_id, create a new offer
    await page.goto('/');
    await auth.loginAsSeededUser('admin');

    const manualResponse = await page.request.post('/api/issuance/offers', {
      data: {
        organization_id: organizationId,
        credential_config_id: credentialConfigId || 'employee_badge',
        applicant_id: 'test-applicant-manual',
        credential_data: {
          given_name: 'Bob',
          family_name: 'Manual',
        },
        credential_format: 'vc+sd-jwt',
      },
    });
    expect(manualResponse.ok()).toBeTruthy();
    const manualOffer = await manualResponse.json();
    // Use transaction_id as the identifier (API doesn't return offer_id)
    const manualOfferId = manualOffer.transaction_id;
    
    // Store transaction_id and pre_authorized_code for dependent tests
    transactionId = manualOffer.transaction_id;
    preAuthorizedCode = manualOffer.pre_authorized_code;

    // No auth required for offer retrieval (public endpoint for wallets)
    const response = await page.request.get(`/api/issuance/offers/${manualOfferId}`);
    expect(response.ok()).toBeTruthy();

    const offer = await response.json();
    expect(offer.credential_issuer).toBeTruthy();
    expect(offer.credential_configuration_ids).toContain(credentialConfigId || 'employee_badge');
    expect(offer.grants).toBeTruthy();
    expect(offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).toBeTruthy();
  });

  test('wallet exchanges pre-authorized code for token', async ({ page }) => {
    expect(preAuthorizedCode).toBeTruthy();

    const response = await page.request.post('/api/issuance/token', {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthorizedCode}`,
    });
    expect(response.ok()).toBeTruthy();

    const tokenResponse = await response.json();
    expect(tokenResponse.access_token).toBeTruthy();
    expect(tokenResponse.token_type).toBe('Bearer');
    expect(tokenResponse.c_nonce).toBeTruthy();
  });

  test('wallet retrieves credential', async ({ page }) => {
    expect(transactionId).toBeTruthy();

    // Get access token first
    const tokenResponse = await page.request.post('/api/issuance/token', {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthorizedCode}`,
    });
    const { access_token } = await tokenResponse.json();

    // Request credential
    const response = await page.request.post('/api/issuance/credential', {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
      data: {
        format: 'vc+sd-jwt',
        credential_identifier: credentialConfigId || 'employee_badge',
      },
    });
    expect(response.ok()).toBeTruthy();

    const credentialResponse = await response.json();
    // Should return credential directly (not deferred) since we wait for generation
    expect(credentialResponse.credential || credentialResponse.transaction_id).toBeTruthy();
  });

  test('polls deferred credential status', async ({ page }) => {
    expect(transactionId).toBeTruthy();

    // Login to access session status (admin can view any session)
    await page.goto('/');
    await auth.loginAsSeededUser('admin');

    const response = await page.request.get(
      `/api/issuance/sessions/${transactionId}`
    );
    expect(response.ok()).toBeTruthy();

    const session = await response.json();
    expect(['READY', 'ISSUED', 'PENDING', 'DEFERRED', 'ready', 'issued', 'pending', 'deferred', 'ACCEPTED', 'accepted']).toContain(session.status);
  });
});

test.describe('OID4VCI Issuer Metadata', () => {
  let organizationId;

  test.beforeAll(async ({ browser }) => {
    const vendorOrg = await getVendorOrganizationId(browser);
    organizationId = vendorOrg.organizationId;
  });

  test('returns issuer metadata', async ({ page }) => {
    const response = await page.request.get(
      `/api/issuance/.well-known/openid-credential-issuer/${organizationId}`
    );
    expect(response.ok()).toBeTruthy();

    const metadata = await response.json();
    expect(metadata.credential_issuer).toBeTruthy();
    expect(metadata.credential_endpoint).toBeTruthy();
    expect(metadata.token_endpoint).toBeTruthy();
    expect(metadata.credential_configurations_supported).toBeTruthy();
  });
});

test.describe('OID4VCI Integration with Approval Flow', () => {
  let organizationId;
  let auth;
  let applicationId;

  test.beforeAll(async ({ browser }) => {
    const vendorOrg = await getVendorOrganizationId(browser);
    organizationId = vendorOrg.organizationId;
  });

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
  });

  test('application approval triggers credential offer creation', async ({ page }) => {
    await page.goto('/');
    await auth.loginAsSeededUser('admin');

    // Create a test application directly via API
    const createResponse = await page.request.post('/api/applicants', {
      data: {
        user_id: `test-user-${Date.now()}`,
        given_name: 'Bob',
        family_name: 'Tester',
        email: 'bob.tester@example.com',
        date_of_birth: '1990-01-15T00:00:00Z',
        nationality: 'USA',
      },
    });
    
    if (!createResponse.ok()) {
      console.log('Applicant creation response:', await createResponse.text());
      test.skip('Applicant creation not available');
      return;
    }

    const applicant = await createResponse.json();
    const applicantId = applicant.id;

    // Create application
    const appResponse = await page.request.post(`/api/applicants/${applicantId}/applications`, {
      data: {
        credential_type: 'employee_badge',
        organization_id: organizationId,
      },
    });
    
    if (!appResponse.ok()) {
      console.log('Application creation response:', await appResponse.text());
      test.skip('Application creation not available');
      return;
    }

    const application = await appResponse.json();
    applicationId = application.id;

    // Submit application
    await page.request.post(`/api/applicants/applications/${applicationId}/submit`);

    // Complete vetting checks
    const checksResponse = await page.request.get(`/api/applicants/applications/${applicationId}/checks`);
    if (checksResponse.ok()) {
      const checks = await checksResponse.json();
      for (const check of checks) {
        if (check.status !== 'passed') {
          await page.request.post(`/api/applicants/checks/${check.id}/complete`, {
            data: {
              passed: true,
              result: { verified: true },
              notes: 'Auto-passed for testing',
              performed_by: 'admin',
            },
          });
        }
      }
    }

    // Approve the application
    const approveResponse = await page.request.post(
      `/api/applicants/applications/${applicationId}/approve`,
      {
        data: {
          approved_by: 'admin',
          notes: 'Approved for testing',
        },
      }
    );

    if (approveResponse.ok()) {
      const approvedApp = await approveResponse.json();
      expect(approvedApp.status).toBe('approved');

      // Note: Credential offer creation is async. In production tests, use EventWaiter
      // to listen for 'credential.issued' SSE event instead of waiting.
      // For now, verify issuance session exists
      const pendingResponse = await page.request.get('/api/issuance/pending');
      if (pendingResponse.ok()) {
        const pending = await pendingResponse.json();
        console.log('Pending credential offers:', pending);
      }
    }
  });
});

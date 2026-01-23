/**
 * MIGRATED: Credential Issuance E2E Test using Split-Screen Harness
 *
 * This test demonstrates the new testing patterns:
 * - Uses authenticatedVendorSplitScreen fixture (web app + wallet side-by-side)
 * - Event-driven waits via EventWaiter (no polling loops)
 * - AuthenticatedApiClient for DRY setup
 * - Custom matchers (toShowCredential, toHaveCredentialCount, etc.)
 * - Proper waitForResponse instead of waitForLoadState
 *
 * Flow:
 * 1. Admin creates credential config for mDL
 * 2. Applicant submits application
 * 3. Admin approves application
 * 4. Credential is auto-issued and pushed to wallet
 * 5. Wallet receives credential via SSE event
 */

const { test, expect } = require('../../fixtures/auth.fixture');
const {
  EventWaiter,
  AuthenticatedApiClient,
  CredentialDataBuilder,
} = require('../../utils/test-helpers');

test.describe('Credential Issuance (Split-Screen)', () => {
  let apiClient;
  let eventWaiter;
  let credentialConfig;

  test.beforeEach(async ({ authenticatedVendorSplitScreen }) => {
    const { page, organizationId, auth } = authenticatedVendorSplitScreen;
    
    // Initialize helpers
    apiClient = new AuthenticatedApiClient(page);
    eventWaiter = new EventWaiter(page);
    
    // Set up credential config for mDL
    credentialConfig = await apiClient.ensureCredentialConfig(organizationId, {
      credential_type: 'drivers_license',
      display_name: "Mobile Driver's License",
      validity_days: 365,
    });
  });

  test('complete mDL issuance flow with split-screen', async ({
    authenticatedVendorSplitScreen,
  }) => {
    const { organizationId, martyFrame, walletFrame, page } = authenticatedVendorSplitScreen;

    // ===========================================================================
    // Step 1: Applicant submits application
    // ===========================================================================
    
    const applicationData = CredentialDataBuilder.mdl()
      .withName('Maria', 'Credentialist')
      .withEmail('maria.credential@example.com')
      .withBirthDate('1988-07-20')
      .withAddress('456 Oak Avenue', 'Austin', 'TX', '78701')
      .withLicenseClass('C')
      .build();

    const applicationResponse = await apiClient.createApplication(
      organizationId,
      credentialConfig.id,
      applicationData
    );
    const applicationId = applicationResponse.application.id;

    console.log(`✅ Application ${applicationId} submitted`);

    // ===========================================================================
    // Step 2: Admin approves application
    // ===========================================================================
    
    // Navigate admin to applications page (in martyFrame)
    await martyFrame.locator('[data-testid="nav-applications"]').click();
    await expect(martyFrame.locator('[data-testid="applications-page"]')).toBeVisible();

    // Wait for application to appear in the list
    const applicationRow = martyFrame.locator(`[data-testid="application-${applicationId}"]`);
    await expect(applicationRow).toBeVisible({ timeout: 10000 });

    // Click approve button
    const approveButton = applicationRow.locator('[data-testid="approve-button"]');
    const approvalResponsePromise = page.waitForResponse(
      (resp) => resp.url().includes(`/applications/${applicationId}/approve`) && resp.ok()
    );
    await approveButton.click();
    await approvalResponsePromise;

    console.log(`✅ Application ${applicationId} approved`);

    // Wait for SSE event: application.approved
    const approvedEvent = await eventWaiter.waitForEvent('application.approved', {
      application_id: applicationId,
    });
    expect(approvedEvent.data.application_id).toBe(applicationId);
    console.log(`✅ Received application.approved event`);

    // ===========================================================================
    // Step 3: Credential auto-issued (backend)
    // ===========================================================================
    
    // Wait for SSE event: credential.issued
    const issuedEvent = await eventWaiter.waitForEvent('credential.issued', {
      application_id: applicationId,
    }, {
      timeout: 30000, // Allow time for issuance processing
    });
    const transactionId = issuedEvent.data.transaction_id;
    expect(transactionId).toBeTruthy();
    console.log(`✅ Received credential.issued event (transaction: ${transactionId})`);

    // ===========================================================================
    // Step 4: Wallet receives credential
    // ===========================================================================
    
    // Check wallet UI shows the credential (in walletFrame)
    await expect(walletFrame.locator('[data-testid="credential-card"]')).toBeVisible({ timeout: 10000 });
    await expect(walletFrame.locator('[data-testid="credential-name"]')).toContainText(
      `${applicationData.firstName} ${applicationData.lastName}`
    );

    console.log(`✅ Wallet displays issued credential`);

    // ===========================================================================
    // Step 5: Verify credential details
    // ===========================================================================
    
    // Open credential details in wallet
    const credentialCard = walletFrame.locator('[data-testid="credential-card"]').first();
    await credentialCard.click();
    
    // Verify credential contains correct data
    await expect(walletFrame.locator('[data-testid="credential-name"]')).toContainText(
      `${applicationData.firstName} ${applicationData.lastName}`
    );
    await expect(walletFrame.locator('[data-testid="credential-birth-date"]')).toContainText(
      applicationData.dateOfBirth
    );
    await expect(walletFrame.locator('[data-testid="credential-license-class"]')).toContainText(
      applicationData.licenseClass
    );

    console.log(`✅ Credential details verified`);
  });

  test('admin can revoke issued credential', async ({
    authenticatedVendorSplitScreen,
  }) => {
    const { organizationId, martyFrame, walletFrame, page } = authenticatedVendorSplitScreen;

    // ===========================================================================
    // Setup: Issue a credential
    // ===========================================================================
    
    const applicationData = CredentialDataBuilder.mdl()
      .withName('Test', 'User')
      .withEmail('test.revoke@example.com')
      .build();

    const applicationResponse = await apiClient.createApplication(
      organizationId,
      credentialConfig.id,
      applicationData
    );
    const applicationId = applicationResponse.application.id;

    // Approve and wait for issuance
    await apiClient.approveApplication(applicationId);
    const issuedEvent = await eventWaiter.waitForEvent('credential.issued', {
      application_id: applicationId,
    });
    const transactionId = issuedEvent.data.transaction_id;

    console.log(`✅ Setup: Credential issued (transaction: ${transactionId})`);

    // ===========================================================================
    // Step 1: Admin revokes credential
    // ===========================================================================
    
    await martyFrame.locator('[data-testid="nav-credentials"]').click();
    const credentialRow = martyFrame.locator(`[data-testid="credential-${transactionId}"]`);
    await expect(credentialRow).toBeVisible({ timeout: 10000 });

    const revokeButton = credentialRow.locator('[data-testid="revoke-button"]');
    const revokeResponsePromise = page.waitForResponse(
      (resp) => resp.url().includes(`/credentials/${transactionId}/revoke`) && resp.ok()
    );
    await revokeButton.click();
    await revokeResponsePromise;

    console.log(`✅ Credential ${transactionId} revoked`);

    // ===========================================================================
    // Step 2: Wallet reflects revocation status
    // ===========================================================================
    
    // Wait for credential to show as revoked in wallet
    await expect(walletFrame.locator(`[data-testid="credential-status-${transactionId}"]`)).toContainText(
      'Revoked',
      { timeout: 10000 }
    );

    console.log(`✅ Wallet shows revoked status`);
  });
});

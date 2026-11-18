/**
 * Fixture Demo Test
 * 
 * Demonstrates the use of reusable fixtures and split-screen recording
 * for realistic E2E testing of the issuance flow.
 */
const { test, expect } = require('../../fixtures/auth.fixture');
const { createCredentialOffer } = require('../../utils/test-helpers');

test.describe('Issuance Flow with Split-Screen Recording', () => {
  
  test('should issue credential with full UI recording', async ({ walletOnboardedPage }) => {
    const { 
      page, 
      martyFrame, 
      walletFrame, 
      walletBridge, 
      auth, 
      organizationId,
      deviceId 
    } = walletOnboardedPage;

    // 1. Ensure credential configuration exists (using API for speed, or UI if needed)
    // We can use the page request context which shares cookies with the frame
    const credentialType = 'employee_badge';
    await page.request.post(`/api/organizations/${organizationId}/credential-types`, {
      data: {
        credential_type: credentialType,
        display_name: 'Employee Badge',
        validity_days: 365,
      },
      ignoreHTTPSErrors: true
    }).catch(() => {}); // Ignore if exists
    
    // Ensure trust config
    await page.request.put(`/api/organizations/${organizationId}/trust-config`, {
      data: { trust_framework: 'marty_hosted', key_source: 'marty_generated' },
      ignoreHTTPSErrors: true
    }).catch(() => {});

    // 2. Issue Credential via Marty UI (Left Frame)
    console.log('Use Case: Issuing credential via Marty UI');
    await martyFrame.getByRole('tab', { name: 'Credentials' }).click();
    
    // Wait for credentials list to load
    await martyFrame.getByText('Employee Badge').waitFor({ timeout: 10000 }).catch(() => {});

    // Create an offer using helper (generates QR code)
    // We need to create the offer via API first to simulate backend process, 
    // OR drive the UI to create it. Let's drive UI if possible, or API for now.
    
    const offer = await createCredentialOffer(page, {
      organizationId,
      credentialType,
      credentialData: {
        given_name: 'Jane',
        family_name: 'Doe',
        job_title: 'Engineer'
      },
      env: process.env
    });
    
    console.log('Offer received:', JSON.stringify(offer, null, 2));

    const offerUrl = offer.url || offer.credential_offer_uri;
    expect(offerUrl).toBeTruthy();
    
    // 3. Wallet scans QR code (Right Frame)
    console.log('Action: Wallet scanning offer...');
    
    // Simulate scan by instructing wallet bridge (in right frame)
    await walletBridge.scanQrCode(offerUrl);
    
    // 4. Verify Wallet UI shows offer
    // This is the key "Realistic" part - we check the Flutter UI elements in the right frame
    // Note: requires semantics enabled in Flutter app
    
    // Wait for "Credential Offer" text/header in wallet
    // Playwright locates elements inside the wallet frame
    await walletFrame.getByLabel('Credential Offer').or(walletFrame.getByText('Credential Offer'))
      .first()
      .waitFor({ timeout: 15000 });
      
    // 5. Accept Offer in Wallet
    const acceptBtn = walletFrame.getByRole('button', { name: /accept|add/i });
    await acceptBtn.click();
    
    // 6. Verify Completion in Wallet
    await walletFrame.getByText('Added').or(walletFrame.getByText('Success'))
      .waitFor({ timeout: 15000 });
      
    // 7. Verify Completion in Marty UI
    // Go to issued credentials tab
    await martyFrame.getByRole('tab', { name: 'Issued' }).click();
    
    // Should see new issuance (refresh if needed)
    await martyFrame.getByRole('button', { name: /refresh/i }).click().catch(() => {});
    await expect(martyFrame.getByText('Jane Doe')).toBeVisible();
  });
});

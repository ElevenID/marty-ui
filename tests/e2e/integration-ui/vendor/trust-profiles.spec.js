/**
 * Trust Profile creation coverage.
 *
 * These tests exercise the trust profile wizard end to end from the browser,
 * but they do not call live ICAO/EU/AAMVA registry endpoints. Registry imports
 * are verified against the product's built-in registry metadata and mocked URL
 * imports only, which keeps the suite compliant with third-party registry terms.
 */
const { test, expect } = require('@playwright/test');

const SAMPLE_CERT_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIIBszCCAVmgAwIBAgIUQ0VSVDEyMzQ1Njc4OTBBQkNERUZHSEkwCgYIKoZIzj0EAwIw',
  'EzERMA8GA1UEAwwIVGVzdCBSb290MB4XDTI2MDQxNDAwMDAwMFoXDTM2MDQxNDAwMDAw',
  'MFowEzERMA8GA1UEAwwIVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE',
  'dGVzdGNlcnRpZmljYXRlYnl0ZXNmb3JwbGF5d3JpZ2h0Y292ZXJhZ2UxMjM0NTY3ODkw',
  'b2FhMEkwRwYDVR0RBEAwPoIQdHJ1c3Qtcm9vdC5leGFtcGxlhhB0cnVzdC5leGFtcGxl',
  'LmNvbYcEfwAAATAKBggqhkjOPQQDAgNIADBFAiEA1m1aR2dnVXlZZVZTdFJvb3QxMjM0',
  'NTY3ODkwQUJDRCICIDJ0ZXN0cm9vdGJ5dGVzZm9yZTI2MDE0cGxheXdyaWdodA==',
  '-----END CERTIFICATE-----',
].join('\n');

const SECOND_CERT_PEM = SAMPLE_CERT_PEM.replace('Q0VSVDEyMzQ1Njc4OTBBQkNERUZHSEkw', 'QU5PVEhFUkNFUlQxMjM0NTY3ODkwQUJD');
const THIRD_CERT_PEM = SAMPLE_CERT_PEM.replace('Q0VSVDEyMzQ1Njc4OTBBQkNERUZHSEkw', 'VEhJUkRDRVJUMTIzNDU2Nzg5MEFCQ0RF');

function uniqueProfileName(prefix) {
  return `${prefix} ${Date.now()}-${Math.floor(Math.random() * 1000)}`;
}

async function bootstrapVendorSession(page) {
  const organization = { id: 'org-playwright', name: 'Playwright Org' };

  await page.addInitScript((orgId) => {
    window.localStorage.setItem('activeOrgId', orgId);
  }, organization.id);

  await page.route('**/v1/auth/me', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        authenticated: true,
        user: {
          user_id: 'user-playwright-vendor',
          email: 'vendor@example.test',
          given_name: 'Playwright',
          family_name: 'Vendor',
          roles: ['vendor'],
          organization_id: organization.id,
          organization_name: organization.name,
          organization: {
            [organization.id]: { name: organization.name },
          },
        },
      }),
    });
  });

  await page.route('**/v1/organizations/mine', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([organization]),
    });
  });

  await page.route('**/v1/me/preferences', async (route) => {
    const method = route.request().method();
    if (method === 'GET') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          last_view_mode: 'org_admin',
          last_active_org_id: organization.id,
        }),
      });
      return;
    }

    if (method === 'PUT') {
      const payload = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(payload),
      });
      return;
    }

    await route.continue();
  });
}

async function loginAndOpenWizard(page) {
  await bootstrapVendorSession(page);
  await page.goto('/console/org/trust/profiles/new');
  await expect(page.getByText('Build Trust Profile')).toBeVisible();
}

async function completeBasics(page, profileName, description = 'Playwright trust profile coverage') {
  await page.getByTestId('wizard.trustProfile.name').fill(profileName);
  await page.getByTestId('wizard.trustProfile.description').fill(description);
  await page.getByTestId('wizard.trustProfile.next').click();
  await expect(page.getByRole('heading', { name: 'Trust Sources' })).toBeVisible();
}

async function goToReview(page) {
  await page.getByTestId('wizard.trustProfile.next').click();
  await expect(page.getByRole('heading', { name: 'Cryptographic Policy' })).toBeVisible();
  await page.getByTestId('wizard.trustProfile.skip').click();
  await expect(page.getByRole('heading', { name: 'Review & Activate' })).toBeVisible();
}

async function submitWizard(page) {
  await page.getByTestId('wizard.trustProfile.submit').click();
  await expect(page.getByTestId('wizard.trustProfile.success')).toBeVisible();
}

async function configureSubmissionMocks(page) {
  const createdProfiles = [];
  const linkedIssuers = [];

  await page.route('**/v1/trust-profiles', async (route) => {
    if (route.request().method() !== 'POST') {
      await route.continue();
      return;
    }

    const payload = route.request().postDataJSON();
    createdProfiles.push(payload);
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        id: `tp-${createdProfiles.length}`,
        name: payload.name,
        status: payload.status || 'active',
        ...payload,
      }),
    });
  });

  await page.route('**/v1/trust-profiles/*/issuers', async (route) => {
    if (route.request().method() !== 'POST') {
      await route.continue();
      return;
    }

    const payload = route.request().postDataJSON();
    linkedIssuers.push(payload);
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({ id: `issuer-${linkedIssuers.length}`, ...payload }),
    });
  });

  return { createdProfiles, linkedIssuers };
}

test.describe('Trust Profile Wizard', () => {
  test('creates a trust profile with a DID issuer and custom cryptographic policy', async ({ page }) => {
    const { createdProfiles, linkedIssuers } = await configureSubmissionMocks(page);
    const profileName = uniqueProfileName('Playwright DID Trust');

    await loginAndOpenWizard(page);
    await completeBasics(page, profileName, 'Covers manual DID issuer entry');

    await page.getByTestId('wizard.trustProfile.issuerDid').fill('did:web:issuer.example.com');
    await page.getByLabel('Name').fill('Issuer Example');
    await page.getByLabel('Country').fill('US');
    await page.getByLabel('Credential Types').fill('MDOC|SD_JWT_VC');
    await page.getByTestId('wizard.trustProfile.addIssuer').click();
    await expect(page.getByText('did:web:issuer.example.com', { exact: true })).toBeVisible();

    await page.getByTestId('wizard.trustProfile.next').click();
    await expect(page.getByRole('heading', { name: 'Cryptographic Policy' })).toBeVisible();

    await page.getByRole('button', { name: /show advanced options/i }).click();
    await page.getByRole('checkbox', { name: /allow self-signed/i }).check();
    await page.getByRole('checkbox', { name: /require.*key usage/i }).uncheck();

    await page.getByTestId('wizard.trustProfile.next').click();
    await expect(page.getByRole('heading', { name: 'Review & Activate' })).toBeVisible();
    await expect(page.getByText(profileName)).toBeVisible();
    await expect(page.getByText('did:web:issuer.example.com')).toBeVisible();

    await submitWizard(page);

    expect(createdProfiles).toHaveLength(1);
    expect(createdProfiles[0]).toMatchObject({
      name: profileName,
      supported_formats: ['VC_JWT', 'SD_JWT_VC', 'MDOC'],
      validation_rules: expect.objectContaining({
        allow_self_signed: true,
        require_key_usage: false,
      }),
    });

    expect(linkedIssuers).toEqual([
      expect.objectContaining({
        issuer_did: 'did:web:issuer.example.com',
        name: 'Issuer Example',
      }),
    ]);
  });

  test('creates a trust profile with X.509 sources from manual, file, and mocked URL imports', async ({ page }) => {
    const { createdProfiles, linkedIssuers } = await configureSubmissionMocks(page);
    const profileName = uniqueProfileName('Playwright X509 Trust');

    await page.route('https://example.test/trust-roots.pem', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/x-pem-file',
        body: THIRD_CERT_PEM,
      });
    });

    await loginAndOpenWizard(page);
    await completeBasics(page, profileName, 'Covers X.509 manual and bulk imports');

    await page.locator('main').getByRole('combobox').first().click();
    await page.getByRole('option', { name: 'X.509 Certificate' }).click();

    await page.getByTestId('wizard.trustProfile.certPem').fill(SAMPLE_CERT_PEM);
    await page.getByLabel('Name').fill('Manual Root CA');
    await page.getByLabel('Country').fill('US');
    await page.getByLabel('Credential Types').fill('MDOC');
    await page.getByTestId('wizard.trustProfile.addIssuer').click();

    await page.locator('input[type="file"]').setInputFiles({
      name: 'roots.pem',
      mimeType: 'application/x-pem-file',
      buffer: Buffer.from(SECOND_CERT_PEM),
    });

    await page.getByPlaceholder('https://example.com/trusted-issuers.csv').fill('https://example.test/trust-roots.pem');
    await page.getByRole('button', { name: 'Import URL' }).click();

    await expect(page.getByText('Imported 1 issuer(s).')).toBeVisible();
    await expect(page.getByText('Manual Root CA')).toBeVisible();
    await expect(page.getByText('X.509').first()).toBeVisible();

    await goToReview(page);
    await submitWizard(page);

    expect(linkedIssuers).toHaveLength(0);
    expect(createdProfiles).toHaveLength(1);
    expect(createdProfiles[0].trust_sources).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          source_type: 'ROOT_CA',
          certificate_pem: SAMPLE_CERT_PEM,
          name: 'Manual Root CA',
        }),
        expect.objectContaining({
          source_type: 'ROOT_CA',
          certificate_pem: SECOND_CERT_PEM,
        }),
        expect.objectContaining({
          source_type: 'ROOT_CA',
          certificate_pem: THIRD_CERT_PEM,
        }),
      ])
    );
  });

  test('captures registry import configuration and its auto-update strategy without contacting live registries', async ({ page }) => {
    const { createdProfiles } = await configureSubmissionMocks(page);
    const profileName = uniqueProfileName('Playwright Registry Trust');
    const externalRegistryRequests = [];

    page.on('request', (request) => {
      const url = request.url();
      if (
        url.includes('pkd.icao.int')
        || url.includes('digital-building-blocks')
        || url.includes('aamva.org')
      ) {
        externalRegistryRequests.push(url);
      }
    });

    await loginAndOpenWizard(page);
    await completeBasics(page, profileName, 'Covers registry import metadata only');

    await page.getByRole('tab', { name: 'Import from Registries' }).click();
    await page.getByTestId('wizard.trustProfile.addRegistry').click();
    const registryDialog = page.getByRole('dialog', { name: 'Import from Registry' });
    await expect(registryDialog).toBeVisible();

    await registryDialog.getByRole('combobox').click();
    await page.getByRole('option', { name: /EU List of Trusted Lists/i }).click();
    await registryDialog.getByRole('button', { name: 'Add' }).click();

    await expect(page.getByText('EU List of Trusted Lists (LoTL)')).toBeVisible();
  await expect(page.getByText('Auto-sync enabled (24h)', { exact: true })).toBeVisible();

    await page.getByRole('tab', { name: 'Manual Issuers' }).click();
    await page.getByTestId('wizard.trustProfile.issuerDid').fill('did:web:registry-proof.example');
    await page.getByTestId('wizard.trustProfile.addIssuer').click();

    await goToReview(page);
    await submitWizard(page);

    expect(externalRegistryRequests).toEqual([]);
    expect(createdProfiles).toHaveLength(1);
    expect(createdProfiles[0].registry_imports).toEqual([
      expect.objectContaining({
        registry_type: 'EU_TRUST_LIST',
        sync_enabled: true,
        metadata: expect.objectContaining({
          name: 'EU List of Trusted Lists (LoTL)',
          frameworks: ['EUDI'],
          credential_types: ['SD_JWT_VC', 'VC_JWT'],
        }),
      }),
    ]);
  });
});

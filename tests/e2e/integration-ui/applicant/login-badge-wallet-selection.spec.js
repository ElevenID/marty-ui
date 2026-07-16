const { test, expect } = require('@playwright/test');

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const USER_ID = 'cbc0c81b-2427-4d24-8c1d-d8dd91b1af38';
const APPLICANT_ID = '45fb5b33-14bb-4b7f-9a37-5d4da525004a';
const TEMPLATE_ID = '50000000-0000-0000-0000-000000000010';
const APPLICATION_TEMPLATE_ID = '60000000-0000-0000-0000-000000000010';
const APPLICATION_ID = '4b6bee6f-6b66-4fd5-b541-b140bc1c0be7';

const martyOrg = {
  id: ORG_ID,
  name: 'Marty Identity Platform',
  display_name: 'Marty Identity Platform',
  membership: {
    roles: [],
  },
};

const applicantUser = {
  user_id: USER_ID,
  applicant_id: APPLICANT_ID,
  email: 'john.doe@marty.demo',
  username: 'john.doe@marty.demo',
  given_name: 'John',
  family_name: 'Doe',
  user_type: 'applicant',
  roles: ['applicant'],
  organization_id: ORG_ID,
  organization_name: 'Marty Identity Platform',
  default_organization_id: ORG_ID,
  default_organization_name: 'Marty Identity Platform',
  organizations: [martyOrg],
};

const applicantProfile = {
  id: APPLICANT_ID,
  user_id: USER_ID,
  organization_id: ORG_ID,
  email: applicantUser.email,
  given_name: applicantUser.given_name,
  family_name: applicantUser.family_name,
};

const loginBadgeTemplate = {
  id: TEMPLATE_ID,
  name: 'Marty Member Login Credential',
  description: 'Verifiable login badge for Marty members.',
  credential_type: 'open_badge',
  claims: [],
  status: 'active',
};

const walletRegistry = [
  {
    id: 'wr-waltid-001',
    name: 'walt.id Wallet',
    description: 'Browser wallet for OID4VCI credential offers.',
    is_active: true,
    supports_qr: true,
    supports_deeplink: true,
    specifications: ['OID4VCI'],
    supported_protocols: ['OID4VCI'],
    supported_platforms: ['web', 'desktop'],
    routing_templates: {
      web: 'https://wallet.demo.walt.id/api/siop/initiateIssuance?{credential_offer_param}={offer_encoded}',
      desktop: 'https://wallet.demo.walt.id/api/siop/initiateIssuance?{credential_offer_param}={offer_encoded}',
    },
  },
  {
    id: 'wr-spruce-001',
    name: 'SpruceKit',
    description: 'SpruceID mobile wallet.',
    is_active: true,
    supports_qr: true,
    supports_deeplink: true,
    specifications: ['OID4VCI'],
    supported_protocols: ['OID4VCI'],
    supported_platforms: ['ios', 'android'],
    routing_templates: {
      generic: 'openid-credential-offer://?credential_offer_uri={offer_encoded}',
    },
  },
  {
    id: 'wr-marty-001',
    name: 'Marty Authenticator',
    description: 'ElevenID-compatible mobile wallet.',
    is_active: true,
    supports_qr: true,
    supports_deeplink: true,
    specifications: ['OID4VCI'],
    supported_platforms: ['ios', 'android'],
    routing_templates: { generic: 'marty-authenticator://open?inner={inner_uri_encoded}' },
  },
  {
    id: 'wr-lissi-001',
    name: 'LISSI Wallet',
    description: 'LISSI mobile wallet.',
    is_active: true,
    supports_qr: true,
    supports_deeplink: true,
    specifications: ['OID4VCI'],
    supported_platforms: ['ios', 'android'],
    routing_templates: { generic: 'lissi-wallet://credential?offer={offer_encoded}' },
  },
  {
    id: 'wr-sphereon-001',
    name: 'Sphereon Wallet',
    description: 'Sphereon mobile wallet.',
    is_active: true,
    supports_qr: true,
    supports_deeplink: true,
    specifications: ['OID4VCI'],
    supported_platforms: ['ios', 'android'],
    routing_templates: { generic: 'sphereon-wallet://credential?offer={offer_encoded}' },
  },
  {
    id: 'wr-dc4eu-001',
    name: 'DC4EU Wallet',
    description: 'DC4EU ecosystem wallet.',
    is_active: true,
    supports_qr: true,
    supports_deeplink: true,
    specifications: ['OID4VCI'],
    supported_platforms: ['ios', 'android'],
    routing_templates: { generic: 'dc4eu-wallet://credential?offer={offer_encoded}' },
  },
  {
    id: 'wr-google-001',
    name: 'Google Wallet',
    description: 'Google Wallet on Android.',
    is_active: true,
    supports_qr: true,
    supports_deeplink: true,
    specifications: ['OID4VCI'],
    supported_platforms: ['android'],
    routing_templates: { android: 'google-wallet://credential?offer={offer_encoded}' },
  },
  {
    id: 'wr-apple-001',
    name: 'Apple Wallet',
    description: 'Apple Wallet on iOS.',
    is_active: true,
    supports_qr: true,
    supports_deeplink: true,
    specifications: ['OID4VCI'],
    supported_platforms: ['ios'],
    routing_templates: { ios: 'apple-wallet://credential?offer={offer_encoded}' },
  },
];

function fulfillJson(route, body, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function overflowDiagnostics(page) {
  return page.evaluate(() => [...document.querySelectorAll('body *')]
    .map((element) => {
      const rect = element.getBoundingClientRect();
      return {
        tag: element.tagName,
        className: String(element.className || '').slice(0, 120),
        text: String(element.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 80),
        left: Math.round(rect.left),
        right: Math.round(rect.right),
        width: Math.round(rect.width),
      };
    })
    .filter((item) => item.right > window.innerWidth + 1 || item.left < -1)
    .slice(0, 12));
}

async function installApplicantWalletMocks(page, { applications = [], credentials = [] } = {}) {
  const issueRequests = [];
  const createRequests = [];

  await page.route('**/v1/**', async (route, request) => {
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();

    if (method === 'GET' && path === '/v1/auth/me') {
      return fulfillJson(route, { authenticated: true, user: applicantUser });
    }

    if (method === 'GET' && path === '/v1/organizations/mine') {
      return fulfillJson(route, [martyOrg]);
    }

    if (method === 'GET' && path === '/v1/me/preferences') {
      return fulfillJson(route, { last_view_mode: 'applicant', last_active_org_id: null });
    }

    if (method === 'PUT' && path === '/v1/me/preferences') {
      return fulfillJson(route, { last_view_mode: 'applicant', last_active_org_id: null });
    }

    if (method === 'GET' && path === `/v1/credential-templates/${TEMPLATE_ID}`) {
      return fulfillJson(route, loginBadgeTemplate);
    }

    if (method === 'GET' && path === '/v1/application-templates') {
      return fulfillJson(route, [{
        id: APPLICATION_TEMPLATE_ID,
        organization_id: ORG_ID,
        credential_template_id: TEMPLATE_ID,
        name: 'Marty Member Login Credential Application',
        status: 'ACTIVE',
        form_fields: [
          { field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true },
          { field_id: 'given_name', label: 'Given name', field_type: 'TEXT', required: true },
          { field_id: 'family_name', label: 'Family name', field_type: 'TEXT', required: true },
        ],
      }]);
    }

    if (method === 'GET' && path === '/v1/me/applicant-profile') {
      return fulfillJson(route, applicantProfile);
    }

    if (method === 'PATCH' && path === '/v1/me/applicant-profile') {
      return fulfillJson(route, { ...applicantProfile, ...(request.postDataJSON?.() || {}) });
    }

    if (method === 'GET' && path === '/v1/me/applications') {
      return fulfillJson(route, { items: applications, total: applications.length, limit: 100, offset: 0 });
    }

    if (method === 'POST' && path === '/v1/me/applications') {
      createRequests.push(request.postDataJSON?.() || {});
      return fulfillJson(route, {
        id: APPLICATION_ID,
        applicant_id: APPLICANT_ID,
        organization_id: ORG_ID,
        credential_template_id: TEMPLATE_ID,
        application_template_id: APPLICATION_TEMPLATE_ID,
        status: 'DRAFT',
      });
    }

    if (method === 'POST' && path === `/v1/me/applications/${APPLICATION_ID}/submit`) {
      return fulfillJson(route, {
        id: APPLICATION_ID,
        applicant_id: APPLICANT_ID,
        organization_id: ORG_ID,
        credential_template_id: TEMPLATE_ID,
        application_template_id: APPLICATION_TEMPLATE_ID,
        status: 'APPROVED',
      });
    }

    if (method === 'POST' && path === `/v1/me/applications/${APPLICATION_ID}/claim`) {
      const payload = request.postDataJSON?.() || {};
      issueRequests.push(payload);

      return fulfillJson(route, {
        id: APPLICATION_ID,
        status: 'APPROVED',
        claim_state: 'OFFER_READY',
        credential_offer_uri: `https://issuer.example.test/offers/${issueRequests.length}`,
        offer_expires_at: '2099-07-10T23:59:00Z',
        credential_offer_uris: Object.fromEntries(walletRegistry.map((wallet) => [wallet.id, `https://issuer.example.test/offers/${wallet.id}`])),
        credential_offer_labels: Object.fromEntries(walletRegistry.map((wallet) => [wallet.id, wallet.name])),
        wallet_registry: Object.fromEntries(walletRegistry.map((wallet) => [wallet.id, wallet])),
      });
    }

    if (method === 'GET' && path === '/v1/wallet-registry') {
      return fulfillJson(route, walletRegistry);
    }

    if (method === 'GET' && path === '/v1/delivery-destinations') {
      return fulfillJson(route, []);
    }

    if (method === 'GET' && path === '/v1/issued-credentials/mine') {
      return fulfillJson(route, { items: credentials, total: credentials.length, limit: 100, offset: 0 });
    }

    return fulfillJson(route, { detail: `Unhandled mocked route: ${method} ${path}` }, 404);
  });

  return { createRequests, issueRequests };
}

test('applicant selects a browser wallet during login badge claim flow', async ({ page }) => {
  const pageErrors = [];
  const failedApiRequests = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('requestfailed', (request) => {
    if (new URL(request.url()).pathname.startsWith('/v1/')) {
      failedApiRequests.push(`${request.method()} ${request.url()}: ${request.failure()?.errorText}`);
    }
  });
  const { createRequests, issueRequests } = await installApplicantWalletMocks(page);

  await page.goto(`/console/applicant/apply/${TEMPLATE_ID}`);

  await expect(page.getByRole('heading', { name: 'Marty Member Login Credential' })).toBeVisible();
  await expect(page.getByText('Issued by')).toBeVisible();

  await page.getByRole('button', { name: 'Add to Wallet' }).click();

  const walletSelector = page.getByTestId('wallet-selector');
  await expect(walletSelector).toBeVisible();
  await expect(page.getByTestId('wallet-option-wr-default')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('wallet-option-wr-waltid-001')).toContainText('Browser');
  await expect(page.getByTestId('wallet-option-wr-spruce-001')).toContainText('Mobile');
  for (const wallet of walletRegistry) {
    await expect(page.getByTestId(`wallet-option-${wallet.id}`)).toBeVisible();
  }

  expect(createRequests).toEqual([{
    organization_id: ORG_ID,
    application_template_id: APPLICATION_TEMPLATE_ID,
    form_data: expect.any(Object),
    integration_context: {},
  }]);
  expect(createRequests[0]).not.toHaveProperty('applicant_id');
  expect(createRequests[0]).not.toHaveProperty('credential_configuration_id');
  expect(createRequests[0]).not.toHaveProperty('issuing_authority');
  expect(createRequests[0]).not.toHaveProperty('metadata');

  await expect.poll(() => issueRequests.length).toBeGreaterThanOrEqual(1);
  expect(issueRequests[0].delivery_destination_ids).toContain('dd-oid4vci-compatible-wallet');

  await page.getByTestId('wallet-option-wr-waltid-001').click();

  await expect(page.getByTestId('wallet-option-wr-waltid-001')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByRole('heading', { name: 'Scan with walt.id Wallet' })).toBeVisible();
  await expect(page.getByText('Secure issuance via OpenID4VCI')).toBeVisible();

  const latestIssueRequest = issueRequests[issueRequests.length - 1];
  expect(latestIssueRequest.delivery_destination_ids).toContain('dd-oid4vci-compatible-wallet');
  expect(latestIssueRequest.canvas_credentials_consent).toBe(false);

  const storedWallets = await page.evaluate((userId) => {
    return JSON.parse(localStorage.getItem(`elevenid_wallets_${userId}`) || '[]');
  }, USER_ID);
  expect(storedWallets).toEqual(['wr-waltid-001']);
  expect(pageErrors).toEqual([]);
  expect(failedApiRequests).toEqual([]);
});

test('holder inventory remains actionable and overflow-free at supported widths', async ({ page }) => {
  const pageErrors = [];
  const failedApiRequests = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('requestfailed', (request) => {
    if (new URL(request.url()).pathname.startsWith('/v1/')) {
      failedApiRequests.push(`${request.method()} ${request.url()}: ${request.failure()?.errorText}`);
    }
  });

  await installApplicantWalletMocks(page, {
    applications: [
      {
        id: 'application-offer-ready',
        organization_id: ORG_ID,
        credential_template_id: TEMPLATE_ID,
        credential_display_name: 'Member Login Credential',
        status: 'APPROVED',
        claim_state: 'OFFER_READY',
        credential_offer_uri: 'https://issuer.example.test/offers/ready',
        offer_expires_at: '2099-07-10T23:59:00Z',
        created_at: '2026-07-11T12:00:00Z',
        updated_at: '2026-07-11T12:00:00Z',
      },
      {
        id: 'application-blocked',
        organization_id: ORG_ID,
        credential_template_id: '50000000-0000-0000-0000-000000000011',
        credential_display_name: 'Employee Access Credential',
        status: 'APPROVED',
        claim_state: 'BLOCKED',
        claim_blocker: {
          code: 'NO_ACTIVE_ISSUANCE_FLOW',
          owner: 'ISSUER',
          message: 'Waiting for the issuer to activate credential delivery',
        },
        created_at: '2026-07-11T11:00:00Z',
        updated_at: '2026-07-11T11:00:00Z',
      },
    ],
  });

  const viewports = [
    { width: 320, height: 700 },
    { width: 390, height: 844 },
    { width: 768, height: 900 },
    { width: 1440, height: 1000 },
  ];

  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    await page.goto('/console/applicant/identity');
    await expect(page.getByRole('heading', { name: 'My Identity' })).toBeVisible();
    await expect(page.getByText('Waiting for the issuer to activate credential delivery')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Claim' })).toHaveCount(1);
    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(scrollWidth, JSON.stringify(await overflowDiagnostics(page), null, 2)).toBeLessThanOrEqual(viewport.width);
  }

  await page.getByRole('button', { name: 'Details' }).first().click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(1440);
  expect(pageErrors).toEqual([]);
  expect(failedApiRequests).toEqual([]);
});

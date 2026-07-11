const { test, expect } = require('@playwright/test');

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const USER_ID = 'cbc0c81b-2427-4d24-8c1d-d8dd91b1af38';
const APPLICANT_ID = '45fb5b33-14bb-4b7f-9a37-5d4da525004a';
const TEMPLATE_ID = '50000000-0000-0000-0000-000000000010';
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
  },
];

function fulfillJson(route, body, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function installApplicantWalletMocks(page) {
  const issueRequests = [];

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

    if (method === 'GET' && path === `/v1/applicants/profiles/${APPLICANT_ID}`) {
      return fulfillJson(route, applicantProfile);
    }

    if (method === 'GET' && path === `/v1/applicants/by-user/${USER_ID}`) {
      return fulfillJson(route, applicantProfile);
    }

    if (method === 'PATCH' && path === `/v1/applicants/profiles/${APPLICANT_ID}`) {
      return fulfillJson(route, { ...applicantProfile, ...(request.postDataJSON?.() || {}) });
    }

    if (method === 'GET' && path === `/v1/applicants/profiles/${APPLICANT_ID}/applications`) {
      return fulfillJson(route, { applications: [], total: 0 });
    }

    if (method === 'POST' && path === '/v1/applicants/applications') {
      return fulfillJson(route, {
        id: APPLICATION_ID,
        applicant_id: APPLICANT_ID,
        credential_configuration_id: TEMPLATE_ID,
        status: 'DRAFT',
      });
    }

    if (method === 'POST' && path === `/v1/applicants/applications/${APPLICATION_ID}/submit`) {
      return fulfillJson(route, {
        id: APPLICATION_ID,
        applicant_id: APPLICANT_ID,
        credential_configuration_id: TEMPLATE_ID,
        status: 'APPROVED',
      });
    }

    if (method === 'POST' && path === `/v1/applicants/applications/${APPLICATION_ID}/issue`) {
      const payload = request.postDataJSON?.() || {};
      issueRequests.push(payload);

      return fulfillJson(route, {
        id: APPLICATION_ID,
        status: 'active',
        credential_offer_uri: `https://issuer.example.test/offers/${issueRequests.length}`,
        offer_expires_at: '2026-07-10T23:59:00Z',
        credential_offer_uris: {
          'wr-default': 'https://issuer.example.test/offers/default',
          'wr-spruce-001': 'https://issuer.example.test/offers/spruce',
          'wr-marty-001': 'https://issuer.example.test/offers/marty',
        },
        credential_offer_labels: {
          'wr-default': 'Any OID4VCI Wallet',
          'wr-spruce-001': 'SpruceKit',
          'wr-marty-001': 'Marty Authenticator',
        },
        wallet_registry: Object.fromEntries(walletRegistry.map((wallet) => [wallet.id, wallet])),
      });
    }

    if (method === 'GET' && path === '/v1/wallet-registry') {
      return fulfillJson(route, walletRegistry);
    }

    if (method === 'GET' && path === '/v1/delivery-destinations') {
      return fulfillJson(route, []);
    }

    if (method === 'GET' && path === '/v1/documents') {
      return fulfillJson(route, { credentials: [] });
    }

    return fulfillJson(route, { detail: `Unhandled mocked route: ${method} ${path}` }, 404);
  });

  return { issueRequests };
}

test('applicant selects a browser wallet during login badge claim flow', async ({ page }) => {
  const { issueRequests } = await installApplicantWalletMocks(page);

  await page.goto(`/console/applicant/apply/${TEMPLATE_ID}`);

  await expect(page.getByRole('heading', { name: 'Marty Member Login Credential' })).toBeVisible();
  await expect(page.getByText('Issued by')).toBeVisible();

  await page.getByRole('button', { name: 'Add to Wallet' }).click();

  const walletSelector = page.getByTestId('wallet-selector');
  await expect(walletSelector).toBeVisible();
  await expect(page.getByTestId('wallet-option-wr-default')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('wallet-option-wr-waltid-001')).toContainText('Browser');
  await expect(page.getByTestId('wallet-option-wr-spruce-001')).toContainText('Mobile');

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
});

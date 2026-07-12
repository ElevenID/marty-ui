const { test, expect } = require('@playwright/test');

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const APPLICATION_ID = '4b6bee6f-6b66-4fd5-b541-b140bc1c0be7';
const REVIEWER_ID = '00000000-0000-0000-0000-000000000099';

function fulfillJson(route, body, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function installReviewerMocks(page) {
  const actions = [];
  const unexpectedRequests = [];
  const pageErrors = [];
  let applicationStatus = 'SUBMITTED';
  page.on('pageerror', (error) => pageErrors.push(error.message));

  const organization = {
    id: ORG_ID,
    name: 'Marty Identity Platform',
    display_name: 'Marty Identity Platform',
    membership: {
      roles: ['reviewer'],
      permissions: ['application:review', 'application:approve', 'application:reject', 'issuance:initiate'],
    },
  };
  const application = () => ({
    id: APPLICATION_ID,
    applicant_id: 'applicant-1',
    applicant_email: 'holder@example.test',
    applicant_given_name: 'Ada',
    applicant_family_name: 'Lovelace',
    organization_id: ORG_ID,
    credential_template_id: 'credential-template-1',
    credential_display_name: 'Employee Access Credential',
    status: applicationStatus,
    submitted_at: '2026-07-11T12:00:00Z',
    form_data: { employee_number: 'E-100' },
    integration_context: {},
  });

  await page.route('**/v1/**', async (route, request) => {
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();

    if (method === 'GET' && path === '/v1/auth/me') {
      return fulfillJson(route, {
        authenticated: true,
        user: {
          user_id: REVIEWER_ID,
          email: 'reviewer@marty.demo',
          name: 'Marty Reviewer',
          given_name: 'Marty',
          family_name: 'Reviewer',
          roles: ['reviewer'],
          organization_id: ORG_ID,
          organization_name: organization.name,
          organizations: [organization],
        },
      });
    }
    if (method === 'GET' && path === '/v1/organizations/mine') return fulfillJson(route, [organization]);
    if (method === 'GET' && path === '/v1/me/preferences') {
      return fulfillJson(route, { last_view_mode: 'org', last_active_org_id: ORG_ID });
    }
    if (method === 'PUT' && path === '/v1/me/preferences') {
      return fulfillJson(route, { last_view_mode: 'org', last_active_org_id: ORG_ID });
    }
    if (method === 'GET' && path === `/v1/organizations/${ORG_ID}/members/me/permissions`) {
      return fulfillJson(route, {
        permissions: ['application:review', 'application:approve', 'application:reject', 'issuance:initiate'],
      });
    }

    const applicantBase = `/v1/organizations/${ORG_ID}/applicants/${APPLICATION_ID}`;
    if (method === 'GET' && path === applicantBase) return fulfillJson(route, application());
    if (method === 'GET' && path === `${applicantBase}/checks`) return fulfillJson(route, []);
    if (method === 'GET' && path === `${applicantBase}/evidence-summary`) {
      return fulfillJson(route, {
        application_id: APPLICATION_ID,
        organization_id: ORG_ID,
        status: 'pending',
        evidence_facts: [],
        policy_decision: null,
        available_api_checks: [],
      });
    }
    if (method === 'POST' && path === `${applicantBase}/lock`) {
      actions.push({ action: 'lock', body: request.postDataJSON?.() || {} });
      return fulfillJson(route, { locked: true, reviewer_id: REVIEWER_ID, reviewer_name: 'Marty Reviewer' });
    }
    if (method === 'DELETE' && path === `${applicantBase}/lock`) return fulfillJson(route, {});
    if (method === 'POST' && path === `${applicantBase}/request-information`) {
      const body = request.postDataJSON?.() || {};
      actions.push({ action: 'request-information', body });
      applicationStatus = 'NEEDS_INFO';
      return fulfillJson(route, application());
    }
    if (method === 'POST' && path === `${applicantBase}/approve`) {
      const body = request.postDataJSON?.() || {};
      actions.push({ action: 'approve', body });
      applicationStatus = 'APPROVED';
      return fulfillJson(route, application());
    }
    if (method === 'POST' && path === `${applicantBase}/reject`) {
      const body = request.postDataJSON?.() || {};
      actions.push({ action: 'reject', body });
      applicationStatus = 'REJECTED';
      return fulfillJson(route, application());
    }
    if (method === 'GET' && path === '/v1/credential-templates') return fulfillJson(route, []);

    unexpectedRequests.push(`${method} ${path}`);
    return fulfillJson(route, { detail: `Unhandled mocked route: ${method} ${path}` }, 404);
  });

  return { actions, pageErrors, unexpectedRequests };
}

function assertServerDerivedReviewer(actions) {
  for (const action of actions) {
    expect(action.body).not.toHaveProperty('reviewer_id');
    expect(action.body).not.toHaveProperty('reviewed_by');
    expect(action.body).not.toHaveProperty('approved_by');
  }
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript((organizationId) => {
    localStorage.setItem('activeOrgId', organizationId);
  }, ORG_ID);
});

test('reviewer acquires the resource lock and requests information', async ({ page }) => {
  const { actions, pageErrors, unexpectedRequests } = await installReviewerMocks(page);
  await page.goto(`/console/org/operate/applications/${APPLICATION_ID}`);

  await expect(page.getByText('You have this open')).toBeVisible();
  await page.getByRole('button', { name: 'Request Info', exact: true }).click();
  await page.getByText('Government-issued photo ID', { exact: true }).click();
  await page.getByLabel('Message to applicant').fill('Please provide a clear identity document.');
  await page.getByRole('button', { name: 'Send Request' }).click();

  await expect(page.getByText('Info request sent to applicant.')).toBeVisible();
  expect(actions.find((entry) => entry.action === 'request-information')?.body).toEqual({
    missing_items: ['Government-issued photo ID'],
    message: 'Please provide a clear identity document.',
    deadline: null,
  });
  assertServerDerivedReviewer(actions);
  expect(pageErrors).toEqual([]);
  expect(unexpectedRequests).toEqual([]);
});

test('reviewer rejects through the canonical organization action', async ({ page }) => {
  const { actions, pageErrors, unexpectedRequests } = await installReviewerMocks(page);
  await page.goto(`/console/org/operate/applications/${APPLICATION_ID}`);

  await page.getByRole('button', { name: 'Reject', exact: true }).click();
  await page.getByRole('combobox').click();
  await page.getByRole('option', { name: 'Data mismatch' }).click();
  await page.getByRole('button', { name: 'Confirm Rejection' }).click();

  await expect(page.getByText('Application rejected.')).toBeVisible();
  expect(actions.find((entry) => entry.action === 'reject')?.body).toEqual({
    reason: 'Data mismatch',
  });
  assertServerDerivedReviewer(actions);
  expect(pageErrors).toEqual([]);
  expect(unexpectedRequests).toEqual([]);
});

test('reviewer approves through the canonical organization action', async ({ page }) => {
  const { actions, pageErrors, unexpectedRequests } = await installReviewerMocks(page);
  await page.goto(`/console/org/operate/applications/${APPLICATION_ID}`);

  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await page.getByLabel('Approval note (optional)').fill('Identity evidence verified.');
  await page.getByRole('button', { name: 'Confirm Approval' }).click();

  await expect(page.getByText(/Application approved/)).toBeVisible();
  expect(actions.find((entry) => entry.action === 'approve')?.body).toEqual({
    notes: 'Identity evidence verified.',
  });
  assertServerDerivedReviewer(actions);
  expect(pageErrors).toEqual([]);
  expect(unexpectedRequests).toEqual([]);
});

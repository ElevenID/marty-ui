/**
 * Narrated, serial credential application demo. Each scene requires observable
 * product results; a video is not evidence that issuance or wallet claim passed.
 *
 * Run from tests: npx playwright test --config playwright.demo.config.js
 * Uses an existing seeded organization and active credential/application template.
 * Select ambiguous fixtures with DEMO_ORGANIZATION_ID / DEMO_CREDENTIAL_TEMPLATE_ID.
 * DEMO_FORM_VALUES_JSON supplies custom values keyed by the rendered field label.
 * Scene 6 requires real wallet redemption; this recorder does not implement a
 * wallet client. An unclaimed offer fails that scene instead of completing it.
 */

const { test, expect } = require('@playwright/test');
const { AuthHelpers } = require('../../utils/test-helpers');
const { SEEDED_USERS } = require('../../fixtures/users');
const {
  readJson, requireSession, selectDemoSetup, requireApplicationId, assertApplicationRecord,
  isClaimedApplication, bindOrganization, scrollIntoView, demoFormValues, fillApplicationStep,
  submitApplication, approveApplication,
} = require('./demo-journey-helpers');

let setup;
let applicationId;

async function signIn(page, role) {
  await page.goto('/');
  await new AuthHelpers(page).loginAsSeededUser(role, { uiOnboarding: true });
  await requireSession(page, SEEDED_USERS[role].email);
  if (role === 'vendor' && setup) await bindOrganization(page, setup.organizationId);
}

async function beat(page, ms = 600) {
  await page.waitForTimeout(ms);
}

test.describe.serial('Marty Platform Demo', () => {
  test.beforeAll(async ({ browser, baseURL }) => {
    const page = await browser.newPage({ baseURL });
    try {
      await signIn(page, 'vendor');
      const organizations = await readJson(page, '/v1/organizations/mine');
      const matches = Array.isArray(organizations) ? organizations.filter((org) => process.env.DEMO_ORGANIZATION_ID
        ? org.id === process.env.DEMO_ORGANIZATION_ID
        : org.name === SEEDED_USERS.vendor.organization || org.display_name === SEEDED_USERS.vendor.organization) : [];
      expect(matches, 'A unique existing vendor demo organization is required; set DEMO_ORGANIZATION_ID').toHaveLength(1);
      const organizationId = matches[0].id;
      const templates = await readJson(page, `/v1/credential-templates?organization_id=${encodeURIComponent(organizationId)}`);
      const applicationTemplates = await readJson(page, `/v1/application-templates?organization_id=${encodeURIComponent(organizationId)}`);
      setup = selectDemoSetup(organizations, templates, applicationTemplates, {
        organizationId, templateId: process.env.DEMO_CREDENTIAL_TEMPLATE_ID,
      });
    } finally {
      await page.close();
    }
  });

  test('Scene 1 · Vendor Admin logs in and views the dashboard', async ({ page }) => {
    await test.step('Sign in as Vendor Admin', () => signIn(page, 'vendor'));
    await test.step('View the loaded admin dashboard', async () => {
      await page.goto('/console/org');
      await expect(page.getByTestId('console.dashboard.page')).toBeVisible();
      await beat(page, 1200);
    });
  });

  test('Scene 2 · Admin reviews the credential catalogue', async ({ page }) => {
    await signIn(page, 'vendor');
    await test.step('Open the selected credential template', async () => {
      await page.goto(`/console/org/templates/credentials/${encodeURIComponent(setup.template.id)}`);
      await expect(page.getByText('Template overview', { exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: setup.template.name, exact: true })).toBeVisible();
      await beat(page, 1200);
    });
  });

  test('Scene 3 · Applicant logs in and browses available credentials', async ({ page }) => {
    await signIn(page, 'applicant1');
    await test.step('Find the selected credential in the catalogue', async () => {
      await page.goto('/console/applicant/catalog');
      await expect(page.getByTestId('credential-catalog-page')).toBeVisible();
      const card = page.getByTestId(`credential-card-${setup.template.id}`);
      await scrollIntoView(page, card);
      await expect(card.getByTestId('apply-btn')).toBeEnabled();
      await beat(page, 1200);
    });
  });

  test('Scene 4 · Applicant completes and submits the mDL application', async ({ page }) => {
    await signIn(page, 'applicant1');
    await page.goto(`/console/applicant/apply/${encodeURIComponent(setup.template.id)}`);
    const form = page.getByTestId('credential-application-form');
    await expect(form, 'The selected template must expose the current application form').toBeVisible();
    const values = demoFormValues(SEEDED_USERS.applicant1, JSON.parse(process.env.DEMO_FORM_VALUES_JSON || '{}'));
    await test.step('Complete every rendered application step', async () => {
      // The number and grouping of fields comes from the active application
      // template. A blocked Next action must fail rather than skip a scene.
      for (let index = 0; ; index += 1) {
        if (await page.getByTestId('review-step').isVisible()) break;
        const step = form.getByTestId(`step-${index}`);
        await expect(step).toBeVisible();
        await fillApplicationStep(page, step, values);
        await form.getByTestId('next-step-btn').click();
        await expect(step).toBeHidden();
        await beat(page);
      }
      await expect(page.getByTestId('review-step')).toBeVisible();
    });
    await test.step('Submit and capture the new application ID', async () => {
      applicationId = await submitApplication(page);
      const profile = await readJson(page, '/v1/me/applicant-profile');
      expect(profile.id, 'The applicant session must resolve the profile used for this submission').toBeTruthy();
      setup.applicantId = profile.id;
      const record = await readJson(page, `/v1/me/applications/${encodeURIComponent(applicationId)}`);
      assertApplicationRecord(record, setup, applicationId,
        ['SUBMITTED', 'UNDER_REVIEW']);
      await beat(page, 1200);
    });
  });

  test('Scene 5 · Admin reviews and approves this application', async ({ page }) => {
    requireApplicationId(applicationId);
    await signIn(page, 'vendor');
    await test.step('Review and approve the application submitted in Scene 4', async () => {
      await approveApplication(page, setup, applicationId);
      await beat(page, 1200);
    });
  });

  test('Scene 6 · Applicant views the actually issued credential', async ({ page }) => {
    requireApplicationId(applicationId);
    await signIn(page, 'applicant1');
    let issuedApplication;
    await test.step('Require completed issuance for this application', async () => {
      await expect.poll(async () => {
        const record = await readJson(page, `/v1/me/applications/${encodeURIComponent(applicationId)}`);
        assertApplicationRecord(record, setup, applicationId,
          ['APPROVED', 'OFFERED', 'ISSUED', 'CREDENTIALED']);
        issuedApplication = record;
        return isClaimedApplication(record);
      }, {
        timeout: 30000,
        message: 'Real wallet redemption must complete issuance; an approved application or unclaimed offer does not finish this demo',
      }).toBe(true);
    });
    await test.step('Show the claimed application in My Identity', async () => {
      await page.goto(`/console/applicant/identity?id=${encodeURIComponent(applicationId)}`);
      const details = page.getByRole('dialog', { name: 'Application Details', exact: true });
      await expect(details).toBeVisible();
      await expect(details.getByText(issuedApplication.credential_display_name || setup.template.name, { exact: true })).toBeVisible();
      await expect(details.getByText('Claim: Claimed', { exact: true })).toBeVisible();
      await beat(page, 1500);
    });
  });
});

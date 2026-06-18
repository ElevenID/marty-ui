/**
 * Marty Platform — Demo Recording Script
 *
 * A narrated walkthrough of the core credential issuance flow, structured as
 * sequential scenes so the Playwright video timeline maps to the product story.
 *
 * Scenes:
 *   1. Vendor Admin logs in and views the admin dashboard
 *   2. Vendor Admin reviews the credential catalogue
 *   3. Applicant logs in and browses available credentials
 *   4. Applicant completes the mDL application form
 *   5. Vendor Admin reviews and approves the application
 *   6. Credential is issued — applicant sees it in their wallet
 *
 * Run:
 *   cd marty-ui/tests
 *   npx playwright test --config playwright.demo.config.js
 *
 * The recording is written to demo-recordings/<scene>/video.webm by default.
 */

const { test, expect } = require('@playwright/test');
const path = require('path');
const { AuthHelpers, AuthenticatedApiClient } = require('../../utils/test-helpers');
const { SEEDED_USERS } = require('../../fixtures/users');

// ---------------------------------------------------------------------------
// Shared demo state (passed between serial tests via module scope)
// ---------------------------------------------------------------------------

/** @type {string|null} */
let credentialConfigId = null;
/** @type {string|null} */
let applicationId = null;
/** @type {string|null} */
let organizationId = null;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PORTRAIT_PATH = path.resolve(__dirname, '../../fixtures/test-portrait.jpg');

const inputSelectorFor = (testId) =>
  `[data-testid="${testId}"] input:not([aria-hidden="true"]), ` +
  `[data-testid="${testId}"] textarea:not([aria-hidden="true"])`;

async function fillField(page, testId, value) {
  await page.locator(inputSelectorFor(testId)).fill(value);
}

/** Graceful pause for visual breathing room between actions in slow-mo. */
async function beat(page, ms = 600) {
  await page.waitForTimeout(ms);
}

/** Try a locator click; silently skip if not visible within timeout. */
async function tryClick(page, selector, timeout = 4000) {
  try {
    await page.locator(selector).waitFor({ state: 'visible', timeout });
    await page.locator(selector).click();
    return true;
  } catch {
    return false;
  }
}

/** Scroll an element into view before interacting (helps video legibility). */
async function scrollIntoView(page, selector) {
  const el = page.locator(selector).first();
  if (await el.count()) {
    await el.scrollIntoViewIfNeeded().catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Demo suite
// ---------------------------------------------------------------------------

test.describe.serial('Marty Platform Demo', () => {

  // ── Scene 0: Pre-flight setup (not recorded as a scene, just state init) ─

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const auth = new AuthHelpers(page);
    const api  = new AuthenticatedApiClient(page);

    await page.goto('/');
    try {
      await auth.loginAsSeededUser('vendor', { uiOnboarding: true });

      // Resolve org ID
      const me = await page.request.get('/auth/me');
      if (me.ok()) {
        const data = await me.json();
        organizationId = data?.user?.organization_id ?? null;
      }

      // Ensure a demo credential config exists
      if (organizationId) {
        const result = await api.ensureCredentialConfig(
          organizationId,
          'drivers_license',
        ).catch(() => null);
        // ensureCredentialConfig returns a string ID directly
        credentialConfigId = typeof result === 'string' ? result : (result?.id ?? null);
      }
    } catch (err) {
      console.warn('[demo] beforeAll setup warning:', err.message);
    } finally {
      await page.close();
    }
  });

  // ── Scene 1: Vendor Admin — Dashboard ────────────────────────────────────

  test('Scene 1 · Vendor Admin logs in and views the dashboard', async ({ page }) => {
    const auth = new AuthHelpers(page);

    await test.step('Navigate to the application', async () => {
      await page.goto('/');
      await beat(page);
    });

    await test.step('Sign in as Vendor Admin', async () => {
      await auth.loginAsSeededUser('vendor', { uiOnboarding: true });
      await beat(page, 800);
    });

    await test.step('Browse the admin dashboard', async () => {
      await page.waitForLoadState('networkidle');
      // Take a moment to show the loaded dashboard
      await beat(page, 1200);

      // Highlight the navigation if present
      await scrollIntoView(page, '[data-testid="nav-tab-dashboard"], nav, header');
      await beat(page, 600);
    });
  });

  // ── Scene 2: Vendor Admin — Credential Catalogue ─────────────────────────

  test('Scene 2 · Admin reviews the credential catalogue', async ({ page }) => {
    const auth = new AuthHelpers(page);

    await test.step('Sign in as Vendor Admin', async () => {
      await page.goto('/');
      await auth.loginAsSeededUser('vendor', { uiOnboarding: true });
    });

    await test.step('Open credential catalogue', async () => {
      // Try sidebar nav first, fall back to direct URL
      const navClicked = await tryClick(
        page,
        '[data-testid="nav-credentials"], a[href*="/credentials"]',
      );
      if (!navClicked) await page.goto('/credentials');
      await page.waitForLoadState('networkidle');
      await beat(page, 800);
    });

    await test.step('View credential types available to this organisation', async () => {
      await scrollIntoView(page, '[data-testid="credential-card"], [data-testid="credential-config"]');
      await beat(page, 1000);
    });
  });

  // ── Scene 3: Applicant — Browse Credentials ───────────────────────────────

  test('Scene 3 · Applicant logs in and browses available credentials', async ({ page }) => {
    const auth = new AuthHelpers(page);

    await test.step('Sign in as Applicant', async () => {
      await page.goto('/');
      await auth.loginAsSeededUser('applicant1');
      await page.waitForLoadState('networkidle');
      await beat(page, 800);
    });

    await test.step('Navigate to the credentials catalogue', async () => {
      const navClicked = await tryClick(
        page,
        '[data-testid="nav-credentials"], a[href*="/credentials"]',
      );
      if (!navClicked) await page.goto('/credentials');
      await page.waitForLoadState('networkidle');
      await beat(page, 800);
    });

    await test.step('Browse available credentials', async () => {
      await scrollIntoView(page, '[data-testid="apply-btn"], [data-testid="credential-card"]');
      await beat(page, 1200);
    });
  });

  // ── Scene 4: Applicant — Submit mDL Application ───────────────────────────

  test('Scene 4 · Applicant completes the mDL application form', async ({ page }) => {
    const auth = new AuthHelpers(page);

    await test.step('Sign in as Applicant', async () => {
      await page.goto('/');
      await auth.loginAsSeededUser('applicant1');
      await page.waitForLoadState('networkidle');
    });

    await test.step('Open the mDL application form', async () => {
      if (credentialConfigId) {
        await page.goto(`/apply/${credentialConfigId}`);
      } else {
        await page.goto('/credentials');
        await page.waitForLoadState('networkidle');
        const applyBtn = page.locator('[data-testid="apply-btn"]').first();
        if (await applyBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
          await applyBtn.click();
        }
      }

      const form = page.locator('[data-testid="credential-application-form"]');
      const formVisible = await form.isVisible({ timeout: 12000 }).catch(() => false);
      if (!formVisible) {
        test.skip('Application form not available — skip this scene');
        return;
      }
      await beat(page, 600);
    });

    await test.step('Fill in personal information', async () => {
      await fillField(page, 'first-name-input', 'Maria').catch(() => {});
      await beat(page, 300);
      await fillField(page, 'last-name-input', 'Credentialist').catch(() => {});
      await beat(page, 300);
      await fillField(page, 'dob-input', '1988-07-20').catch(() => {});
      await beat(page, 300);

      // Email (pre-filled for seeded users, fill only if empty)
      const emailInput = page.locator(inputSelectorFor('email-input'));
      if (await emailInput.isVisible({ timeout: 2000 }).catch(() => false)) {
        const current = await emailInput.inputValue().catch(() => '');
        if (!current) await emailInput.fill('maria.credential@example.com');
      }
      await beat(page, 400);
      await tryClick(page, '[data-testid="next-step-btn"]');
      await beat(page, 600);
    });

    await test.step('Fill in address details', async () => {
      const addressStep = page.locator('[data-testid="address-step"]');
      if (await addressStep.isVisible({ timeout: 4000 }).catch(() => false)) {
        await fillField(page, 'street-input', '456 Oak Avenue').catch(() => {});
        await beat(page, 200);
        await fillField(page, 'city-input', 'Austin').catch(() => {});
        await beat(page, 200);
        await fillField(page, 'zip-input', '78701').catch(() => {});
        await beat(page, 400);
        await tryClick(page, '[data-testid="next-step-btn"]');
        await beat(page, 600);
      }
    });

    await test.step('Add portrait photo', async () => {
      const photoStep = page.locator('[data-testid="photo-step"]');
      if (await photoStep.isVisible({ timeout: 4000 }).catch(() => false)) {
        const uploadInput = page.locator('[data-testid="portrait-upload-input"]');
        if (await uploadInput.isVisible({ timeout: 3000 }).catch(() => false)) {
          await uploadInput.setInputFiles(PORTRAIT_PATH);
          await beat(page, 800);
        }
        await tryClick(page, '[data-testid="next-step-btn"]');
        await beat(page, 600);
      }
    });

    await test.step('Review and submit the application', async () => {
      // Accept terms if present
      await tryClick(page, '[data-testid="accept-terms-checkbox"]');
      await beat(page, 400);

      const submitBtn = page.locator('[data-testid="submit-application-btn"]');
      if (await submitBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
        await scrollIntoView(page, '[data-testid="submit-application-btn"]');
        await beat(page, 400);
        await submitBtn.click();

        // Wait for confirmation
        const submitted = page.locator(
          '[data-testid="application-submitted"], [data-testid="application-id"]',
        );
        const confirmed = await submitted.first()
          .isVisible({ timeout: 20000 })
          .catch(() => false);

        if (confirmed) {
          // Capture the application ID for the approval scene
          const appIdEl = page.locator('[data-testid="application-id"]');
          if (await appIdEl.isVisible({ timeout: 2000 }).catch(() => false)) {
            applicationId = await appIdEl.getAttribute('data-value').catch(() => null);
          }
          await beat(page, 1200);
        }
      }
    });
  });

  // ── Scene 5: Vendor Admin — Approve Application ───────────────────────────

  test('Scene 5 · Admin reviews and approves the application', async ({ page }) => {
    const auth = new AuthHelpers(page);
    const api  = new AuthenticatedApiClient(page);

    await test.step('Sign in as Vendor Admin', async () => {
      await page.goto('/');
      await auth.loginAsSeededUser('vendor', { uiOnboarding: true });
      await page.waitForLoadState('networkidle');
      await beat(page, 600);
    });

    await test.step('Navigate to the applications queue', async () => {
      const navClicked = await tryClick(
        page,
        '[data-testid="nav-applications"], a[href*="/applications"]',
      );
      if (!navClicked) await page.goto('/applications');
      await page.waitForLoadState('networkidle');
      await beat(page, 800);
    });

    await test.step('Open the pending application', async () => {
      // Click the most recent pending application row
      const pendingRow = page.locator(
        '[data-testid="application-row"][data-status="pending"], ' +
        '[data-testid="application-row"]:has-text("pending"), ' +
        'tr:has-text("pending")',
      ).first();

      if (await pendingRow.isVisible({ timeout: 5000 }).catch(() => false)) {
        await scrollIntoView(page, pendingRow);
        await beat(page, 400);
        await pendingRow.click();
        await page.waitForLoadState('networkidle');
        await beat(page, 800);
      }
    });

    await test.step('Approve the application and issue credential', async () => {
      // Prefer UI approval button
      const approveBtn = page.locator(
        '[data-testid="approve-btn"], button:has-text("Approve"), button:has-text("Issue")',
      ).first();

      if (await approveBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
        await scrollIntoView(page, approveBtn);
        await beat(page, 400);
        await approveBtn.click();
        await beat(page, 1000);

        // Handle confirmation dialog if present
        await tryClick(page, '[data-testid="confirm-approve-btn"], button:has-text("Confirm")', 3000);
        await beat(page, 1200);
      } else if (applicationId) {
        // Fall back to API approval so the recording can continue
        console.log('[demo] UI approve button not found — using API approval for application', applicationId);
        await api.approveApplication(applicationId).catch((err) => {
          console.warn('[demo] API approval failed:', err.message);
        });
        await page.reload();
        await page.waitForLoadState('networkidle');
        await beat(page, 1000);
      }
    });
  });

  // ── Scene 6: Applicant — See Issued Credential ────────────────────────────

  test('Scene 6 · Applicant views their issued credential', async ({ page }) => {
    const auth = new AuthHelpers(page);

    await test.step('Sign in as Applicant', async () => {
      await page.goto('/');
      await auth.loginAsSeededUser('applicant1');
      await page.waitForLoadState('networkidle');
      await beat(page, 800);
    });

    await test.step('Navigate to wallet / credentials', async () => {
      const navClicked = await tryClick(
        page,
        '[data-testid="nav-wallet"], [data-testid="nav-documents"], a[href*="/wallet"], a[href*="/documents"]',
      );
      if (!navClicked) {
        // Try common wallet route variants
        for (const route of ['/wallet', '/documents', '/credentials/issued', '/my-credentials']) {
          try {
            await page.goto(route);
            await page.waitForLoadState('networkidle');
            const hasContent = await page.locator(
              '[data-testid="credential-card"], [data-testid="issued-credential"], .credential-card',
            ).first().isVisible({ timeout: 4000 });
            if (hasContent) break;
          } catch {
            // try next route
          }
        }
      }
      await beat(page, 800);
    });

    await test.step('View the issued Mobile Driver\'s License', async () => {
      // Scroll through the wallet to show the credential
      const credentialCard = page.locator(
        '[data-testid="credential-card"], [data-testid="issued-credential"], .credential-card',
      ).first();

      if (await credentialCard.isVisible({ timeout: 8000 }).catch(() => false)) {
        await scrollIntoView(page, credentialCard);
        await beat(page, 600);
        // Open the credential detail if clickable
        await credentialCard.click().catch(() => {});
        await page.waitForLoadState('networkidle').catch(() => {});
        await beat(page, 1500);
      } else {
        // Credential may not be visible yet (issuance async); show current state
        await beat(page, 1500);
      }
    });

    await test.step('End of demo', async () => {
      await beat(page, 800);
    });
  });
});

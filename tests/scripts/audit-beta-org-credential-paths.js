#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');
const {
  acceptOfferInLocalWallet,
  collectBetaOffer,
  loadEnvFile,
  redact,
  registerAndLoginLocalWallet,
  waitFor,
} = require('./verify-beta-waltid-acceptance');

const ROOT = path.resolve(__dirname, '..', '..');
const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const WALLET_ORIGIN = process.env.WALTID_WALLET_ORIGIN || 'http://127.0.0.1:7101';
const ORG_ID = process.env.BETA_AUDIT_ORG_ID || '02af5d70-04e6-40d8-80e2-3e8400d4b018';
const HEADLESS = process.env.HEADED !== '1';

async function login(page, email, password) {
  await page.goto(`${BETA_ORIGIN}/v1/auth/login?redirect_uri=${encodeURIComponent('/console/org')}`, {
    waitUntil: 'domcontentloaded', timeout: 60_000,
  });
  await page.locator('#username, input[name="username"], input[type="email"]').first().fill(email);
  await page.locator('#password, input[name="password"], input[type="password"]').first().fill(password);
  await Promise.all([
    page.waitForURL((url) => url.origin === BETA_ORIGIN && url.pathname.startsWith('/console'), { timeout: 60_000 }).catch(() => {}),
    page.locator('#kc-login, button[type="submit"], input[type="submit"]').first().click(),
  ]);
  await waitFor(() => page.evaluate(async () => {
    const response = await fetch('/v1/auth/me', { credentials: 'include' });
    const body = await response.json().catch(() => null);
    return response.ok && body?.authenticated;
  }), 60_000);
}

async function selectOrg(page) {
  const selection = await page.evaluate(async (organizationId) => {
    const membershipsResponse = await fetch('/v1/organizations/mine', { credentials: 'include' });
    const memberships = await membershipsResponse.json().catch(() => []);
    const eligible = memberships.find((item) => item.id === organizationId && item.membership?.has_org_console_access);
    return {
      ok: Boolean(eligible),
      membershipsStatus: membershipsResponse.status,
      targetName: eligible?.display_name || eligible?.name || null,
    };
  }, ORG_ID);
  if (!selection.ok) return selection;
  const orgButton = page.getByRole('button', { name: /Marty Identity Platform|Audit Production Flow|Select Organization/i }).first();
  await orgButton.click({ timeout: 15_000 });
  const search = page.getByPlaceholder('Search organizations');
  await search.fill(selection.targetName);
  const target = page.getByRole('menuitem').filter({ hasText: selection.targetName }).first();
  await target.click({ timeout: 15_000 });
  await page.waitForTimeout(5_000);
  selection.activeOrgId = await page.evaluate(() => localStorage.getItem('activeOrgId'));
  selection.ok = selection.activeOrgId === ORG_ID;
  return selection;
}

function waltPresentationUrl(oid4vpUri) {
  const parsed = new URL(oid4vpUri);
  return `${WALLET_ORIGIN}/api/siop/initiatePresentation${parsed.search}`;
}

async function presentWithWalt(walletPage, oid4vpUri) {
  const events = [];
  walletPage.on('response', async (response) => {
    if (!response.url().includes('/exchange/')) return;
    const entry = { status: response.status(), method: response.request().method(), endpoint: new URL(response.url()).pathname.split('/').pop() };
    if (response.status() >= 400) {
      const body = await response.json().catch(() => null);
      entry.error = body ? {
        id: body.id || body.error || null,
        exception: Boolean(body.exception),
        message: redact(String(body.message || body.error_description || '')).slice(0, 500),
      } : null;
    }
    events.push(entry);
  });
  await walletPage.goto(waltPresentationUrl(oid4vpUri), { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await walletPage.waitForLoadState('networkidle', { timeout: 45_000 }).catch(() => {});
  await walletPage.waitForTimeout(4_000);
  const before = await walletPage.locator('body').innerText();
  const discloseAll = walletPage.locator('input[type="checkbox"]:visible').first();
  if (await discloseAll.isChecked().catch(() => true) === false) await discloseAll.check({ force: true });
  const disclose = walletPage.getByRole('button', { name: /^disclose$/i });
  const actionable = await disclose.isVisible().catch(() => false);
  if (actionable) await disclose.click({ timeout: 10_000 });
  await walletPage.waitForTimeout(8_000);
  return {
    matched: /credential to present/i.test(before),
    noMatch: /don't have any credentials matching/i.test(before),
    consentVisible: actionable,
    finalText: redact((await walletPage.locator('body').innerText()).slice(0, 1800)),
    events,
  };
}

async function pollFlowInstance(page, instanceId) {
  let last = null;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    last = await page.evaluate(async (id) => {
      const response = await fetch(`/v1/flows/instances/${encodeURIComponent(id)}`, {
        credentials: 'include',
      });
      const body = await response.json().catch(() => null);
      return {
        httpStatus: response.status,
        status: String(body?.status || body?.state || '').toUpperCase() || null,
      };
    }, instanceId);
    if (last.httpStatus === 200 && ['COMPLETED', 'PASSED', 'VERIFIED', 'FAILED', 'EXPIRED'].includes(last.status)) {
      return last;
    }
    await page.waitForTimeout(1500);
  }
  return last;
}

async function main() {
  loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
  loadEnvFile(path.join(ROOT, '.env'));
  const email = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const password = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  if (!email || !password) throw new Error('Missing beta vendor test credentials');

  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const artifactDir = path.join(ROOT, 'tests', 'artifacts', `beta-org-credential-paths-${stamp}`);
  fs.mkdirSync(artifactDir, { recursive: true });
  const report = { createdAt: new Date().toISOString(), organizationId: ORG_ID, artifactDir, apiResponses: [], badResponses: [], pageErrors: [] };
  const browser = await chromium.launch({ headless: HEADLESS });
  try {
    let wallet = null;
    try {
      wallet = await registerAndLoginLocalWallet(browser);
      const betaOffer = await collectBetaOffer(browser);
      const acceptance = await acceptOfferInLocalWallet(wallet.page, wallet.walletId, betaOffer.offerUri);
      report.wallet = {
        offerSource: betaOffer.offerSource,
        badgeAccepted: acceptance.afterCount > acceptance.beforeCount,
        expectedVctStored: acceptance.checks.storedExpectedVct,
      };
    } catch (error) {
      report.wallet = {
        badgeAccepted: false,
        blocker: redact(error.stack || error.message || String(error)),
      };
    }

    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    page.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
    page.on('response', (response) => {
      if (/\/v1\/(application-templates|credential-templates|presentation-policies|flows)(?:[/?]|$)/.test(response.url())) {
        report.apiResponses.push({ status: response.status(), method: response.request().method(), url: redact(response.url()) });
      }
      if (response.url().startsWith(BETA_ORIGIN) && response.status() >= 400 && !response.url().includes('/cdn-cgi/rum')) {
        report.badResponses.push({ status: response.status(), method: response.request().method(), url: redact(response.url()) });
      }
    });
    await login(page, email, password);
    report.orgSelection = await selectOrg(page);

    await page.goto(`${BETA_ORIGIN}/console/org/templates/applications/new?mode=advanced`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    await page.waitForTimeout(5_000);
    await page.screenshot({ path: path.join(artifactDir, '01-application-template-editor.png'), fullPage: true });
    const appBefore = await page.locator('body').innerText();
    const credentialSelect = page.locator('[role="combobox"]').nth(1);
    const editorReady = await credentialSelect.isVisible().catch(() => false);
    let saveResponse = null;
    let savedTemplateId = null;
    let validationStatus = null;
    let credentialOptions = [];
    if (editorReady) {
      await credentialSelect.click();
      const options = page.getByRole('option');
      credentialOptions = await options.allTextContents();
      if (credentialOptions.length) await options.first().click();
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill(`Browser Audit Application ${stamp}`);
      const saveButton = page.getByRole('button', { name: /save draft/i });
      if (await saveButton.isEnabled().catch(() => false)) {
        const responsePromise = page.waitForResponse((response) => (
          response.url().includes('/v1/application-templates') && response.request().method() === 'POST'
        ), { timeout: 30_000 }).catch(() => null);
        const validationPromise = page.waitForResponse((response) => (
          response.url().includes('/v1/application-templates/')
          && response.url().endsWith('/validate')
          && response.request().method() === 'POST'
        ), { timeout: 30_000 }).catch(() => null);
        await saveButton.click();
        const response = await responsePromise;
        if (response) {
          const body = await response.json().catch(() => null);
          saveResponse = {
            status: response.status(),
            ok: response.ok(),
            createdStatus: String(body?.status || '').toUpperCase() || null,
          };
          savedTemplateId = response.ok() ? body?.id : null;
          if (saveResponse.createdStatus === 'DRAFT') {
            const validationResponse = await validationPromise;
            validationStatus = validationResponse?.status() || null;
          }
        }
      }
      await page.waitForTimeout(3_000);
    }
    await page.screenshot({ path: path.join(artifactDir, '02-application-template-result.png'), fullPage: true });
    report.applicationTemplate = {
      editorReady,
      credentialOptions,
      initialText: redact(appBefore.slice(0, 1800)),
      derivedFieldCount: await page.getByLabel('Claim').count().catch(() => 0),
      saveResponse,
      validationStatus,
      savedTemplateId,
      resultText: redact((await page.locator('body').innerText()).slice(0, 1800)),
    };

    if (savedTemplateId) {
      const activate = page.getByRole('button', { name: /^activate$/i });
      if (await activate.isVisible().catch(() => false)) {
        const activationResponse = page.waitForResponse((response) => (
          response.url().endsWith(`/v1/application-templates/${savedTemplateId}/activate`)
        ), { timeout: 20_000 }).catch(() => null);
        await activate.click();
        const response = await activationResponse;
        const body = await response?.json().catch(() => null);
        report.applicationTemplate.activationStatus = response?.status() || null;
        report.applicationTemplate.activatedStatus = String(body?.status || '').toUpperCase() || null;
      } else {
        report.applicationTemplate.activationStatus = null;
        report.applicationTemplate.activatedStatus = null;
      }
    }

    await page.goto(`${BETA_ORIGIN}/console/org/operate/verify`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    await page.waitForTimeout(5_000);
    await page.screenshot({ path: path.join(artifactDir, '03-verification-sessions.png'), fullPage: true });
    const newVerification = page.getByRole('button', { name: /new verification/i });
    const verificationPageReady = await newVerification.isVisible().catch(() => false);
    let verificationSession = null;
    let policyOptions = [];
    let nextEnabled = false;
    if (verificationPageReady) {
      await newVerification.click();
      await page.waitForTimeout(4_000);
      const dialog = page.getByRole('dialog', { name: /new verification session/i });
      const policySelect = dialog.locator('[role="combobox"]').nth(1);
      if (await policySelect.isVisible().catch(() => false)) {
        await policySelect.click();
        const policies = page.getByRole('option');
        policyOptions = await policies.allTextContents();
        if (policyOptions.length) await policies.first().click();
        const nextButton = page.getByRole('button', { name: /^next$/i });
        nextEnabled = await nextButton.isEnabled().catch(() => false);
        if (nextEnabled) {
          await nextButton.click();
          await page.getByLabel('Verification Purpose').fill('Browser wallet credential verification audit');
          const sessionResponsePromise = page.waitForResponse((response) => (
            response.url().endsWith('/v1/flows/verify') && response.request().method() === 'POST'
          ), { timeout: 30_000 }).catch(() => null);
          await page.getByRole('button', { name: /start session/i }).click();
          const response = await sessionResponsePromise;
          if (response) {
            const body = await response.json().catch(() => null);
            verificationSession = {
              status: response.status(), ok: response.ok(),
              instanceId: body?.instance_id || body?.id || null,
              requestUri: body?.request_uri || null,
            };
          }
        }
        await page.waitForTimeout(4_000);
      }
    }
    await page.screenshot({ path: path.join(artifactDir, '04-verification-session-result.png'), fullPage: true });
    report.verification = {
      pageReady: verificationPageReady,
      policyOptions,
      nextEnabled,
      session: verificationSession ? { ...verificationSession, requestUri: verificationSession.requestUri ? '[present]' : null } : null,
      resultText: redact((await page.locator('body').innerText()).slice(0, 2200)),
    };
    if (verificationSession?.requestUri && wallet) {
      report.verification.wallet = await presentWithWalt(wallet.page, verificationSession.requestUri);
      await wallet.page.screenshot({ path: path.join(artifactDir, '05-wallet-verification-result.png'), fullPage: true });
    } else if (verificationSession?.requestUri) {
      report.verification.wallet = {
        blocked: true,
        message: 'No credential was available in the browser wallet for presentation.',
      };
    }
    if (verificationSession?.instanceId) {
      report.verification.poll = await pollFlowInstance(page, verificationSession.instanceId);
    }
    report.finishedAt = new Date().toISOString();
    report.releaseReady = Boolean(
      report.wallet.badgeAccepted
      && report.applicationTemplate.saveResponse?.ok
      && report.applicationTemplate.saveResponse?.createdStatus === 'DRAFT'
      && report.applicationTemplate.validationStatus >= 200
      && report.applicationTemplate.validationStatus < 300
      && report.applicationTemplate.activationStatus >= 200
      && report.applicationTemplate.activationStatus < 300
      && report.applicationTemplate.activatedStatus === 'ACTIVE'
      && verificationSession?.ok
      && report.verification.wallet?.events.some((event) => event.endpoint === 'usePresentationRequest' && event.status < 300)
      && report.verification.poll?.httpStatus === 200
      && ['COMPLETED', 'PASSED', 'VERIFIED'].includes(report.verification.poll?.status)
      && report.badResponses.length === 0
      && report.pageErrors.length === 0
    );
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
    if (!report.releaseReady) process.exitCode = 1;
  } finally {
    await browser.close();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
    process.exitCode = 1;
  });
}

module.exports = { login, selectOrg };

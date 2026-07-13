#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');
const {
  collectBetaOffer,
  loadEnvFile,
  redact,
  waitFor,
} = require('./verify-beta-waltid-acceptance');

const ROOT = path.resolve(__dirname, '..', '..');
const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const TEST_WALLET_ORIGIN = process.env.MARTY_TEST_WALLET_ORIGIN || 'http://127.0.0.1:8787';
const ORG_ID = process.env.BETA_AUDIT_ORG_ID || '02af5d70-04e6-40d8-80e2-3e8400d4b018';
const HEADLESS = process.env.HEADED !== '1';
const MEMBERSHIP_BADGE_VCT = process.env.MARTY_LOGIN_BADGE_VCT
  || `${BETA_ORIGIN}/credentials/marty-verified-member-badge`;

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

async function receiveInTestWallet(walletPage, offerUri, expectedVct) {
  await walletPage.goto(TEST_WALLET_ORIGIN, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await walletPage.getByLabel('Credential offer URI').fill(offerUri);
  const responsePromise = walletPage.waitForResponse((response) => (
    response.url() === `${TEST_WALLET_ORIGIN}/api/receive`
    && response.request().method() === 'POST'
  ), { timeout: 60_000 });
  await walletPage.getByRole('button', { name: /^receive$/i }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  await walletPage.getByRole('status').filter({ hasText: 'Credential received' }).waitFor({ timeout: 60_000 }).catch(() => {});
  const inventory = await walletPage.locator('#credentials').innerText();
  return {
    status: response.status(),
    ok: response.ok(),
    storedExpectedVct: expectedVct ? inventory.includes(expectedVct) : true,
    error: response.ok() ? null : redact(body?.error || 'Credential receipt failed'),
  };
}

async function presentWithTestWallet(walletPage, oid4vpUri) {
  await walletPage.getByLabel('Presentation request URI').fill(oid4vpUri);
  const responsePromise = walletPage.waitForResponse((response) => (
    response.url() === `${TEST_WALLET_ORIGIN}/api/present`
    && response.request().method() === 'POST'
  ), { timeout: 60_000 });
  await walletPage.getByRole('button', { name: /^present$/i }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  await walletPage.getByRole('status').filter({ hasText: 'Presentation accepted' }).waitFor({ timeout: 60_000 }).catch(() => {});
  return {
    status: response.status(),
    ok: response.ok() && body?.ok === true,
    error: response.ok() ? null : redact(body?.error || 'Presentation failed'),
  };
}

async function loginWithTestWallet(browser, walletPage, report) {
  const context = await browser.newContext({ viewport: { width: 1365, height: 900 } });
  const page = await context.newPage();
  page.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
  page.on('response', (response) => {
    if (response.url().startsWith(BETA_ORIGIN) && response.status() >= 400) {
      report.badResponses.push({
        status: response.status(),
        method: response.request().method(),
        url: redact(response.url()),
      });
    }
  });

  try {
    await page.goto(`${BETA_ORIGIN}/v1/auth/credential-login`, {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    const request = await page.evaluate(() => ({
      nonce: document.body.dataset.nonce,
      href: document.querySelector('#wallet-link')?.href || null,
      text: document.body.innerText.slice(0, 1600),
    }));
    if (!request.nonce || !request.href) {
      return { ok: false, error: 'Credential login did not provide a nonce and wallet link.' };
    }

    const wallet = await presentWithTestWallet(walletPage, request.href);
    const completion = await waitFor(() => page.evaluate(async (nonce) => {
      const response = await fetch(`/v1/auth/credential-login/status?nonce=${encodeURIComponent(nonce)}`, {
        credentials: 'include',
      });
      const body = await response.json().catch(() => null);
      return body?.status && body.status !== 'pending' ? body : null;
    }, request.nonce), 60_000, 1_000).catch(() => ({ status: 'pending-timeout' }));

    if (completion?.redirect_to) {
      await page.goto(new URL(completion.redirect_to, BETA_ORIGIN).href, {
        waitUntil: 'domcontentloaded',
        timeout: 60_000,
      });
    }
    const auth = await page.evaluate(async () => {
      const response = await fetch('/v1/auth/me', { credentials: 'include' });
      return { status: response.status, body: await response.json().catch(() => null) };
    });
    await page.screenshot({
      path: path.join(report.artifactDir, '02-credential-login-complete.png'),
      fullPage: true,
    });
    return {
      ok: wallet.ok && completion?.status === 'completed' && auth.body?.authenticated === true,
      requestProvided: true,
      wallet,
      completionStatus: completion?.status || null,
      authenticated: Boolean(auth.body?.authenticated),
      authStatus: auth.status,
      authenticatedEmail: auth.body?.authenticated ? auth.body?.user?.email : null,
    };
  } finally {
    await context.close();
  }
}

async function pollFlowInstance(page, instanceId) {
  let last = null;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    last = await page.evaluate(async (id) => {
      const response = await fetch(`/v1/flows/instances/${encodeURIComponent(id)}/result`, {
        credentials: 'include',
      });
      const body = await response.json().catch(() => null);
      const evaluation = body?.result?.evaluation_result || null;
      const decision = body?.result?.decision || null;
      return {
        httpStatus: response.status,
        status: String(body?.status || body?.state || '').toUpperCase() || null,
        evaluation,
        decision,
        decisionReason: body?.result?.decision_reason || null,
      };
    }, instanceId);
    if (last.httpStatus === 200 && ['COMPLETED', 'PASSED', 'VERIFIED', 'FAILED', 'EXPIRED'].includes(last.status)) {
      return last;
    }
    await page.waitForTimeout(1500);
  }
  return last;
}

async function issuePolicyCredential(page) {
  return page.evaluate(async ({ organizationId }) => {
    const normalizeList = (body) => (
      Array.isArray(body) ? body : body?.items || body?.data?.items || body?.data || []
    );
    const [templatesResponse, policiesResponse] = await Promise.all([
      fetch(`/v1/credential-templates?organization_id=${encodeURIComponent(organizationId)}`, {
        credentials: 'include',
      }),
      fetch(`/v1/presentation-policies?organization_id=${encodeURIComponent(organizationId)}`, {
        credentials: 'include',
      }),
    ]);
    const templates = normalizeList(await templatesResponse.json().catch(() => []));
    const policies = normalizeList(await policiesResponse.json().catch(() => []));
    const activePolicies = policies.filter((policy) => String(policy?.status || '').trim().toUpperCase() === 'ACTIVE');

    let selectedPolicy = null;
    let selectedTemplate = null;
    for (const policy of activePolicies) {
      const requirementIds = (policy.credential_requirements || [])
        .map((requirement) => requirement?.credential_template_id)
        .filter(Boolean);
      const requiredClaimTypes = (policy.required_claims || [])
        .map((claim) => claim?.credential_type)
        .filter(Boolean);
      const candidate = templates.find((template) => (
        String(template?.status || '').trim().toUpperCase() === 'ACTIVE'
        && (
          requirementIds.includes(template.id)
          || requiredClaimTypes.includes(template.id)
          || requiredClaimTypes.includes(template.vct)
          || (policy.accepted_credential_types || []).includes(template.vct)
        )
      ));
      if (candidate) {
        selectedPolicy = policy;
        selectedTemplate = candidate;
        break;
      }
    }
    if (!selectedPolicy || !selectedTemplate) {
      return {
        ok: false,
        status: 0,
        error: 'No active Presentation Policy has a matching active Credential Template.',
        activePolicyNames: activePolicies.map((policy) => policy.name),
        activeTemplateNames: templates
          .filter((template) => String(template?.status || '').trim().toUpperCase() === 'ACTIVE')
          .map((template) => template.name),
      };
    }

    const claims = Object.fromEntries((selectedTemplate.claims || []).map((claim) => {
      const name = claim?.name || claim?.claim_name;
      const normalizedName = String(name || '').toLowerCase();
      const type = String(claim?.type || claim?.data_type || 'STRING').toUpperCase();
      const options = claim?.options || claim?.enum || [];
      let value;
      if (Array.isArray(options) && options.length) {
        const first = options[0];
        value = typeof first === 'object' ? first.value ?? first.label : first;
      } else if (type === 'DATE') value = '2026-07-12';
      else if (type === 'DATETIME') value = '2026-07-12T12:00:00Z';
      else if (type === 'NUMBER' || type === 'INTEGER') value = 1;
      else if (type === 'BOOLEAN') value = true;
      else if (normalizedName.includes('email')) value = 'wallet-holder@example.test';
      else if (normalizedName.includes('given') || normalizedName.includes('first')) value = 'Ada';
      else if (normalizedName.includes('family') || normalizedName.includes('last') || normalizedName.includes('surname')) value = 'Lovelace';
      else if (normalizedName.includes('employee') || normalizedName.endsWith('_id')) value = 'E2E-1001';
      else if (normalizedName.includes('department')) value = 'Engineering';
      else if (normalizedName.includes('position') || normalizedName.includes('title')) value = 'Verification Engineer';
      else value = `Browser audit ${name || 'value'}`;
      return [name, value];
    }).filter(([name]) => Boolean(name)));
    const issuanceResponse = await fetch('/v1/issuance', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        organization_id: organizationId,
        credential_template_id: selectedTemplate.id,
        claims,
      }),
    });
    const body = await issuanceResponse.json().catch(() => null);
    return {
      ok: issuanceResponse.ok,
      status: issuanceResponse.status,
      error: issuanceResponse.ok ? null : body?.detail || body?.message || 'Credential issuance failed.',
      policyId: selectedPolicy.id,
      policyName: selectedPolicy.name,
      templateId: selectedTemplate.id,
      templateName: selectedTemplate.name,
      expectedVct: selectedTemplate.vct || null,
      offerUri: body?.credential_offer_uri || body?.offer_url || null,
    };
  }, { organizationId: ORG_ID });
}

async function cancelStaleVerificationInstances(page) {
  return page.evaluate(async (organizationId) => {
    const listResponse = await fetch(
      `/v1/flows/instances?organization_id=${encodeURIComponent(organizationId)}`,
      { credentials: 'include' },
    );
    const body = await listResponse.json().catch(() => []);
    const instances = Array.isArray(body) ? body : body?.items || body?.instances || body?.data || [];
    const cancellable = instances.filter((instance) => {
      const status = String(instance?.status || instance?.state || '').toUpperCase();
      const metadata = instance?.metadata || {};
      const context = instance?.context_data || instance?.context || {};
      const descriptors = [
        instance?.flow_type,
        instance?.type,
        metadata.flow_type,
        metadata.flow_definition_reference,
        context.flow_type,
        context.protocol_flow_type,
        context.flow_definition_reference,
        instance?.purpose,
        metadata.purpose,
        context.purpose,
      ].map((value) => String(value || '').toLowerCase());
      return ['PENDING', 'AWAITING_WALLET', 'IN_PROGRESS'].includes(status)
        && descriptors.some((value) => (
          value.includes('verif')
          || value.includes('oid4vp')
          || value.includes('presentation')
          || value === '__verification__'
        ));
    });
    const results = [];
    for (const instance of cancellable) {
      const response = await fetch(`/v1/flows/instances/${encodeURIComponent(instance.id)}/cancel`, {
        method: 'POST',
        credentials: 'include',
      });
      results.push({ id: instance.id, status: response.status, ok: response.ok });
    }
    return {
      listStatus: listResponse.status,
      found: cancellable.length,
      results,
    };
  }, ORG_ID);
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
  const report = {
    createdAt: new Date().toISOString(),
    organizationId: ORG_ID,
    artifactDir,
    apiResponses: [],
    expectedEntitlementResponses: [],
    badResponses: [],
    pageErrors: [],
  };
  const browser = await chromium.launch({ headless: HEADLESS });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    const testWalletPage = await context.newPage();
    await testWalletPage.goto(TEST_WALLET_ORIGIN, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    const resetResponse = await testWalletPage.request.post(`${TEST_WALLET_ORIGIN}/api/reset`, { data: {} });
    report.testWallet = { ready: resetResponse.status() === 204 };
    try {
      const betaOffer = await collectBetaOffer(browser, {
        walletId: 'wr-default',
        logoutAfterOffer: true,
      });
      const acceptance = await receiveInTestWallet(
        testWalletPage,
        betaOffer.offerUri,
        MEMBERSHIP_BADGE_VCT,
      );
      report.membershipBadge = {
        walletId: 'wr-default',
        offerSource: betaOffer.offerSource,
        issueStatus: betaOffer.issueStatus,
        loggedOut: betaOffer.loggedOut,
        accepted: acceptance.ok,
        storedExpectedVct: acceptance.storedExpectedVct,
        walletStatus: acceptance.status,
        walletError: acceptance.error,
      };
    } catch (error) {
      report.membershipBadge = {
        accepted: false,
        storedExpectedVct: false,
        blocker: redact(error.stack || error.message || String(error)),
      };
    }
    report.credentialLogin = await loginWithTestWallet(browser, testWalletPage, report);
    page.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
    page.on('response', async (response) => {
      if (/\/v1\/(application-templates|credential-templates|presentation-policies|flows)(?:[/?]|$)/.test(response.url())) {
        report.apiResponses.push({ status: response.status(), method: response.request().method(), url: redact(response.url()) });
      }
      if (response.url().startsWith(BETA_ORIGIN) && response.status() >= 400 && !response.url().includes('/cdn-cgi/rum')) {
        const body = await response.json().catch(() => null);
        const entry = {
          status: response.status(),
          method: response.request().method(),
          url: redact(response.url()),
        };
        if (response.status() === 403 && body?.error === 'plan_feature_unavailable') {
          report.expectedEntitlementResponses.push({
            ...entry,
            error: body.error,
            feature: body.feature || null,
            currentPlan: body.current_plan || null,
          });
        } else {
          report.badResponses.push(entry);
        }
      }
    });
    await login(page, email, password);
    report.orgSelection = await selectOrg(page);
    if (!report.orgSelection.ok) {
      report.blocker = `Test user cannot select organization ${ORG_ID}`;
      report.finishedAt = new Date().toISOString();
      report.releaseReady = false;
      fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
      console.log(JSON.stringify(report, null, 2));
      process.exitCode = 1;
      return;
    }

    report.staleVerificationCleanup = await cancelStaleVerificationInstances(page);

    const policyCredential = await issuePolicyCredential(page);
    report.policyCredential = {
      ...policyCredential,
      offerUri: policyCredential.offerUri ? '[present]' : null,
    };
    if (policyCredential.ok && policyCredential.offerUri) {
      const acceptance = await receiveInTestWallet(
        testWalletPage,
        policyCredential.offerUri,
        policyCredential.expectedVct,
      );
      report.policyCredential.accepted = acceptance.ok;
      report.policyCredential.storedExpectedVct = acceptance.storedExpectedVct;
      report.policyCredential.walletStatus = acceptance.status;
      report.policyCredential.walletError = acceptance.error;
      await testWalletPage.screenshot({
        path: path.join(artifactDir, '01-wallet-with-policy-credential.png'),
        fullPage: true,
      });
    }

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
        const matchingPolicy = policyCredential.policyName
          ? page.getByRole('option', { name: policyCredential.policyName, exact: true })
          : null;
        if (matchingPolicy && await matchingPolicy.isVisible().catch(() => false)) {
          await matchingPolicy.click();
        } else if (policyOptions.length) {
          await policies.first().click();
        }
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
    if (verificationSession?.requestUri) {
      report.verification.wallet = await presentWithTestWallet(testWalletPage, verificationSession.requestUri);
      await testWalletPage.screenshot({ path: path.join(artifactDir, '05-wallet-verification-result.png'), fullPage: true });
    }
    if (verificationSession?.instanceId) {
      report.verification.poll = await pollFlowInstance(page, verificationSession.instanceId);
      if (!['COMPLETED', 'PASSED', 'VERIFIED', 'FAILED', 'EXPIRED', 'CANCELLED'].includes(report.verification.poll?.status)) {
        report.verification.cleanup = await page.evaluate(async (instanceId) => {
          const response = await fetch(`/v1/flows/instances/${encodeURIComponent(instanceId)}/cancel`, {
            method: 'POST',
            credentials: 'include',
          });
          return { status: response.status, ok: response.ok };
        }, verificationSession.instanceId);
      }
    }
    report.finishedAt = new Date().toISOString();
    report.releaseReady = Boolean(
      report.membershipBadge?.offerSource === 'canonical-ui'
      && report.membershipBadge?.walletId === 'wr-default'
      && report.membershipBadge?.loggedOut
      && report.membershipBadge?.accepted
      && report.membershipBadge?.storedExpectedVct
      && report.credentialLogin?.ok
      && report.policyCredential?.ok
      && report.policyCredential?.accepted
      && report.policyCredential?.storedExpectedVct
      && report.applicationTemplate.saveResponse?.ok
      && report.applicationTemplate.saveResponse?.createdStatus === 'DRAFT'
      && report.applicationTemplate.validationStatus >= 200
      && report.applicationTemplate.validationStatus < 300
      && report.applicationTemplate.activationStatus >= 200
      && report.applicationTemplate.activationStatus < 300
      && report.applicationTemplate.activatedStatus === 'ACTIVE'
      && verificationSession?.ok
      && report.testWallet?.ready
      && report.verification.wallet?.ok
      && report.verification.poll?.httpStatus === 200
      && ['COMPLETED', 'PASSED', 'VERIFIED'].includes(report.verification.poll?.status)
      && report.verification.poll?.evaluation === 'passed'
      && report.verification.poll?.decision === 'allow'
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

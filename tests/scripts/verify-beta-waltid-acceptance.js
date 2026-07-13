#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');

const ROOT = path.resolve(__dirname, '..', '..');
const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const WALLET_ORIGIN = process.env.WALTID_WALLET_ORIGIN || 'http://127.0.0.1:7101';
const TEMPLATE_ID = process.env.LOGIN_BADGE_TEMPLATE_ID || '50000000-0000-0000-0000-000000000010';
const EXPECTED_VCT = process.env.EXPECTED_LOGIN_BADGE_VCT || `${BETA_ORIGIN}/credentials/marty-verified-member-badge`;
const HEADLESS = process.env.HEADED !== '1';

function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = value;
  }
}

function redact(value) {
  if (value == null) return value;
  let text = typeof value === 'string' ? value : JSON.stringify(value);
  text = text.replace(/(credential_offer_uri=)[^&\s"']+/gi, '$1[redacted]');
  text = text.replace(/(credential_offer=)[^&\s"']+/gi, '$1[redacted]');
  text = text.replace(/("pre-authorized_code"\s*:\s*")[^"]+/gi, '$1[redacted]');
  text = text.replace(/("(?:token|accessToken|idToken|refreshToken)"\s*:\s*")[^"]+/gi, '$1[redacted]');
  text = text.replace(/(Bearer\s+)[A-Za-z0-9._-]+/g, '$1[redacted]');
  text = text.replace(/([?&](?:code|state|session_state|request)=)[^&\s"']+/gi, '$1[redacted]');
  return text;
}

function offerPart(offerUri) {
  try {
    const parsed = new URL(offerUri);
    const inline = parsed.searchParams.get('credential_offer');
    if (inline) return { key: 'credential_offer', value: inline };
    const byReference = parsed.searchParams.get('credential_offer_uri');
    if (byReference) return { key: 'credential_offer_uri', value: byReference };
  } catch {
    // Fall through to by-reference handling.
  }
  return { key: 'credential_offer_uri', value: offerUri };
}

function issuerUrlWithWaltidPath(issuerUrl) {
  if (typeof issuerUrl !== 'string' || !issuerUrl.trim()) return issuerUrl;
  const issuer = issuerUrl.trim().replace(/\/+$/, '');
  if (issuer.endsWith('/waltid')) return issuer;
  return `${issuer.replace(/\/(credential-manager|apple-wallet|spruce|waltid)$/, '')}/waltid`;
}

function credentialConfigurationIdForWaltid(configId) {
  if (typeof configId !== 'string' || !configId.trim()) return configId;
  const id = configId.trim();
  if (id.endsWith('#sd-jwt') || id.endsWith('#mdoc') || id.endsWith('#vds-nc')) return id;
  if (id.endsWith('#credential-manager') || id.endsWith('#apple-wallet') || id.endsWith('#spruce-sd-jwt')) {
    return `${id.split('#')[0]}#sd-jwt`;
  }
  if (id.includes('#')) return id;
  return `${id}#sd-jwt`;
}

function adaptOfferUriForWaltid(offerUri) {
  const part = offerPart(offerUri);
  if (part.key !== 'credential_offer') return offerUri;

  try {
    const offer = JSON.parse(part.value);
    if (!offer || typeof offer !== 'object' || Array.isArray(offer)) return offerUri;
    const adaptedOffer = {
      ...offer,
      credential_issuer: issuerUrlWithWaltidPath(offer.credential_issuer),
    };
    if (Array.isArray(offer.credential_configuration_ids)) {
      adaptedOffer.credential_configuration_ids = offer.credential_configuration_ids
        .map(credentialConfigurationIdForWaltid);
    }
    return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(adaptedOffer))}`;
  } catch {
    return offerUri;
  }
}

function localWalletAcceptUrl(offerUri) {
  const part = offerPart(adaptOfferUriForWaltid(offerUri));
  return `${WALLET_ORIGIN}/api/siop/initiateIssuance?${part.key}=${encodeURIComponent(part.value)}`;
}

async function waitFor(fn, timeoutMs = 30_000, intervalMs = 500) {
  const start = Date.now();
  let lastError = null;
  while (Date.now() - start < timeoutMs) {
    try {
      const result = await fn();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`Timed out waiting for condition${lastError ? `: ${lastError.message}` : ''}`);
}

async function responseText(response, maxLength = 650) {
  try {
    return redact((await response.text()).slice(0, maxLength));
  } catch {
    return null;
  }
}

async function registerAndLoginLocalWallet(browser) {
  const context = await browser.newContext({ viewport: { width: 1365, height: 900 } });
  const page = await context.newPage();
  const timestamp = Date.now();
  const email = `marty-wallet-${timestamp}@example.test`;
  const password = `TestWallet${timestamp}!`;

  await page.goto(`${WALLET_ORIGIN}/signup`, { waitUntil: 'commit', timeout: 30_000 });
  await page.locator('input#name:visible').fill('Marty Wallet Test');
  await page.locator('input#email:visible').fill(email);
  await page.locator('input#password:visible').fill(password);
  await page.locator('button:visible', { hasText: /sign up/i }).click();
  await page.waitForURL(/\/login/, { timeout: 30_000 });
  await page.locator('input#email:visible').fill(email);
  await page.locator('input#password:visible').fill(password);
  await Promise.all([
    page.waitForLoadState('networkidle', { timeout: 30_000 }).catch(() => {}),
    page.locator('button:visible', { hasText: /sign in/i }).click(),
  ]);

  const listing = await waitFor(() => page.evaluate(async () => {
    const response = await fetch('/wallet-api/wallet/accounts/wallets', { credentials: 'include' });
    if (!response.ok) return null;
    return response.json();
  }));
  const walletId = listing.wallets?.[0]?.id;
  if (!walletId) throw new Error('walt.id did not create an account wallet');
  return { context, page, walletId };
}

async function loginToBetaApplicant(page, email, password) {
  const applyUrl = `${BETA_ORIGIN}/console/applicant/apply/${TEMPLATE_ID}`;
  await page.context().clearCookies();
  await page.goto(BETA_ORIGIN, { waitUntil: 'domcontentloaded', timeout: 60_000 }).catch(() => {});
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  }).catch(() => {});
  await page.goto(`${BETA_ORIGIN}/v1/auth/login?redirect_uri=${encodeURIComponent(applyUrl)}`, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  await page.locator('input[name="username"], #username, input[type="email"]').first().fill(email, { timeout: 30_000 });
  await page.locator('input[name="password"], #password, input[type="password"]').first().fill(password, { timeout: 30_000 });
  await Promise.all([
    page.waitForURL((url) => url.href.startsWith(applyUrl), {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    }),
    page.locator('button[type="submit"], input[type="submit"], button:has-text("Sign In"), button:has-text("Login")').first().click(),
  ]);
  await waitFor(async () => page.url().startsWith(BETA_ORIGIN) && page.evaluate(async () => {
    const response = await fetch('/v1/auth/me', { credentials: 'include' });
    if (!response.ok) return null;
    const body = await response.json();
    return body?.authenticated ? true : null;
  }), 60_000);
}

async function collectBetaOffer(browser, {
  walletId = 'wr-waltid-001',
  logoutAfterOffer = false,
  contextOptions = {},
  keepContext = false,
  onStep = null,
} = {}) {
  loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
  loadEnvFile(path.join(ROOT, '.env'));
  const email = process.env.TEST_APPLICANT_EMAIL || process.env.TEST_APPLICANT1_EMAIL;
  const password = process.env.TEST_APPLICANT_PASSWORD || process.env.TEST_APPLICANT1_PASSWORD;
  if (!email || !password) {
    throw new Error('Missing TEST_APPLICANT_EMAIL/TEST_APPLICANT_PASSWORD env values');
  }

  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    ...contextOptions,
  });
  const page = await context.newPage();
  const issueResponses = [];
  const badResponses = [];
  const consoleErrors = [];

  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(redact(message.text()).slice(0, 400));
  });
  page.on('response', async (response) => {
    const url = response.url();
    if (url.includes('/cdn-cgi/rum')) return;
    const canonicalClaim = /\/v1\/me\/applications\/[^/]+\/claim(?:\?|$)/.test(url);
    if (canonicalClaim && response.request().method() === 'POST') {
      try {
        issueResponses.push({ status: response.status(), json: await response.json() });
      } catch {
        issueResponses.push({ status: response.status(), text: await responseText(response) });
      }
    }
    if (url.startsWith(BETA_ORIGIN) && response.status() >= 400) {
      badResponses.push({ status: response.status(), url: redact(url), body: await responseText(response, 250) });
    }
  });

  await loginToBetaApplicant(page, email, password);
  if (onStep) {
    await onStep(
      page,
      'Membership application ready',
      'The applicant is authenticated and the approved membership badge is ready to claim.',
    );
  }
  await page.getByRole('button', { name: /add to wallet/i }).click({ timeout: 60_000 });
  await page.getByTestId('wallet-selector').waitFor({ state: 'visible', timeout: 15_000 });
  if (onStep) {
    await onStep(
      page,
      'Choose a browser wallet',
      'The holder chooses where the standards-based OpenID4VCI credential offer will be received.',
    );
  }
  await page.getByTestId(`wallet-option-${walletId}`).click();
  await waitFor(() => issueResponses.length > 0 && issueResponses[issueResponses.length - 1].json, 60_000);
  const latest = issueResponses[issueResponses.length - 1].json;
  const selectedWallets = await page.evaluate(() => (
    Object.fromEntries(Object.entries(localStorage).filter(([key]) => key.startsWith('elevenid_wallets_')))
  ));
  let loggedOut = false;
  if (logoutAfterOffer) {
    const closeDialog = page.getByRole('button', { name: /^close$/i }).last();
    if (await closeDialog.isVisible().catch(() => false)) {
      await closeDialog.click();
    }
    const logoutControl = page.locator('button:visible, a:visible')
      .filter({ hasText: /^logout$/i })
      .first();
    await logoutControl.click({ timeout: 15_000 });
    loggedOut = await waitFor(() => page.evaluate(async () => {
      const response = await fetch('/v1/auth/me', { credentials: 'include' });
      const body = await response.json().catch(() => null);
      return body?.authenticated === false ? true : null;
    }), 60_000).catch(() => false);
    if (onStep) {
      await onStep(
        page,
        'Signed out after issuance',
        'The original password-backed session is closed before credential login begins.',
      );
    }
  }
  if (!keepContext) await context.close();

  const result = {
    offerUri: latest.offer_url || latest.credential_offer_uri,
    offerSource: 'canonical-ui',
    issueStatus: latest.status,
    issueWalletOfferIds: Object.keys(latest.credential_offer_uris || {}),
    selectedWallets,
    loggedOut,
    badResponses,
    consoleErrors,
  };
  if (keepContext) {
    result.context = context;
    result.page = page;
  }
  return result;
}

async function clickWalletAcceptButton(page) {
  const patterns = [/accept/i, /receive/i, /claim/i, /add/i, /save/i, /continue/i, /confirm/i];
  for (let round = 0; round < 8; round += 1) {
    const buttons = await page.locator('button:visible')
      .evaluateAll((elements) => elements.map((element) => element.innerText.trim()).filter(Boolean))
      .catch(() => []);
    for (const pattern of patterns) {
      const match = buttons.find((text) => pattern.test(text));
      if (match) {
        await page.locator('button:visible').filter({ hasText: pattern }).first().click({ timeout: 5000 });
        await page.waitForLoadState('networkidle', { timeout: 30_000 }).catch(() => {});
        await page.waitForTimeout(3000);
        return { clicked: match, visibleButtons: buttons };
      }
    }
    await page.waitForTimeout(1500);
  }
  return {
    clicked: null,
    visibleButtons: await page.locator('button:visible')
      .evaluateAll((elements) => elements.map((element) => element.innerText.trim()).filter(Boolean))
      .catch(() => []),
  };
}

async function acceptOfferInLocalWallet(walletPage, walletId, offerUri) {
  const events = [];
  const consoleErrors = [];
  const pageErrors = [];
  walletPage.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(redact(message.text()).slice(0, 600));
  });
  walletPage.on('pageerror', (error) => {
    pageErrors.push(redact(error.stack || error.message || String(error)).slice(0, 1200));
  });
  walletPage.on('response', async (response) => {
    const url = response.url();
    if (url.includes('/wallet-api/') || url.includes('/api/siop/')) {
      events.push({
        status: response.status(),
        method: response.request().method(),
        url: redact(url),
        body: await responseText(response),
      });
    }
  });

  const before = await walletPage.evaluate(async (id) => {
    const response = await fetch(`/wallet-api/wallet/${id}/credentials?showDeleted=false&showPending=false`, {
      credentials: 'include',
    });
    return response.json();
  }, walletId);

  const adaptedOfferUri = adaptOfferUriForWaltid(offerUri);
  const acceptUrl = localWalletAcceptUrl(offerUri);
  await walletPage.goto(acceptUrl, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await walletPage.waitForLoadState('networkidle', { timeout: 60_000 }).catch(() => {});
  await walletPage.waitForTimeout(4000);
  const click = await clickWalletAcceptButton(walletPage);
  await walletPage.waitForTimeout(12_000);

  const after = await walletPage.evaluate(async (id) => {
    const credentialsResponse = await fetch(`/wallet-api/wallet/${id}/credentials?showDeleted=false&showPending=false`, {
      credentials: 'include',
    });
    const historyResponse = await fetch(`/wallet-api/wallet/${id}/history`, { credentials: 'include' });
    return {
      url: location.href,
      text: document.body.innerText.slice(0, 2400),
      html: document.documentElement.outerHTML.slice(0, 2400),
      credentialsStatus: credentialsResponse.status,
      credentials: await credentialsResponse.json().catch(() => []),
      historyStatus: historyResponse.status,
      historyText: await historyResponse.text(),
    };
  }, walletId);
  const credentialPreviews = (after.credentials || []).map((credential) => (
    credential.parsedDocument ? JSON.stringify(credential.parsedDocument) : credential.document || ''
  ));
  const vctResolutionEvents = events.filter((event) => event.url.includes('/exchange/resolveVctUrl'));

  return {
    routeParam: offerPart(adaptedOfferUri).key,
    adaptedOfferParam: offerPart(adaptedOfferUri).key,
    acceptUrl: redact(acceptUrl),
    beforeCount: before.length,
    click,
    afterCount: (after.credentials || []).length,
    credentialSummaries: (after.credentials || []).map((credential) => ({
      id: credential.id,
      format: credential.format,
      pending: credential.pending,
      preview: redact((credential.parsedDocument ? JSON.stringify(credential.parsedDocument) : credential.document || '').slice(0, 900)),
    })),
    checks: {
      expectedVct: EXPECTED_VCT,
      storedExpectedVct: credentialPreviews.some((preview) => preview.includes(EXPECTED_VCT)),
      storedLegacyExampleVct: credentialPreviews.some((preview) => preview.includes('marty.example')),
      vctResolutionOk: vctResolutionEvents.some((event) => event.status === 200 && (event.body || '').includes(EXPECTED_VCT)),
      vctResolutionStatuses: vctResolutionEvents.map((event) => event.status),
      walletShowsCredentialTitle: /Marty Verified Membe|Member Login Credential/i.test(after.text || ''),
    },
    page: {
      url: redact(after.url),
      text: redact(after.text),
      htmlPreview: redact(after.html),
      credentialsStatus: after.credentialsStatus,
      historyStatus: after.historyStatus,
      historyPreview: redact((after.historyText || '').slice(0, 1000)),
    },
    consoleErrors,
    pageErrors,
    events,
  };
}

async function main() {
  const browser = await chromium.launch({ headless: HEADLESS });
  try {
    const wallet = await registerAndLoginLocalWallet(browser);
    const beta = await collectBetaOffer(browser);
    const acceptance = await acceptOfferInLocalWallet(wallet.page, wallet.walletId, beta.offerUri);
    const accepted = acceptance.afterCount > acceptance.beforeCount;
    const releaseReady = (
      beta.offerSource === 'canonical-ui'
      &&
      accepted
      && acceptance.checks.storedExpectedVct
      && !acceptance.checks.storedLegacyExampleVct
      && acceptance.checks.vctResolutionOk
      && acceptance.checks.walletShowsCredentialTitle
    );
    const result = {
      beta: {
        issueStatus: beta.issueStatus,
        offerSource: beta.offerSource,
        issueWalletOfferIds: beta.issueWalletOfferIds,
        selectedWalletValues: Object.values(beta.selectedWallets).map(redact),
        badResponses: beta.badResponses,
        consoleErrors: beta.consoleErrors,
        offerParam: offerPart(beta.offerUri).key,
      },
      wallet: { walletId: wallet.walletId },
      acceptance,
      accepted,
      releaseReady,
    };
    console.log(JSON.stringify(result, null, 2));
    if (!releaseReady) process.exitCode = 1;
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

module.exports = {
  acceptOfferInLocalWallet,
  collectBetaOffer,
  loadEnvFile,
  offerPart,
  redact,
  registerAndLoginLocalWallet,
  waitFor,
};

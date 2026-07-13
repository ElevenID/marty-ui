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
const MEMBERSHIP_BADGE_VCT = process.env.MARTY_LOGIN_BADGE_VCT
  || `${BETA_ORIGIN}/credentials/marty-verified-member-badge`;
const HEADLESS = process.env.HEADED !== '1';

async function receiveBadge(walletPage, offerUri) {
  await walletPage.goto(TEST_WALLET_ORIGIN, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await walletPage.getByLabel('Credential offer URI').fill(offerUri);
  const responsePromise = walletPage.waitForResponse((response) => (
    response.url() === `${TEST_WALLET_ORIGIN}/api/receive`
    && response.request().method() === 'POST'
  ), { timeout: 60_000 });
  await walletPage.getByRole('button', { name: /^receive$/i }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  const inventory = await walletPage.locator('#credentials').innerText();
  return {
    status: response.status(),
    accepted: response.ok(),
    storedExpectedVct: inventory.includes(MEMBERSHIP_BADGE_VCT),
    error: response.ok() ? null : redact(body?.error || 'Credential receipt failed'),
  };
}

async function presentBadge(walletPage, requestUri) {
  await walletPage.getByLabel('Presentation request URI').fill(requestUri);
  const responsePromise = walletPage.waitForResponse((response) => (
    response.url() === `${TEST_WALLET_ORIGIN}/api/present`
    && response.request().method() === 'POST'
  ), { timeout: 60_000 });
  await walletPage.getByRole('button', { name: /^present$/i }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  return {
    status: response.status(),
    accepted: response.ok() && body?.ok === true,
    error: response.ok() ? null : redact(body?.error || 'Presentation failed'),
  };
}

async function main() {
  loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
  loadEnvFile(path.join(ROOT, '.env'));
  const artifactDir = path.join(
    ROOT,
    'tests',
    'artifacts',
    `beta-credential-login-${new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '')}`,
  );
  fs.mkdirSync(artifactDir, { recursive: true });

  const browser = await chromium.launch({ headless: HEADLESS });
  const report = {
    startedAt: new Date().toISOString(),
    betaOrigin: BETA_ORIGIN,
    walletOrigin: TEST_WALLET_ORIGIN,
    artifactDir,
    pageErrors: [],
    badResponses: [],
  };

  try {
    const ready = await fetch(`${TEST_WALLET_ORIGIN}/ready`).then((response) => response.ok).catch(() => false);
    if (!ready) throw new Error(`Marty browser wallet is not ready at ${TEST_WALLET_ORIGIN}`);
    await fetch(`${TEST_WALLET_ORIGIN}/api/reset`, { method: 'POST' });

    const offer = await collectBetaOffer(browser, { walletId: 'wr-default', logoutAfterOffer: true });
    const walletContext = await browser.newContext({ viewport: { width: 1365, height: 900 } });
    const walletPage = await walletContext.newPage();
    report.badge = {
      offerSource: offer.offerSource,
      loggedOut: offer.loggedOut === true,
      ...await receiveBadge(walletPage, offer.offerUri),
    };
    await walletPage.screenshot({ path: path.join(artifactDir, '01-wallet-with-badge.png'), fullPage: true });

    const loginContext = await browser.newContext({ viewport: { width: 1365, height: 900 } });
    const loginPage = await loginContext.newPage();
    loginPage.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
    loginPage.on('response', (response) => {
      if (response.url().startsWith(BETA_ORIGIN) && response.status() >= 400) {
        report.badResponses.push({
          status: response.status(),
          method: response.request().method(),
          url: redact(response.url()),
        });
      }
    });
    await loginPage.goto(`${BETA_ORIGIN}/v1/auth/credential-login`, {
      waitUntil: 'domcontentloaded', timeout: 60_000,
    });
    const loginRequest = await loginPage.evaluate(() => ({
      nonce: document.body.dataset.nonce,
      href: document.querySelector('#wallet-link')?.href || null,
      walletOptions: Array.from(document.querySelectorAll('#wallet-select option'))
        .map((option) => option.textContent.trim()),
    }));
    if (!loginRequest.nonce || !loginRequest.href) {
      throw new Error('Credential login did not provide a nonce and signed presentation link');
    }
    report.loginPage = {
      hasNonce: true,
      walletOptions: loginRequest.walletOptions,
    };
    report.presentation = await presentBadge(walletPage, loginRequest.href);

    const completion = await waitFor(() => loginPage.evaluate(async (nonce) => {
      const response = await fetch(`/v1/auth/credential-login/status?nonce=${encodeURIComponent(nonce)}`, {
        credentials: 'include',
      });
      const body = await response.json().catch(() => null);
      return body?.status && body.status !== 'pending' ? body : null;
    }, loginRequest.nonce), 60_000, 1_000).catch(() => ({ status: 'pending-timeout' }));
    if (completion?.redirect_to) {
      await loginPage.goto(new URL(completion.redirect_to, BETA_ORIGIN).href, {
        waitUntil: 'domcontentloaded', timeout: 60_000,
      });
    }
    const auth = await loginPage.evaluate(async () => {
      const response = await fetch('/v1/auth/me', { credentials: 'include' });
      return { status: response.status, body: await response.json().catch(() => null) };
    });
    await loginPage.screenshot({ path: path.join(artifactDir, '02-login-complete.png'), fullPage: true });

    report.completion = {
      status: completion?.status || null,
      authenticated: auth.body?.authenticated === true,
      authStatus: auth.status,
      authenticatedEmail: auth.body?.authenticated ? auth.body?.user?.email : null,
    };
    report.releaseReady = (
      report.badge.offerSource === 'canonical-ui'
      && report.badge.loggedOut
      && report.badge.accepted
      && report.badge.storedExpectedVct
      && report.presentation.accepted
      && report.completion.status === 'completed'
      && report.completion.authenticated
      && report.pageErrors.length === 0
      && report.badResponses.length === 0
    );
    report.finishedAt = new Date().toISOString();
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
    if (!report.releaseReady) process.exitCode = 1;

    await loginContext.close();
    await walletContext.close();
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
  process.exitCode = 1;
});

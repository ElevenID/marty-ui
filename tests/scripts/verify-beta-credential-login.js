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
const HEADLESS = process.env.HEADED !== '1';

function presentationUrl(oid4vpUri) {
  const parsed = new URL(oid4vpUri);
  return `${WALLET_ORIGIN}/api/siop/initiatePresentation${parsed.search}`;
}

async function clickPresentationAction(page) {
  const patterns = [/disclose/i, /present/i, /share/i, /authorize/i, /accept/i, /continue/i, /confirm/i];
  for (let round = 0; round < 12; round += 1) {
    const discloseAll = page.locator('input[type="checkbox"]:visible').first();
    if (await discloseAll.isChecked().catch(() => true) === false) {
      await discloseAll.check({ force: true, timeout: 3_000 }).catch(() => {});
      await page.waitForTimeout(500);
    }
    const buttons = await page.locator('button:visible')
      .evaluateAll((elements) => elements.map((element) => element.innerText.trim()).filter(Boolean))
      .catch(() => []);
    for (const pattern of patterns) {
      const candidate = buttons.find((label) => pattern.test(label));
      if (candidate) {
        await page.locator('button:visible').filter({ hasText: pattern }).first().click({ timeout: 8_000 });
        await page.waitForTimeout(2_500);
        return { clicked: candidate, buttons };
      }
    }
    await page.waitForTimeout(1_000);
  }
  return {
    clicked: null,
    buttons: await page.locator('button:visible')
      .evaluateAll((elements) => elements.map((element) => element.innerText.trim()).filter(Boolean))
      .catch(() => []),
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
    walletOrigin: WALLET_ORIGIN,
    artifacts: artifactDir,
    pageErrors: [],
    badResponses: [],
  };

  try {
    const wallet = await registerAndLoginLocalWallet(browser);
    const betaOffer = await collectBetaOffer(browser);
    const acceptance = await acceptOfferInLocalWallet(wallet.page, wallet.walletId, betaOffer.offerUri);
    report.badge = {
      offerSource: betaOffer.offerSource,
      accepted: acceptance.afterCount > acceptance.beforeCount,
      storedExpectedVct: acceptance.checks.storedExpectedVct,
      walletShowsCredentialTitle: acceptance.checks.walletShowsCredentialTitle,
      walletConsoleErrors: acceptance.consoleErrors,
      walletPageErrors: acceptance.pageErrors,
    };
    await wallet.page.screenshot({ path: path.join(artifactDir, '01-wallet-with-badge.png'), fullPage: true });

    const loginContext = await browser.newContext({ viewport: { width: 1365, height: 900 } });
    const loginPage = await loginContext.newPage();
    loginPage.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
    loginPage.on('response', async (response) => {
      if (response.url().startsWith(BETA_ORIGIN) && response.status() >= 400) {
        report.badResponses.push({ status: response.status(), url: redact(response.url()) });
      }
    });
    await loginPage.goto(`${BETA_ORIGIN}/v1/auth/credential-login`, {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    await loginPage.screenshot({ path: path.join(artifactDir, '02-credential-login.png'), fullPage: true });
    const loginRequest = await loginPage.evaluate(() => ({
      nonce: document.body.dataset.nonce,
      href: document.querySelector('#wallet-link')?.href,
      walletOptions: Array.from(document.querySelectorAll('#wallet-select option')).map((option) => ({
        value: option.value,
        label: option.textContent.trim(),
      })),
      text: document.body.innerText.slice(0, 1600),
    }));
    if (!loginRequest.href) throw new Error('Credential login did not provide an OID4VP wallet link');
    report.loginPage = {
      walletOptions: loginRequest.walletOptions,
      hasNonce: Boolean(loginRequest.nonce),
      text: loginRequest.text,
    };

    const walletEvents = [];
    wallet.page.on('response', (response) => {
      const url = response.url();
      if (url.includes('/wallet-api/') || url.includes('/api/siop/')) {
        walletEvents.push({ status: response.status(), method: response.request().method(), url: redact(url) });
      }
    });
    await wallet.page.goto(presentationUrl(loginRequest.href), {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    await wallet.page.waitForLoadState('networkidle', { timeout: 45_000 }).catch(() => {});
    await wallet.page.waitForTimeout(4_000);
    await wallet.page.screenshot({ path: path.join(artifactDir, '03-wallet-presentation-request.png'), fullPage: true });

    const initialWalletState = await wallet.page.evaluate(() => ({
      url: location.href,
      text: document.body.innerText.slice(0, 2400),
      buttons: Array.from(document.querySelectorAll('button')).filter((button) => button.offsetParent)
        .map((button) => button.innerText.trim()).filter(Boolean),
      inputs: Array.from(document.querySelectorAll('input')).map((input) => ({
        type: input.type,
        checked: input.checked,
        value: input.type === 'checkbox' || input.type === 'radio' ? input.value : '[redacted]',
      })),
    }));
    const action = await clickPresentationAction(wallet.page);
    await wallet.page.waitForTimeout(8_000);
    await wallet.page.screenshot({ path: path.join(artifactDir, '04-wallet-after-presentation.png'), fullPage: true });

    let completion = null;
    try {
      completion = await waitFor(async () => loginPage.evaluate(async (nonce) => {
        const response = await fetch(`/v1/auth/credential-login/status?nonce=${encodeURIComponent(nonce)}`);
        const body = await response.json();
        return body.status !== 'pending' ? body : null;
      }, loginRequest.nonce), 30_000, 1_000);
    } catch {
      completion = { status: 'pending-timeout' };
    }

    if (completion?.redirect_to) {
      await loginPage.goto(new URL(completion.redirect_to, BETA_ORIGIN).href, {
        waitUntil: 'domcontentloaded',
        timeout: 60_000,
      });
    }
    const auth = await loginPage.evaluate(async () => {
      const response = await fetch('/v1/auth/me', { credentials: 'include' });
      return { status: response.status, body: await response.json().catch(() => null) };
    });
    await loginPage.screenshot({ path: path.join(artifactDir, '05-login-final-state.png'), fullPage: true });

    report.presentation = {
      initialWalletState: {
        url: redact(initialWalletState.url),
        text: redact(initialWalletState.text),
        buttons: initialWalletState.buttons,
        inputs: initialWalletState.inputs,
      },
      action,
      finalWalletUrl: redact(wallet.page.url()),
      finalWalletText: redact((await wallet.page.locator('body').innerText().catch(() => '')).slice(0, 2400)),
      walletEvents,
      completion,
      authenticated: Boolean(auth.body?.authenticated),
      authStatus: auth.status,
      authenticatedUser: auth.body?.authenticated ? {
        email: auth.body?.user?.email,
        role: auth.body?.user?.role,
      } : null,
    };
    report.releaseReady = (
      report.badge.offerSource === 'canonical-ui'
      && report.badge.accepted
      && report.presentation.completion?.status === 'completed'
      && report.presentation.authenticated
    );
    report.finishedAt = new Date().toISOString();
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
    if (!report.releaseReady) process.exitCode = 1;
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
  process.exitCode = 1;
});

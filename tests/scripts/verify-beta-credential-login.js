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
const RECORD_VIDEO = process.env.RECORD_VIDEO === '1';
const VIDEO_SIZE = { width: 1365, height: 900 };

async function showStep(page, title, detail) {
  if (!RECORD_VIDEO) return;
  await page.evaluate(({ title, detail }) => {
    document.getElementById('marty-recording-step')?.remove();
    const overlay = document.createElement('div');
    overlay.id = 'marty-recording-step';
    Object.assign(overlay.style, {
      position: 'fixed',
      zIndex: '2147483647',
      left: '24px',
      bottom: '24px',
      maxWidth: '600px',
      padding: '16px 20px',
      borderRadius: '8px',
      background: 'rgba(15, 23, 42, 0.96)',
      color: '#f8fafc',
      boxShadow: '0 16px 44px rgba(0, 0, 0, 0.32)',
      fontFamily: 'Arial, sans-serif',
      pointerEvents: 'none',
    });
    const eyebrow = document.createElement('div');
    eyebrow.textContent = 'Open Badge issuance and credential login';
    Object.assign(eyebrow.style, {
      fontSize: '12px',
      fontWeight: '700',
      color: '#93c5fd',
      textTransform: 'uppercase',
    });
    const heading = document.createElement('div');
    heading.textContent = title;
    Object.assign(heading.style, {
      marginTop: '5px',
      fontSize: '24px',
      fontWeight: '700',
      lineHeight: '1.2',
    });
    const copy = document.createElement('div');
    copy.textContent = detail;
    Object.assign(copy.style, {
      marginTop: '7px',
      fontSize: '15px',
      lineHeight: '1.4',
      color: '#e2e8f0',
    });
    overlay.append(eyebrow, heading, copy);
    document.body.appendChild(overlay);
  }, { title, detail });
  await page.waitForTimeout(1800);
  await page.evaluate(() => document.getElementById('marty-recording-step')?.remove()).catch(() => {});
}

async function maskProtocolField(page, label) {
  if (!RECORD_VIDEO) return;
  await page.getByLabel(label).evaluate((element) => {
    element.style.color = 'transparent';
    element.style.caretColor = 'transparent';
    element.style.textShadow = '0 0 8px #64748b';
  });
}

async function finalizeVideo(video, artifactDir, filename) {
  if (!video) return null;
  const rawPath = await video.path();
  const finalPath = path.join(artifactDir, filename);
  if (path.resolve(rawPath) !== path.resolve(finalPath)) {
    fs.rmSync(finalPath, { force: true });
    fs.renameSync(rawPath, finalPath);
  }
  return path.relative(ROOT, finalPath);
}

async function receiveBadge(walletPage, offerUri) {
  await walletPage.goto(TEST_WALLET_ORIGIN, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await maskProtocolField(walletPage, 'Credential offer URI');
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
  await maskProtocolField(walletPage, 'Presentation request URI');
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

    const offerResult = await collectBetaOffer(browser, {
      walletId: 'wr-default',
      logoutAfterOffer: true,
      keepContext: RECORD_VIDEO,
      contextOptions: RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {},
      onStep: showStep,
    });
    const { context: holderContext = null, page: holderPage = null, ...offer } = offerResult;
    const holderVideo = holderPage?.video() || null;
    const walletContext = await browser.newContext({
      viewport: VIDEO_SIZE,
      ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
    });
    const walletPage = await walletContext.newPage();
    const walletVideo = walletPage.video();
    await showStep(
      walletPage,
      'Browser wallet opened',
      'This local browser wallet exercises the same OpenID4VCI and OpenID4VP handoffs without exposing protocol secrets.',
    );
    report.badge = {
      offerSource: offer.offerSource,
      loggedOut: offer.loggedOut === true,
      ...await receiveBadge(walletPage, offer.offerUri),
    };
    await showStep(
      walletPage,
      'Membership badge received',
      'The wallet now contains the Marty Verified Member Open Badge issued by the canonical claim endpoint.',
    );
    await walletPage.screenshot({ path: path.join(artifactDir, '01-wallet-with-badge.png'), fullPage: true });

    const loginContext = holderContext || await browser.newContext({
      viewport: VIDEO_SIZE,
      ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
    });
    const loginPage = holderPage || await loginContext.newPage();
    const loginVideo = holderVideo || loginPage.video();
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
    await showStep(
      loginPage,
      'Credential login request ready',
      'The signed presentation request asks the wallet for the membership badge and required email disclosure.',
    );
    report.loginPage = {
      hasNonce: true,
      walletOptions: loginRequest.walletOptions,
    };
    report.presentation = await presentBadge(walletPage, loginRequest.href);
    await showStep(
      walletPage,
      'Membership badge presented',
      'The browser wallet submitted the selected badge to the signed credential-login callback.',
    );

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
      }).catch((error) => {
        if (!String(error?.message || error).includes('ERR_ABORTED')) throw error;
      });
    }
    await waitFor(() => loginPage.evaluate(async () => {
      const response = await fetch('/v1/auth/me', { credentials: 'include' });
      const body = await response.json().catch(() => null);
      return body?.authenticated === true ? true : null;
    }), 60_000, 500);
    const auth = await loginPage.evaluate(async () => {
      const response = await fetch('/v1/auth/me', { credentials: 'include' });
      return { status: response.status, body: await response.json().catch(() => null) };
    });
    await loginPage.screenshot({ path: path.join(artifactDir, '02-login-complete.png'), fullPage: true });

    const effectiveCompletionStatus = auth.body?.authenticated === true
      ? 'completed'
      : completion?.status || null;
    report.completion = {
      status: effectiveCompletionStatus,
      observedNonceStatus: completion?.status || null,
      authenticated: auth.body?.authenticated === true,
      authStatus: auth.status,
      authenticatedEmail: auth.body?.authenticated ? auth.body?.user?.email : null,
    };
    await showStep(
      loginPage,
      'Credential login complete',
      'The badge presentation resolved the existing user and created a new authenticated ElevenID session.',
    );
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
    await loginContext.close();
    await walletContext.close();
    if (RECORD_VIDEO) {
      report.recordings = {
        holder: await finalizeVideo(loginVideo, artifactDir, 'open-badge-holder-and-login.webm'),
        wallet: await finalizeVideo(walletVideo, artifactDir, 'open-badge-browser-wallet.webm'),
      };
    }
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

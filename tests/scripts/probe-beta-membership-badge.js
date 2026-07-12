#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');

const ROOT = path.resolve(__dirname, '..', '..');
const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const TEMPLATE_ID = process.env.LOGIN_BADGE_TEMPLATE_ID || '50000000-0000-0000-0000-000000000010';

function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const value = line.trim();
    if (!value || value.startsWith('#')) continue;
    const separator = value.indexOf('=');
    if (separator < 1) continue;
    const key = value.slice(0, separator).trim();
    let raw = value.slice(separator + 1).trim();
    if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
      raw = raw.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = raw;
  }
}

function redact(value) {
  let text = typeof value === 'string' ? value : JSON.stringify(value);
  return text
    .replace(/(credential_offer(?:_uri)?=)[^&\s"']+/gi, '$1[redacted]')
    .replace(/("pre-authorized_code"\s*:\s*")[^"]+/gi, '$1[redacted]')
    .replace(/(Bearer\s+)[A-Za-z0-9._-]+/g, '$1[redacted]')
    .replace(/([?&](?:code|state|session_state|request)=)[^&\s"']+/gi, '$1[redacted]');
}

async function readResponse(response) {
  try {
    return redact((await response.text()).slice(0, 700));
  } catch {
    return null;
  }
}

async function login(page, email, password, destination) {
  await page.goto(`${BETA_ORIGIN}/v1/auth/login?redirect_uri=${encodeURIComponent(destination)}`, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  await page.locator('input[name="username"], #username, input[type="email"]').first().fill(email);
  await page.locator('input[name="password"], #password, input[type="password"]').first().fill(password);
  await Promise.all([
    page.waitForURL((url) => url.href.startsWith(destination), {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    }),
    page.locator('button[type="submit"], input[type="submit"]').first().click(),
  ]);
}

async function browserFetch(page, url, options = {}) {
  return page.evaluate(async ({ target, init }) => {
    const response = await fetch(target, { credentials: 'include', ...init });
    const text = await response.text();
    let body = text;
    try { body = JSON.parse(text); } catch {}
    return {
      status: response.status,
      mipVersion: response.headers.get('X-MIP-Version'),
      body,
    };
  }, { target: url, init: options });
}

async function main() {
  loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
  loadEnvFile(path.join(ROOT, '.env'));
  const email = process.env.TEST_APPLICANT_EMAIL || process.env.TEST_APPLICANT1_EMAIL;
  const password = process.env.TEST_APPLICANT_PASSWORD || process.env.TEST_APPLICANT1_PASSWORD;
  if (!email || !password) throw new Error('Applicant beta test credentials are unavailable.');

  const runId = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
  const artifactDir = path.join(ROOT, 'tests', 'artifacts', `beta-membership-probe-${runId}`);
  fs.mkdirSync(artifactDir, { recursive: true });

  const browser = await chromium.launch({ headless: process.env.HEADED !== '1' });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  const responses = [];
  const failedRequests = [];
  const pageErrors = [];
  const consoleErrors = [];

  page.on('pageerror', (error) => pageErrors.push(redact(error.stack || error.message)));
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(redact(message.text()).slice(0, 700));
  });
  page.on('requestfailed', (request) => {
    if (!request.url().includes('/cdn-cgi/rum')) {
      failedRequests.push({ method: request.method(), url: redact(request.url()), failure: request.failure()?.errorText });
    }
  });
  page.on('response', async (response) => {
    const url = response.url();
    if (!url.startsWith(BETA_ORIGIN)) return;
    const api = new URL(url).pathname.startsWith('/v1/');
    const important = api && (response.status() >= 400 || response.request().method() !== 'GET');
    if (important) {
      responses.push({
        method: response.request().method(),
        status: response.status(),
        url: redact(url),
        body: await readResponse(response),
      });
    }
  });

  const applyUrl = `${BETA_ORIGIN}/console/applicant/apply/${TEMPLATE_ID}`;
  try {
    await login(page, email, password, applyUrl);
    if (!page.url().startsWith(applyUrl)) {
      await page.goto(applyUrl, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    }
    await page.waitForTimeout(4000);
    const before = {
      url: page.url(),
      title: await page.title(),
      body: redact((await page.locator('body').innerText()).slice(0, 4000)),
    };
    await page.screenshot({ path: path.join(artifactDir, 'before-add-to-wallet.png'), fullPage: true });

    const addButton = page.getByRole('button', { name: /add to wallet/i });
    const addVisible = await addButton.isVisible().catch(() => false);
    if (addVisible) {
      await addButton.click();
      await page.waitForTimeout(8000);
    }
    const after = {
      url: page.url(),
      body: redact((await page.locator('body').innerText()).slice(0, 5000)),
      walletSelectorVisible: await page.getByTestId('wallet-selector').isVisible().catch(() => false),
      alerts: await page.locator('[role="alert"]').allInnerTexts().catch(() => []),
    };
    await page.screenshot({ path: path.join(artifactDir, 'after-add-to-wallet.png'), fullPage: true });

    const authProbe = await browserFetch(page, '/v1/auth/me');
    const userId = authProbe.body?.user?.user_id || authProbe.body?.user?.sub || null;
    const routeProbes = {
      auth: authProbe,
      profile: await browserFetch(page, '/v1/me/applicant-profile'),
      applications: await browserFetch(page, '/v1/me/applications?limit=100'),
      holderInventory: await browserFetch(page, '/v1/issued-credentials/mine?limit=100'),
      removedApplications: await browserFetch(page, '/v1/applicants/applications'),
      removedOrgApplications: await browserFetch(page, '/v1/applicants/org-applications'),
      removedProfileApplications: await browserFetch(page, '/v1/applicants/profiles/removed-route-probe/applications'),
      removedByUser: userId
        ? await browserFetch(page, `/v1/applicants/by-user/${encodeURIComponent(userId)}`)
        : { status: 0, body: null },
      credentialLogin: await browserFetch(page, '/v1/auth/credential-login'),
    };
    routeProbes.auth.body = routeProbes.auth.body?.authenticated
      ? { authenticated: true, user_id_present: Boolean(routeProbes.auth.body?.user?.user_id) }
      : routeProbes.auth.body;

    const canonicalRoutes = [
      routeProbes.profile,
      routeProbes.applications,
      routeProbes.holderInventory,
    ];
    const removedRoutes = [
      routeProbes.removedApplications,
      routeProbes.removedOrgApplications,
      routeProbes.removedProfileApplications,
      routeProbes.removedByUser,
    ];
    const serverErrors = responses.filter((response) => response.status >= 500);
    const releaseReady = (
      canonicalRoutes.every((probe) => probe.status === 200 && probe.mipVersion === '0.3.0')
      && removedRoutes.every((probe) => probe.status === 404 && probe.mipVersion === '0.3.0')
      && serverErrors.length === 0
      && failedRequests.length === 0
      && pageErrors.length === 0
    );

    const report = {
      created_at: new Date().toISOString(),
      artifact_dir: path.relative(ROOT, artifactDir),
      before,
      addVisible,
      after,
      routeProbes,
      responses,
      serverErrors,
      failedRequests,
      pageErrors,
      consoleErrors,
      releaseReady,
    };
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify({
      artifact_dir: report.artifact_dir,
      addVisible,
      walletSelectorVisible: after.walletSelectorVisible,
      alerts: after.alerts,
      routeStatuses: Object.fromEntries(Object.entries(routeProbes).map(([key, value]) => [key, value.status])),
      importantResponses: responses,
      failedRequestCount: failedRequests.length,
      pageErrorCount: pageErrors.length,
      consoleErrorCount: consoleErrors.length,
      releaseReady,
    }, null, 2));
    if (!releaseReady) process.exitCode = 1;
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
  process.exitCode = 1;
});

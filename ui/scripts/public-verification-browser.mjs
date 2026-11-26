// Browser worker for the owned Rust acceptance fixture. No API interception.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import puppeteer from 'puppeteer';

const channel = process.env.MARTY_TEST_PUBLIC_DEMO_BROWSER_CHANNEL;
assert(channel === undefined || channel === 'chrome', 'Unsupported public fixture browser channel');
const launchOptions = { headless: true, ...(channel ? { channel } : {}) };
const executable = await puppeteer.executablePath(channel);
assert(existsSync(executable), 'Selected sandboxed Chrome is required before fixtures start');
if (process.argv[2] === '--check') {
  // Exercise the same sandboxed launch before allocating KMS fixtures. A cache
  // path alone does not establish that this host can start Chromium.
  const probe = await puppeteer.launch(launchOptions);
  let version;
  try {
    version = await probe.version();
  } finally {
    await probe.close();
  }
  console.log(JSON.stringify({ browserAvailable: true, sandboxedLaunch: true,
    browserChannel: channel || 'bundled', executable, version }));
  process.exit(0);
}
const { build, preview } = await import('vite');
const gateway = new URL(process.argv[2]);
assert.equal(gateway.protocol, 'http:');
assert.equal(gateway.hostname, '127.0.0.1');
assert(gateway.port && gateway.pathname === '/' && !gateway.search && !gateway.username && !gateway.password);
const root = fileURLToPath(new URL('../', import.meta.url));
process.chdir(root);
process.env.MARTY_UI_SURFACE = 'application';
process.env.VITE_API_URL = gateway.origin;
process.env.VITE_DEV_PROXY_TARGET = gateway.origin;
let server;
let browser;
let page;
let stage = 'startup';
const apiResponses = [];
const failures = [];
const consoleErrors = [];
const pendingRequests = new Map();
function gatewayDiagnosticRoute(pathname) {
  if (pathname === '/v1/auth/me') return 'auth-session';
  const prefix = '/v1/flows/public/verification';
  if (pathname === `${prefix}/catalog`) return 'verification-catalog';
  if (pathname === `${prefix}/preview`) return 'verification-preview';
  if (pathname === `${prefix}/sessions`) return 'verification-launch';
  if (pathname.startsWith(`${prefix}/sessions/`)) return 'verification-session';
  return 'other-gateway';
}
const artifactDir = path.join(root, '../rust/target/public-verification-browser');
// A new output directory preserves earlier qualification artifacts and avoids
// emptying any existing build or operator directory.
const bundleDir = path.join(artifactDir, `bundle-${randomUUID()}`);
let closed = false;
async function cleanup() {
  if (closed) return;
  closed = true;
  if (browser) await browser.close();
  if (server) await server.close();
  process.stdin.destroy();
}
const deadline = setTimeout(async () => {
  console.error('Browser qualification deadline exceeded');
  await cleanup();
  process.exit(1);
}, 150_000);
try {
  stage = 'production-build';
  await build({ root, mode: 'production', logLevel: 'silent', clearScreen: false,
    build: { outDir: bundleDir, emptyOutDir: false } });
  stage = 'production-preview';
  server = await preview({ root, mode: 'production', logLevel: 'silent',
    build: { outDir: bundleDir }, preview: { host: '127.0.0.1', port: 0, open: false } });
  const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
  console.log(`MARTY_BROWSER_READY ${JSON.stringify({ origin })}`);
  const input = createInterface({ input: process.stdin });
  input.on('close', () => {
    if (!closed) cleanup().then(() => process.exit(1), () => process.exit(1));
  });
  const [command] = await once(input, 'line');
  assert.equal(command, 'RUN');
  browser = await puppeteer.launch(launchOptions);
  const browserVersion = await browser.version();
  const chromium = browser.process();
  page = await browser.newPage();
  await page.setViewport({ width: 1365, height: 1000 });
  page.on('pageerror', error => failures.push(error.message));
  page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text().slice(0, 500)); });
  page.on('response', response => {
    const url = new URL(response.url());
    const pending = pendingRequests.get(response.request());
    if (pending) pending.responseStatus = response.status();
    if (url.origin === gateway.origin && url.pathname.startsWith('/v1/flows/public/verification/')) {
      const headers = response.request().headers();
      if (['cookie', 'authorization', 'x-api-key', 'x-user-id', 'x-organization-id'].some(name => headers[name])) {
        failures.push('Public verification request sent browser authority');
      }
      apiResponses.push({ method: response.request().method(), path: url.pathname, status: response.status() });
    }
  });
  page.on('requestfinished', request => pendingRequests.delete(request));
  page.on('requestfailed', request => pendingRequests.delete(request));
  await page.setRequestInterception(true);
  page.on('request', request => {
    const url = new URL(request.url());
    // Keep only fixed location classes: fixture URLs can carry capabilities,
    // so failure diagnostics must not publish raw URLs, headers or bodies.
    pendingRequests.set(request, {
      method: request.method(), type: request.resourceType(),
      location: url.origin === origin ? 'application'
        : url.origin === gateway.origin ? 'gateway' : 'external',
      ...(url.origin === gateway.origin ? { route: gatewayDiagnosticRoute(url.pathname) } : {}),
      responseStatus: null,
    });
    if (url.origin === origin && /\/(?:@vite|@id|src)\//.test(url.pathname)) {
      failures.push('Production journey requested development source');
    }
    if ([origin, gateway.origin].includes(url.origin) || ['data:', 'blob:'].includes(url.protocol)) request.continue().catch(() => {});
    else request.abort().catch(() => {});
  });
  async function click(text) {
    await page.waitForFunction(label => [...document.querySelectorAll('button')].some(button => button.textContent.trim() === label && !button.disabled), {}, text);
    await page.evaluate(label => [...document.querySelectorAll('button')].find(button => button.textContent.trim() === label).click(), text);
  }
  async function consent() {
    await page.waitForSelector('input[type=checkbox]:not(:disabled)');
    await page.waitForFunction(() => !document.querySelector('[role=listbox]'));
    await page.locator('input[type=checkbox]:not(:disabled)').click();
    await page.waitForFunction(() => document.querySelector('input[type=checkbox]')?.checked === true);
  }
  stage = 'load';
  await page.goto(`${origin}/verify`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('input[type=checkbox]:not(:disabled)');
  assert(await page.evaluate(() => [...document.querySelectorAll('button')].find(button => button.textContent.trim() === 'Verify example')?.disabled));
  stage = 'verify';
  await page.evaluate(() => { document.cookie = 'sessionId=browser-fixture; path=/; SameSite=Lax'; });
  await consent();
  await click('Verify example');
  await page.waitForFunction(() => [...document.querySelectorAll('[role=status]')].some(node => node.textContent.includes('The verifier accepted this presentation')));
  mkdirSync(artifactDir, { recursive: true });
  await page.screenshot({ path: path.join(artifactDir, 'verified.png'), fullPage: true });
  const launches = apiResponses.filter(item => item.method === 'POST' && item.path.endsWith('/sessions')).length;
  assert.equal(launches, 1);
  stage = 'reload';
  await page.reload({ waitUntil: 'networkidle0' });
  await page.waitForFunction(() => [...document.querySelectorAll('[role=status]')].some(node => node.textContent.includes('The verifier accepted this presentation')));
  assert.equal(apiResponses.filter(item => item.method === 'POST' && item.path.endsWith('/sessions')).length, 1);
  stage = 'customize';
  await click('Customize the request');
  stage = 'customize-select';
  await page.locator('[role=combobox][aria-labelledby*="verify-choice-label"]').click();
  stage = 'customize-options';
  await page.waitForFunction(() => [...document.querySelectorAll('[role=option]')].some(node => node.textContent.trim() === '21 or older'));
  await page.evaluate(() => [...document.querySelectorAll('[role=option]')].find(node => node.textContent.trim() === '21 or older').click());
  assert(await page.evaluate(() => [...document.querySelectorAll('button')].find(button => button.textContent.trim() === 'Verify example')?.disabled));
  stage = 'customize-consent';
  await consent();
  stage = 'customize-verify';
  await click('Verify example');
  await page.waitForFunction(() => [...document.querySelectorAll('[role=status]')].some(node => node.textContent.includes('The verifier did not accept this presentation')));
  await page.screenshot({ path: path.join(artifactDir, 'denied.png'), fullPage: true });
  await click('Start a new verification');
  stage = 'wallet';
  await page.setViewport({ width: 390, height: 844 });
  await click('Use your wallet instead');
  assert(await page.evaluate(() => [...document.querySelectorAll('button')].find(button => button.textContent.trim() === 'Create wallet request')?.disabled));
  await consent();
  await click('Create wallet request');
  await page.waitForSelector('a[href^="openid4vp:"]');
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'Mobile layout must not overflow');
  await page.screenshot({ path: path.join(artifactDir, 'wallet-request.png'), fullPage: true });
  await click('Cancel');
  await page.waitForFunction(() => [...document.querySelectorAll('[role=status]')].some(node => node.textContent.includes('Verification cancelled')));
  assert(apiResponses.some(item => item.method === 'OPTIONS' && item.status === 200));
  assert(apiResponses.some(item => item.path.endsWith('/example') && item.status === 200));
  assert(apiResponses.some(item => item.path.endsWith('/cancel') && item.status === 200));
  assert.deepEqual(failures, []);
  await cleanup();
  assert(chromium.exitCode !== null || chromium.signalCode !== null, 'Owned Chromium must exit');
  console.log(`MARTY_BROWSER_RESULT ${JSON.stringify({ verified: true, reloadDidNotRelaunch: true, customizedDenialVerified: true,
    walletRequestCancelled: true, browserVersion, browserChannel: channel || 'bundled', chromiumPid: chromium.pid, chromiumExited: true, viteClosed: !server.httpServer.listening,
    productionBundle: true, apiResponses })}`);
} catch (error) {
  console.error(`Browser qualification failed at ${stage}: ${error.message}`);
  if (page) {
    mkdirSync(artifactDir, { recursive: true });
    const diagnostics = { stage, pendingRequests: [...pendingRequests.values()].slice(0, 24),
      pendingRequestCount: pendingRequests.size, pageErrorCount: failures.length,
      consoleErrorCount: consoleErrors.length, apiResponseCount: apiResponses.length,
      documentReadyState: await page.evaluate(() => document.readyState).catch(() => 'unavailable') };
    writeFileSync(path.join(artifactDir, 'diagnostics.json'), JSON.stringify(diagnostics, null, 2));
    console.error(`Browser qualification diagnostics: ${JSON.stringify(diagnostics)}`);
    await page.screenshot({ path: path.join(artifactDir, 'failed.png'), fullPage: true }).catch(() => {});
    const text = await page.evaluate(() => document.body.innerText.slice(0, 3000)).catch(() => 'unavailable');
    writeFileSync(path.join(artifactDir, 'failed.json'), JSON.stringify({ stage, text, failures, consoleErrors, apiResponses }, null, 2));
  }
  await cleanup();
  process.exitCode = 1;
} finally {
  clearTimeout(deadline);
}

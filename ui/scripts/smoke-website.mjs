// Runs the built website with its real Nginx configuration and a local edge.
// Application requests land on a sentinel document: no backend or billing
// transaction is required to prove a browser handoff occurred.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer';
import { getWebSurface } from './web-surface-contract.mjs';
import { renderWebsiteNginx } from './render-website-nginx.mjs';

const uiRoot = fileURLToPath(new URL('../', import.meta.url));
const dist = path.resolve(process.argv[2] || path.join(uiRoot, 'dist-website'));
const metadata = JSON.parse(readFileSync(path.join(dist, 'marty-website-release.json'), 'utf8'));
const nginxPath = (value) => JSON.stringify(value.replaceAll('\\', '/'));
const temporary = mkdtempSync(path.join(tmpdir(), 'marty-website-smoke-'));
const socket = http.createServer();
await new Promise((resolve) => socket.listen(0, '127.0.0.1', resolve));
const nginxPort = socket.address().port;
await new Promise((resolve) => socket.close(resolve));
writeFileSync(path.join(temporary, 'routes.conf'), renderWebsiteNginx(metadata.revision));
writeFileSync(path.join(temporary, 'headers.conf'), readFileSync(path.join(uiRoot, 'nginx.website.headers.conf')));
const serverConfig = readFileSync(path.join(uiRoot, 'nginx.website.conf'), 'utf8')
  .replace('listen 80;', `listen 127.0.0.1:${nginxPort};`)
  .replace('/usr/share/nginx/html', nginxPath(dist))
  .replace('/etc/nginx/marty-website-routes.conf', nginxPath(path.join(temporary, 'routes.conf')))
  .replaceAll('/etc/nginx/marty-website-headers.conf', nginxPath(path.join(temporary, 'headers.conf')));
// The production image supplies mime.types; list the exercised content types
// here so the smoke can use an uninstalled, locally compiled Nginx binary.
writeFileSync(path.join(temporary, 'nginx.conf'), `${process.getuid?.() === 0 ? 'user root;' : ''} error_log stderr; pid ${nginxPath(path.join(temporary, 'nginx.pid'))};
events {} http { access_log off; types { text/html html; application/javascript js; text/css css;
application/json json; application/xml xml; text/plain txt; image/png png; image/svg+xml svg; image/x-icon ico; }
${serverConfig} }`);
const nginx = spawn(process.env.NGINX_BIN || 'nginx', ['-p', `${temporary.replaceAll('\\', '/')}/`, '-e', 'stderr', '-c', 'nginx.conf', '-g', 'daemon off; master_process off;'], { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
let nginxError = '';
nginx.stderr.on('data', (data) => { nginxError += data; });
nginx.on('error', (error) => { nginxError += error.message; });
const websiteOrigin = `http://127.0.0.1:${nginxPort}`;
let browser;
let edge;
try {
  let ready = false;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try { ready = (await fetch(`${websiteOrigin}/healthz`)).ok; } catch { /* wait for Nginx startup */ }
    if (ready) break;
    if (nginx.exitCode !== null) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.ok(ready, `Nginx did not start. Set NGINX_BIN to a compatible binary. ${nginxError}`);
  for (const pathname of ['/', '/product', '/product/', '/resources', '/robots.txt', '/sitemap.xml']) {
    const response = await fetch(`${websiteOrigin}${pathname}`, { redirect: 'manual' });
    assert.equal(response.status, 200, pathname);
    assert.equal(response.headers.get('x-marty-website-revision'), metadata.revision, pathname);
  }
  for (const pathname of ['/pricing', '/pricing/', '/pricing/checkout', '/resources/', '/login', '/login/error', '/docs', '/unknown', '/missing.js', '/demos/missing.js', `/_website/${metadata.revision}/missing.js`]) {
    assert.equal((await fetch(`${websiteOrigin}${pathname}`, { redirect: 'manual' })).status, 404, pathname);
  }
  assert.equal((await fetch(`${websiteOrigin}/_website/runtime-config.js`)).headers.get('cache-control'), 'no-store');
  assert.match((await fetch(`${websiteOrigin}/_website/${metadata.revision}/startup.js`)).headers.get('cache-control'), /immutable/);

  const backendRequests = [];
  const applicationDocuments = [];
  edge = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    if (/^\/(?:v1|api|auth)(?:\/|$)/.test(url.pathname)) backendRequests.push(request.url);
    if (getWebSurface(url.pathname) === 'application') {
      applicationDocuments.push(request.url);
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end('<!doctype html><title>Application handoff</title><main data-application-handoff>Application handoff</main>');
      return;
    }
    const upstream = http.request(`${websiteOrigin}${request.url}`, { method: request.method }, (incoming) => {
      response.writeHead(incoming.statusCode, incoming.headers); incoming.pipe(response);
    });
    upstream.on('error', (error) => { response.writeHead(502); response.end(error.message); });
    request.pipe(upstream);
  });
  await new Promise((resolve) => edge.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${edge.address().port}`;
  browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.setRequestInterception(true);
  page.on('request', (request) => {
    if (request.url().startsWith(origin) || request.url().startsWith('data:')) void request.continue();
    else void request.abort();
  });
  const visit = async (route) => {
    await page.goto(`${origin}${route}`, { waitUntil: 'networkidle0' });
    await page.waitForSelector('html.app-ready h1');
    assert.ok(!(await page.$eval('h1', (element) => element.textContent)).includes('could not be loaded'), route);
  };
  const clickButton = async (text) => {
    const found = await page.evaluate((label) => {
      const button = [...document.querySelectorAll('button')].find((element) => element.textContent.trim() === label);
      if (!button || button.disabled) return false;
      button.click(); return true;
    }, text);
    assert.ok(found, `Enabled button not found: ${text}`);
  };
  await visit('/');
  await page.click('[data-testid="proof-lab-run-button"]');
  await page.waitForSelector('[data-testid="proof-lab-result-chip"]');
  assert.equal(await page.$eval('[data-testid="proof-lab-result-chip"]', (element) => element.textContent), 'VERIFIED');
  await Promise.all([page.waitForNavigation(), page.click('a[href="/docs"]')]);
  await page.waitForSelector('[data-application-handoff]');
  assert.equal(new URL(page.url()).pathname, '/docs');
  await visit('/ai');
  assert.ok((await page.$eval('body', (element) => element.textContent)).includes('product support snapshot included with this website'));
  await visit('/demos/2026.07.0');
  await page.waitForSelector('[data-demo-render-state="settled"]');
  await visit('/product/');
  await Promise.all([page.waitForNavigation(), clickButton('Read Docs')]);
  await page.waitForSelector('[data-application-handoff]');
  assert.equal(new URL(page.url()).pathname, '/docs');
  await visit('/product/');
  await Promise.all([page.waitForNavigation(), page.click('a[href^="/login?"]')]);
  await page.waitForSelector('[data-application-handoff]');
  assert.equal(new URL(page.url()).searchParams.get('next'), '/console');
  for (const route of ['/', '/product', '/eudi-wallet-verification', '/iso-18013-5-mdoc-verification', '/verifiable-credential-api']) {
    await visit(route);
    const exposed = await page.evaluate(() => ({
      links: [...document.querySelectorAll('a[href]')].filter((element) => {
        const url = new URL(element.href, location.href);
        return url.origin === location.origin && /^\/pricing(?:\/|$)/.test(url.pathname);
      }).length,
      actions: [...document.querySelectorAll('button')].filter((element) => !element.disabled
        && /^(?:View Pricing|Review Commercial Scope|Start Hosted Pilot)$/.test(element.textContent.trim())).length,
    }));
    assert.deepEqual(exposed, { links: 0, actions: 0 }, `Pricing must remain withheld on ${route}`);
  }
  assert.deepEqual(backendRequests, [], 'website must not initialize backend requests');
  assert.deepEqual(errors, [], 'website must not produce uncaught browser errors');
  console.log(`Website browser and Nginx smoke passed (${metadata.production_pages} pages): public routes, static catalog, proof lab, ${applicationDocuments.length} document handoffs, zero backend requests.`);
} finally {
  if (browser) await browser.close();
  if (edge) await new Promise((resolve) => edge.close(resolve));
  nginx.kill('SIGTERM');
  if (nginx.exitCode === null) await new Promise((resolve) => nginx.once('exit', resolve));
  rmSync(temporary, { recursive: true, force: true });
}

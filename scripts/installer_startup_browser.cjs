#!/usr/bin/env node
'use strict';

// Fixed installed-browser owner. No web server, fixtures, response routing,
// saved authentication, registration, arbitrary URLs, or launch overrides.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const INPUT_SCHEMA = 'elevenid.installer-startup-browser-input/v1';
const SCHEMA = 'elevenid.installer-startup-browser/v1';
const LIMIT = 65536;
const BODY_LIMIT = 4 * 1024 * 1024;
const TOTAL_LIMIT = 16 * 1024 * 1024;
const RUN_LIMIT_MS = 150000;
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
function requireCondition(value) { if (!value) throw new Error('installed browser observation refused'); }
function exact(value, keys) {
  requireCondition(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'));
}
function canonical(value) {
  const sorted = v => Array.isArray(v) ? v.map(sorted) : v && typeof v === 'object'
    ? Object.fromEntries(Object.keys(v).sort().map(key => [key, sorted(v[key])])) : v;
  return JSON.stringify(sorted(value)).replace(/[\u007f-\uffff]/g,
    char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`) + '\n';
}
function origin(value, ip) {
  requireCondition(typeof value === 'string');
  const url = new URL(value);
  requireCondition(url.origin === value && url.protocol === 'https:' && !url.username && !url.password
    && !url.search && !url.hash && url.pathname === '/');
  const address = url.hostname.replace(/^\[|\]$/g, '');
  requireCondition(Boolean(net.isIP(address)) === ip);
  return value;
}
function input(value) {
  exact(value, ['schema','request','native_sha256','installation_id','engine_id','operator_sha256',
    'context_sha256','selection_sha256','canonical_origin','public_entry_origin','certificate_der_sha256',
    'app_name','assets','runtime']);
  requireCondition(value.schema === INPUT_SCHEMA);
  exact(value.request, ['observation_id','challenge']);
  requireCondition(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.request.observation_id));
  for (const key of ['native_sha256','operator_sha256','context_sha256','selection_sha256','certificate_der_sha256'])
    requireCondition(hex(value[key]));
  requireCondition(hex(value.request.challenge));
  origin(value.canonical_origin, false); origin(value.public_entry_origin, true);
  requireCondition(typeof value.app_name === 'string' && value.app_name.length > 0 && value.app_name.length <= 256);
  requireCondition(Array.isArray(value.assets) && value.assets.length >= 5 && value.assets.length <= 52);
  const paths = new Set();
  for (const item of value.assets) {
    exact(item, ['path','media_type','size_bytes','sha256']);
    requireCondition(typeof item.path === 'string' && (['/','/runtime-config.js','/startup.js','/config.json'].includes(item.path)
      || /^\/assets\/[A-Za-z0-9_-]+\.(?:js|css)$/.test(item.path)) && !paths.has(item.path));
    requireCondition(hex(item.sha256) && Number.isSafeInteger(item.size_bytes) && item.size_bytes > 0 && item.size_bytes <= BODY_LIMIT);
    const mediaType = item.path === '/' ? 'text/html' : item.path === '/config.json' ? 'application/json'
      : item.path.endsWith('.css') ? 'text/css' : 'application/javascript';
    requireCondition(item.media_type === mediaType);
    paths.add(item.path);
  }
  requireCondition(['/','/runtime-config.js','/startup.js','/config.json'].every(item => paths.has(item))
    && [...paths].some(item => item.startsWith('/assets/') && item.endsWith('.js'))
    && value.assets.reduce((total,item) => total + item.size_bytes,0) <= TOTAL_LIMIT);
  exact(value.runtime, ['schema','platform','node_version','playwright_version','chromium_version',
    'chromium_revision','manifest_sha256','node_sha256','chromium_sha256']);
  requireCondition(value.runtime.schema === 'elevenid.installer-browser-runtime/v1'
    && value.runtime.platform === 'linux/amd64' && value.runtime.node_version === '24.22.1'
    && value.runtime.playwright_version === '1.62.1'
    && value.runtime.chromium_revision === '1234' && value.runtime.chromium_version === '151.0.7922.34');
  for (const key of ['manifest_sha256','node_sha256','chromium_sha256']) requireCondition(hex(value.runtime[key]));
  return value;
}
function normalizedType(value) {
  const type = String(value || '').split(';')[0].trim().toLowerCase();
  return type === 'text/javascript' ? 'application/javascript' : type;
}
function safePath(url) {
  const value = new URL(url);
  requireCondition(value.username === '' && value.password === '' && value.protocol === 'https:');
  return { origin: value.origin, path: value.pathname };
}
function staticPath(value) {
  return ['/', '/index.html', '/runtime-config.js', '/startup.js', '/config.json', '/manifest.json',
    '/site.webmanifest', '/favicon.ico', '/favicon.svg', '/favicon-96x96.png', '/apple-touch-icon.png',
    '/logo192.png', '/logo512.png'].includes(value)
    || /^\/(?:assets|locales|images)\/[A-Za-z0-9_./-]+$/.test(value)
      && !value.split('/').some(part => part === '.' || part === '..');
}
function checkLanding(value, expected) {
  exact(value, ['url','heading_count','branding_visible','image_count','images_loaded','screenshot_sha256','assets','certificate_der_sha256']);
  requireCondition(value.url === `${expected.public_entry_origin}/` && value.heading_count > 0
    && value.branding_visible === true && value.images_loaded === true && hex(value.screenshot_sha256)
    && value.certificate_der_sha256 === expected.certificate_der_sha256);
  const observed = new Map(value.assets.map(item => [item.path, item]));
  requireCondition(observed.size === expected.assets.length && value.assets.length === expected.assets.length);
  for (const item of expected.assets) {
    const actual = observed.get(item.path);
    requireCondition(actual && actual.status === 200 && actual.media_type === item.media_type
      && actual.size_bytes === item.size_bytes && actual.sha256 === item.sha256);
  }
}

async function observe(browser, expected) {
  const start = Date.now();
  const now = () => Math.floor(Date.now() / 1000);
  const startedAt = now();
  const evidence = { ip_requests: 0, ip_session_requests: 0, ip_credential_headers: 0,
    ip_response_cookies: 0, ip_stored_cookies: 0, page_errors: 0, failed_asset_requests: 0 };
  let failure = null;
  let totalReceived = 0;
  const pending = new Set();
  const tasks = operation => {
    const promise = operation().catch(() => { failure = true; }).finally(() => pending.delete(promise));
    pending.add(promise);
  };
  const clean = async () => {
    await Promise.all([...pending]);
    requireCondition(!failure && Date.now() - start < RUN_LIMIT_MS
      && Object.entries(evidence).every(([key, value]) => key === 'ip_requests' || value === 0));
  };
  async function context() {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: false, serviceWorkers: 'block',
      viewport: { width: 1280, height: 800 }, locale: 'en-US', reducedMotion: 'reduce' });
    ctx.setDefaultTimeout(20000);
    ctx.setDefaultNavigationTimeout(30000);
    const pages = new Set();
    ctx.on('page', page => { pages.add(page); page.on('pageerror', () => { evidence.page_errors++; }); });
    ctx.on('request', request => tasks(async () => {
      const target = safePath(request.url());
      if (target.origin !== expected.public_entry_origin) return;
      evidence.ip_requests++;
      requireCondition(evidence.ip_requests <= 512);
      const headers = await request.allHeaders();
      if (headers.cookie || headers.authorization || headers['proxy-authorization']) evidence.ip_credential_headers++;
      if (!['GET','HEAD'].includes(request.method()) || !staticPath(target.path)) evidence.ip_session_requests++;
    }));
    ctx.on('response', response => tasks(async () => {
      if (safePath(response.url()).origin !== expected.public_entry_origin) return;
      const headers = await response.headersArray();
      if (headers.some(item => item.name.toLowerCase() === 'set-cookie')) evidence.ip_response_cookies++;
      if (response.status() !== 200 && response.status() !== 304) evidence.failed_asset_requests++;
      requireCondition(response.fromServiceWorker() === false);
    }));
    ctx.on('requestfailed', request => {
      try { if (safePath(request.url()).origin === expected.public_entry_origin) evidence.failed_asset_requests++; }
      catch { failure = true; }
    });
    const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('Network.enable');
    cdp.on('Network.dataReceived', event => {
      totalReceived += event.dataLength;
      if (totalReceived > 3 * TOTAL_LIMIT) { failure = true; void ctx.close(); }
    });
    const certificate = async authority => {
      const result = await cdp.send('Network.getCertificate', { origin: authority });
      requireCondition(Array.isArray(result.tableNames) && result.tableNames.length >= 1 && result.tableNames.length <= 8);
      const der = Buffer.from(result.tableNames[0], 'base64');
      requireCondition(der.length > 0 && der.length <= 65536 && sha(der) === expected.certificate_der_sha256);
      return sha(der);
    };
    const finish = async () => {
      evidence.ip_stored_cookies += (await ctx.cookies(expected.public_entry_origin)).length;
      await clean();
      requireCondition(pages.size === 1);
      await ctx.close();
    };
    return { ctx, page, certificate, finish };
  }

  const landing = await context();
  let landingEvidence;
  try {
    const expectedAssets = new Map(expected.assets.map(item => [item.path, item]));
    const assets = new Map();
    landing.page.on('response', response => tasks(async () => {
      const target = safePath(response.url());
      if (target.origin !== expected.public_entry_origin || !expectedAssets.has(target.path)) return;
      requireCondition(response.status() === 200 && !(await response.finished()));
      const headers = await response.allHeaders();
      const length = headers['content-length'];
      requireCondition(length === undefined || /^\d+$/.test(length) && Number(length) <= BODY_LIMIT);
      const bytes = await response.body();
      requireCondition(bytes.length > 0 && bytes.length <= BODY_LIMIT);
      const record = { path: target.path, status: response.status(), media_type: normalizedType(headers['content-type']),
        size_bytes: bytes.length, sha256: sha(bytes) };
      requireCondition(!assets.has(target.path) || canonical(assets.get(target.path)) === canonical(record));
      assets.set(target.path, record);
    }));
    const response = await landing.page.goto(`${expected.public_entry_origin}/`, { waitUntil: 'domcontentloaded' });
    requireCondition(response && response.status() === 200 && (await response.securityDetails()) !== null);
    await landing.page.getByRole('heading', { level: 1 }).first().waitFor({ state: 'visible' });
    await landing.page.getByTestId('login-button').waitFor({ state: 'visible' });
    await landing.page.getByTestId('public-entry-console').waitFor({ state: 'visible' });
    await landing.page.getByText(expected.app_name, { exact: true }).first().waitFor({ state: 'visible' });
    await landing.page.evaluate(async () => { await document.fonts.ready; });
    // Exercise lazy landing content without following any link or synthesizing
    // application state. Every image present after this scroll must load.
    await landing.page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await landing.page.waitForFunction(() => Array.from(document.images).every(image => image.complete && image.naturalWidth > 0));
    await landing.page.evaluate(() => window.scrollTo(0, 0));
    const until = Date.now() + 15000;
    while (assets.size !== expectedAssets.size && Date.now() < until) {
      await clean(); await new Promise(resolve => setTimeout(resolve, 50));
    }
    await clean();
    requireCondition(landing.page.url() === `${expected.public_entry_origin}/`);
    const rendered = await landing.page.evaluate(() => ({
      heading_count: [...document.querySelectorAll('h1')].filter(node => node.getBoundingClientRect().width > 0 && node.textContent.trim()).length,
      image_count: document.images.length, images_loaded: [...document.images].every(image => image.complete && image.naturalWidth > 0),
    }));
    const screenshot = await landing.page.screenshot({ type: 'png', fullPage: false, animations: 'disabled' });
    requireCondition(screenshot.length > 0 && screenshot.length <= 4*1024*1024);
    landingEvidence = { url: landing.page.url(), ...rendered, branding_visible: true,
      screenshot_sha256: sha(screenshot), assets: [...assets.values()].sort((a,b) => a.path.localeCompare(b.path)),
      certificate_der_sha256: await landing.certificate(expected.public_entry_origin) };
    checkLanding(landingEvidence, expected);
    await landing.finish();
  } finally { await landing.ctx.close(); }

  const actions = {};
  for (const [action, selector, expectedPath] of [
    ['sign_in','login-button','/v1/auth/login'], ['console','public-entry-console','/console'],
  ]) {
    const current = await context();
    try {
      await current.page.goto(`${expected.public_entry_origin}/`, { waitUntil: 'domcontentloaded' });
      await current.page.getByTestId(selector).waitFor({ state: 'visible' });
      requireCondition(current.page.url() === `${expected.public_entry_origin}/`);
      const navigations = [];
      const listener = req => {
        if (req.isNavigationRequest() && req.frame() === current.page.mainFrame()) {
          const target = safePath(req.url());
          navigations.push({ ...target, method: req.method() });
          if (navigations.length > 16 || target.origin !== expected.canonical_origin) failure = true;
        }
      };
      current.page.on('request', listener);
      const navigation = current.page.waitForURL(url => url.origin === expected.canonical_origin,
        { waitUntil: 'domcontentloaded', timeout: 30000 });
      await current.page.getByTestId(selector).click();
      await navigation;
      await clean();
      requireCondition(navigations.length > 0 && navigations[0].origin === expected.canonical_origin
        && navigations[0].path === expectedPath && navigations.every(item => item.method === 'GET'));
      const final = safePath(current.page.url());
      requireCondition(final.origin === expected.canonical_origin);
      actions[action] = { selector, source_url: `${expected.public_entry_origin}/`, document_requests: navigations,
        final_origin: final.origin, final_path: final.path,
        certificate_der_sha256: await current.certificate(expected.canonical_origin) };
      await current.finish();
    } finally { await current.ctx.close(); }
  }
  await clean();
  return { schema: SCHEMA, request: expected.request, native_sha256: expected.native_sha256,
    installation_id: expected.installation_id, engine_id: expected.engine_id,
    operator_sha256: expected.operator_sha256, context_sha256: expected.context_sha256,
    selection_sha256: expected.selection_sha256, runtime: expected.runtime,
    canonical_origin: expected.canonical_origin, public_entry_origin: expected.public_entry_origin,
    landing: landingEvidence, actions, observations: evidence, started_at: startedAt, completed_at: now(),
    https_errors_ignored: false, installation_ready: false, functional_recovery_qualified: false, load_characterized: false };
}

function privateFile(filename) {
  requireCondition(path.isAbsolute(filename) && path.resolve(filename) === filename);
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  const before = fs.fstatSync(fd);
  const parent = fs.lstatSync(path.dirname(filename));
  requireCondition(before.isFile() && before.nlink === 1 && before.uid === process.getuid()
    && (before.mode & 0o777) === 0o600 && before.size > 0 && before.size <= LIMIT
    && parent.isDirectory() && !parent.isSymbolicLink() && parent.uid === process.getuid() && (parent.mode & 0o777) === 0o700);
  const bytes = fs.readFileSync(fd);
  const check = () => {
    const current = fs.lstatSync(filename);
    requireCondition(current.dev === before.dev && current.ino === before.ino && current.size === before.size
      && current.ctimeMs === before.ctimeMs && current.mtimeMs === before.mtimeMs
      && fs.readFileSync(filename).equals(bytes));
  };
  check();
  const value = JSON.parse(bytes.toString('utf8'));
  requireCondition(Buffer.from(canonical(value)).equals(bytes));
  return { value, check, close: () => fs.closeSync(fd) };
}

async function main() {
  requireCondition(process.platform === 'linux' && process.arch === 'x64' && process.getuid() > 0);
  requireCondition(process.argv.length === 8 && process.argv[2] === '--input'
    && process.argv[4] === '--runtime-root' && process.argv[6] === '--output');
  const [inputFile, runtimeRoot, outputFile] = [process.argv[3], process.argv[5], process.argv[7]];
  requireCondition(path.isAbsolute(runtimeRoot) && path.resolve(runtimeRoot) === runtimeRoot
    && process.execPath === path.join(runtimeRoot, 'node/bin/node'));
  const held = privateFile(inputFile);
  let browser;
  try {
    const expected = input(held.value);
    requireCondition(process.versions.node === expected.runtime.node_version);
    const packageRoot = path.join(runtimeRoot, 'playwright-core');
    requireCondition(require(path.join(packageRoot, 'package.json')).version === expected.runtime.playwright_version);
    const { chromium } = require(packageRoot);
    browser = await chromium.launch({ executablePath: path.join(runtimeRoot, 'chrome-linux64/chrome'),
      headless: true, chromiumSandbox: true, timeout: 30000 });
    requireCondition(browser.version() === expected.runtime.chromium_version);
    const result = await Promise.race([observe(browser, expected), new Promise((_, reject) => {
      const timeout = setTimeout(() => reject(new Error('bounded browser deadline')), RUN_LIMIT_MS);
      timeout.unref();
    })]);
    await browser.close(); browser = null;
    held.check();
    const raw = Buffer.from(canonical(result));
    requireCondition(raw.length <= LIMIT && path.isAbsolute(outputFile) && path.resolve(outputFile) === outputFile
      && path.dirname(outputFile) === path.dirname(inputFile));
    const descriptor = fs.openSync(outputFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(descriptor, raw); fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
    const parent = fs.openSync(path.dirname(outputFile), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
    held.check();
  } finally {
    if (browser) await browser.close();
    held.close();
  }
}

module.exports = { input, canonical, checkLanding, staticPath, normalizedType, observe };
if (require.main === module) main().catch(() => { process.stderr.write('Installed browser observation failed; no startup result emitted.\n'); process.exitCode = 1; });

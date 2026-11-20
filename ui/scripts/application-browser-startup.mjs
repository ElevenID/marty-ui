import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { APPLICATION_RESOURCE_MIME_TYPES } from './application-public-assets.mjs';
import { expectedDefaultRuntimeBytes, validateApplicationRuntimeContext } from './application-runtime-context.mjs';

const SELF = fileURLToPath(import.meta.url);
const MAX_REQUESTS = 512;
const MAX_ERRORS = 64;
const AUTH_HEADING = 'Sign-in is temporarily unavailable';
const AUTH_RETRY = 'Retry sign-in check';
const RECOVERY_HEADING = 'ElevenID could not start';
const FONT_STYLESHEETS = new Set([
  'https://fonts.googleapis.com/css?family=Roboto:300,400,500,700&display=swap',
  'https://fonts.googleapis.com/icon?family=Material+Icons',
]);
export const APPLICATION_BROWSER_ROUTES = Object.freeze([
  '/login?next=%2Fconsole&lng=en', '/console?lng=en',
]);

function require(condition, message) { if (!condition) throw new Error(message); }
function digest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function boundedText(value) { return String(value ?? '').slice(0, 1000); }
function ordinaryDirectory(value) {
  require(typeof value === 'string' && path.isAbsolute(value), 'Browser paths must be absolute');
  const root = path.resolve(value);
  const metadata = lstatSync(root);
  require(metadata.isDirectory() && !metadata.isSymbolicLink() && realpathSync(root) === root,
    'Browser paths must use ordinary directories');
  return root;
}

export function validateApplicationBrowserOrigin(origin) {
  const url = new URL(origin);
  require(url.protocol === 'http:' && url.hostname === '127.0.0.1'
    && /^[1-9][0-9]{0,4}$/.test(url.port) && Number(url.port) <= 65535
    && !url.username && !url.password && !url.search && !url.hash && url.pathname === '/'
    && url.origin === origin, 'Browser origin must be the exact owned loopback origin');
  return url.origin;
}

function googleFont(url, type) {
  return (type === 'stylesheet' && FONT_STYLESHEETS.has(url.href))
    || (type === 'font' && url.protocol === 'https:' && url.hostname === 'fonts.gstatic.com'
      && !url.port && !url.username && !url.password && !url.search && !url.hash
      && /^\/s\/[A-Za-z0-9/_-]+\.(?:woff2?|ttf)$/.test(url.pathname));
}

// This is a request allowlist, not a replacement response. Every allowed asset
// and session request reaches the owned nginx container unchanged.
export function classifyApplicationBrowserRequest({ origin, route, resourcePaths, wasmPath, abortWasm = false }, request) {
  validateApplicationBrowserOrigin(origin);
  require(APPLICATION_BROWSER_ROUTES.includes(route), 'Unknown browser qualification route');
  const url = new URL(request.url);
  if (request.method !== 'GET') return { action: 'abort', disposition: 'forbidden-method' };
  if (request.navigation) {
    return request.mainFrame && url.href === `${origin}${route}`
      ? { action: 'continue', disposition: 'navigation', path: route.startsWith('/console') ? 'console/index.html' : 'index.html' }
      : { action: 'abort', disposition: 'forbidden-navigation' };
  }
  if (url.origin !== origin) {
    if (googleFont(url, request.resourceType)) return { action: 'abort', disposition: 'blocked-google-font' };
    if (request.resourceType === 'image' && /^data:image\/(?:png|jpeg|gif|webp|svg\+xml);/i.test(request.url)) {
      return { action: 'continue', disposition: 'embedded-image' };
    }
    return { action: 'abort', disposition: 'forbidden-external-request' };
  }
  if (url.username || url.password || url.hash) return { action: 'abort', disposition: 'forbidden-url' };
  if (url.pathname === '/v1/auth/me' && !url.search) return { action: 'continue', disposition: 'session-check' };
  const relative = url.pathname.slice(1);
  if (!resourcePaths.includes(relative) || (url.search && !(relative === 'favicon.ico' && url.search === '?v=2'))) {
    return { action: 'abort', disposition: 'forbidden-resource' };
  }
  return { action: abortWasm && relative === wasmPath ? 'abort' : 'continue',
    disposition: abortWasm && relative === wasmPath ? 'aborted-sdk-wasm' : 'asset', path: relative };
}

export function applicationBrowserLaunchOptions({ profileDirectory, logger, channel = 'chrome' }) {
  require(channel === 'chrome', 'Only the reviewed sandboxed Chrome channel is supported');
  ordinaryDirectory(profileDirectory);
  return { headless: true, channel, userDataDir: profileDirectory, timeout: 20_000,
    protocolTimeout: 20_000, acceptInsecureCerts: false, logger };
}

export function validateApplicationBrowserRouteEvidence(evidence, { origin, route, wasm, negative = false }) {
  validateApplicationBrowserOrigin(origin);
  require(evidence.route === route && evidence.final_url === `${origin}${route}`, 'Browser route or destination changed');
  require(evidence.context_isolated === true && evidence.cookies_initially_empty === true
    && evidence.cache_disabled === true && evidence.context_closed === true, 'Browser context isolation or cleanup is incomplete');
  require(evidence.navigation?.status === 200 && evidence.navigation.url === `${origin}${route}`
    && evidence.navigation.content_type === 'text/html' && evidence.navigation.bytes > 0,
  'Browser did not load the selected application document');
  const csp = evidence.navigation.content_security_policy;
  require(typeof csp === 'string' && csp.includes("script-src 'self' 'wasm-unsafe-eval'") && !csp.includes("'unsafe-eval'"),
    'Browser navigation did not retain the production WASM CSP');
  require(Array.isArray(evidence.violations) && evidence.violations.length === 0, 'Browser observed an unexpected request or execution error');
  require(Array.isArray(evidence.assets) && evidence.assets.length > 0
    && evidence.assets.every((item) => item.status === 200 && item.from_cache === false && item.from_service_worker === false
      && item.bytes > 0 && /^sha256:[0-9a-f]{64}$/.test(item.sha256)), 'Browser asset evidence is incomplete');
  require(Array.isArray(evidence.external_requests) && evidence.external_requests.every((item) => {
    return item.disposition === 'blocked-google-font' && googleFont(new URL(item.url), item.resource_type);
  }), 'Browser allowed an unreviewed external request');
  require(Array.isArray(evidence.session_checks), 'Browser session evidence is missing');
  for (const item of evidence.session_checks) {
    require(item.method === 'GET' && item.path === '/v1/auth/me'
      && ((item.outcome === 'http-502' && item.status === 502)
        || (item.outcome === 'application-timeout' && item.error === 'net::ERR_ABORTED'
          && item.duration_ms >= 14_000 && item.duration_ms <= 20_000)), 'Unexpected browser session outcome');
  }
  if (negative) {
    require(evidence.ready === false && evidence.root_populated === false && evidence.wasm === null,
      'Aborted SDK WASM unexpectedly reached application readiness');
    require(evidence.aborted_wasm_requests === 1 && evidence.session_checks.length === 0,
      'Negative control did not isolate the initial SDK WASM request');
    require(evidence.recovery?.visible === true && evidence.recovery.title === RECOVERY_HEADING
      && evidence.recovery.message === 'Part of the application could not be loaded. Reload this page to try again.'
      && evidence.recovery.retry_label === 'Reload page' && evidence.recovery.retry_enabled === true,
    'The actual startup failure recovery UI was not observed');
    require(evidence.page_errors.length > 0 && evidence.page_errors.every((message) => /fetch|WebAssembly|wasm/i.test(message)),
      'Negative control did not observe the SDK load failure');
  } else {
    require(evidence.ready === true && evidence.root_populated === true && evidence.heading === AUTH_HEADING,
      'Application readiness and mounted authentication-unavailable UI were not observed');
    require(evidence.page_errors.length === 0 && evidence.aborted_wasm_requests === 0,
      'Positive startup observed a script or SDK failure');
    require(evidence.retry?.label === AUTH_RETRY && evidence.retry.enabled === true
      && evidence.retry.clicked === true && evidence.retry.session_rechecked === true
      && evidence.session_checks.length >= 2, 'Authentication retry did not perform a real session recheck');
    require(evidence.wasm?.path === wasm.path && evidence.wasm.status === 200 && evidence.wasm.content_type === 'application/wasm'
      && evidence.wasm.bytes === wasm.bytes && evidence.wasm.sha256 === wasm.sha256
      && evidence.wasm.from_cache === false && evidence.wasm.from_service_worker === false,
    'Browser SDK WASM bytes or MIME differ from the bound runtime context');
    const observedWasm = evidence.assets.filter((item) => item.path === wasm.path);
    require(observedWasm.length === 1, 'Browser SDK WASM response evidence is ambiguous');
    assert.deepEqual(evidence.wasm, observedWasm[0], 'SDK WASM evidence differs from the observed response');
  }
  return evidence;
}

async function deadline(promise, milliseconds, label) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} exceeded its deadline`)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

async function until(predicate, milliseconds, label) {
  const end = Date.now() + milliseconds;
  while (!predicate()) {
    require(Date.now() < end, `${label} exceeded its deadline`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

function linuxProcess(pid) {
  require(process.platform === 'linux' && Number.isSafeInteger(pid) && pid > 1, 'Expected an owned Linux Chromium process');
  const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
  const fields = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/);
  return { pid, process_group: Number(fields[2]), start_time: fields[19], parent_pid: Number(fields[1]) };
}

async function loadBrowserDriver() {
  // Fresh-install and container-only gates import this module before the source
  // checkout has dependencies. Only the explicit worker resolves Puppeteer.
  const { default: puppeteer } = await import('puppeteer');
  const requirePackage = createRequire(import.meta.url);
  const metadata = JSON.parse(readFileSync(requirePackage.resolve('puppeteer/package.json'), 'utf8'));
  return { launch: (options) => puppeteer.launch(options), executable: await puppeteer.executablePath('chrome'),
    puppeteer_version: metadata.version };
}

async function observeRoute(browser, specification, remaining) {
  const { origin, route, expected, wasm, negative } = specification;
  const context = await browser.createBrowserContext();
  const evidence = { route, context_isolated: true, cookies_initially_empty: false, cache_disabled: false,
    navigation: null, assets: [], wasm: null, session_checks: [], external_requests: [], failed_requests: [],
    page_errors: [], console_errors: [], violations: [], aborted_wasm_requests: 0, context_closed: false };
  const pending = new Set();
  const decisions = new WeakMap();
  const sessions = new WeakMap();
  let page;
  let closing = false;
  let count = 0;
  function violation(message) { if (evidence.violations.length < MAX_ERRORS) evidence.violations.push(boundedText(message)); }
  function observe(promise) {
    pending.add(promise);
    promise.catch((error) => { if (!closing) violation(error.message); }).finally(() => pending.delete(promise));
  }
  try {
    evidence.cookies_initially_empty = (await context.cookies()).length === 0;
    require(evidence.cookies_initially_empty, 'Fresh browser context already has cookies');
    page = await context.newPage();
    await page.setViewport({ width: 1365, height: 1000 });
    await page.setCacheEnabled(false);
    await page.setBypassServiceWorker(true);
    evidence.cache_disabled = true;
    page.setDefaultTimeout(remaining(25_000));
    page.on('pageerror', (error) => {
      if (evidence.page_errors.length < MAX_ERRORS) evidence.page_errors.push(boundedText(error.message));
      else violation('Too many browser script errors');
    });
    page.on('console', (message) => {
      if (message.type() !== 'error') return;
      if (evidence.console_errors.length >= MAX_ERRORS) { violation('Too many browser console errors'); return; }
      evidence.console_errors.push({ text: boundedText(message.text()), url: boundedText(message.location()?.url) });
    });
    page.on('popup', (popup) => { violation('Application opened an unexpected browser window'); observe(popup.close()); });
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame() && frame.url() !== `${origin}${route}`) violation('Application changed the selected browser route');
    });
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      try {
        require(++count <= MAX_REQUESTS, 'Browser request count exceeded its bound');
        const decision = classifyApplicationBrowserRequest({ origin, route, resourcePaths: [...expected.keys()],
          wasmPath: wasm.path, abortWasm: negative }, { url: request.url(), method: request.method(),
          resourceType: request.resourceType(), navigation: request.isNavigationRequest(), mainFrame: request.frame() === page.mainFrame() });
        decisions.set(request, decision);
        if (decision.disposition.startsWith('forbidden-')) violation(`${decision.disposition}: ${request.url()}`);
        if (decision.disposition === 'blocked-google-font') evidence.external_requests.push({ url: request.url(),
          resource_type: request.resourceType(), disposition: decision.disposition });
        if (decision.disposition === 'aborted-sdk-wasm') evidence.aborted_wasm_requests += 1;
        if (decision.disposition === 'session-check') {
          const session = { method: request.method(), path: '/v1/auth/me', outcome: 'pending', started_at_ms: Date.now() };
          evidence.session_checks.push(session); sessions.set(request, session);
        }
        observe(decision.action === 'continue' ? request.continue() : request.abort('failed'));
      } catch (error) { violation(error.message); observe(request.abort('failed')); }
    });
    page.on('requestfailed', (request) => {
      const decision = decisions.get(request);
      const error = request.failure()?.errorText || 'unknown';
      const session = sessions.get(request);
      if (session && session.outcome === 'pending') {
        session.duration_ms = Date.now() - session.started_at_ms;
        session.error = error;
        session.outcome = error === 'net::ERR_ABORTED' && session.duration_ms >= 14_000 && session.duration_ms <= 20_000
          ? 'application-timeout' : 'unexpected-failure';
      }
      evidence.failed_requests.push({ url: request.url(), error, disposition: decision?.disposition || 'unknown' });
      if (!['blocked-google-font', 'aborted-sdk-wasm', 'session-check'].includes(decision?.disposition)
        && !decision?.disposition?.startsWith('forbidden-') && !closing) violation(`Unexpected failed browser request: ${request.url()}`);
    });
    page.on('response', (response) => {
      const request = response.request();
      const decision = decisions.get(request);
      if (decision?.disposition === 'session-check') {
        const session = sessions.get(request);
        session.status = response.status(); session.duration_ms = Date.now() - session.started_at_ms;
        session.outcome = response.status() === 502 ? 'http-502' : 'unexpected-http-status';
        return;
      }
      if (!['navigation', 'asset'].includes(decision?.disposition)) {
        if (decision?.disposition !== 'embedded-image') violation('Browser received an unreviewed response');
        return;
      }
      observe((async () => {
        const bytes = Buffer.from(await response.buffer());
        const wanted = expected.get(decision.path);
        require(wanted && bytes.equals(wanted), `Browser response differs from the bound runtime context: ${decision.path}`);
        const type = (response.headers()['content-type'] || '').split(';')[0].trim().toLowerCase();
        require(APPLICATION_RESOURCE_MIME_TYPES[path.extname(decision.path)]?.includes(type), `Browser resource has an unexpected MIME type: ${decision.path}`);
        const item = { path: decision.path, url: response.url(), status: response.status(), content_type: type,
          bytes: bytes.length, sha256: digest(bytes), from_cache: response.fromCache(), from_service_worker: response.fromServiceWorker() };
        require(item.status === 200 && !item.from_cache && !item.from_service_worker, 'Browser response did not come freshly from nginx');
        if (decision.disposition === 'navigation') evidence.navigation = { ...item,
          content_security_policy: response.headers()['content-security-policy'] || '' };
        else {
          evidence.assets.push(item);
          if (decision.path === wasm.path) { require(!evidence.wasm, 'SDK WASM was fetched more than once in a fresh context'); evidence.wasm = item; }
        }
      })());
    });
    const navigation = await page.goto(`${origin}${route}`, { waitUntil: 'domcontentloaded', timeout: remaining(25_000) });
    require(navigation?.status() === 200, 'Browser navigation did not return the application document');
    if (negative) {
      await page.waitForFunction(() => document.querySelector('[data-app-startup-recovery]')?.hidden === false
        && document.getElementById('app-startup-title')?.textContent === 'ElevenID could not start', { timeout: remaining(20_000) });
    } else {
      const ready = () => document.documentElement.classList.contains('app-ready')
        && [...document.querySelectorAll('h1')].some((node) => node.textContent.trim() === 'Sign-in is temporarily unavailable')
        && [...document.querySelectorAll('button')].some((node) => node.textContent.trim() === 'Retry sign-in check' && !node.disabled);
      await page.waitForFunction(ready, { timeout: remaining(25_000) });
      await until(() => evidence.session_checks.some((item) => item.outcome !== 'pending'), remaining(20_000), 'Initial session check');
      const initialCount = evidence.session_checks.length;
      await page.evaluate(() => [...document.querySelectorAll('button')].find((node) => node.textContent.trim() === 'Retry sign-in check' && !node.disabled).click());
      await until(() => evidence.session_checks.length > initialCount
        && evidence.session_checks.slice(initialCount).every((item) => item.outcome !== 'pending'), remaining(20_000), 'Retry session check');
      await page.waitForFunction(ready, { timeout: remaining(20_000) });
      evidence.retry = { label: AUTH_RETRY, enabled: true, clicked: true, session_rechecked: true };
    }
    const snapshot = await page.evaluate(() => {
      const visible = (element) => {
        if (!element) return false;
        const bounds = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return !element.hidden && bounds.width > 0 && bounds.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';
      };
      const recovery = document.querySelector('[data-app-startup-recovery]');
      const retry = document.querySelector('[data-app-startup-retry]');
      return { ready: document.documentElement.classList.contains('app-ready'),
        root_populated: Boolean(document.getElementById('root')?.childElementCount),
        heading: [...document.querySelectorAll('h1')].filter(visible).map((node) => node.textContent.trim()).find((label) => label === 'Sign-in is temporarily unavailable') || null,
        recovery: { visible: visible(recovery), title: document.getElementById('app-startup-title')?.textContent || '',
          message: document.getElementById('app-startup-message')?.textContent || '', retry_label: retry?.textContent.trim() || '',
          retry_enabled: visible(retry) && !retry.disabled } };
    });
    Object.assign(evidence, snapshot, { final_url: page.url() });
    await deadline((async () => { while (pending.size) await Promise.allSettled([...pending]); })(), remaining(20_000), 'Browser response verification');
    for (const item of evidence.session_checks) delete item.started_at_ms;
    for (const error of evidence.console_errors) {
      let expectedError = false;
      try {
        const url = new URL(error.url);
        expectedError = googleFont(url, 'stylesheet') || googleFont(url, 'font')
          || (url.origin === origin && url.pathname === '/v1/auth/me' && evidence.session_checks.some((item) => item.outcome === 'http-502'))
          || (negative && url.origin === origin && url.pathname === `/${wasm.path}`);
      } catch { /* An unlocated console error remains unexpected. */ }
      if (!expectedError) violation(`Unexpected browser console error: ${error.text}`);
    }
  } catch (error) {
    evidence.final_url = page?.url() || null;
    error.browserRoute = evidence;
    throw error;
  } finally {
    closing = true;
    await deadline(context.close(), 5_000, 'Browser context cleanup');
    evidence.context_closed = true;
  }
  evidence.assets.sort((a, b) => a.path.localeCompare(b.path));
  return validateApplicationBrowserRouteEvidence(evidence, { origin, route, wasm, negative });
}

export async function qualifyApplicationBrowserStartup({ origin, runtimeContext, contextManifestSha256, temporaryRoot, channel = 'chrome' },
  { driverLoader = loadBrowserDriver } = {}) {
  validateApplicationBrowserOrigin(origin);
  const temporary = ordinaryDirectory(temporaryRoot);
  const verified = validateApplicationRuntimeContext(runtimeContext);
  require(verified.manifest_sha256 === contextManifestSha256, 'Browser context differs from its owning runtime check');
  require(!temporary.startsWith(`${verified.root}${path.sep}`) && temporary !== verified.root, 'Browser state must be outside the closed runtime context');
  require(channel === 'chrome', 'Unsupported browser channel');
  const { manifest, root } = verified;
  const expected = new Map(manifest.output_inventory.files.map((item) => [item.path,
    expectedDefaultRuntimeBytes(item.path, readFileSync(path.join(root, 'html', item.path)))]));
  const wasm = manifest.output_inventory.files.find((item) => item.path === manifest.sdk_wasm);
  require(wasm && WebAssembly.validate(expected.get(wasm.path)), 'Browser requires the context-bound SDK WASM');
  const fixture = driverLoader !== loadBrowserDriver;
  const result = { schema: 'marty.application-browser-startup/v1', status: 'failed', fixture,
    context_sha256: contextManifestSha256, source_commit: manifest.source_commit, effective_source_sha: manifest.effective_source_sha,
    exact_committed_source: manifest.exact_committed_source, origin, browser: null, routes: [], negative_control: null,
    qualification: { browser_startup_observed: false, sdk_wasm_initialized_in_browser: false,
      host_deployment_tested: false, oidc_journey_tested: false, published: false, activated: false },
    cleanup: { browser_closed: false, chromium_exited: false, contexts_closed: false, profile_removed: false } };
  const profile = mkdtempSync(path.join(temporary, 'chrome-profile-'));
  const journalPath = path.join(temporary, 'browser-process.json');
  let browser;
  let chromium;
  let launchAttempted = false;
  let identity;
  let failure;
  let phase = 'launch';
  const end = Date.now() + 90_000;
  const remaining = (limit) => {
    require(Date.now() < end, 'Browser startup qualification exceeded its deadline');
    return Math.min(limit, end - Date.now());
  };
  function journal(pid) {
    if (fixture) return;
    const current = linuxProcess(pid);
    require(current.parent_pid === process.pid && current.process_group === pid, 'Chromium is not the expected owned process group');
    if (identity) { assert.deepEqual(current, identity, 'Chromium process identity changed'); return; }
    identity = current;
    writeFileSync(journalPath, `${JSON.stringify({ ...current, profile_directory: profile })}\n`, { flag: 'wx', mode: 0o600 });
  }
  try {
    await deadline((async () => {
      const driver = await driverLoader();
      require(typeof driver.puppeteer_version === 'string' && typeof driver.executable === 'string', 'Browser tooling identity is missing');
      const logger = (namespace) => (message) => {
        if (namespace !== 'puppeteer:browsers:launcher') return;
        const match = /^Launched ([1-9][0-9]*)$/.exec(message);
        if (match) journal(Number(match[1]));
      };
      launchAttempted = true;
      browser = await driver.launch(applicationBrowserLaunchOptions({ profileDirectory: profile, logger, channel }));
      chromium = browser.process();
      require(chromium && Number.isSafeInteger(chromium.pid), 'Browser launcher did not expose its owned process');
      journal(chromium.pid);
      require(!chromium.spawnargs?.some((argument) => /^(?:--no-sandbox|--disable-setuid-sandbox|--disable-web-security|--disable-features=.*(?:Sandbox|Isolate)|--single-process)(?:=|$)/.test(argument)),
        'Browser launch weakened sandbox or web security');
      result.browser = { channel, sandboxed: !fixture, version: await browser.version(),
        puppeteer_version: driver.puppeteer_version, node_version: process.version,
        executable: driver.executable, chromium_pid: chromium.pid, fresh_profile: true, csp_bypassed: false };
      for (const route of APPLICATION_BROWSER_ROUTES) {
        phase = `positive:${route}`;
        result.routes.push(await observeRoute(browser, { origin, route, expected, wasm, negative: false }, remaining));
      }
      phase = 'aborted-sdk-wasm-control';
      result.negative_control = await observeRoute(browser, { origin, route: APPLICATION_BROWSER_ROUTES[0], expected, wasm, negative: true }, remaining);
      result.cleanup.contexts_closed = true;
    })(), remaining(90_000), 'Browser startup qualification');
  } catch (error) {
    failure = error;
    if (error.browserRoute) result.failed_route = error.browserRoute;
  }
  finally {
    if (browser) {
      try {
        await deadline(browser.close(), 5_000, 'Chromium cleanup');
        result.cleanup.browser_closed = true;
      } catch (error) { failure ||= error; }
    }
    if (chromium) {
      try {
        await until(() => Number.isInteger(chromium.exitCode) || typeof chromium.signalCode === 'string', 3_000, 'Chromium exit');
        result.cleanup.chromium_exited = true;
      } catch (error) { failure ||= error; }
    }
    try {
      // A rejected launch may have spawned Chrome before returning its handle.
      // Leave uncertain process/profile ownership to the parent subreaper. It
      // removes the whole temporary directory only after ECHILD proves cleanup.
      if (!launchAttempted || result.cleanup.chromium_exited) {
        rmSync(profile, { recursive: true, force: true });
        result.cleanup.profile_removed = !existsSync(profile);
      }
    } catch (error) { failure ||= error; }
    try { require(validateApplicationRuntimeContext(root).manifest_sha256 === contextManifestSha256,
      'Browser qualification changed the closed runtime context'); } catch (error) { failure ||= error; }
  }
  if (!failure) {
    require(Object.values(result.cleanup).every((value) => value === true), 'Browser cleanup is incomplete');
    result.status = fixture ? 'fixture-passed' : 'passed';
    result.qualification.browser_startup_observed = !fixture;
    result.qualification.sdk_wasm_initialized_in_browser = !fixture;
  } else result.failure = { phase, message: boundedText(failure.message || failure) };
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  try {
    const args = process.argv.slice(2);
    require(args.shift() === '--worker', 'Browser startup is an explicit owned runtime worker');
    const options = {};
    const names = new Map([['--origin', 'origin'], ['--context', 'runtimeContext'], ['--manifest-sha256', 'contextManifestSha256'],
      ['--temporary-root', 'temporaryRoot'], ['--report', 'reportPath'], ['--channel', 'channel']]);
    while (args.length) {
      const key = names.get(args.shift());
      require(key && !Object.hasOwn(options, key) && args.length, 'Unknown, repeated or incomplete browser worker option');
      options[key] = args.shift();
    }
    require(Object.keys(options).length === names.size, 'Browser worker requires all explicit owned inputs');
    const temporary = ordinaryDirectory(options.temporaryRoot);
    require(path.isAbsolute(options.reportPath) && path.dirname(options.reportPath) === temporary
      && path.extname(options.reportPath) === '.json' && !existsSync(options.reportPath), 'Browser worker report must be new and owned by its parent');
    const result = await qualifyApplicationBrowserStartup(options);
    writeFileSync(options.reportPath, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    if (result.status !== 'passed') process.exitCode = 1;
  } catch (error) {
    console.error(`Application browser startup failed: ${boundedText(error.message || error)}`);
    process.exitCode = 1;
  }
}

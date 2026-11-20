import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  APPLICATION_BROWSER_ROUTES, applicationBrowserLaunchOptions, classifyApplicationBrowserRequest,
  qualifyApplicationBrowserStartup, validateApplicationBrowserOrigin, validateApplicationBrowserRouteEvidence,
} from './application-browser-startup.mjs';
import { APPLICATION_RETAINED_PUBLIC_FILES, APPLICATION_RESOURCE_MIME_TYPES } from './application-public-assets.mjs';
import { APPLICATION_RUNTIME_INPUTS, createApplicationRuntimeContext } from './application-runtime-context.mjs';

const ORIGIN = 'http://127.0.0.1:49152';
const ROUTE = APPLICATION_BROWSER_ROUTES[0];
const WASM = { path: 'assets/marty_api_client_bg-fixture.wasm', bytes: 8, sha256: `sha256:${'a'.repeat(64)}` };
const SPECIFICATION = { origin: ORIGIN, route: ROUTE,
  resourcePaths: ['assets/application.js', 'favicon.ico', WASM.path], wasmPath: WASM.path };
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
function request(url, changes = {}) { return { url, method: 'GET', resourceType: 'script', navigation: false, mainFrame: true, ...changes }; }
function classify(value, options = {}) { return classifyApplicationBrowserRequest({ ...SPECIFICATION, ...options }, value); }
function hash(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function temporary(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'marty-browser-control-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test('only the exact owned IPv4 loopback origin is accepted', () => {
  assert.equal(validateApplicationBrowserOrigin(ORIGIN), ORIGIN);
  for (const origin of ['https://127.0.0.1:49152', 'http://localhost:49152', 'http://[::1]:49152',
    'http://127.0.0.2:49152', 'http://127.0.0.1', `${ORIGIN}/`, `${ORIGIN}/login`, `${ORIGIN}?token=x`,
    'http://user:secret@127.0.0.1:49152', 'http://127.0.0.1:65536']) {
    assert.throws(() => validateApplicationBrowserOrigin(origin), origin);
  }
});

test('the selected document, inventoried assets and exact session read reach nginx unchanged', () => {
  assert.deepEqual(classify(request(`${ORIGIN}${ROUTE}`, { navigation: true, resourceType: 'document' })),
    { action: 'continue', disposition: 'navigation', path: 'index.html' });
  assert.deepEqual(classify(request(`${ORIGIN}/assets/application.js`)),
    { action: 'continue', disposition: 'asset', path: 'assets/application.js' });
  assert.equal(classify(request(`${ORIGIN}/favicon.ico?v=2`, { resourceType: 'image' })).action, 'continue');
  assert.deepEqual(classify(request(`${ORIGIN}/v1/auth/me`, { resourceType: 'fetch' })),
    { action: 'continue', disposition: 'session-check' });
});

test('negative control aborts only the bound SDK WASM and does not fabricate a response', () => {
  assert.deepEqual(classify(request(`${ORIGIN}/${WASM.path}`, { resourceType: 'fetch' }), { abortWasm: true }),
    { action: 'abort', disposition: 'aborted-sdk-wasm', path: WASM.path });
  assert.equal(classify(request(`${ORIGIN}/assets/application.js`), { abortWasm: true }).action, 'continue');
  assert.equal(classify(request(`${ORIGIN}/v1/auth/me`, { resourceType: 'fetch' }), { abortWasm: true }).action, 'continue');
});

test('external Google fonts are narrowly blocked and explicitly classified', () => {
  for (const url of [
    'https://fonts.googleapis.com/css?family=Roboto:300,400,500,700&display=swap',
    'https://fonts.googleapis.com/icon?family=Material+Icons',
  ]) {
    assert.deepEqual(classify(request(url, { resourceType: 'stylesheet' })), { action: 'abort', disposition: 'blocked-google-font' });
    assert.equal(classify(request(url, { resourceType: 'script' })).disposition, 'forbidden-external-request');
  }
  assert.equal(classify(request('https://fonts.gstatic.com/s/roboto/v30/font.woff2', { resourceType: 'font' })).disposition, 'blocked-google-font');
  assert.equal(classify(request('https://fonts.gstatic.com/s/roboto/v30/font.woff2?unreviewed=1', { resourceType: 'font' })).disposition, 'forbidden-external-request');
});

for (const [label, value, disposition] of [
  ['external navigation', request('https://example.test/', { navigation: true, resourceType: 'document' }), 'forbidden-navigation'],
  ['an embedded frame', request(`${ORIGIN}${ROUTE}`, { navigation: true, mainFrame: false, resourceType: 'document' }), 'forbidden-navigation'],
  ['SSO initiation', request(`${ORIGIN}/v1/auth/login?redirect_uri=/console`, { resourceType: 'fetch' }), 'forbidden-resource'],
  ['an API write', request(`${ORIGIN}/v1/auth/me`, { method: 'POST', resourceType: 'fetch' }), 'forbidden-method'],
  ['an unexpected same-origin API', request(`${ORIGIN}/v1/organizations`, { resourceType: 'fetch' }), 'forbidden-resource'],
  ['a development module', request(`${ORIGIN}/src/index.jsx`), 'forbidden-resource'],
  ['a different localhost port', request('http://127.0.0.1:49153/assets/application.js'), 'forbidden-external-request'],
  ['an unreviewed font stylesheet', request('https://fonts.googleapis.com/css?family=Other', { resourceType: 'stylesheet' }), 'forbidden-external-request'],
  ['a font-host credential', request('https://user:password@fonts.gstatic.com/s/roboto/font.woff2', { resourceType: 'font' }), 'forbidden-external-request'],
  ['a changed source query', request(`${ORIGIN}/assets/application.js?injected=true`), 'forbidden-resource'],
]) test(`blocks ${label}`, () => { assert.deepEqual(classify(value), { action: 'abort', disposition }); });

function positiveEvidence() {
  const wasm = { ...WASM, url: `${ORIGIN}/${WASM.path}`, status: 200, content_type: 'application/wasm', from_cache: false, from_service_worker: false };
  return { route: ROUTE, final_url: `${ORIGIN}${ROUTE}`, context_isolated: true, cookies_initially_empty: true,
    cache_disabled: true, context_closed: true, navigation: { url: `${ORIGIN}${ROUTE}`, status: 200,
      content_type: 'text/html', bytes: 100, content_security_policy: "default-src 'self'; script-src 'self' 'wasm-unsafe-eval';" },
    assets: [wasm], wasm, session_checks: [1, 2].map(() => ({ method: 'GET', path: '/v1/auth/me', outcome: 'http-502', status: 502, duration_ms: 10 })),
    external_requests: [], violations: [], page_errors: [], console_errors: [], aborted_wasm_requests: 0,
    ready: true, root_populated: true, heading: 'Sign-in is temporarily unavailable',
    retry: { label: 'Retry sign-in check', enabled: true, clicked: true, session_rechecked: true } };
}

function validate(evidence, negative = false) {
  return validateApplicationBrowserRouteEvidence(evidence, { origin: ORIGIN, route: ROUTE, wasm: WASM, negative });
}

test('positive evidence requires real auth-unavailable rendering and a bounded unavailable session service', () => {
  assert.equal(validate(positiveEvidence()).ready, true);
  const timeout = positiveEvidence();
  timeout.session_checks[1] = { method: 'GET', path: '/v1/auth/me', outcome: 'application-timeout', error: 'net::ERR_ABORTED', duration_ms: 15_005 };
  assert.equal(validate(timeout).session_checks[1].outcome, 'application-timeout');
});

for (const [label, mutate] of [
  ['a foreign final route', (value) => { value.final_url = 'https://example.test/'; }],
  ['a reused browser context', (value) => { value.context_isolated = false; }],
  ['an existing cookie', (value) => { value.cookies_initially_empty = false; }],
  ['a live context left behind', (value) => { value.context_closed = false; }],
  ['disabled production CSP', (value) => { value.navigation.content_security_policy = ''; }],
  ['JavaScript unsafe-eval', (value) => { value.navigation.content_security_policy += " script-src 'unsafe-eval';"; }],
  ['a missing ready state', (value) => { value.ready = false; }],
  ['an empty React root', (value) => { value.root_populated = false; }],
  ['an unrelated error heading', (value) => { value.heading = 'Something failed'; }],
  ['a disabled retry action', (value) => { value.retry.enabled = false; }],
  ['a retry without another session request', (value) => { value.session_checks.pop(); }],
  ['a session success fixture', (value) => { value.session_checks[0].status = 200; }],
  ['a fabricated early timeout', (value) => { value.session_checks[0] = { method: 'GET', path: '/v1/auth/me', outcome: 'application-timeout', error: 'net::ERR_ABORTED', duration_ms: 12 }; }],
  ['an unexpected network failure', (value) => { value.session_checks[0] = { method: 'GET', path: '/v1/auth/me', outcome: 'application-timeout', error: 'net::ERR_CONNECTION_RESET', duration_ms: 15_000 }; }],
  ['a wrong WASM hash', (value) => { value.wasm.sha256 = `sha256:${'b'.repeat(64)}`; }],
  ['a wrong WASM MIME', (value) => { value.wasm.content_type = 'application/octet-stream'; }],
  ['a cached WASM response', (value) => { value.wasm.from_cache = true; }],
  ['a service-worker WASM response', (value) => { value.wasm.from_service_worker = true; }],
  ['a script exception', (value) => { value.page_errors.push('ReferenceError'); }],
  ['an unexpected external request', (value) => { value.violations.push('forbidden-external-request'); }],
]) test(`refuses positive qualification with ${label}`, () => {
  const evidence = positiveEvidence(); mutate(evidence); assert.throws(() => validate(evidence));
});

function negativeEvidence() {
  const value = positiveEvidence();
  value.assets = [{ path: 'startup.js', status: 200, content_type: 'application/javascript', bytes: 10,
    sha256: `sha256:${'c'.repeat(64)}`, from_cache: false, from_service_worker: false }];
  value.wasm = null; value.session_checks = []; value.ready = false; value.root_populated = false;
  value.heading = null; delete value.retry; value.aborted_wasm_requests = 1;
  value.page_errors = ['TypeError: Failed to fetch'];
  value.recovery = { visible: true, title: 'ElevenID could not start',
    message: 'Part of the application could not be loaded. Reload this page to try again.',
    retry_label: 'Reload page', retry_enabled: true };
  return value;
}

test('aborting SDK WASM requires actual failure recovery without application startup', () => {
  assert.equal(validate(negativeEvidence(), true).ready, false);
});

for (const [label, mutate] of [
  ['a ready application', (value) => { value.ready = true; }],
  ['a mounted React tree', (value) => { value.root_populated = true; }],
  ['no WASM abort', (value) => { value.aborted_wasm_requests = 0; }],
  ['an unisolated second abort', (value) => { value.aborted_wasm_requests = 2; }],
  ['a completed session check', (value) => { value.session_checks.push(positiveEvidence().session_checks[0]); }],
  ['the slow-loading watchdog', (value) => { value.recovery.title = 'ElevenID is taking longer to load'; }],
  ['hidden recovery', (value) => { value.recovery.visible = false; }],
  ['a disabled reload action', (value) => { value.recovery.retry_enabled = false; }],
  ['an unrelated script failure', (value) => { value.page_errors = ['ReferenceError: unexpected is not defined']; }],
]) test(`refuses the negative control with ${label}`, () => {
  const evidence = negativeEvidence(); mutate(evidence); assert.throws(() => validate(evidence, true));
});

test('launch options keep the sandbox and a newly owned profile with no custom browser arguments', (t) => {
  const profileDirectory = temporary(t);
  const logger = () => () => {};
  assert.deepEqual(applicationBrowserLaunchOptions({ profileDirectory, logger }), {
    headless: true, channel: 'chrome', userDataDir: profileDirectory, timeout: 20_000,
    protocolTimeout: 20_000, acceptInsecureCerts: false, logger,
  });
  assert.throws(() => applicationBrowserLaunchOptions({ profileDirectory, channel: 'chrome-beta' }), /reviewed sandboxed Chrome/);
});

function contextFixture(t) {
  const temporaryRoot = temporary(t);
  const sourceRoot = path.join(temporaryRoot, 'source');
  const outputRoot = path.join(temporaryRoot, 'output');
  mkdirSync(sourceRoot); mkdirSync(outputRoot);
  function write(directory, relative, bytes) {
    const target = path.join(directory, relative);
    mkdirSync(path.dirname(target), { recursive: true }); writeFileSync(target, bytes); chmodSync(target, 0o644);
  }
  for (const input of APPLICATION_RUNTIME_INPUTS) write(sourceRoot, input.path, readFileSync(path.join(ROOT, input.path)));
  for (const relative of APPLICATION_RETAINED_PUBLIC_FILES) write(outputRoot, relative, readFileSync(path.join(ROOT, 'ui/public', relative)));
  for (const relative of ['index.html', 'console/index.html']) write(outputRoot, relative, '<html><body>fixture</body></html>\n');
  write(outputRoot, 'assets/application.js', 'export const fixture = true;\n');
  write(outputRoot, WASM.path, Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
  write(outputRoot, 'marty-web-routes.json', JSON.stringify({ schema: 'marty.application-web-compatibility/v1',
    surface: 'application', source_sha: 'd'.repeat(40), route_contract: {} }));
  function inventory(directory, relative = '') {
    return readdirSync(path.join(directory, relative), { withFileTypes: true }).flatMap((entry) => {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) return inventory(directory, name);
      const bytes = readFileSync(path.join(directory, name));
      return [{ path: name, bytes: bytes.length, sha256: hash(bytes), mode: lstatSync(path.join(directory, name)).mode & 0o777 }];
    }).sort((a, b) => a.path.localeCompare(b.path, 'en'));
  }
  const files = inventory(outputRoot);
  const byteRecord = ({ path: relative, bytes, sha256 }) => ({ path: relative, bytes, sha256 });
  const publicResources = APPLICATION_RETAINED_PUBLIC_FILES.map((relative) => byteRecord(files.find((item) => item.path === relative)));
  const resourceResult = { schema: 'marty.application-resource-smoke/v1', status: 'passed', public_resources: publicResources,
    served_resources: files.filter((item) => item.path !== 'marty-web-routes.json').map((item) => ({ ...byteRecord(item),
      status: 200, content_type: APPLICATION_RESOURCE_MIME_TYPES[path.extname(item.path)][0] })),
    preview: { closed: true }, qualification: { resources_served: true, locale_fallback_observed: true,
      browser_startup_observed: false, host_deployment_tested: false, oidc_journey_tested: false } };
  const runtimeContext = path.join(temporaryRoot, 'context');
  const created = createApplicationRuntimeContext({ sourceRoot, outputRoot, destination: runtimeContext, sourceCommit: 'd'.repeat(40),
    outputInventory: { files, inventory_sha256: hash(canonical(files)), public_resources: publicResources }, resourceResult });
  return { origin: ORIGIN, runtimeContext, contextManifestSha256: created.manifest_sha256, temporaryRoot, channel: 'chrome' };
}

test('a rejected launch retains uncertain process state for its parent and cannot claim qualification', async (t) => {
  const options = contextFixture(t);
  let profile;
  const result = await qualifyApplicationBrowserStartup(options, { driverLoader: async () => ({
    executable: 'fixture-chrome', puppeteer_version: 'fixture', launch: async (launchOptions) => {
      profile = launchOptions.userDataDir; assert.equal(existsSync(profile), true); throw new Error('controlled launch failure');
    },
  }) });
  assert.equal(result.status, 'failed'); assert.equal(result.fixture, true);
  assert.equal(result.failure.phase, 'launch'); assert.match(result.failure.message, /controlled launch failure/);
  assert.equal(result.cleanup.profile_removed, false); assert.equal(existsSync(profile), true);
  assert.ok(Object.values(result.qualification).every((value) => value === false));
});

test('a post-launch failure still closes Chromium and removes its owned profile', async (t) => {
  const options = contextFixture(t);
  const child = { pid: 12345, spawnargs: ['fixture-chrome'], exitCode: null, signalCode: null };
  let closed = false;
  const result = await qualifyApplicationBrowserStartup(options, { driverLoader: async () => ({
    executable: 'fixture-chrome', puppeteer_version: 'fixture', launch: async () => ({
      process: () => child, version: async () => { throw new Error('controlled handshake failure'); },
      close: async () => { closed = true; child.exitCode = 0; },
    }),
  }) });
  assert.equal(result.status, 'failed'); assert.equal(result.fixture, true); assert.equal(closed, true);
  assert.equal(result.cleanup.browser_closed, true); assert.equal(result.cleanup.chromium_exited, true);
  assert.equal(result.cleanup.profile_removed, true);
  assert.ok(Object.values(result.qualification).every((value) => value === false));
});

test('context identity mismatch fails before loading browser tooling', async (t) => {
  const options = contextFixture(t);
  let loaded = false;
  await assert.rejects(qualifyApplicationBrowserStartup({ ...options, contextManifestSha256: `sha256:${'0'.repeat(64)}` },
    { driverLoader: async () => { loaded = true; throw new Error('must not load'); } }), /differs from its owning runtime check/);
  assert.equal(loaded, false);
});
